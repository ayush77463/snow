package org.snow.capabilities

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.protocol.ErrorCode
import org.snow.protocol.SnowError
import org.snow.security.SafeLog
import org.snow.transfer.FileTransferClient
import java.io.File

/**
 * Central router dispatching incoming SNOW Device Protocol v1 requests to
 * appropriate Android capability handlers.
 */
class AndroidCapabilityDispatcher(
    private val context: Context,
    private val transferClientProvider: () -> FileTransferClient?
) {
    companion object {
        private const val TAG = "CapabilityDispatcher"
    }

    val batteryHandler = BatteryHandler(context)
    val ringerHandler = RingerHandler(context)
    val clipboardHandler = ClipboardHandler(context)
    val appLauncherHandler = AppLauncherHandler(context)
    val fileHandler = AndroidFileHandler(context, transferClientProvider)
    val messagingHandler = MessagingHandler(context)

    /**
     * Centralized pre-execution contract check validating OS constraints, runtime
     * permissions, and foreground requirements before invoking any handler.
     *
     * Returns null if all execution contract requirements are satisfied.
     * Returns a structured rejection map if any requirement fails.
     */
    fun validateExecutionContract(action: String, data: Map<String, Any?>?): Map<String, Any?>? {
        when (action) {
            "clipboard_pull" -> {
                if (!ClipboardHandler.isAppInForeground) {
                    return mapOf(
                        "success" to false,
                        "status" to "FOREGROUND_REQUIRED",
                        "error" to "Android OS requires SNOW to be in the foreground to access the clipboard.",
                        "remediation_hint" to "Bring SNOW to the foreground on the Android device."
                    )
                }
                if (!ClipboardHandler.isUserIntentGranted) {
                    return mapOf(
                        "success" to false,
                        "status" to "USER_CONFIRMATION_REQUIRED",
                        "error" to "Explicit user confirmation is required to read Android clipboard.",
                        "remediation_hint" to "Confirm clipboard read intent on the Android device."
                    )
                }
            }
            "launch_app" -> {
                if (!ClipboardHandler.isAppInForeground && !ActionNotificationHelper.canPostNotifications(context)) {
                    return mapOf(
                        "success" to false,
                        "status" to "FOREGROUND_REQUIRED",
                        "error" to "Background activity launch restricted by Android OS. Notification permission is required to deliver tap action.",
                        "remediation_hint" to "Open SNOW on your phone or grant Notification permission in Android Settings to launch applications."
                    )
                }
            }
            "send_message" -> {
                val mode = (data?.get("mode") as? String)?.trim()?.lowercase() ?: MessagingHandler.MODE_INTENT
                val userConfirmed = (data?.get("user_confirmed") as? Boolean) ?: false
                if (mode == MessagingHandler.MODE_SMS && !userConfirmed) {
                    return mapOf(
                        "success" to false,
                        "status" to "USER_CONFIRMATION_REQUIRED",
                        "error" to "Direct SMS dispatch requires explicit on-device user confirmation.",
                        "remediation_hint" to "Confirm SMS dispatch intent on the Android device."
                    )
                }
                if (!ClipboardHandler.isAppInForeground && !ActionNotificationHelper.canPostNotifications(context)) {
                    return mapOf(
                        "success" to false,
                        "status" to "FOREGROUND_REQUIRED",
                        "error" to "Background messaging compose restricted by Android OS. Notification permission is required to deliver tap action.",
                        "remediation_hint" to "Open SNOW on your phone or grant Notification permission in Android Settings to send messages."
                    )
                }
            }
        }
        return null
    }

    suspend fun dispatch(
        action: String,
        data: Map<String, Any?>?,
        serverHost: String = "127.0.0.1",
        defaultTransferPort: Int = 8766
    ): Pair<Map<String, Any?>?, SnowError?> {
        SafeLog.i(TAG, "Dispatching capability request action='$action'")

        // 1. Centralized execution contract check
        val contractViolation = validateExecutionContract(action, data)
        if (contractViolation != null) {
            val status = contractViolation["status"] as? String ?: "CONTRACT_VIOLATION"
            val errorMsg = contractViolation["error"] as? String ?: "Execution contract check failed."
            val hint = contractViolation["remediation_hint"] as? String ?: ""
            val code = when (status) {
                "FOREGROUND_REQUIRED", "RUNTIME_PERMISSION_REQUIRED", "PERMISSION_DENIED", "USER_CONFIRMATION_REQUIRED" -> ErrorCode.UNAUTHORIZED
                else -> ErrorCode.INVALID_PAYLOAD
            }
            return Pair(null, SnowError(code = code, message = "$status: $errorMsg ($hint)"))
        }

        // 2. Handler execution
        return when (action) {
            "battery_status" -> {
                val res = batteryHandler.getBatteryStatus()
                Pair(res, null)
            }
            "ring_phone" -> {
                val duration = (data?.get("duration_seconds") as? Number)?.toInt() ?: RingerHandler.DEFAULT_DURATION_SECONDS
                val res = ringerHandler.ringPhone(duration)
                if (res["status"] == "success" || res["success"] == true) {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = res["error"] as? String ?: "Ring failed"))
                }
            }
            "clipboard_push" -> {
                val type = data?.get("type") as? String
                if (type == "image") {
                    val transferId = data?.get("transfer_id") as? String
                    val sha256 = data?.get("sha256") as? String ?: ""
                    val transferPort = (data?.get("transfer_port") as? Number)?.toInt() ?: defaultTransferPort
                    val host = serverHost
                    val transferClient = transferClientProvider()
                    if (transferClient != null && transferId != null && host.isNotBlank()) {
                        val cacheDir = File(context.cacheDir, "clipboard").apply { mkdirs() }
                        val localFile = File(cacheDir, "clip_${sha256.take(16)}.png")
                        val dlRes = transferClient.downloadFile(
                            serverHost = host,
                            transferPort = transferPort,
                            transferId = transferId,
                            destinationFile = localFile,
                            expectedSha256 = sha256
                        )
                        if (dlRes is FileTransferClient.TransferResult.Success) {
                            try {
                                val contentUri = FileProvider.getUriForFile(
                                    context,
                                    "${context.packageName}.fileprovider",
                                    dlRes.file
                                )
                                withContext(Dispatchers.Main) {
                                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    val clip = ClipData.newUri(context.contentResolver, "Image", contentUri)
                                    cm.setPrimaryClip(clip)
                                }
                                org.snow.ui.SnowUiRepository.getInstance(context).recordIncomingClipboardText(sha256)
                                SafeLog.i(TAG, "Pushed image to Android clipboard via FileProvider.")
                                Pair(mapOf("status" to "success", "type" to "image"), null)
                            } catch (e: Exception) {
                                SafeLog.e(TAG, "Failed placing image on Android clipboard: ${e.message}", e)
                                Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = "Failed setting image clip"))
                            }
                        } else {
                            Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = "Failed downloading clipboard image"))
                        }
                    } else {
                        Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = "Transfer client not ready"))
                    }
                } else {
                    val text = data?.get("text") as? String
                    try {
                        org.snow.ui.SnowUiRepository.getInstance(context).recordIncomingClipboardText(text)
                    } catch (_: Exception) {}
                    val res = clipboardHandler.pushClipboard(text)
                    if (res["status"] == "success" || res["success"] == true) {
                        Pair(res, null)
                    } else {
                        Pair(null, SnowError(code = ErrorCode.INVALID_PAYLOAD, message = res["error"] as? String ?: "Clipboard push failed"))
                    }
                }
            }
            "clipboard_pull" -> {
                val res = clipboardHandler.pullClipboard()
                if (res["status"] == "success" || res["success"] == true) {
                    Pair(res, null)
                } else {
                    val errType = res["error"] as? String ?: "CLIPBOARD_PULL_FAILED"
                    val code = when (errType) {
                        "FOREGROUND_REQUIRED", "USER_CONFIRMATION_REQUIRED" -> ErrorCode.UNAUTHORIZED
                        else -> ErrorCode.INVALID_PAYLOAD
                    }
                    val msg = res["message"] as? String ?: errType
                    Pair(null, SnowError(code = code, message = "$errType: $msg"))
                }
            }
            "list_apps" -> {
                val limit = (data?.get("limit") as? Number)?.toInt() ?: AppLauncherHandler.DEFAULT_APP_LIMIT
                val res = appLauncherHandler.listApps(limit)
                if (res["status"] == "success" || res["success"] == true) {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = res["error"] as? String ?: "List apps failed"))
                }
            }
            "launch_app" -> {
                val packageName = data?.get("package_name") as? String
                val res = appLauncherHandler.launchApp(packageName)
                if (res["status"] == "success" || res["success"] == true) {
                    Pair(res, null)
                } else {
                    val status = res["status"] as? String ?: "error"
                    val code = when (status) {
                        "POLICY_DENIED" -> ErrorCode.UNAUTHORIZED
                        "PERMISSION_DENIED" -> ErrorCode.UNAUTHORIZED
                        "FOREGROUND_REQUIRED" -> ErrorCode.UNAUTHORIZED
                        "MALFORMED_PACKAGE_NAME" -> ErrorCode.INVALID_PAYLOAD
                        else -> ErrorCode.FILE_NOT_FOUND
                    }
                    Pair(null, SnowError(code = code, message = "$status: ${res["message"] ?: res["error"] ?: "App launch failed"}"))
                }
            }
            "file_send_request" -> {
                val res = fileHandler.handleFileSendRequest(data, serverHost, defaultTransferPort)
                if (res["status"] == "success" || res["success"] == true) {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = res["error"] as? String ?: "File receive failed"))
                }
            }
            "file_receive_request" -> {
                val res = fileHandler.handleFileReceiveRequest(data, serverHost, defaultTransferPort)
                if (res["status"] == "success" || res["success"] == true) {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.FILE_NOT_FOUND, message = res["error"] as? String ?: "File send failed"))
                }
            }
            "send_message" -> {
                val recipient = data?.get("recipient") as? String
                val message = data?.get("message") as? String
                val mode = (data?.get("mode") as? String) ?: MessagingHandler.MODE_INTENT
                val userConfirmed = (data?.get("user_confirmed") as? Boolean) ?: false
                val res = messagingHandler.sendMessage(recipient, message, mode, userConfirmed)
                if (res["status"] == "success" || res["success"] == true) {
                    Pair(res, null)
                } else {
                    val err = res["error"] as? String ?: "SEND_FAILED"
                    val isPerm = err in setOf("PERMISSION_REQUIRED", "USER_CONFIRMATION_REQUIRED", "FOREGROUND_REQUIRED", "UNSUPPORTED_MODE")
                    val code = if (isPerm) ErrorCode.UNAUTHORIZED else ErrorCode.INVALID_PAYLOAD
                    Pair(null, SnowError(code = code, message = "$err: ${res["message"] ?: res["error"] ?: "Send message failed"}"))
                }
            }
            else -> {
                Pair(
                    null,
                    SnowError(
                        code = ErrorCode.UNSUPPORTED_ACTION,
                        message = "Unsupported action '$action' on Android client."
                    )
                )
            }
        }
    }
}
