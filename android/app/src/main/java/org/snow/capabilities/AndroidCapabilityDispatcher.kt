package org.snow.capabilities

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
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
    val mediaControlHandler = MediaControlHandler(context)
    val linkShareHandler = LinkShareHandler(context)
    val screenCaptureHandler = ScreenCaptureHandler(context, transferClientProvider)
    val cameraCaptureHandler = CameraCaptureHandler(context, transferClientProvider)

    var activePermissionProfile: String = "full_control"

    fun isActionAllowedByProfile(action: String): Boolean {
        return when (activePermissionProfile.lowercase()) {
            "clipboard_only" -> {
                action in setOf(
                    "battery_status", "android_battery", "android_battery_status",
                    "clipboard_pull", "clipboard_push", "android_clipboard_pull",
                    "android_clipboard_push", "android_clipboard_get", "android_clipboard_set"
                )
            }
            "files_and_clipboard" -> {
                action in setOf(
                    "battery_status", "android_battery", "android_battery_status",
                    "clipboard_pull", "clipboard_push", "android_clipboard_pull",
                    "android_clipboard_push", "android_clipboard_get", "android_clipboard_set",
                    "file_list", "android_file_list", "file_send_request", "file_receive_request",
                    "android_file_receive", "ring_phone", "android_ring"
                )
            }
            else -> true // full_control
        }
    }

    /**
     * Centralized pre-execution contract check validating OS constraints, runtime
     * permissions, and foreground requirements before invoking any handler.
     *
     * Returns null if all execution contract requirements are satisfied.
     * Returns a structured rejection map if any requirement fails.
     */
    fun validateExecutionContract(action: String, data: Map<String, Any?>?): Map<String, Any?>? {
        if (!isActionAllowedByProfile(action)) {
            return mapOf(
                "success" to false,
                "status" to "PERMISSION_DENIED",
                "error" to "Action '$action' is blocked by permission profile '$activePermissionProfile'.",
                "remediation_hint" to "Switch permission profile to 'Full Control' in SNOW device settings."
            )
        }
        when (action) {
            "android_screenshot", "screen_capture" -> {
                if (!screenCaptureHandler.hasConsent()) {
                    val reqIntent = Intent(context, org.snow.ui.MainActivity::class.java).apply {
                        this.action = Intent.ACTION_MAIN
                        addCategory(Intent.CATEGORY_LAUNCHER)
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                        putExtra("request_screen_capture", true)
                    }
                    ActionNotificationHelper.postActionNotification(
                        context = context,
                        title = "Screen Capture Requested",
                        content = "Your paired PC requested a one-time screen capture. Tap to review and grant permission.",
                        intent = reqIntent
                    )
                    return mapOf(
                        "success" to false,
                        "status" to "SCREEN_CAPTURE_CONSENT_REQUIRED",
                        "error" to "MediaProjection consent has not been granted by user. Action notification posted.",
                        "remediation_hint" to "Tap the notification on your Android device to authorize one-time screen capture."
                    )
                }
            }
            "android_camera_capture", "camera_capture" -> {
                if (!cameraCaptureHandler.hasCameraPermission()) {
                    return mapOf(
                        "success" to false,
                        "status" to "CAMERA_PERMISSION_REQUIRED",
                        "error" to "Camera runtime permission has not been granted by user.",
                        "remediation_hint" to "Grant Camera permission in Android Settings."
                    )
                }
                if (!cameraCaptureHandler.isInteractionPermitted() && CameraCaptureHandler.mockBitmapProvider == null) {
                    return mapOf(
                        "success" to false,
                        "status" to "FOREGROUND_USER_INTERACTION_REQUIRED",
                        "error" to "Camera capture requires SNOW to be in the foreground with active visible user interaction.",
                        "remediation_hint" to "Open SNOW on your Android phone and confirm camera capture."
                    )
                }
            }
            "clipboard_pull" -> {
                if (!ClipboardHandler.isAppInForeground) {
                    return mapOf(
                        "success" to false,
                        "status" to "FOREGROUND_REQUIRED",
                        "error" to "Android OS requires SNOW to be in the foreground to access the clipboard.",
                        "remediation_hint" to "Bring SNOW to the foreground on the Android device."
                    )
                }
                val instantSyncEnabled = try {
                    context.getSharedPreferences(org.snow.ui.SnowUiRepository.PREFS_SETTINGS, android.content.Context.MODE_PRIVATE)
                        ?.getBoolean(org.snow.ui.SnowUiRepository.PREF_KEY_INSTANT_SYNC, false) ?: false
                } catch (_: Exception) {
                    false
                }
                if (!ClipboardHandler.isUserIntentGranted && !instantSyncEnabled) {
                    return mapOf(
                        "success" to false,
                        "status" to "USER_CONFIRMATION_REQUIRED",
                        "error" to "Explicit user confirmation is required to read Android clipboard.",
                        "remediation_hint" to "Confirm clipboard read intent on the Android device or enable Instant Sync in settings."
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
                "FOREGROUND_REQUIRED",
                "RUNTIME_PERMISSION_REQUIRED",
                "PERMISSION_DENIED",
                "USER_CONFIRMATION_REQUIRED",
                "SCREEN_CAPTURE_CONSENT_REQUIRED",
                "CAMERA_PERMISSION_REQUIRED",
                "FOREGROUND_USER_INTERACTION_REQUIRED" -> ErrorCode.UNAUTHORIZED
                else -> ErrorCode.INVALID_PAYLOAD
            }
            return Pair(null, SnowError(code = code, message = "$status: $errorMsg ($hint)"))
        }

        // 2. Handler execution
        return when (action) {
            "battery_status", "android_battery", "android_battery_status", "snow_android_battery" -> {
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
            "clipboard_buffer_updated" -> {
                try {
                    org.snow.ui.SnowUiRepository.getInstance(context).fetchClipboardBuffer()
                } catch (_: Exception) {}
                Pair(mapOf("status" to "success", "action" to "clipboard_buffer_updated"), null)
            }
            "clipboard_push" -> {
                val type = data?.get("type") as? String
                if (type == "image") {
                    val transferId = data?.get("transfer_id") as? String
                    val sha256 = data?.get("sha256") as? String ?: ""
                    val transferPort = (data?.get("transfer_port") as? Number)?.toInt() ?: defaultTransferPort
                    val mimeType = (data?.get("mime_type") as? String)?.lowercase() ?: "image/png"
                    val ext = if (mimeType.contains("jpeg") || mimeType.contains("jpg")) "jpg" else "png"
                    val host = serverHost
                    val transferClient = transferClientProvider()
                    if (transferClient != null && transferId != null && host.isNotBlank()) {
                        val cacheDir = ClipboardHandler.getClipboardCacheDir(context)
                        val fileName = "clip_${sha256.take(16)}.$ext"
                        val localFile = File(cacheDir, fileName)
                        ClipboardHandler.pruneImageCache(cacheDir, preserveFileName = fileName)

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
                                val resolvedMime = if (ext == "jpg") "image/jpeg" else "image/png"
                                withContext(Dispatchers.Main) {
                                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    val clip = android.content.ClipData(
                                        android.content.ClipDescription("SNOW Image", arrayOf(resolvedMime)),
                                        android.content.ClipData.Item(contentUri)
                                    )
                                    cm.setPrimaryClip(clip)
                                }
                                ClipboardHandler.grantImeUriPermission(context, contentUri)
                                val isUserInitiated = (data?.get("user_initiated") == true)
                                ClipboardHandler.postShareFallbackNotification(
                                    context,
                                    contentUri,
                                    resolvedMime,
                                    isUserInitiated = isUserInitiated
                                )

                                org.snow.ui.SnowUiRepository.getInstance(context).recordIncomingClipboardText(sha256)
                                SafeLog.i(TAG, "Pushed image to Android clipboard via FileProvider ($resolvedMime).")
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
                val principal = data?.get("principal") as? String
                val res = appLauncherHandler.launchApp(packageName, principal)
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
            "file_list" -> {
                val res = fileHandler.handleFileList(data)
                Pair(res, null)
            }
            "notifications_list" -> {
                val isOpted = org.snow.service.SnowNotificationListenerService.isOptedIn(context)
                val isGranted = org.snow.ui.settings.SettingsFragment.isNotificationServiceEnabled(context)
                if (!isGranted) {
                    Pair(mapOf("status" to "PERMISSION_NOT_GRANTED", "error" to "Notification access not granted in Android system settings.", "notifications" to emptyList<Any>(), "count" to 0), null)
                } else if (!isOpted) {
                    Pair(mapOf("status" to "SYNC_OPT_OUT", "error" to "Notification synchronization is disabled in SNOW settings.", "notifications" to emptyList<Any>(), "count" to 0), null)
                } else {
                    var notifs = org.snow.service.SnowNotificationListenerService.liveNotifications
                    if (notifs.isEmpty()) {
                        org.snow.service.SnowNotificationListenerService.instance?.refreshActiveNotifications()
                        notifs = org.snow.service.SnowNotificationListenerService.liveNotifications
                    }
                    Pair(mapOf("status" to "success", "notifications" to notifs, "count" to notifs.size), null)
                }
            }
            "notification_dismiss" -> {
                val key = data?.get("key") as? String ?: ""
                if (key.isBlank()) {
                    Pair(mapOf("status" to "error", "error" to "Notification key is required."), null)
                } else {
                    val res = org.snow.service.SnowNotificationListenerService.dismissNotification(key)
                    Pair(res, null)
                }
            }
            "notification_reply" -> {
                val key = data?.get("key") as? String ?: ""
                val text = data?.get("text") as? String ?: ""
                if (key.isBlank() || text.isBlank()) {
                    Pair(mapOf("status" to "error", "error" to "Notification key and non-empty reply text are required."), null)
                } else {
                    val res = org.snow.service.SnowNotificationListenerService.replyToNotification(key, text)
                    Pair(res, null)
                }
            }
            "media_control" -> {
                val act = data?.get("action") as? String
                val res = mediaControlHandler.handleMediaControl(act)
                Pair(res, null)
            }
            "share_link" -> {
                val url = data?.get("url") as? String
                val text = data?.get("text") as? String
                val res = linkShareHandler.handleShareLink(url, text)
                Pair(res, null)
            }
            "android_screenshot", "screen_capture" -> {
                val res = screenCaptureHandler.captureScreen(serverHost = serverHost, transferPort = defaultTransferPort)
                if (res["success"] == true) {
                    Pair(res, null)
                } else {
                    val code = if (res["status"] == "SCREEN_CAPTURE_CONSENT_REQUIRED") ErrorCode.UNAUTHORIZED else ErrorCode.INTERNAL_ERROR
                    Pair(null, SnowError(code = code, message = "${res["status"]}: ${res["error"] ?: "Screen capture failed"}"))
                }
            }
            "android_camera_capture", "camera_capture" -> {
                val res = cameraCaptureHandler.capturePhoto(serverHost = serverHost, transferPort = defaultTransferPort)
                if (res["success"] == true) {
                    Pair(res, null)
                } else {
                    val code = when (res["status"]) {
                        "CAMERA_PERMISSION_REQUIRED", "FOREGROUND_USER_INTERACTION_REQUIRED" -> ErrorCode.UNAUTHORIZED
                        else -> ErrorCode.INTERNAL_ERROR
                    }
                    Pair(null, SnowError(code = code, message = "${res["status"]}: ${res["error"] ?: "Camera capture failed"}"))
                }
            }
            "screen_stream_stop" -> {
                org.snow.service.SnowForegroundService.stopScreenShare(context)
                Pair(mapOf("status" to "success", "action" to "screen_stream_stop"), null)
            }
            "approval_event" -> {
                val eventType = data?.get("event_type") as? String ?: ""
                val appReq = data?.get("request") as? Map<*, *>
                val reqId = appReq?.get("request_id") as? String ?: ""
                if (eventType == "APPROVAL_REQUESTED" && reqId.isNotBlank() && appReq != null) {
                    val principal = appReq["principal"] as? String ?: "AI Assistant"
                    val operation = appReq["action"] as? String ?: "Operation"
                    val riskLevel = appReq["risk_level"] as? String ?: "MEDIUM"
                    ActionNotificationHelper.postApprovalNotification(
                        context = context,
                        requestId = reqId,
                        principal = principal,
                        operation = operation,
                        riskLevel = riskLevel,
                    )
                } else if (eventType == "APPROVAL_RESOLVED" && reqId.isNotBlank()) {
                    ActionNotificationHelper.cancelApprovalNotification(context, reqId)
                }
                Pair(mapOf("status" to "success"), null)
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
