package org.snow.capabilities

import android.content.Context
import org.snow.protocol.ErrorCode
import org.snow.protocol.SnowError
import org.snow.security.SafeLog
import org.snow.transfer.FileTransferClient

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

    suspend fun dispatch(
        action: String,
        data: Map<String, Any?>?,
        serverHost: String,
        defaultTransferPort: Int
    ): Pair<Map<String, Any?>?, SnowError?> {
        SafeLog.i(TAG, "Dispatching capability request action='$action'")
        return when (action) {
            "battery_status" -> {
                val res = batteryHandler.getBatteryStatus()
                Pair(res, null)
            }
            "ring_phone" -> {
                val duration = (data?.get("duration_seconds") as? Number)?.toInt() ?: RingerHandler.DEFAULT_DURATION_SECONDS
                val res = ringerHandler.ringPhone(duration)
                if (res["status"] == "success") {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = res["error"] as? String ?: "Ring failed"))
                }
            }
            "clipboard_push" -> {
                val text = data?.get("text") as? String
                val res = clipboardHandler.pushClipboard(text)
                if (res["status"] == "success") {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.INVALID_PAYLOAD, message = res["error"] as? String ?: "Clipboard push failed"))
                }
            }
            "list_apps" -> {
                val limit = (data?.get("limit") as? Number)?.toInt() ?: AppLauncherHandler.DEFAULT_APP_LIMIT
                val res = appLauncherHandler.listApps(limit)
                if (res["status"] == "success") {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = res["error"] as? String ?: "List apps failed"))
                }
            }
            "launch_app" -> {
                val packageName = data?.get("package_name") as? String
                val res = appLauncherHandler.launchApp(packageName)
                if (res["status"] == "success") {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.UNSUPPORTED_ACTION, message = res["error"] as? String ?: "App launch failed"))
                }
            }
            "file_send_request" -> {
                val res = fileHandler.handleFileSendRequest(data, serverHost, defaultTransferPort)
                if (res["status"] == "success") {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = res["error"] as? String ?: "File receive failed"))
                }
            }
            "file_receive_request" -> {
                val res = fileHandler.handleFileReceiveRequest(data, serverHost, defaultTransferPort)
                if (res["status"] == "success") {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.FILE_NOT_FOUND, message = res["error"] as? String ?: "File send failed"))
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
