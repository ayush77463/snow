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
    var transferStatusReporter: ((Map<String, Any?>) -> Unit)? = null
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
        val norm = activePermissionProfile.trim().lowercase()
        val telemetry = setOf("battery_status", "android_battery", "android_battery_status")
        val clipboard = setOf(
            "clipboard_pull", "clipboard_push", "android_clipboard_pull",
            "android_clipboard_push", "android_clipboard_get", "android_clipboard_set",
            "clipboard_buffer_updated", "clipboard_buffer_list", "clipboard_ack"
        )
        val files = setOf(
            "file_list", "android_file_list", "file_send_request",
            "file_receive_request", "android_file_receive", "ring_phone", "android_ring",
            "transfer_cancel", "file_transfer_cancel"
        )
        return when (norm) {
            "not_allowed" -> false
            "clipboard_only" -> action in (telemetry + clipboard)
            "files_only" -> action in (telemetry + files)
            "files_and_clipboard" -> action in (telemetry + clipboard + files)
            "full_control" -> true
            else -> false // Fail closed on unknown tier
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
                    val reqIntent = Intent(context, org.snow.ui.MainActivity::class.java).apply {
                        this.action = Intent.ACTION_MAIN
                        addCategory(Intent.CATEGORY_LAUNCHER)
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                        putExtra("request_camera_capture", true)
                    }
                    if (ClipboardHandler.isAppInForeground) {
                        try {
                            context.startActivity(reqIntent)
                        } catch (_: Exception) {}
                    } else {
                        ActionNotificationHelper.postActionNotification(
                            context = context,
                            title = "Camera Photo Requested",
                            content = "Tap to grant camera permission and capture photo for PC",
                            intent = reqIntent
                        )
                    }
                    return mapOf(
                        "success" to false,
                        "status" to "CAMERA_PERMISSION_REQUIRED",
                        "error" to "Camera runtime permission has not been granted by user.",
                        "remediation_hint" to "Grant Camera permission in Android Settings."
                    )
                }
                if (!cameraCaptureHandler.isInteractionPermitted() && CameraCaptureHandler.mockBitmapProvider == null) {
                    val reqIntent = Intent(context, org.snow.ui.MainActivity::class.java).apply {
                        this.action = Intent.ACTION_MAIN
                        addCategory(Intent.CATEGORY_LAUNCHER)
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                        putExtra("request_camera_capture", true)
                    }
                    if (ClipboardHandler.isAppInForeground) {
                        try {
                            context.startActivity(reqIntent)
                        } catch (_: Exception) {
                            ActionNotificationHelper.postActionNotification(
                                context = context,
                                title = "Camera Photo Requested",
                                content = "Tap to capture & send to PC",
                                intent = reqIntent
                            )
                        }
                        return mapOf(
                            "success" to false,
                            "status" to "FOREGROUND_USER_INTERACTION_REQUIRED",
                            "error" to "Camera shutter opened on phone; awaiting explicit user capture confirmation.",
                            "remediation_hint" to "Capture and confirm the photo on your phone camera screen."
                        )
                    } else {
                        ActionNotificationHelper.postActionNotification(
                            context = context,
                            title = "Camera Photo Requested",
                            content = "Tap to capture & send to PC",
                            intent = reqIntent
                        )
                        return mapOf(
                            "success" to false,
                            "status" to "FOREGROUND_USER_INTERACTION_REQUIRED",
                            "error" to "Camera capture requires SNOW to be in the foreground with active visible user interaction. Action notification posted.",
                            "remediation_hint" to "Tap 'Camera Photo Requested' on your phone to capture & send to PC."
                        )
                    }
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
                        ?.getBoolean(org.snow.ui.SnowUiRepository.PREF_KEY_INSTANT_SYNC, true) ?: true
                } catch (_: Exception) {
                    true
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
                        "error" to "Background activity launch requires Notification permission for tap-to-open delivery.",
                        "remediation_hint" to "Enable Notifications for SNOW to open requested apps via tap-to-open notification."
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
                handleIncomingClipboardPush(
                    data = data,
                    serverHost = serverHost,
                    defaultTransferPort = defaultTransferPort,
                    transferClient = transferClientProvider()
                )
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
                val res = fileHandler.handleFileSendRequest(
                    data = data,
                    serverHost = serverHost,
                    defaultTransferPort = defaultTransferPort,
                    completionNotifier = transferStatusReporter
                )
                if (res["status"] == "success" || res["status"] == "accepted" || res["success"] == true) {
                    Pair(res, null)
                } else {
                    Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = res["error"] as? String ?: "File receive failed"))
                }
            }
            "transfer_cancel", "file_transfer_cancel" -> {
                val transferId = (data?.get("transfer_id") as? String)?.trim().orEmpty()
                if (transferId.isBlank()) {
                    Pair(null, SnowError(code = ErrorCode.INVALID_PAYLOAD, message = "transfer_id is required"))
                } else {
                    val cancelled = fileHandler.cancelTransfer(transferId)
                    Pair(mapOf("status" to "cancelled", "transfer_id" to transferId, "cancelled" to cancelled), null)
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
                val isGranted = org.snow.service.SnowNotificationListenerService.isNotificationServiceEnabled(context)
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
                val key = (data?.get("key") as? String)
                    ?: (data?.get("notification_key") as? String)
                    ?: ""
                val text = (data?.get("text") as? String)
                    ?: (data?.get("reply_text") as? String)
                    ?: ""
                if (key.isBlank() || text.isBlank()) {
                    Pair(mapOf("status" to "error", "error" to "Notification key and non-empty reply text are required."), null)
                } else {
                    val res = org.snow.service.SnowNotificationListenerService.replyToNotification(key, text)
                    Pair(res, null)
                }
            }
            "whatsapp_send", "android_whatsapp_send", "snow_android_whatsapp_send" -> {
                val recipient = data?.get("recipient") as? String
                val message = data?.get("message") as? String
                val userConfirmed = (data?.get("user_confirmed") as? Boolean) ?: false
                val res = WhatsAppHandler(context).composeWhatsApp(recipient, message, userConfirmed)
                Pair(res, null)
            }
            "android_dnd_toggle", "snow_android_dnd_toggle", "dnd_toggle" -> {
                val enabled = data?.get("enabled") as? Boolean
                if (enabled == null) {
                    Pair(mapOf("status" to "error", "error" to "INVALID_ARGUMENT", "message" to "Boolean 'enabled' is required."), null)
                } else {
                    val res = DndHandler(context).toggleDnd(enabled)
                    Pair(res, null)
                }
            }
            "media_control" -> {
                val act = data?.get("action") as? String
                val volValue = data?.get("value") as? Number
                val res = mediaControlHandler.handleMediaControl(act, volValue)
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
            "screen_stream_stop", "android_screen_stream_stop" -> {
                org.snow.service.SnowForegroundService.stopScreenShare(context)
                Pair(mapOf("status" to "success", "action" to "screen_stream_stop"), null)
            }
            "screen_stream_event" -> {
                try {
                    org.snow.ui.SnowUiRepository.getInstance(context).onScreenStreamEvent(data ?: emptyMap())
                } catch (_: Exception) {}
                Pair(mapOf("status" to "success", "action" to "screen_stream_event"), null)
            }
            "screen_stream_status" -> {
                val active = org.snow.ui.SnowUiRepository.getInstance(context).screenShareState.value
                Pair(mapOf("status" to "success", "state" to active.name), null)
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
                } else if ((eventType == "APPROVAL_RESOLVED" || eventType == "APPROVAL_EXPIRED") && reqId.isNotBlank()) {
                    ActionNotificationHelper.cancelApprovalNotification(context, reqId)
                }
                try {
                    org.snow.ui.SnowUiRepository.getInstance(context).onApprovalEventReceived()
                } catch (_: Exception) {}
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

    suspend fun handleIncomingClipboardPush(
        data: Map<String, Any?>?,
        serverHost: String,
        defaultTransferPort: Int,
        transferClient: FileTransferClient?,
        repoOverride: org.snow.ui.SnowUiRepository? = null,
        clipboardHandlerOverride: ClipboardHandler? = null,
        imageClipApplierOverride: ((File, String) -> Unit)? = null
    ): Pair<Map<String, Any?>?, SnowError?> {
        val repo = repoOverride ?: try {
            org.snow.ui.SnowUiRepository.getInstance(context)
        } catch (_: Exception) {
            null
        }
        val originDeviceId = (data?.get("origin_device_id") as? String)?.trim()
        val eventId = (data?.get("event_id") as? String)?.trim() ?: ""
        val seq = (data?.get("seq") as? Number)?.toLong() ?: 0L

        if (repo != null && repo.isSelfOriginClipboardEvent(originDeviceId)) {
            SafeLog.i(TAG, "Suppressed self-origin clipboard_push echo (event=$eventId).")
            return Pair(mapOf("status" to "success", "ignored_echo" to true), null)
        }

        val type = (data?.get("type") as? String)?.trim()?.lowercase() ?: "text"
        if (type == "file" || type == "file_bundle") {
            if (repo == null || transferClient == null || serverHost.isBlank()) {
                return Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = "Transfer client or repository not ready"))
            }
            val bundleResult = repo.handleIncomingClipboardFilePush(
                data = data ?: emptyMap(),
                transferClient = transferClient,
                serverHost = serverHost,
                defaultTransferPort = defaultTransferPort
            )
            return if (bundleResult.isSuccess) {
                val saved = bundleResult.getOrNull().orEmpty()
                Pair(
                    mapOf(
                        "status" to "success",
                        "type" to type,
                        "saved_files" to saved,
                        "file_count" to saved.size
                    ),
                    null
                )
            } else {
                Pair(
                    null,
                    SnowError(
                        code = ErrorCode.INTERNAL_ERROR,
                        message = bundleResult.exceptionOrNull()?.message ?: "Failed saving clipboard files"
                    )
                )
            }
        }

        if (type == "image") {
            val transferId = data?.get("transfer_id") as? String
            val sha256 = data?.get("sha256") as? String ?: ""
            val declaredSize = (data?.get("size") as? Number)?.toLong() ?: 0L
            if (declaredSize > ClipboardHandler.MAX_IMAGE_BYTES) {
                return Pair(null, SnowError(code = ErrorCode.INVALID_PAYLOAD, message = "Clipboard image exceeds 15 MiB limit"))
            }
            val transferPort = (data?.get("transfer_port") as? Number)?.toInt() ?: defaultTransferPort
            val mimeType = (data?.get("mime_type") as? String)?.lowercase() ?: "image/png"
            val ext = if (mimeType.contains("jpeg") || mimeType.contains("jpg")) "jpg" else "png"
            if (transferClient == null || transferId.isNullOrBlank() || serverHost.isBlank()) {
                return Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = "Transfer client not ready"))
            }
            val cacheDir = ClipboardHandler.getClipboardCacheDir(context)
            val fileName = "clip_${sha256.take(16)}.$ext"
            val localFile = File(cacheDir, fileName)
            ClipboardHandler.pruneImageCache(cacheDir, preserveFileName = fileName)

            val dlRes = transferClient.downloadFile(
                serverHost = serverHost,
                transferPort = transferPort,
                transferId = transferId,
                destinationFile = localFile,
                expectedSha256 = sha256
            )
            if (dlRes !is FileTransferClient.TransferResult.Success) {
                return Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = "Failed downloading clipboard image"))
            }
            if (dlRes.file.length() > ClipboardHandler.MAX_IMAGE_BYTES) {
                dlRes.file.delete()
                return Pair(null, SnowError(code = ErrorCode.INVALID_PAYLOAD, message = "Downloaded image exceeds 15 MiB limit"))
            }
            return try {
                val resolvedMime = if (ext == "jpg") "image/jpeg" else "image/png"
                if (imageClipApplierOverride != null) {
                    withContext(Dispatchers.Main) {
                        imageClipApplierOverride.invoke(dlRes.file, resolvedMime)
                    }
                } else {
                    val contentUri = FileProvider.getUriForFile(
                        context,
                        "${context.packageName}.fileprovider",
                        dlRes.file
                    )
                    withContext(Dispatchers.Main) {
                        val clip = ClipData(
                            android.content.ClipDescription("SNOW Image", arrayOf(resolvedMime)),
                            ClipData.Item(contentUri)
                        )
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
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
                }
                val computedCanonical = CanonicalImageDigest.computeFromFile(dlRes.file)
                    ?: (data?.get("canonical_sha256") as? String)?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
                repo?.recordIncomingClipboardImageSha256(
                    sha256.ifBlank { dlRes.sha256 },
                    computedCanonical
                )
                if (seq > 0L && eventId.isNotBlank()) {
                    repo?.sendClipboardAck(seq, eventId)
                }
                SafeLog.i(TAG, "Pushed image to Android clipboard via FileProvider ($resolvedMime).")
                Pair(mapOf("status" to "success", "type" to "image"), null)
            } catch (e: Exception) {
                SafeLog.e(TAG, "Failed placing image on Android clipboard: ${e.message}", e)
                Pair(null, SnowError(code = ErrorCode.INTERNAL_ERROR, message = "Failed setting image clip"))
            }
        }

        val text = data?.get("text") as? String
        if (!ClipboardHandler.isTextWithinLimit(text)) {
            return Pair(
                null,
                SnowError(code = ErrorCode.INVALID_PAYLOAD, message = "Clipboard text missing or exceeds 64 KiB limit.")
            )
        }
        val effectiveClipboard = clipboardHandlerOverride ?: clipboardHandler
        val res = effectiveClipboard.pushClipboard(text)
        return if (res["status"] == "success" || res["success"] == true) {
            try {
                repo?.recordIncomingClipboardText(text)
                if (seq > 0L && eventId.isNotBlank()) {
                    repo?.sendClipboardAck(seq, eventId)
                }
            } catch (_: Exception) {}
            Pair(res, null)
        } else {
            Pair(null, SnowError(code = ErrorCode.INVALID_PAYLOAD, message = res["error"] as? String ?: "Clipboard push failed"))
        }
    }
}
