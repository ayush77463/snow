package org.snow.capabilities

import android.content.Context
import android.content.Intent
import android.net.Uri
import org.snow.security.SafeLog
import java.net.URLEncoder

/**
 * Explicit-consent WhatsApp message draft composer.
 *
 * Security invariants:
 * - Never sends WhatsApp messages silently in the background.
 * - Uses verified WhatsApp package (com.whatsapp or com.whatsapp.w4b) compose intents
 *   or actionable notifications requiring manual user tap to submit.
 */
class WhatsAppHandler(
    private val context: Context,
    private val isForegroundProvider: () -> Boolean = { ClipboardHandler.isAppInForeground },
    private val installedWhatsAppPackageProvider: (() -> String?)? = null,
    private val activityStarter: ((Intent) -> Unit)? = null,
    private val notificationPoster: (Context, String, String, Intent) -> Boolean = { ctx, title, content, intent ->
        ActionNotificationHelper.postActionNotification(ctx, title, content, intent)
    }
) {
    companion object {
        private const val TAG = "WhatsAppHandler"
        private const val MAX_MESSAGE_LEN = 2000
        private val CANDIDATE_PACKAGES = listOf("com.whatsapp", "com.whatsapp.w4b")
    }

    private fun resolveInstalledWhatsAppPackage(): String? {
        installedWhatsAppPackageProvider?.let { return it.invoke() }
        val pm = context.packageManager
        for (pkg in CANDIDATE_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0)
                return pkg
            } catch (_: Exception) {
            }
        }
        return null
    }

    fun composeWhatsApp(
        recipient: String?,
        message: String?,
        userConfirmed: Boolean = false
    ): Map<String, Any?> {
        val cleanRecipient = recipient?.trim().orEmpty()
        val cleanMsg = message?.trim().orEmpty()

        if (cleanRecipient.isEmpty() || cleanMsg.isEmpty()) {
            return mapOf(
                "status" to "error",
                "error" to "INVALID_ARGUMENT",
                "message" to "Both 'recipient' and 'message' must be provided."
            )
        }
        if (cleanRecipient.length > 64 || cleanRecipient.any { it.isISOControl() }) {
            return mapOf(
                "status" to "error",
                "error" to "INVALID_ARGUMENT",
                "message" to "Recipient contains invalid characters or exceeds 64 characters."
            )
        }
        if (cleanMsg.length > MAX_MESSAGE_LEN || cleanMsg.contains('\u0000')) {
            return mapOf(
                "status" to "error",
                "error" to "INVALID_ARGUMENT",
                "message" to "Message exceeds $MAX_MESSAGE_LEN characters or contains illegal control bytes."
            )
        }

        val whatsappPkg = resolveInstalledWhatsAppPackage()
            ?: return mapOf(
                "status" to "error",
                "error" to "WHATSAPP_NOT_INSTALLED",
                "message" to "Neither WhatsApp (com.whatsapp) nor WhatsApp Business (com.whatsapp.w4b) is installed."
            )

        val phoneDigits = cleanRecipient.filter { it.isDigit() }
        val composeIntent = if (phoneDigits.length >= 7) {
            val encodedText = URLEncoder.encode(cleanMsg, "UTF-8")
            Intent(Intent.ACTION_VIEW, Uri.parse("https://wa.me/$phoneDigits?text=$encodedText")).apply {
                setPackage(whatsappPkg)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        } else {
            Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, cleanMsg)
                setPackage(whatsappPkg)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        }

        val canAutoOpenUi = isForegroundProvider() && userConfirmed
        return if (canAutoOpenUi) {
            try {
                if (activityStarter != null) {
                    activityStarter.invoke(composeIntent)
                } else {
                    context.startActivity(composeIntent)
                }
                SafeLog.i(TAG, "Opened WhatsApp compose draft via $whatsappPkg (user tap still required)")
                mapOf(
                    "status" to "success",
                    "package" to whatsappPkg,
                    "auto_sent" to false,
                    "requires_manual_tap" to true,
                    "delivery_mode" to "intent_compose",
                    "message" to "Opened WhatsApp compose screen. Tap Send on phone to deliver."
                )
            } catch (e: Exception) {
                mapOf(
                    "status" to "error",
                    "error" to "WHATSAPP_LAUNCH_FAILED",
                    "message" to (e.message ?: "Failed opening WhatsApp compose screen.")
                )
            }
        } else {
            val posted = notificationPoster(
                context,
                "WhatsApp Draft for $cleanRecipient",
                "Tap to open WhatsApp and review before sending",
                composeIntent
            )
            if (posted) {
                mapOf(
                    "status" to "success",
                    "package" to whatsappPkg,
                    "auto_sent" to false,
                    "requires_manual_tap" to true,
                    "delivery_mode" to "actionable_notification",
                    "message" to "Posted WhatsApp compose notification. Tap to review and send manually."
                )
            } else {
                mapOf(
                    "status" to "error",
                    "error" to "NOTIFICATION_POST_FAILED",
                    "message" to "Could not post actionable WhatsApp notification."
                )
            }
        }
    }
}
