package org.snow.capabilities

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog

/**
 * Android messaging capability handler for SNOW.
 *
 * Implements user-confirmed intent compose via Intent.ACTION_SENDTO with 'smsto:' URI scheme.
 * In accordance with Phase 19A security hardening:
 * - Direct background SMS sending via SmsManager is strictly removed.
 * - No SEND_SMS permission is requested or used.
 * - Messaging is strictly user-confirmed through Intent.ACTION_SENDTO with 'smsto:' URI.
 * - In the background, posts an action notification requiring an explicit user tap.
 */
class MessagingHandler(private val context: Context) {

    companion object {
        private const val TAG = "MessagingHandler"
        const val MODE_INTENT = "intent"
        const val MODE_SMS = "sms"
        const val ACTION_COMPOSE = Intent.ACTION_SENDTO
        const val SCHEME_SMSTO = "smsto"

        /**
         * Construct the canonical 'smsto:' URI string for the recipient.
         */
        fun buildSmstoUri(recipient: String): String = "$SCHEME_SMSTO:${recipient.trim()}"

        /**
         * Construct the system SMS compose intent using Intent.ACTION_SENDTO and the 'smsto:' URI scheme.
         */
        fun createComposeIntent(recipient: String, message: String): Intent {
            val uri = Uri.parse(buildSmstoUri(recipient))
            return Intent(Intent.ACTION_SENDTO, uri).apply {
                putExtra("sms_body", message)
                putExtra(Intent.EXTRA_TEXT, message)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
        }
    }

    suspend fun sendMessage(
        recipient: String?,
        message: String?,
        mode: String = MODE_INTENT,
        @Suppress("UNUSED_PARAMETER") userConfirmed: Boolean = false
    ): Map<String, Any?> = withContext(Dispatchers.IO) {
        val cleanRecipient = recipient?.trim()
        if (cleanRecipient.isNullOrEmpty()) {
            return@withContext mapOf(
                "status" to "error",
                "action" to "send_message",
                "error" to "INVALID_ARGUMENT",
                "message" to "Recipient cannot be null or empty."
            )
        }

        if (message == null) {
            return@withContext mapOf(
                "status" to "error",
                "action" to "send_message",
                "error" to "INVALID_ARGUMENT",
                "message" to "Message body cannot be null."
            )
        }

        val cleanMode = mode.trim().lowercase()

        when (cleanMode) {
            MODE_INTENT -> sendViaIntent(cleanRecipient, message)
            MODE_SMS -> {
                // Direct SMS is prohibited; only intent compose is supported
                SafeLog.w(TAG, "Direct SMS mode rejected: SNOW messaging is strictly user-confirmed intent compose.")
                mapOf(
                    "success" to false,
                    "status" to "error",
                    "action" to "send_message",
                    "mode" to MODE_SMS,
                    "error" to "UNSUPPORTED_MODE",
                    "message" to "Direct SMS is not supported. SNOW messaging is strictly user-confirmed compose via 'intent' mode.",
                    "remediation_hint" to "Use mode 'intent' to launch the system messaging composer."
                )
            }
            else -> mapOf(
                "status" to "error",
                "action" to "send_message",
                "error" to "UNSUPPORTED_MODE",
                "message" to "Unsupported messaging mode '$mode'. Expected 'intent'."
            )
        }
    }

    private fun sendViaIntent(recipient: String, message: String): Map<String, Any?> {
        val intent = createComposeIntent(recipient, message)

        val inForeground = ClipboardHandler.isAppInForeground
        if (inForeground) {
            return try {
                context.startActivity(intent)
                SafeLog.i(TAG, "Launched messaging compose intent in foreground for recipient '$recipient'.")
                mapOf(
                    "success" to true,
                    "status" to "success",
                    "delivery_mode" to "DIRECT_FOREGROUND",
                    "action" to "send_message",
                    "mode" to MODE_INTENT,
                    "recipient" to recipient,
                    "result" to "INTENT_LAUNCHED",
                    "message" to "Messaging composer intent launched in foreground; user confirmation required to send."
                )
            } catch (e: ActivityNotFoundException) {
                SafeLog.w(TAG, "No messaging application available for sms intent: ${e.message}")
                mapOf(
                    "success" to false,
                    "status" to "error",
                    "action" to "send_message",
                    "error" to "NO_MESSAGING_APP",
                    "message" to "No messaging application available to handle sms URI."
                )
            } catch (e: Exception) {
                SafeLog.e(TAG, "Failed launching messaging intent: ${e.message}")
                mapOf(
                    "success" to false,
                    "status" to "error",
                    "action" to "send_message",
                    "error" to "INTENT_FAILED",
                    "message" to "Failed launching messaging intent: ${e.message}"
                )
            }
        } else {
            // Android background launch restriction: post notification with PendingIntent
            if (ActionNotificationHelper.canPostNotifications(context)) {
                val posted = ActionNotificationHelper.postActionNotification(
                    context = context,
                    title = "SNOW: Tap to open message compose",
                    content = "Tap to review and compose message in your messaging app.",
                    intent = intent
                )

                if (posted) {
                    SafeLog.i(TAG, "Posted action notification for background messaging compose intent.")
                    return mapOf(
                        "success" to true,
                        "status" to "success",
                        "delivery_mode" to "NOTIFICATION_TAP_REQUIRED",
                        "action" to "send_message",
                        "mode" to MODE_INTENT,
                        "recipient" to recipient,
                        "message" to "Application is in background. Tap the notification on your phone to review and send the message."
                    )
                }
            }

            SafeLog.w(TAG, "Background messaging compose rejected: notifications disabled or unavailable.")
            return mapOf(
                "success" to false,
                "status" to "FOREGROUND_REQUIRED",
                "action" to "send_message",
                "error" to "Background messaging compose requires notification permission to deliver tap action.",
                "remediation_hint" to "Open SNOW on your phone or grant Notification permission in Android Settings to compose messages."
            )
        }
    }
}
