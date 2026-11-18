package org.snow.capabilities

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.telephony.SmsManager
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog

/**
 * Android messaging and SMS capability handler for SNOW.
 *
 * Implements Phase 10 messaging:
 * - "intent" mode: Spawns Intent.ACTION_SENDTO with pre-filled recipient and body,
 *   allowing user confirmation in default messaging app without dangerous background SMS permissions.
 * - "sms" mode: Requires explicit Manifest.permission.SEND_SMS. If granted, uses
 *   SmsManager to send SMS message or multipart text message. If not granted, returns
 *   structured PERMISSION_REQUIRED error.
 */
class MessagingHandler(private val context: Context) {

    companion object {
        private const val TAG = "MessagingHandler"
        const val MODE_INTENT = "intent"
        const val MODE_SMS = "sms"
    }

    suspend fun sendMessage(
        recipient: String?,
        message: String?,
        mode: String = MODE_INTENT,
        userConfirmed: Boolean = false
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
                // Strict safety check: Never silently send SMS for remote / unconfirmed requests
                if (!userConfirmed) {
                    SafeLog.w(TAG, "Direct SMS rejected: missing explicit on-device user confirmation.")
                    return@withContext mapOf(
                        "success" to false,
                        "status" to "error",
                        "action" to "send_message",
                        "mode" to MODE_SMS,
                        "error" to "USER_CONFIRMATION_REQUIRED",
                        "message" to "Direct SMS dispatch requires explicit on-device user confirmation. Use 'intent' mode for AI-originated requests.",
                        "remediation_hint" to "Confirm SMS dispatch intent on the Android device."
                    )
                }
                sendViaSms(cleanRecipient, message)
            }
            else -> mapOf(
                "status" to "error",
                "action" to "send_message",
                "error" to "UNSUPPORTED_MODE",
                "message" to "Unsupported messaging mode '$mode'. Expected 'intent' or 'sms'."
            )
        }
    }

    private fun sendViaIntent(recipient: String, message: String): Map<String, Any?> {
        val uri = Uri.parse("smsto:${Uri.encode(recipient)}")
        val intent = Intent(Intent.ACTION_SENDTO, uri).apply {
            putExtra("sms_body", message)
            putExtra(Intent.EXTRA_TEXT, message)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }

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
                SafeLog.w(TAG, "No messaging application available for smsto intent: ${e.message}")
                mapOf(
                    "success" to false,
                    "status" to "error",
                    "action" to "send_message",
                    "error" to "NO_MESSAGING_APP",
                    "message" to "No messaging application available to handle smsto URI."
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
            // Android 17 background launch restriction: post notification with PendingIntent
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

    private fun sendViaSms(recipient: String, message: String): Map<String, Any?> {
        val hasPermission = try {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.SEND_SMS
            ) == PackageManager.PERMISSION_GRANTED
        } catch (e: Exception) {
            false
        }

        if (!hasPermission) {
            SafeLog.w(TAG, "SEND_SMS permission not granted; rejecting direct SMS.")
            return mapOf(
                "status" to "error",
                "action" to "send_message",
                "mode" to MODE_SMS,
                "error" to "PERMISSION_REQUIRED",
                "message" to "SEND_SMS runtime permission is not granted on this device."
            )
        }

        return try {
            val smsManager: SmsManager = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                context.getSystemService(SmsManager::class.java) ?: SmsManager.getDefault()
            } else {
                @Suppress("DEPRECATION")
                SmsManager.getDefault()
            }

            val parts = smsManager.divideMessage(message)
            if (parts.size > 1) {
                smsManager.sendMultipartTextMessage(recipient, null, parts, null, null)
            } else {
                smsManager.sendTextMessage(recipient, null, message, null, null)
            }

            SafeLog.i(TAG, "Sent SMS to '$recipient' (${parts.size} part(s)).")
            mapOf(
                "status" to "success",
                "action" to "send_message",
                "mode" to MODE_SMS,
                "recipient" to recipient,
                "parts" to parts.size,
                "result" to "SMS_SENT",
                "message" to "SMS dispatched successfully."
            )
        } catch (e: SecurityException) {
            SafeLog.e(TAG, "SecurityException while sending SMS: ${e.message}")
            mapOf(
                "status" to "error",
                "action" to "send_message",
                "mode" to MODE_SMS,
                "error" to "PERMISSION_REQUIRED",
                "message" to "SMS send permission denied by system: ${e.message}"
            )
        } catch (e: Exception) {
            SafeLog.e(TAG, "Exception while sending SMS: ${e.message}")
            mapOf(
                "status" to "error",
                "action" to "send_message",
                "mode" to MODE_SMS,
                "error" to "SMS_SEND_FAILED",
                "message" to "Failed sending SMS: ${e.message}"
            )
        }
    }
}
