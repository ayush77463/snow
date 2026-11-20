package org.snow.capabilities

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import org.snow.security.SafeLog

/**
 * Safe text and link sharing handler for Android.
 *
 * Implements Phase 21 Pillar 3D:
 * - Strictly validates HTTP/HTTPS schemes.
 * - Rejects unsafe schemes: javascript:, file:, intent:, data:.
 * - Abides by Android background activity start restrictions:
 *   If foregrounded: launches ACTION_VIEW intent.
 *   If backgrounded: delivers actionable notification.
 */
class LinkShareHandler(
    private val context: Context,
    private val isForegroundProvider: () -> Boolean = { ClipboardHandler.isAppInForeground },
    private val notificationPoster: (Context, String, String, Intent) -> Boolean = { ctx, title, content, intent ->
        ActionNotificationHelper.postActionNotification(ctx, title, content, intent)
    }
) {

    companion object {
        private const val TAG = "LinkShareHandler"
        private const val NOTIFICATION_ID_LINK_SHARE = 2001
    }

    fun handleShareLink(url: String?, text: String?): Map<String, Any?> {
        val cleanUrl = url?.trim()
        val cleanText = text?.trim()

        if (cleanUrl.isNullOrEmpty() && cleanText.isNullOrEmpty()) {
            return mapOf(
                "status" to "error",
                "error" to "INVALID_ARGUMENT",
                "message" to "Either 'url' or 'text' must be provided."
            )
        }

        if (!cleanUrl.isNullOrEmpty()) {
            // Strict URL validation
            val lower = cleanUrl.lowercase()
            if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
                return mapOf(
                    "status" to "error",
                    "error" to "INVALID_URL_SCHEME",
                    "message" to "Only http:// and https:// URL schemes are permitted."
                )
            }

            if (cleanUrl.contains("\n") || cleanUrl.contains("\r") || cleanUrl.contains("\u0000")) {
                return mapOf(
                    "status" to "error",
                    "error" to "MALFORMED_URL",
                    "message" to "URL contains illegal control characters."
                )
            }

            val javaUri = try {
                java.net.URI(cleanUrl)
            } catch (e: Exception) {
                return mapOf(
                    "status" to "error",
                    "error" to "MALFORMED_URL",
                    "message" to (e.message ?: "Invalid URL format.")
                )
            }

            val scheme = javaUri.scheme?.lowercase()
            if (scheme != "http" && scheme != "https") {
                return mapOf(
                    "status" to "error",
                    "error" to "INVALID_URL_SCHEME",
                    "message" to "Only http:// and https:// URL schemes are permitted."
                )
            }

            val parsedUri = try {
                Uri.parse(cleanUrl)
            } catch (_: Exception) {
                null
            }

            val intent = Intent(Intent.ACTION_VIEW, parsedUri).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            return if (isForegroundProvider()) {
                try {
                    context.startActivity(intent)
                    SafeLog.i(TAG, "Launched browser in foreground for: $cleanUrl")
                    mapOf("status" to "success", "action" to "opened_browser", "url" to cleanUrl)
                } catch (e: Exception) {
                    SafeLog.e(TAG, "Failed starting browser activity: ${e.message}")
                    mapOf("status" to "error", "error" to "BROWSER_LAUNCH_FAILED", "message" to (e.message ?: "Failed launching browser"))
                }
            } else {
                // Background delivery: post actionable notification instead of background activity launch
                val posted = notificationPoster(
                    context,
                    "Link received from PC",
                    cleanUrl,
                    intent
                )
                if (posted) {
                    SafeLog.i(TAG, "Posted actionable notification for link: $cleanUrl")
                    mapOf(
                        "status" to "NOTIFICATION_TAP_REQUIRED",
                        "action" to "notification_posted",
                        "url" to cleanUrl,
                        "requires_tap" to true
                    )
                } else {
                    SafeLog.e(TAG, "Failed posting action notification for link: $cleanUrl")
                    mapOf(
                        "status" to "error",
                        "error" to "NOTIFICATION_POST_FAILED",
                        "message" to "Unable to post actionable notification in background; notification permission denied or disabled."
                    )
                }
            }
        }

        // Handle text note copy
        if (!cleanText.isNullOrEmpty()) {
            return try {
                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                val clip = ClipData.newPlainText("SNOW Shared Note", cleanText)
                cm?.setPrimaryClip(clip)
                mapOf("status" to "success", "action" to "copied_to_clipboard", "text_length" to cleanText.length)
            } catch (e: Exception) {
                mapOf("status" to "error", "error" to (e.message ?: "Failed copying to clipboard"))
            }
        }

        return mapOf("status" to "error", "error" to "No content processed.")
    }
}
