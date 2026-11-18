package org.snow.capabilities

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog

/**
 * Android clipboard capability handler.
 *
 * Implements bidirectional clipboard support:
 * - pushClipboard: Pushes text to the Android clipboard on the Main thread (max 64 KiB UTF-8).
 * - pullClipboard: Reads plain-text clipboard content strictly subject to Android foreground
 *   and explicit user confirmation/intent checks. Never logs clipboard content.
 */
class ClipboardHandler(private val context: Context) {

    companion object {
        private const val TAG = "ClipboardHandler"
        const val MAX_TEXT_BYTES = 64 * 1024 // 64 KiB

        /**
         * Tracks whether the SNOW application is currently in the foreground with window focus.
         * Maintained by MainActivity lifecycle (onResume / onPause).
         */
        @Volatile
        var isAppInForeground: Boolean = false

        /**
         * Tracks whether an explicit user action has authorized a clipboard read.
         * Must be granted by user action (e.g. tapping sync/confirm) and is consumed on read.
         */
        @Volatile
        var isUserIntentGranted: Boolean = false
    }

    suspend fun pushClipboard(text: String?): Map<String, Any?> = withContext(Dispatchers.Main) {
        if (text == null) {
            return@withContext mapOf(
                "status" to "error",
                "error" to "Clipboard text cannot be null."
            )
        }

        val rawBytes = text.toByteArray(Charsets.UTF_8)
        if (rawBytes.size > MAX_TEXT_BYTES) {
            return@withContext mapOf(
                "status" to "error",
                "error" to "Clipboard text size (${rawBytes.size} bytes) exceeds maximum limit (${MAX_TEXT_BYTES} bytes)."
            )
        }

        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            if (clipboard == null) {
                return@withContext mapOf(
                    "status" to "error",
                    "error" to "ClipboardManager service unavailable."
                )
            }

            val clip = ClipData.newPlainText("SNOW", text)
            clipboard.setPrimaryClip(clip)

            SafeLog.i(TAG, "Successfully pushed ${rawBytes.size} bytes to Android clipboard.")
            return@withContext mapOf(
                "status" to "success",
                "bytes_written" to rawBytes.size,
                "message" to "Text successfully copied to Android clipboard."
            )
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed writing to clipboard: ${e.message}", e)
            return@withContext mapOf(
                "status" to "error",
                "error" to "Failed setting clipboard content: ${e.message}"
            )
        }
    }

    suspend fun pullClipboard(): Map<String, Any?> = withContext(Dispatchers.Main) {
        // 1. Android OS foreground restriction check
        if (!isAppInForeground) {
            SafeLog.w(TAG, "Clipboard read rejected: SNOW is not in the foreground.")
            return@withContext mapOf(
                "status" to "error",
                "error" to "FOREGROUND_REQUIRED",
                "message" to "Android OS requires SNOW to be active in the foreground to access the clipboard."
            )
        }

        // 2. Explicit user intent/confirmation check
        if (!isUserIntentGranted) {
            SafeLog.w(TAG, "Clipboard read rejected: explicit user confirmation has not been granted.")
            return@withContext mapOf(
                "status" to "error",
                "error" to "USER_CONFIRMATION_REQUIRED",
                "message" to "Clipboard reading requires explicit user authorization on the Android device."
            )
        }

        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            if (clipboard == null) {
                return@withContext mapOf(
                    "status" to "error",
                    "error" to "SERVICE_UNAVAILABLE",
                    "message" to "ClipboardManager service unavailable."
                )
            }

            if (!clipboard.hasPrimaryClip()) {
                return@withContext mapOf(
                    "status" to "error",
                    "error" to "EMPTY_CLIPBOARD",
                    "message" to "Android clipboard is empty."
                )
            }

            val clip = clipboard.primaryClip
            if (clip == null || clip.itemCount == 0) {
                return@withContext mapOf(
                    "status" to "error",
                    "error" to "EMPTY_CLIPBOARD",
                    "message" to "Android clipboard contains no clip items."
                )
            }

            val item = clip.getItemAt(0)
            val text = item.coerceToText(context)?.toString()
            if (text.isNullOrEmpty()) {
                return@withContext mapOf(
                    "status" to "error",
                    "error" to "EMPTY_CLIPBOARD",
                    "message" to "Android clipboard contains no text content."
                )
            }

            val rawBytes = text.toByteArray(Charsets.UTF_8)
            if (rawBytes.size > MAX_TEXT_BYTES) {
                return@withContext mapOf(
                    "status" to "error",
                    "error" to "OVERSIZED_CLIPBOARD",
                    "message" to "Clipboard text size (${rawBytes.size} bytes) exceeds maximum limit (${MAX_TEXT_BYTES} bytes)."
                )
            }

            // Consume single-use user authorization
            isUserIntentGranted = false

            SafeLog.i(TAG, "Successfully pulled ${rawBytes.size} bytes from Android clipboard.")
            return@withContext mapOf(
                "status" to "success",
                "text" to text,
                "bytes_read" to rawBytes.size,
                "message" to "Text successfully retrieved from Android clipboard."
            )
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed reading clipboard: ${e.message}", e)
            return@withContext mapOf(
                "status" to "error",
                "error" to "CLIPBOARD_READ_FAILED",
                "message" to "Failed reading clipboard: ${e.message}"
            )
        }
    }
}
