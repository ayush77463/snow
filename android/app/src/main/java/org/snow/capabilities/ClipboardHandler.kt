package org.snow.capabilities

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog

/**
 * Android clipboard push capability handler.
 *
 * Implements Sub-Milestone 6.3:
 * - Pushes text to the Android clipboard on the Main thread.
 * - Maximum text size: 64 KiB UTF-8.
 * - Strictly write-only: never reads or exfiltrates clipboard contents.
 */
class ClipboardHandler(private val context: Context) {

    companion object {
        private const val TAG = "ClipboardHandler"
        const val MAX_TEXT_BYTES = 64 * 1024 // 64 KiB
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
}
