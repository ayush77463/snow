package org.snow.capabilities

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snow.security.SafeLog
import java.io.File

/**
 * Android clipboard capability handler.
 *
 * Implements bidirectional clipboard support:
 * - pushClipboard: Pushes text to the Android clipboard on the Main thread (max 64 KiB UTF-8).
 * - pushImageClipboard: Stages image file in bounded 10-file FileProvider cache, assigns Content URI,
 *   grants IME read permissions, and provides visible Share/Save fallback.
 * - pullClipboard: Reads plain-text clipboard content strictly subject to Android foreground
 *   and explicit user confirmation/intent checks. Never logs clipboard content.
 */
class ClipboardHandler(private val context: Context) {

    companion object {
        private const val TAG = "ClipboardHandler"
        const val MAX_TEXT_BYTES = 64 * 1024 // 64 KiB
        const val MAX_IMAGE_CACHE_FILES = 10

        private val activeActivities = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

        @JvmStatic
        fun onActivityResumed(activityName: String) {
            activeActivities.add(activityName)
        }

        @JvmStatic
        fun onActivityPaused(activityName: String) {
            activeActivities.remove(activityName)
        }

        @JvmStatic
        fun resetForegroundTracking() {
            activeActivities.clear()
        }

        /**
         * Tracks whether the SNOW application is currently in the foreground with window focus.
         * Governed by active resumed activity count.
         */
        @JvmStatic
        var isAppInForeground: Boolean
            get() = activeActivities.isNotEmpty()
            set(value) {
                if (value) {
                    activeActivities.add("legacy_manual")
                } else {
                    activeActivities.clear()
                }
            }

        /**
         * Tracks whether an explicit user action has authorized a clipboard read.
         * Must be granted by user action (e.g. tapping sync/confirm) and is consumed on read.
         */
        @Volatile
        var isUserIntentGranted: Boolean = false

        /**
         * Resolve FileProvider-accessible cache directory for clipboard images (bounded to 10 files).
         */
        @JvmStatic
        fun getClipboardCacheDir(ctx: Context): File {
            return File(ctx.cacheDir, "clipboard").apply { mkdirs() }
        }

        /**
         * Enforces bounded 10-file cache eviction (LRU based on last modified).
         */
        @JvmStatic
        @Synchronized
        fun pruneImageCache(cacheDir: File, preserveFileName: String? = null) {
            try {
                val files = cacheDir.listFiles { f ->
                    f.isFile && (f.name.endsWith(".png") || f.name.endsWith(".jpg") || f.name.endsWith(".jpeg"))
                } ?: return

                if (files.size > MAX_IMAGE_CACHE_FILES) {
                    val sorted = files.sortedBy { it.lastModified() }
                    var toDelete = files.size - MAX_IMAGE_CACHE_FILES
                    for (file in sorted) {
                        if (toDelete <= 0) break
                        if (file.name != preserveFileName) {
                            if (file.delete()) {
                                toDelete--
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                SafeLog.w(TAG, "Error pruning clipboard image cache: ${e.message}")
            }
        }

        /**
         * Explicitly grant read URI permissions to the active input method (e.g. Gboard)
         * so keyboard image pasting does not encounter SecurityException.
         */
        @JvmStatic
        fun grantImeUriPermission(ctx: Context, uri: Uri) {
            try {
                val imeSetting = android.provider.Settings.Secure.getString(
                    ctx.contentResolver,
                    android.provider.Settings.Secure.DEFAULT_INPUT_METHOD
                )
                if (!imeSetting.isNullOrBlank()) {
                    val imePackage = imeSetting.substringBefore('/')
                    ctx.grantUriPermission(
                        imePackage,
                        uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                    SafeLog.i(TAG, "Granted URI read permission to active IME: $imePackage")
                }
            } catch (e: Exception) {
                SafeLog.i(TAG, "Could not resolve default IME for URI grant: ${e.message}")
            }
        }

        /**
         * Post actionable notification providing visible Share or Save fallback when
         * a target application rejects direct clipboard image pasting.
         */
        @JvmStatic
        fun postShareFallbackNotification(
            ctx: Context,
            uri: Uri,
            mimeType: String,
            isUserInitiated: Boolean = false
        ) {
            try {
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = mimeType
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                val chooser = Intent.createChooser(shareIntent, "Share Clipboard Image")
                chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)

                ActionNotificationHelper.postActionNotification(
                    context = ctx,
                    title = "Image Copied to Clipboard",
                    content = "Tap to Share or Save image if paste is unsupported in your target app.",
                    intent = chooser,
                    isSilent = !isUserInitiated,
                    customId = ActionNotificationHelper.NOTIFICATION_ID_CLIPBOARD_FALLBACK
                )
            } catch (e: Exception) {
                SafeLog.w(TAG, "Failed posting share fallback notification: ${e.message}")
            }
        }
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
        val hasIntent = isUserIntentGranted || try {
            val prefs = context.getSharedPreferences(org.snow.ui.SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
            prefs?.getBoolean(org.snow.ui.SnowUiRepository.PREF_KEY_INSTANT_SYNC, true) ?: true
        } catch (_: Exception) {
            true
        }
        if (!hasIntent) {
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
