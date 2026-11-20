package org.snow.capabilities

import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.snow.ui.SnowUiRepository

/**
 * Observes MediaStore for newly captured screenshots.
 * When enabled in preferences and connected to desktop, automatically uploads
 * new screenshots to the connected Windows PC and sets the PC clipboard.
 */
class ScreenshotObserver(
    private val context: Context
) : ContentObserver(Handler(Looper.getMainLooper())) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val processedUris = mutableSetOf<String>()
    private var isRegistered = false

    fun register() {
        if (isRegistered) return
        try {
            context.contentResolver.registerContentObserver(
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                true,
                this
            )
            isRegistered = true
            Log.d(TAG, "ScreenshotObserver registered successfully")
        } catch (e: Exception) {
            Log.w(TAG, "Failed registering ScreenshotObserver: ${e.message}")
        }
    }

    fun unregister() {
        if (!isRegistered) return
        try {
            context.contentResolver.unregisterContentObserver(this)
            isRegistered = false
            Log.d(TAG, "ScreenshotObserver unregistered")
        } catch (e: Exception) {
            Log.w(TAG, "Failed unregistering ScreenshotObserver: ${e.message}")
        }
    }

    override fun onChange(selfChange: Boolean, uri: Uri?) {
        super.onChange(selfChange, uri)
        val targetUri = uri ?: MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        scope.launch {
            kotlinx.coroutines.delay(350L)
            handleMediaChange(targetUri)
        }
    }

    private fun handleMediaChange(targetUri: Uri) {
        val prefs = context.getSharedPreferences(SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
        val isAutoSyncEnabled = prefs.getBoolean(SnowUiRepository.PREF_KEY_AUTO_SYNC_SCREENSHOTS, false)
        if (!isAutoSyncEnabled) return

        val repository = SnowUiRepository.getInstance(context)
        if (!repository.isConnectedAndAuthenticated()) return

        val projection = mutableListOf(
            MediaStore.Images.Media._ID,
            MediaStore.Images.Media.DISPLAY_NAME,
            MediaStore.Images.Media.DATE_ADDED,
            MediaStore.Images.Media.DATE_MODIFIED,
            MediaStore.Images.Media.SIZE
        ).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                add(MediaStore.Images.Media.RELATIVE_PATH)
                add(MediaStore.Images.Media.IS_PENDING)
            }
        }.toTypedArray()

        val sortOrder = "${MediaStore.Images.Media.DATE_MODIFIED} DESC, ${MediaStore.Images.Media.DATE_ADDED} DESC"
        val queryUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI

        try {
            val cursor = context.contentResolver.query(
                queryUri,
                projection,
                null,
                null,
                sortOrder
            ) ?: return

            cursor.use {
                if (!it.moveToFirst()) return

                val idIndex = it.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
                val nameIndex = it.getColumnIndexOrThrow(MediaStore.Images.Media.DISPLAY_NAME)
                val dateIndex = it.getColumnIndexOrThrow(MediaStore.Images.Media.DATE_ADDED)
                val sizeIndex = it.getColumnIndexOrThrow(MediaStore.Images.Media.SIZE)

                val id = it.getLong(idIndex)
                val displayName = it.getString(nameIndex) ?: "screenshot.png"
                val dateAdded = it.getLong(dateIndex)
                val size = it.getLong(sizeIndex)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val pendingIndex = it.getColumnIndex(MediaStore.Images.Media.IS_PENDING)
                    if (pendingIndex != -1 && it.getInt(pendingIndex) != 0) {
                        // File write is still in progress, skip until IS_PENDING == 0
                        return
                    }
                }

                // Check recency: only files added in the last 60 seconds
                val nowSec = System.currentTimeMillis() / 1000L
                if (nowSec - dateAdded > 60) return

                // Check if it's a screenshot by name or relative path
                val isScreenshot = displayName.contains("screenshot", ignoreCase = true) ||
                    displayName.startsWith("Screenshot_", ignoreCase = true) ||
                    (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && it.getColumnIndex(MediaStore.Images.Media.RELATIVE_PATH).let { idx ->
                        if (idx != -1) it.getString(idx)?.contains("screenshot", ignoreCase = true) == true else false
                    })

                if (!isScreenshot || size <= 0L) return

                val contentUri = Uri.withAppendedPath(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, id.toString())
                val uriKey = contentUri.toString()
                synchronized(processedUris) {
                    if (processedUris.contains(uriKey)) return
                    processedUris.add(uriKey)
                    if (processedUris.size > 100) {
                        processedUris.clear()
                        processedUris.add(uriKey)
                    }
                }

                Log.i(TAG, "Detected new screenshot: $displayName ($size bytes). Auto-uploading to PC...")
                repository.uploadScreenshot(contentUri, displayName, size)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error checking media change for screenshots: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "ScreenshotObserver"
    }
}
