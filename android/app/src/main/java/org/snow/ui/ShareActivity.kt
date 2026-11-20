package org.snow.ui

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

/**
 * Quick-share target handling ACTION_SEND intents from Android system share sheets.
 * Allows users to share images or text directly to SNOW to update the PC clipboard / storage.
 */
class ShareActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val action = intent.action
        val type = intent.type

        if (Intent.ACTION_SEND == action && type != null) {
            handleSendIntent(intent, type)
        } else {
            finish()
        }
    }

    private fun handleSendIntent(intent: Intent, mimeType: String) {
        val repository = SnowUiRepository.getInstance(applicationContext)
        if (!repository.isConnectedAndAuthenticated()) {
            Toast.makeText(this, "SNOW is not connected to desktop. Connect in SNOW first.", Toast.LENGTH_LONG).show()
            finish()
            return
        }

        if (mimeType.startsWith("text/")) {
            val text = intent.getStringExtra(Intent.EXTRA_TEXT)
            if (!text.isNullOrBlank()) {
                repository.pushClipboard(text) { success, err ->
                    runOnUiThread {
                        if (success) {
                            Toast.makeText(this, "Text copied to PC clipboard ❄️", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(this, "Failed copying to PC: $err", Toast.LENGTH_SHORT).show()
                        }
                        finish()
                    }
                }
            } else {
                Toast.makeText(this, "No text found to share", Toast.LENGTH_SHORT).show()
                finish()
            }
        } else if (mimeType.startsWith("image/")) {
            val imageUri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
            }

            if (imageUri != null) {
                var displayName = "shared_image_${System.currentTimeMillis()}.png"
                var size = 0L

                try {
                    contentResolver.query(imageUri, null, null, null, null)?.use { cursor ->
                        if (cursor.moveToFirst()) {
                            val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                            val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                            if (nameIdx != -1) displayName = cursor.getString(nameIdx) ?: displayName
                            if (sizeIdx != -1) size = cursor.getLong(sizeIdx)
                        }
                    }
                } catch (_: Exception) {}

                Toast.makeText(this, "Sharing image to PC clipboard ❄️...", Toast.LENGTH_SHORT).show()
                repository.uploadScreenshot(imageUri, displayName, size)
                finish()
            } else {
                Toast.makeText(this, "No image found to share", Toast.LENGTH_SHORT).show()
                finish()
            }
        } else {
            Toast.makeText(this, "Unsupported share format: $mimeType", Toast.LENGTH_SHORT).show()
            finish()
        }
    }
}
