package org.snow.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import org.snow.capabilities.ClipboardHandler
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Transparent trampoline activity that briefly acquires window focus to
 * read the primary clipboard subject to Android 10+ / ColorOS 17 foreground
 * restrictions, pushes the content to the connected PC, and immediately finishes.
 */
class ClipSyncActivity : AppCompatActivity() {

    private val hasTriggered = AtomicBoolean(false)
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ClipboardHandler.isAppInForeground = true
        ClipboardHandler.isUserIntentGranted = true
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && hasTriggered.compareAndSet(false, true)) {
            ClipboardHandler.isAppInForeground = true
            ClipboardHandler.isUserIntentGranted = true
            handler.postDelayed({
                val repo = SnowUiRepository.getInstance(applicationContext)
                repo.pushCurrentClipboard { success, errOrMsg ->
                    runOnUiThread {
                        if (success) {
                            Toast.makeText(applicationContext, "Clipboard pushed to PC ❄️", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(applicationContext, "Clipboard push: ${errOrMsg ?: "Failed"}", Toast.LENGTH_SHORT).show()
                        }
                        finish()
                    }
                }
            }, 150)
        }
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
        ClipboardHandler.isAppInForeground = false
    }
}
