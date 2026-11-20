package org.snow.capabilities

import android.content.Context
import android.media.AudioManager
import android.os.SystemClock
import android.view.KeyEvent
import org.snow.security.SafeLog

/**
 * Android media playback and volume control capability handler.
 *
 * Implements Phase 21 Pillar 3C:
 * - Play/Pause, Next, Previous track control via AudioManager.dispatchMediaKeyEvent.
 * - Volume Up, Volume Down, Mute adjustment via AudioManager.adjustStreamVolume.
 */
class MediaControlHandler(private val context: Context) {

    companion object {
        private const val TAG = "MediaControlHandler"
    }

    private val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager

    fun handleMediaControl(action: String?): Map<String, Any?> {
        if (action.isNullOrBlank()) {
            return mapOf(
                "status" to "error",
                "error" to "Missing or empty media action."
            )
        }

        val canonical = action.trim().lowercase()
        val supportedActions = setOf(
            "play_pause", "play", "pause",
            "next", "next_track",
            "previous", "prev", "prev_track",
            "volume_up", "vol_up",
            "volume_down", "vol_down",
            "mute", "unmute", "toggle_mute"
        )
        if (!supportedActions.contains(canonical)) {
            return mapOf(
                "status" to "error",
                "error" to "UNSUPPORTED_MEDIA_ACTION",
                "message" to "Unsupported media action '$action' on Android client."
            )
        }

        val am = audioManager
        if (am == null) {
            return mapOf(
                "status" to "error",
                "error" to "AudioManager is not available on this Android device."
            )
        }

        return when (canonical) {
            "play_pause", "play", "pause" -> dispatchKeyEvent(KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE, canonical)
            "next", "next_track" -> dispatchKeyEvent(KeyEvent.KEYCODE_MEDIA_NEXT, canonical)
            "previous", "prev", "prev_track" -> dispatchKeyEvent(KeyEvent.KEYCODE_MEDIA_PREVIOUS, canonical)
            "volume_up", "vol_up" -> {
                try {
                    am.adjustStreamVolume(AudioManager.STREAM_MUSIC, AudioManager.ADJUST_RAISE, AudioManager.FLAG_SHOW_UI)
                    mapOf("status" to "success", "action" to canonical, "platform" to "android")
                } catch (e: Exception) {
                    mapOf("status" to "error", "error" to (e.message ?: "Failed raising volume"))
                }
            }
            "volume_down", "vol_down" -> {
                try {
                    am.adjustStreamVolume(AudioManager.STREAM_MUSIC, AudioManager.ADJUST_LOWER, AudioManager.FLAG_SHOW_UI)
                    mapOf("status" to "success", "action" to canonical, "platform" to "android")
                } catch (e: Exception) {
                    mapOf("status" to "error", "error" to (e.message ?: "Failed lowering volume"))
                }
            }
            "mute", "unmute", "toggle_mute" -> {
                try {
                    am.adjustStreamVolume(AudioManager.STREAM_MUSIC, AudioManager.ADJUST_TOGGLE_MUTE, AudioManager.FLAG_SHOW_UI)
                    mapOf("status" to "success", "action" to canonical, "platform" to "android")
                } catch (e: Exception) {
                    mapOf("status" to "error", "error" to (e.message ?: "Failed toggling mute"))
                }
            }
            else -> {
                mapOf(
                    "status" to "error",
                    "error" to "UNSUPPORTED_MEDIA_ACTION",
                    "message" to "Unsupported media action '$action' on Android client."
                )
            }
        }
    }

    private fun dispatchKeyEvent(keyCode: Int, actionName: String): Map<String, Any?> {
        val am = audioManager ?: return mapOf("status" to "error", "error" to "AudioManager unavailable.")
        return try {
            val eventTime = SystemClock.uptimeMillis()
            val down = KeyEvent(eventTime, eventTime, KeyEvent.ACTION_DOWN, keyCode, 0)
            val up = KeyEvent(eventTime, eventTime, KeyEvent.ACTION_UP, keyCode, 0)
            am.dispatchMediaKeyEvent(down)
            am.dispatchMediaKeyEvent(up)
            SafeLog.i(TAG, "Dispatched media key event: $actionName (keyCode=$keyCode)")
            mapOf("status" to "success", "action" to actionName, "platform" to "android")
        } catch (e: Exception) {
            SafeLog.e(TAG, "Error dispatching media key $keyCode: ${e.message}")
            mapOf("status" to "error", "error" to (e.message ?: "Failed dispatching media key"))
        }
    }
}
