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

    fun handleMediaControl(action: String?, value: Number? = null): Map<String, Any?> {
        if (action.isNullOrBlank()) {
            return mapOf(
                "status" to "error",
                "error" to "Missing or empty media action."
            )
        }

        val canonical = action.trim().lowercase()
        val supportedActions = setOf(
            "play_pause", "play", "pause",
            "stop",
            "next", "next_track",
            "previous", "prev", "prev_track",
            "volume_up", "vol_up",
            "volume_down", "vol_down",
            "volume_set", "volume",
            "mute", "unmute", "toggle_mute", "volume_mute"
        )
        if (!supportedActions.contains(canonical)) {
            return mapOf(
                "status" to "error",
                "error" to "UNSUPPORTED_MEDIA_ACTION",
                "message" to "Unsupported media action '$action' on Android client."
            )
        }

        val boundedVolume: Int? = if (canonical == "volume_set" || canonical == "volume") {
            val raw = value?.toDouble()
            if (raw == null || raw.isNaN() || raw.isInfinite() || raw < 0.0 || raw > 100.0) {
                return mapOf(
                    "status" to "error",
                    "error" to "INVALID_VOLUME_LEVEL",
                    "message" to "Volume level must be a number between 0 and 100."
                )
            }
            raw.toInt().coerceIn(0, 100)
        } else {
            null
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
            "stop" -> dispatchKeyEvent(KeyEvent.KEYCODE_MEDIA_STOP, canonical)
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
            "volume_set", "volume" -> {
                val bounded = boundedVolume ?: 0
                try {
                    val maxVol = am.getStreamMaxVolume(AudioManager.STREAM_MUSIC).coerceAtLeast(1)
                    val targetIndex = kotlin.math.round((bounded * maxVol) / 100.0).toInt().coerceIn(0, maxVol)
                    am.setStreamVolume(AudioManager.STREAM_MUSIC, targetIndex, AudioManager.FLAG_SHOW_UI)
                    mapOf(
                        "status" to "success",
                        "action" to "volume_set",
                        "volume_percent" to bounded,
                        "platform" to "android"
                    )
                } catch (e: Exception) {
                    mapOf("status" to "error", "error" to (e.message ?: "Failed setting volume"))
                }
            }
            "mute", "unmute", "toggle_mute", "volume_mute" -> {
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
