package org.snow.capabilities

import android.content.Context
import android.media.AudioAttributes
import android.media.Ringtone
import android.media.RingtoneManager
import android.net.Uri
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.snow.security.SafeLog

/**
 * Ring phone / audible alert capability handler.
 *
 * Implements Sub-Milestone 6.2:
 * - Plays alarm/ringtone using RingtoneManager with USAGE_ALARM.
 * - Bounded duration from 1 to 15 seconds (default 5).
 * - Thread-safe duplicate prevention and deterministic cleanup.
 * - Explicit stop support.
 */
class RingerHandler(
    private val context: Context,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.Main)
) {
    companion object {
        private const val TAG = "RingerHandler"
        const val DEFAULT_DURATION_SECONDS = 5
        const val MIN_DURATION_SECONDS = 1
        const val MAX_DURATION_SECONDS = 15
    }

    private val mutex = Mutex()
    private var currentRingtone: Ringtone? = null
    private var activeRingJob: Job? = null

    suspend fun ringPhone(durationSeconds: Int = DEFAULT_DURATION_SECONDS): Map<String, Any?> = mutex.withLock {
        // Enforce duration boundaries
        val boundedDuration = durationSeconds.coerceIn(MIN_DURATION_SECONDS, MAX_DURATION_SECONDS)

        // Stop any running ring operation first
        stopInternal()

        try {
            var alertUri: Uri? = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM)
            if (alertUri == null) {
                alertUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
            }
            if (alertUri == null) {
                alertUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
            }

            val ringtone = alertUri?.let { RingtoneManager.getRingtone(context, it) }
            if (ringtone == null) {
                return mapOf(
                    "status" to "error",
                    "error" to "No system ringtone or audio resource available on this device."
                )
            }

            ringtone.audioAttributes = AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_ALARM)
                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .build()

            ringtone.play()
            currentRingtone = ringtone

            activeRingJob = scope.launch {
                delay(boundedDuration * 1000L)
                mutex.withLock {
                    stopInternal()
                }
            }

            SafeLog.i(TAG, "Ringtone playback initiated for $boundedDuration seconds.")
            return mapOf(
                "status" to "success",
                "duration_seconds" to boundedDuration,
                "message" to "Audible alert initiated on Android device for $boundedDuration seconds."
            )
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed initiating ringtone: ${e.message}", e)
            return mapOf(
                "status" to "error",
                "error" to "Audio playback failed: ${e.message}"
            )
        }
    }

    suspend fun stopRinging(): Map<String, Any?> = mutex.withLock {
        stopInternal()
        mapOf("status" to "success", "message" to "Ringtone stopped.")
    }

    private fun stopInternal() {
        activeRingJob?.cancel()
        activeRingJob = null
        try {
            currentRingtone?.let {
                if (it.isPlaying) {
                    it.stop()
                }
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "Error stopping ringtone: ${e.message}")
        } finally {
            currentRingtone = null
        }
    }
}
