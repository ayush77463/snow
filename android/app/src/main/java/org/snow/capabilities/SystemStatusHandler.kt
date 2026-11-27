package org.snow.capabilities

import android.app.ActivityManager
import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.media.AudioManager
import android.os.Build
import android.os.PowerManager
import android.os.StatFs
import org.snow.security.SafeLog

/**
 * Read-only Android device and audio telemetry handler for M4.4 capabilities:
 * - `android_device_info`: model, OS version, RAM, storage, screen/lock state, and live M4.3 transport
 * - `android_audio_status`: music/ring/alarm volumes, ringer mode, and non-mutating DND readback
 *
 * Requires ZERO additional runtime/manifest permissions and never exposes hardware serials or IMEI.
 */
class SystemStatusHandler(
    private val context: Context,
    private val transportSnapshotProvider: (() -> Map<String, Any?>)? = null,
    private val memoryInfoProvider: (() -> Pair<Long, Long>?)? = null,
    private val storageInfoProvider: (() -> Pair<Long, Long>?)? = null,
    private val interactiveAndLockedProvider: (() -> Pair<Boolean?, Boolean?>)? = null,
    private val dndPolicyAccessProvider: (() -> Boolean)? = null,
    private val dndFilterProvider: (() -> Int?)? = null,
    private val audioStreamsProvider: (() -> Map<String, Any?>)? = null
) {
    companion object {
        private const val TAG = "SystemStatusHandler"
    }

    fun getDeviceInfo(): Map<String, Any?> {
        val (ramTotalMb, ramAvailMb) = memoryInfoProvider?.invoke() ?: readMemoryMb()
        val (storageTotalBytes, storageAvailBytes) = storageInfoProvider?.invoke() ?: readStorageBytes()
        val (interactive, locked) = interactiveAndLockedProvider?.invoke() ?: readScreenLockState()
        val transport = transportSnapshotProvider?.invoke() ?: readActiveTransportSnapshot()

        val result = linkedMapOf<String, Any?>(
            "status" to "success",
            "model" to (Build.MODEL ?: "unknown"),
            "manufacturer" to (Build.MANUFACTURER ?: "unknown"),
            "brand" to (Build.BRAND ?: "unknown"),
            "android_version" to (Build.VERSION.RELEASE ?: "unknown"),
            "sdk_int" to Build.VERSION.SDK_INT,
            "ram_total_mb" to ramTotalMb,
            "ram_available_mb" to ramAvailMb,
            "storage_total_bytes" to storageTotalBytes,
            "storage_available_bytes" to storageAvailBytes,
            "screen_interactive" to interactive,
            "device_locked" to locked,
            "active_transport" to transport
        )
        SafeLog.i(TAG, "Collected Android device info (sdk=${Build.VERSION.SDK_INT})")
        return result
    }

    fun getAudioStatus(): Map<String, Any?> {
        val streamInfo = audioStreamsProvider?.invoke() ?: readAudioStreams()
        val nm = try {
            context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        } catch (_: Throwable) {
            null
        }
        val policyGranted = try {
            dndPolicyAccessProvider?.invoke()
                ?: (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && (nm?.isNotificationPolicyAccessGranted == true))
        } catch (_: Throwable) {
            false
        }

        val (dndStatus, filterCode) = if (!policyGranted) {
            "unavailable" to null
        } else {
            val f = try {
                dndFilterProvider?.invoke() ?: nm?.currentInterruptionFilter
            } catch (_: Throwable) {
                null
            }
            val label = when (f) {
                NotificationManager.INTERRUPTION_FILTER_ALL -> "all"
                NotificationManager.INTERRUPTION_FILTER_PRIORITY -> "priority"
                NotificationManager.INTERRUPTION_FILTER_NONE -> "none"
                NotificationManager.INTERRUPTION_FILTER_ALARMS -> "alarms"
                null -> "unavailable"
                else -> "unknown"
            }
            label to f
        }

        val out = linkedMapOf<String, Any?>(
            "status" to "success",
            "notification_policy_access_granted" to policyGranted,
            "dnd_status" to dndStatus
        )
        if (filterCode != null) {
            out["interruption_filter"] = filterCode
        }
        out.putAll(streamInfo)
        SafeLog.i(TAG, "Collected Android audio status (dnd=$dndStatus policyGranted=$policyGranted)")
        return out
    }

    private fun readMemoryMb(): Pair<Long, Long> {
        return try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
                ?: return -1L to -1L
            val mi = ActivityManager.MemoryInfo()
            am.getMemoryInfo(mi)
            val totalMb = (mi.totalMem / (1024L * 1024L)).coerceAtLeast(0L)
            val availMb = (mi.availMem / (1024L * 1024L)).coerceAtLeast(0L)
            totalMb to availMb
        } catch (_: Throwable) {
            -1L to -1L
        }
    }

    private fun readStorageBytes(): Pair<Long, Long> {
        return try {
            val targetPath = context.filesDir?.path ?: return -1L to -1L
            val stat = StatFs(targetPath)
            val total = stat.totalBytes.coerceAtLeast(0L)
            val avail = stat.availableBytes.coerceAtLeast(0L)
            total to avail
        } catch (_: Throwable) {
            -1L to -1L
        }
    }

    private fun readScreenLockState(): Pair<Boolean?, Boolean?> {
        val interactive = try {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            pm?.isInteractive
        } catch (_: Throwable) {
            null
        }
        val locked = try {
            val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            km?.isDeviceLocked
        } catch (_: Throwable) {
            null
        }
        return interactive to locked
    }

    private fun readActiveTransportSnapshot(): Map<String, Any?> {
        return try {
            val svc = org.snow.service.SnowForegroundService.getActiveInstance()
            if (svc == null) {
                mapOf("route" to "offline", "badge" to "Offline", "connected" to false)
            } else {
                val targetId = svc.client.activeTargetDeviceId() ?: ""
                val snapshot = if (targetId.isNotBlank()) svc.transportOrchestrator.snapshotFor(targetId) else null
                mapOf(
                    "route" to (snapshot?.activeRoute?.wireName ?: org.snow.network.TransportClassifier.classifyRoute(host = svc.client.currentTargetHost).wireName),
                    "badge" to (snapshot?.activeBadge ?: org.snow.network.TransportClassifier.classifyTransportBadge(host = svc.client.currentTargetHost)),
                    "connected" to (svc.client.connectionState.value == org.snow.network.ConnectionState.CONNECTED),
                    "switching" to (snapshot?.switching ?: false)
                )
            }
        } catch (_: Throwable) {
            mapOf("route" to "unknown", "badge" to "Unknown", "connected" to false)
        }
    }

    private fun readAudioStreams(): Map<String, Any?> {
        val am = try {
            context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
        } catch (_: Throwable) {
            null
        } ?: return mapOf("streams" to emptyMap<String, Any?>(), "ringer_mode" to "unknown")

        fun streamEntry(streamType: Int): Map<String, Any?> {
            val cur = am.getStreamVolume(streamType)
            val max = am.getStreamMaxVolume(streamType).coerceAtLeast(1)
            val pct = ((cur.toDouble() / max.toDouble()) * 100.0).toInt().coerceIn(0, 100)
            return mapOf("volume" to cur, "max_volume" to max, "percent" to pct)
        }

        val ringer = when (am.ringerMode) {
            AudioManager.RINGER_MODE_NORMAL -> "normal"
            AudioManager.RINGER_MODE_VIBRATE -> "vibrate"
            AudioManager.RINGER_MODE_SILENT -> "silent"
            else -> "unknown"
        }

        return mapOf(
            "ringer_mode" to ringer,
            "streams" to mapOf(
                "media" to streamEntry(AudioManager.STREAM_MUSIC),
                "ring" to streamEntry(AudioManager.STREAM_RING),
                "alarm" to streamEntry(AudioManager.STREAM_ALARM)
            )
        )
    }
}
