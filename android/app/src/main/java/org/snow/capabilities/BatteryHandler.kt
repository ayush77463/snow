package org.snow.capabilities

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs

/**
 * Real Android battery and device telemetry capability handler.
 *
 * Implements Sub-Milestone 6.1 & Stage 2A Telemetry:
 * - Queries battery percentage, charging state, power source, and health.
 * - Queries total and available RAM via ActivityManager.
 * - Queries total and available internal storage via StatFs.
 * - Extracts battery temperature where available.
 * - Collects device manufacturer, model, and OS version info.
 * - Gracefully handles missing telemetry without fabricating values.
 */
class BatteryHandler(private val context: Context) {

    fun getBatteryStatus(): Map<String, Any?> {
        val batteryIntent: Intent? = context.registerReceiver(
            null,
            IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        )

        val level = batteryIntent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryIntent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val percent: Int? = if (level >= 0 && scale > 0) {
            ((level.toFloat() / scale.toFloat()) * 100).toInt()
        } else {
            null
        }

        val statusInt = batteryIntent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val isCharging = statusInt == BatteryManager.BATTERY_STATUS_CHARGING ||
                statusInt == BatteryManager.BATTERY_STATUS_FULL

        val pluggedInt = batteryIntent?.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) ?: 0
        val powerSource = when (pluggedInt) {
            BatteryManager.BATTERY_PLUGGED_AC -> "AC"
            BatteryManager.BATTERY_PLUGGED_USB -> "USB"
            BatteryManager.BATTERY_PLUGGED_WIRELESS -> "WIRELESS"
            else -> if (isCharging) "OTHER" else "NONE"
        }

        val healthInt = batteryIntent?.getIntExtra(BatteryManager.EXTRA_HEALTH, -1) ?: -1
        val health = when (healthInt) {
            BatteryManager.BATTERY_HEALTH_GOOD -> "GOOD"
            BatteryManager.BATTERY_HEALTH_OVERHEAT -> "OVERHEAT"
            BatteryManager.BATTERY_HEALTH_DEAD -> "DEAD"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "OVER_VOLTAGE"
            BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "UNSPECIFIED_FAILURE"
            BatteryManager.BATTERY_HEALTH_COLD -> "COLD"
            else -> "UNKNOWN"
        }

        val tempRaw = batteryIntent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1
        val temperatureCelsius: Double? = if (tempRaw > 0) {
            tempRaw / 10.0
        } else {
            null
        }

        // Telemetry: RAM Metrics via ActivityManager
        var ramTotalBytes: Long? = null
        var ramAvailableBytes: Long? = null
        try {
            val actManager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            if (actManager != null) {
                val memInfo = ActivityManager.MemoryInfo()
                actManager.getMemoryInfo(memInfo)
                ramTotalBytes = memInfo.totalMem
                ramAvailableBytes = memInfo.availMem
            }
        } catch (_: Exception) {
        }

        // Telemetry: Storage Metrics via StatFs
        var storageTotalBytes: Long? = null
        var storageAvailableBytes: Long? = null
        try {
            val stat = StatFs(Environment.getDataDirectory().path)
            storageTotalBytes = stat.totalBytes
            storageAvailableBytes = stat.availableBytes
        } catch (_: Exception) {
        }

        return mapOf(
            "status" to "success",
            "available" to (percent != null),
            "level" to percent,
            "charging" to isCharging,
            "power_source" to powerSource,
            "health" to health,
            "temperature_celsius" to temperatureCelsius,
            "ram_total_bytes" to ramTotalBytes,
            "ram_available_bytes" to ramAvailableBytes,
            "storage_total_bytes" to storageTotalBytes,
            "storage_available_bytes" to storageAvailableBytes,
            "device_model" to Build.MODEL,
            "manufacturer" to Build.MANUFACTURER,
            "android_version" to Build.VERSION.RELEASE,
            "sdk_int" to Build.VERSION.SDK_INT
        )
    }
}
