package org.snow.capabilities

import android.app.NotificationManager
import android.content.Context
import android.os.Build
import org.snow.security.SafeLog

/**
 * Android Do Not Disturb (DND) toggle handler with real policy access verification.
 *
 * Returns RUNTIME_PERMISSION_REQUIRED with actionable guidance if notification policy
 * access is not granted, and returns actual read-back filter state after applying changes.
 */
class DndHandler(
    private val context: Context,
    private val hasPolicyAccessProvider: (() -> Boolean)? = null,
    private val setInterruptionFilterProvider: ((Int) -> Boolean)? = null,
    private val currentFilterProvider: (() -> Int)? = null,
) {
    companion object {
        private const val TAG = "DndHandler"
    }

    fun toggleDnd(enabled: Boolean): Map<String, Any?> {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        val hasAccess = hasPolicyAccessProvider?.invoke()
            ?: (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && (nm?.isNotificationPolicyAccessGranted == true))

        if (!hasAccess) {
            return mapOf(
                "status" to "error",
                "error" to "RUNTIME_PERMISSION_REQUIRED",
                "message" to "Notification Policy Access (Do Not Disturb) permission is required. Open Settings -> Apps -> Special app access -> Do Not Disturb access -> Enable SNOW."
            )
        }

        val targetFilter = if (enabled) {
            NotificationManager.INTERRUPTION_FILTER_PRIORITY
        } else {
            NotificationManager.INTERRUPTION_FILTER_ALL
        }

        return try {
            val applied = setInterruptionFilterProvider?.invoke(targetFilter) ?: run {
                if (nm == null) {
                    false
                } else {
                    nm.setInterruptionFilter(targetFilter)
                    true
                }
            }
            if (!applied) {
                return mapOf(
                    "status" to "error",
                    "error" to "DND_TOGGLE_FAILED",
                    "message" to "Android NotificationManager was unavailable."
                )
            }
            val currentFilter = currentFilterProvider?.invoke() ?: (nm?.currentInterruptionFilter ?: targetFilter)
            val activeDnd = currentFilter != NotificationManager.INTERRUPTION_FILTER_ALL
            SafeLog.i(TAG, "Updated Android DND state: requested=$enabled active=$activeDnd filter=$currentFilter")
            mapOf(
                "status" to "success",
                "enabled" to activeDnd,
                "requested" to enabled,
                "interruption_filter" to currentFilter,
                "message" to if (activeDnd) "Do Not Disturb enabled." else "Do Not Disturb disabled."
            )
        } catch (e: SecurityException) {
            mapOf(
                "status" to "error",
                "error" to "RUNTIME_PERMISSION_REQUIRED",
                "message" to "Do Not Disturb access was denied by Android: ${e.message}"
            )
        } catch (e: Exception) {
            mapOf(
                "status" to "error",
                "error" to "DND_TOGGLE_FAILED",
                "message" to (e.message ?: "Failed updating Do Not Disturb state.")
            )
        }
    }
}
