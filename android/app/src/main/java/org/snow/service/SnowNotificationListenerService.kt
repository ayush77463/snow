package org.snow.service

import android.app.Notification
import android.app.RemoteInput
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import org.snow.security.SafeLog
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Opt-in NotificationListenerService for SNOW V3.
 *
 * Implements Phase 21 Pillar 3B:
 * - Disabled by default; requires explicit user opt-in.
 * - Sensitive app denylist (banking, OTP, authenticator, password managers).
 * - ZERO disk persistence of notification bodies: retained in-memory only.
 * - Dismissal and Quick Reply through supported RemoteInput actions.
 */
class SnowNotificationListenerService : NotificationListenerService() {

    companion object {
        private const val TAG = "NotificationListener"
        private const val PREFS_NAME = "snow_notification_prefs"
        private const val KEY_OPT_IN = "notification_sync_opt_in"
        private const val MAX_IN_MEMORY_NOTIFICATIONS = 50

        // In-memory live notification feed (zero disk persistence)
        val liveNotifications = CopyOnWriteArrayList<Map<String, Any?>>()

        @Volatile
        var instance: SnowNotificationListenerService? = null

        // Default sensitive application package keywords & identifiers
        private val SENSITIVE_KEYWORDS = listOf(
            "bank",
            "chase",
            "finance",
            "otp",
            "pay",
            "authenticator",
            "password",
            "crypto",
            "wallet",
            "security",
            "token",
            "2fa",
            "mfa"
        )

        private val SENSITIVE_PACKAGES = setOf(
            "com.google.android.apps.authenticator2",
            "com.duosecurity.duomobile",
            "com.twofasapp",
            "com.bitwarden",
            "com.lastpass",
            "com.onepassword",
            "org.keepass",
            "com.coinbase.android",
            "com.binance.dev"
        )

        fun isOptedIn(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            if (!prefs.contains(KEY_OPT_IN)) {
                return true
            }
            return prefs.getBoolean(KEY_OPT_IN, true)
        }

        fun setOptedIn(context: Context, enabled: Boolean) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putBoolean(KEY_OPT_IN, enabled).apply()
            SafeLog.i(TAG, "Notification sync opt-in updated: $enabled")
            if (!enabled) {
                liveNotifications.clear()
            }
        }

        fun isSensitivePackage(packageName: String): Boolean {
            val lower = packageName.lowercase()
            if (SENSITIVE_PACKAGES.contains(lower)) {
                return true
            }
            return SENSITIVE_KEYWORDS.any { lower.contains(it) }
        }

        fun dismissNotification(key: String): Map<String, Any?> {
            val svc = instance
            if (svc == null) {
                return mapOf("status" to "error", "error" to "NotificationListenerService not active or bound.")
            }
            return try {
                svc.cancelNotification(key)
                liveNotifications.removeAll { it["key"] == key }
                mapOf("status" to "success", "key" to key, "action" to "dismissed")
            } catch (e: Exception) {
                mapOf("status" to "error", "error" to (e.message ?: "Failed dismissing notification"))
            }
        }

        fun replyToNotification(key: String, replyText: String): Map<String, Any?> {
            val svc = instance
            if (svc == null) {
                return mapOf("status" to "error", "error" to "NotificationListenerService not active or bound.")
            }
            val sbn = svc.activeNotifications?.firstOrNull { it.key == key }
                ?: return mapOf("status" to "error", "error" to "REPLY_NOT_SUPPORTED", "message" to "Notification no longer active.")

            val actions = sbn.notification.actions ?: return mapOf(
                "status" to "error",
                "error" to "REPLY_NOT_SUPPORTED",
                "message" to "Notification does not have any actions."
            )

            for (action in actions) {
                val remoteInputs = action.remoteInputs ?: continue
                for (remoteInput in remoteInputs) {
                    try {
                        val bundle = Bundle()
                        bundle.putCharSequence(remoteInput.resultKey, replyText)
                        val intent = Intent()
                        RemoteInput.addResultsToIntent(arrayOf(remoteInput), intent, bundle)
                        action.actionIntent.send(svc, 0, intent)
                        return mapOf("status" to "success", "action" to "replied", "key" to key)
                    } catch (e: Exception) {
                        return mapOf("status" to "error", "error" to (e.message ?: "Failed sending reply"))
                    }
                }
            }

            return mapOf(
                "status" to "error",
                "error" to "REPLY_NOT_SUPPORTED",
                "message" to "No RemoteInput action found on this notification."
            )
        }
    }

    fun refreshActiveNotifications() {
        if (!isOptedIn(this)) return
        val current = try { activeNotifications } catch (_: Exception) { null } ?: return
        for (sbn in current) {
            onNotificationPosted(sbn)
        }
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        instance = this
        SafeLog.i(TAG, "Notification listener connected.")
        refreshActiveNotifications()
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        if (instance === this) {
            instance = null
        }
        liveNotifications.clear()
        SafeLog.i(TAG, "Notification listener disconnected.")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null || !isOptedIn(this)) {
            return
        }

        val pkgName = sbn.packageName ?: return
        if (isSensitivePackage(pkgName)) {
            SafeLog.i(TAG, "Excluded notification from sensitive package: $pkgName")
            return
        }

        // Ignore our own foreground service persistent notification
        if (pkgName == packageName) {
            return
        }

        val extras = sbn.notification?.extras
        val title = extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""

        // Determine if notification supports Quick Reply
        var canReply = false
        val actions = sbn.notification?.actions
        if (actions != null) {
            for (action in actions) {
                if (!action.remoteInputs.isNullOrEmpty()) {
                    canReply = true
                    break
                }
            }
        }

        val appName = try {
            val pm = packageManager
            val ai = pm.getApplicationInfo(pkgName, 0)
            pm.getApplicationLabel(ai).toString()
        } catch (_: Exception) {
            pkgName
        }

        val notifMap = mapOf(
            "key" to sbn.key,
            "id" to sbn.id,
            "package_name" to pkgName,
            "app_name" to appName,
            "title" to title,
            "text" to text,
            "timestamp" to sbn.postTime,
            "can_reply" to canReply
        )

        // Add to in-memory list (dedup by key)
        liveNotifications.removeAll { it["key"] == sbn.key }
        liveNotifications.add(0, notifMap)
        while (liveNotifications.size > MAX_IN_MEMORY_NOTIFICATIONS) {
            liveNotifications.removeAt(liveNotifications.size - 1)
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        if (sbn == null) return
        liveNotifications.removeAll { it["key"] == sbn.key }
    }
}
