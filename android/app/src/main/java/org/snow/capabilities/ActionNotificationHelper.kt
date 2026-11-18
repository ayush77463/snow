package org.snow.capabilities

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import org.snow.security.SafeLog
import java.util.concurrent.atomic.AtomicInteger

/**
 * Dedicated helper managing high-priority user-action notifications for Android background operations.
 *
 * Implements Android 17 Background Activity Launch Compliance (Phase 15):
 * - Creates and manages 'snow_actions_channel' with IMPORTANCE_HIGH.
 * - Wraps background launch/messaging intents into immutable PendingIntents.
 * - Validates POST_NOTIFICATIONS permission and OS notification enablement before posting.
 * - Does not expose sensitive payload details in notification text.
 */
object ActionNotificationHelper {

    private const val TAG = "ActionNotificationHelper"
    const val CHANNEL_ID = "snow_actions_channel"
    private val nextNotificationId = AtomicInteger(2000)

    /**
     * Ensure the dedicated SNOW Actions notification channel is registered with the OS.
     */
    fun createActionChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SNOW Action Requests",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifications for actions requiring user confirmation or interaction"
            }
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            manager?.createNotificationChannel(channel)
        }
    }

    /**
     * Check whether the application is permitted and able to post notifications to the user.
     */
    fun canPostNotifications(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) return false
        }
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        return manager?.areNotificationsEnabled() ?: false
    }

    /**
     * Post a high-priority action notification wrapping an authorized Intent.
     *
     * @param context Android application or service context.
     * @param title User-facing notification title.
     * @param content Generic non-sensitive description of the required action.
     * @param intent Intent to be triggered when user taps the notification.
     * @return True if the notification was constructed and dispatched to NotificationManager; False otherwise.
     */
    fun postActionNotification(
        context: Context,
        title: String,
        content: String,
        intent: Intent
    ): Boolean {
        if (!canPostNotifications(context)) {
            SafeLog.w(TAG, "Cannot post action notification: notification permission denied or disabled.")
            return false
        }

        createActionChannel(context)

        val notificationId = nextNotificationId.getAndIncrement()
        val pendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(content)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return false

        return try {
            manager.notify(notificationId, notification)
            SafeLog.i(TAG, "Posted action notification id=$notificationId: '$title'")
            true
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed posting action notification: ${e.message}", e)
            false
        }
    }
}
