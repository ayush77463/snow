package org.snow.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.snow.R
import org.snow.network.ConnectionState
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.Constants
import org.snow.ui.MainActivity

/**
 * Foreground service maintaining active connection and heartbeat loop to the SNOW desktop core.
 */
class SnowForegroundService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var stateObserverJob: Job? = null

    val client: SnowWebSocketClient by lazy {
        SnowWebSocketClient()
    }

    private val binder = LocalBinder()

    inner class LocalBinder : Binder() {
        val service: SnowForegroundService
            get() = this@SnowForegroundService
    }

    override fun onBind(intent: Intent?): IBinder {
        return binder
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            buildNotification("Initializing SNOW bridge..."),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
        )

        stateObserverJob = serviceScope.launch {
            client.connectionState.collectLatest { state ->
                val statusText = when (state) {
                    ConnectionState.DISCONNECTED -> "Disconnected"
                    ConnectionState.CONNECTING -> "Connecting..."
                    ConnectionState.CONNECTED -> "Connected to desktop"
                    ConnectionState.RECONNECTING -> "Reconnecting..."
                }
                updateNotification(statusText)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val host = intent.getStringExtra(EXTRA_HOST) ?: "127.0.0.1"
                val port = intent.getIntExtra(EXTRA_PORT, Constants.DEFAULT_PORT)
                client.connect(host, port)
            }
            ACTION_DISCONNECT -> {
                client.disconnect()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SNOW Connection Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows live connection status of the SNOW capability bridge"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String): Notification {
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingOpenApp = PendingIntent.getActivity(
            this,
            0,
            openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val disconnectIntent = Intent(this, SnowForegroundService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val pendingDisconnect = PendingIntent.getService(
            this,
            1,
            disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SNOW Capability Bridge")
            .setContentText(statusText)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentIntent(pendingOpenApp)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", pendingDisconnect)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(statusText: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(statusText))
    }

    override fun onDestroy() {
        super.onDestroy()
        stateObserverJob?.cancel()
        client.disconnect()
        serviceScope.cancel()
    }

    companion object {
        const val CHANNEL_ID = "snow_connection_channel"
        const val NOTIFICATION_ID = 1001

        const val ACTION_CONNECT = "org.snow.action.CONNECT"
        const val ACTION_DISCONNECT = "org.snow.action.DISCONNECT"
        const val EXTRA_HOST = "org.snow.extra.HOST"
        const val EXTRA_PORT = "org.snow.extra.PORT"

        fun startConnect(context: Context, host: String, port: Int) {
            val intent = Intent(context, SnowForegroundService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_HOST, host)
                putExtra(EXTRA_PORT, port)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, SnowForegroundService::class.java).apply {
                action = ACTION_DISCONNECT
            }
            context.startService(intent)
        }
    }
}
