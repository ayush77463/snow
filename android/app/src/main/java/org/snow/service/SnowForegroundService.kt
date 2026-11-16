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
import org.snow.security.DeviceIdentity
import org.snow.security.EncryptedCertPinStorage
import org.snow.security.SharedPreferencesTokenStorage
import org.snow.ui.MainActivity

/**
 * Foreground service maintaining active connection and heartbeat loop to the SNOW desktop core.
 */
class SnowForegroundService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var stateObserverJob: Job? = null

    val client: SnowWebSocketClient by lazy {
        val identity = DeviceIdentity.getOrCreate(applicationContext)
        val tokenStorage = SharedPreferencesTokenStorage(applicationContext)
        val certPinStorage = EncryptedCertPinStorage(applicationContext)
        SnowWebSocketClient(
            certPinStorage = certPinStorage,
            tokenStorage = tokenStorage,
            identity = identity,
            useTls = true
        )
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
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val host = intent.getStringExtra(EXTRA_HOST) ?: "127.0.0.1"
                val port = intent.getIntExtra(EXTRA_PORT, Constants.DEFAULT_PORT)

                // In Android 8.0+ (and strictly enforced in Android 14/16), any service
                // invoked via startForegroundService MUST call startForeground() synchronously
                // in onStartCommand() to satisfy the OS timeout contract.
                ServiceCompat.startForeground(
                    this,
                    NOTIFICATION_ID,
                    buildNotification("Connecting to $host:$port..."),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )

                startObservingState()
                client.connect(host, port)
            }
            ACTION_DISCONNECT -> {
                handleDisconnect()
            }
            else -> {
                // Defensive fallback: if invoked via startForegroundService with null or unexpected action,
                // fulfill the OS contract immediately then cleanly stop.
                ServiceCompat.startForeground(
                    this,
                    NOTIFICATION_ID,
                    buildNotification("SNOW Capability Bridge"),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun startObservingState() {
        stateObserverJob?.cancel()
        stateObserverJob = serviceScope.launch {
            client.connectionState.collectLatest { state ->
                when (state) {
                    ConnectionState.DISCONNECTED -> {
                        // When disconnected, remove the ongoing foreground notification completely.
                        ServiceCompat.stopForeground(this@SnowForegroundService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                        manager.cancel(NOTIFICATION_ID)
                    }
                    ConnectionState.CONNECTING -> {
                        updateNotification("Connecting...")
                    }
                    ConnectionState.CONNECTED -> {
                        updateNotification("Connected to desktop")
                    }
                    ConnectionState.RECONNECTING -> {
                        updateNotification("Reconnecting...")
                    }
                }
            }
        }
    }

    private fun handleDisconnect() {
        // 1. Cancel the state observer first so that DISCONNECTED state does NOT trigger updateNotification()
        stateObserverJob?.cancel()
        stateObserverJob = null

        // 2. Disconnect the WebSocket client (sends clean 1000 close frame)
        client.disconnect()

        // 3. Remove foreground service status and remove the notification
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)

        // 4. Explicitly cancel the notification to ensure OEM notification managers clear it immediately
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.cancel(NOTIFICATION_ID)

        // 5. Stop the service
        stopSelf()
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
        stateObserverJob = null
        client.disconnect()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.cancel(NOTIFICATION_ID)
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
