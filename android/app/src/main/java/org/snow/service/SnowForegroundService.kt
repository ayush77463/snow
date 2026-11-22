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
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.network.DiscoveryManager
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.Constants
import org.snow.security.DeviceIdentity
import org.snow.security.EncryptedCertPinStorage
import org.snow.security.SharedPreferencesTokenStorage
import org.snow.transfer.FileTransferClient
import org.snow.ui.MainActivity

/**
 * Foreground service maintaining active connection and heartbeat loop to the SNOW desktop core.
 */
class SnowForegroundService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var stateObserverJob: Job? = null
    private var discoveryObserverJob: Job? = null
    private var authObserverJob: Job? = null

    val client: SnowWebSocketClient by lazy {
        val identity = DeviceIdentity.getOrCreate(applicationContext)
        val tokenStorage = SharedPreferencesTokenStorage(applicationContext)
        val certPinStorage = EncryptedCertPinStorage(applicationContext)
        SnowWebSocketClient(
            certPinStorage = certPinStorage,
            tokenStorage = tokenStorage,
            identity = identity,
            useTls = true,
            context = applicationContext
        )
    }

    val discoveryManager: DiscoveryManager by lazy {
        val certPinStorage = EncryptedCertPinStorage(applicationContext)
        val tokenStorage = SharedPreferencesTokenStorage(applicationContext)
        DiscoveryManager(
            certPinStorage = certPinStorage,
            tokenStorage = tokenStorage
        )
    }

    val transferClient: FileTransferClient by lazy {
        val identity = DeviceIdentity.getOrCreate(applicationContext)
        val tokenStorage = SharedPreferencesTokenStorage(applicationContext)
        val certPinStorage = EncryptedCertPinStorage(applicationContext)
        FileTransferClient(
            context = applicationContext,
            deviceId = identity.deviceId,
            certPinStorage = certPinStorage,
            tokenStorage = tokenStorage,
            useTls = true
        )
    }

    val capabilityDispatcher: AndroidCapabilityDispatcher by lazy {
        AndroidCapabilityDispatcher(
            context = applicationContext,
            transferClientProvider = { transferClient }
        )
    }

    val liveScreenHandler: org.snow.capabilities.LiveScreenStreamHandler by lazy {
        org.snow.capabilities.LiveScreenStreamHandler(
            context = applicationContext,
            transferClientProvider = { transferClient }
        )
    }

    val peerHostManager: org.snow.network.AndroidPeerHostManager by lazy {
        org.snow.network.AndroidPeerHostManager()
    }

    var relayClient: org.snow.network.RelayClient? = null

    fun startRelay(endpoint: String) {
        if (endpoint.isBlank()) return
        stopRelay()
        val deviceId = org.snow.security.DeviceIdentity.getOrCreate(applicationContext).deviceId
        relayClient = org.snow.network.RelayClient(
            relayUrl = endpoint,
            deviceId = deviceId,
            groupId = "default_group",
            ticket = "temp_ticket",
            targetPeerId = "desktop-core",
            certPinStorage = null,
            expectedPeerFingerprint = null,
            isClientMode = true
        )
        relayClient?.connect()
    }

    fun stopRelay() {
        relayClient?.disconnect()
        relayClient = null
    }

    fun startPeerHost() {
        peerHostManager.setHostModeSettingEnabled(true)
        val tokenStorage = SharedPreferencesTokenStorage(
            applicationContext,
            prefName = SharedPreferencesTokenStorage.PEER_HOST_PREFS_NAME
        )
        val success = peerHostManager.enableHostMode(
            port = org.snow.network.AndroidPeerHostManager.DEFAULT_HOST_PORT,
            tokenStorage = tokenStorage,
            dispatcher = capabilityDispatcher,
            localDeviceId = org.snow.security.DeviceIdentity.getOrCreate(applicationContext).deviceId,
            manifestProvider = { org.snow.network.DeviceNode.buildAndroidManifest(applicationContext).toMap() },
            parentScope = serviceScope
        )
        if (success) {
            updateNotification("Peer Host Active on Port ${peerHostManager.activePort}")
        }
    }

    fun stopPeerHost() {
        peerHostManager.setHostModeSettingEnabled(false)
        peerHostManager.disableHostMode()
        updateNotification("Peer Host Stopped")
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
        org.snow.ui.SnowUiRepository.getInstance(applicationContext).bindService(this)
        client.requestDispatcher = { action, data ->
            capabilityDispatcher.dispatch(
                action = action,
                data = data,
                serverHost = client.currentTargetHost,
                defaultTransferPort = 8766
            )
        }
    }

    /**
     * Build live capability manifest reflecting current runtime/foreground state
     * and transmit over active authenticated WSS session.
     */
    fun updateManifest() {
        if (client.connectionState.value == org.snow.network.ConnectionState.CONNECTED &&
            client.authState.value is org.snow.network.AuthState.Authenticated) {
            val liveManifest = org.snow.network.DeviceNode.buildAndroidManifest(applicationContext)
            client.sendManifestUpdate(liveManifest)
        }
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

                discoveryManager.startListening()
                startObservingState()
                startObservingDiscovery()
                startObservingAuth()
                client.connect(host, port)
            }
            ACTION_START_SCREEN_SHARE -> {
                val resultCode = intent.getIntExtra(EXTRA_RESULT_CODE, android.app.Activity.RESULT_CANCELED)
                val resultData: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(EXTRA_RESULT_DATA, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(EXTRA_RESULT_DATA)
                }

                // 1. Elevate foreground service with FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION first
                ServiceCompat.startForeground(
                    this,
                    NOTIFICATION_ID,
                    buildScreenShareNotification(),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE or ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION
                )

                // 2. Only after foreground elevation, obtain the MediaProjection
                val projectionManager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? android.media.projection.MediaProjectionManager
                val projection = if (resultCode == android.app.Activity.RESULT_OK && resultData != null) {
                    projectionManager?.getMediaProjection(resultCode, resultData)
                } else null

                if (projection != null) {
                    liveScreenHandler.onRevoked = {
                        demoteScreenShareNotification()
                    }
                    val host = client.currentTargetHost.ifBlank { "127.0.0.1" }
                    liveScreenHandler.startStreaming(projection, host, 8766)
                } else {
                    org.snow.security.SafeLog.w("SnowForegroundService", "MediaProjection is null after elevation, cannot start screen share.")
                    demoteScreenShareNotification()
                }
            }
            ACTION_STOP_SCREEN_SHARE -> {
                val host = client.currentTargetHost.ifBlank { "127.0.0.1" }
                liveScreenHandler.stopStreaming(host, 8766)
                demoteScreenShareNotification()
            }
            ACTION_START_PEER_HOST -> {
                ServiceCompat.startForeground(
                    this,
                    NOTIFICATION_ID,
                    buildNotification("Direct Phone-to-Phone Host Mode Active"),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )
                startPeerHost()
            }
            ACTION_STOP_PEER_HOST -> {
                stopPeerHost()
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

    private fun startObservingDiscovery() {
        discoveryObserverJob?.cancel()
        discoveryObserverJob = serviceScope.launch {
            discoveryManager.peers.collectLatest { _ ->
                val currentHost = client.currentTargetHost.trim().lowercase()
                if (currentHost in setOf("127.0.0.1", "localhost", "::1")) {
                    return@collectLatest
                }
                val candidate = discoveryManager.getCandidateForPairedDesktop()
                if (candidate != null) {
                    client.updateTargetEndpoint(candidate.ipAddress, candidate.port)
                }
            }
        }
    }

    private fun startObservingAuth() {
        authObserverJob?.cancel()
        authObserverJob = serviceScope.launch {
            client.authState.collectLatest { auth ->
                if (auth is AuthState.Authenticated) {
                    val host = client.currentTargetHost
                    val port = client.currentTargetPort
                    if (host.isNotBlank()) {
                        val prefs = getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                        prefs.edit()
                            .putString(PREF_SAVED_HOST, host)
                            .putInt(PREF_SAVED_PORT, port)
                            .apply()
                    }
                }
            }
        }
    }

    private fun handleDisconnect() {
        // 0. Stop live screen sharing if active
        liveScreenHandler.stopStreaming(client.currentTargetHost, 8766)

        // 1. Cancel observers first so that DISCONNECTED state does NOT trigger updateNotification()
        peerHostManager.disableHostMode()
        stateObserverJob?.cancel()
        stateObserverJob = null
        discoveryObserverJob?.cancel()
        discoveryObserverJob = null
        authObserverJob?.cancel()
        authObserverJob = null

        // 2. Stop discovery listener
        discoveryManager.stopListening()

        // 3. Disconnect the WebSocket client (sends clean 1000 close frame)
        client.disconnect()

        // 4. Remove foreground service status and remove the notification
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)

        // 5. Explicitly cancel the notification to ensure OEM notification managers clear it immediately
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.cancel(NOTIFICATION_ID)

        // 6. Stop the service
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

        val pushClipIntent = Intent(this, org.snow.ui.ClipSyncActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingPushClip = PendingIntent.getActivity(
            this,
            2,
            pushClipIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SNOW Capability Bridge")
            .setContentText(statusText)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentIntent(pendingOpenApp)
            .addAction(android.R.drawable.ic_menu_send, "Push Clipboard", pendingPushClip)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", pendingDisconnect)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(statusText: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(statusText))
    }

    private fun buildScreenShareNotification(): Notification {
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingOpenApp = PendingIntent.getActivity(
            this,
            0,
            openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopShareIntent = Intent(this, SnowForegroundService::class.java).apply {
            action = ACTION_STOP_SCREEN_SHARE
        }
        val pendingStopShare = PendingIntent.getService(
            this,
            3,
            stopShareIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SNOW Live Screen Sharing")
            .setContentText("Active live screen sharing to desktop")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentIntent(pendingOpenApp)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop Sharing", pendingStopShare)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        liveScreenHandler.stopStreaming()
        org.snow.ui.SnowUiRepository.getInstance(applicationContext).unbindService()
        peerHostManager.disableHostMode()
        stateObserverJob?.cancel()
        stateObserverJob = null
        discoveryObserverJob?.cancel()
        discoveryObserverJob = null
        authObserverJob?.cancel()
        authObserverJob = null
        discoveryManager.stopListening()
        client.disconnect()
        client.teardown()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.cancel(NOTIFICATION_ID)
        serviceScope.cancel()
    }

    fun demoteScreenShareNotification() {
        if (client.connectionState.value == ConnectionState.CONNECTED) {
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                buildNotification("Connected to desktop"),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        }
    }

    companion object {
        const val PREFS_ENDPOINT = "snow_endpoint_prefs"
        const val PREF_SAVED_HOST = "saved_host"
        const val PREF_SAVED_PORT = "saved_port"

        const val CHANNEL_ID = "snow_connection_channel"
        const val NOTIFICATION_ID = 1001

        const val ACTION_CONNECT = "org.snow.action.CONNECT"
        const val ACTION_DISCONNECT = "org.snow.action.DISCONNECT"
        const val ACTION_START_SCREEN_SHARE = "org.snow.action.START_SCREEN_SHARE"
        const val ACTION_STOP_SCREEN_SHARE = "org.snow.action.STOP_SCREEN_SHARE"
        const val ACTION_START_PEER_HOST = "org.snow.action.START_PEER_HOST"
        const val ACTION_STOP_PEER_HOST = "org.snow.action.STOP_PEER_HOST"
        const val EXTRA_HOST = "org.snow.extra.HOST"
        const val EXTRA_PORT = "org.snow.extra.PORT"
        const val EXTRA_RESULT_CODE = "org.snow.extra.RESULT_CODE"
        const val EXTRA_RESULT_DATA = "org.snow.extra.RESULT_DATA"

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

        fun startScreenShare(context: Context, resultCode: Int, data: Intent) {
            val intent = Intent(context, SnowForegroundService::class.java).apply {
                action = ACTION_START_SCREEN_SHARE
                putExtra(EXTRA_RESULT_CODE, resultCode)
                putExtra(EXTRA_RESULT_DATA, data)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stopScreenShare(context: Context) {
            val intent = Intent(context, SnowForegroundService::class.java).apply {
                action = ACTION_STOP_SCREEN_SHARE
            }
            context.startService(intent)
        }
    }
}
