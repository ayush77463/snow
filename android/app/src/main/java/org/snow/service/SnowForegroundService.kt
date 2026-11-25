package org.snow.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.snow.R
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import org.snow.network.DiscoveryManager
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.Constants
import org.snow.security.DeviceIdentity
import org.snow.security.EncryptedCertPinStorage
import org.snow.security.SafeLog
import org.snow.security.SharedPreferencesTokenStorage
import org.snow.transfer.FileTransferClient
import org.snow.ui.MainActivity
import org.snow.ui.SnowUiRepository

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
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile internal var userDisconnected = false
    private var autoConnectJob: Job? = null

    fun startRelay(endpoint: String) {
        if (endpoint.isBlank()) return
        stopRelay()
        val deviceId = org.snow.security.DeviceIdentity.getOrCreate(applicationContext).deviceId
        val certPinStorage = EncryptedCertPinStorage(applicationContext)
        val relayTokenStorage = SharedPreferencesTokenStorage(
            applicationContext,
            prefName = "snow_relay_security"
        )
        val ticket = relayTokenStorage.getToken()
        if (ticket.isNullOrBlank()) {
            SafeLog.e("SnowForegroundService", "Relay connection aborted: missing or unauthenticatable relay ticket in snow_relay_security")
            return
        }
        val prefs = getSharedPreferences(org.snow.ui.SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
        val groupId = prefs.getString("remote_relay_group_id", null) ?: "default_group"
        val targetPeerId = prefs.getString("remote_relay_target_peer", null) ?: "desktop-core"
        val expectedFingerprint = certPinStorage.getPinnedFingerprint()
        val isClientMode = (deviceId < targetPeerId)

        relayClient = org.snow.network.RelayClient(
            relayUrl = endpoint,
            deviceId = deviceId,
            groupId = groupId,
            ticket = ticket,
            targetPeerId = targetPeerId,
            certPinStorage = certPinStorage,
            expectedPeerFingerprint = expectedFingerprint,
            isClientMode = isClientMode
        )
        relayClient?.connect()
    }

    fun stopRelay() {
        relayClient?.disconnect()
        relayClient = null
    }

    fun registerNetworkCallback() {
        if (networkCallback != null) return
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (userDisconnected) {
                    SafeLog.i("SnowForegroundService", "Network restored but userDisconnected == true; suppressing reconnection.")
                    return
                }
                val autoConnectEnabled = getSharedPreferences(SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
                    .getBoolean(SnowUiRepository.PREF_KEY_AUTO_CONNECT_ENABLED, true)
                if (!autoConnectEnabled) {
                    SafeLog.i("SnowForegroundService", "Network restored but autoConnectEnabled == false; suppressing reconnection.")
                    return
                }
                if (client.connectionState.value == ConnectionState.DISCONNECTED ||
                    client.connectionState.value == ConnectionState.RECONNECTING) {
                    val prefs = getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                    val savedHost = prefs.getString(PREF_SAVED_HOST, null)
                    val savedPort = prefs.getInt(PREF_SAVED_PORT, Constants.DEFAULT_PORT)
                    if (!savedHost.isNullOrBlank()) {
                        SafeLog.i("SnowForegroundService", "Network restored: triggering reconnect to $savedHost:$savedPort")
                        client.connect(savedHost, savedPort)
                    }
                }
            }
        }
        try {
            connectivityManager.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (e: Exception) {
            SafeLog.w("SnowForegroundService", "Failed to register network callback: ${e.message}")
        }
    }

    fun unregisterNetworkCallback() {
        val callback = networkCallback ?: return
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        try {
            connectivityManager?.unregisterNetworkCallback(callback)
        } catch (_: Exception) {}
        networkCallback = null
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
        registerNetworkCallback()
        val settingsPrefs = getSharedPreferences(SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
        val savedProfile = settingsPrefs.getString(
            SnowUiRepository.PREF_KEY_PERMISSION_PROFILE,
            settingsPrefs.getString("active_permission_profile", "full_control")
        ) ?: "full_control"
        capabilityDispatcher.activePermissionProfile = savedProfile
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
            ACTION_AUTO_CONNECT -> {
                userDisconnected = false
                isUserDisconnected = false
                getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean(PREF_USER_DISCONNECTED, false)
                    .apply()

                ServiceCompat.startForeground(
                    this,
                    NOTIFICATION_ID,
                    buildNotification("Auto-connecting to SNOW desktop..."),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )

                discoveryManager.startListening()
                startObservingState()
                startObservingDiscovery()
                startObservingAuth()
                executeAutoConnectCascade()
            }
            ACTION_CONNECT -> {
                userDisconnected = false
                isUserDisconnected = false
                getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean(PREF_USER_DISCONNECTED, false)
                    .apply()
                autoConnectJob?.cancel()
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
            ACTION_ONE_TIME_SCREEN_CAPTURE -> {
                val resultCode = intent.getIntExtra(EXTRA_RESULT_CODE, android.app.Activity.RESULT_CANCELED)
                val resultData: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(EXTRA_RESULT_DATA, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(EXTRA_RESULT_DATA)
                }

                // 1. Elevate foreground service with FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION first (Android 14+ prerequisite)
                ServiceCompat.startForeground(
                    this,
                    NOTIFICATION_ID,
                    buildScreenShareNotification(),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE or ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION
                )

                // 2. Only after foreground elevation, obtain MediaProjection
                val projectionManager = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as? android.media.projection.MediaProjectionManager
                val projection = if (resultCode == android.app.Activity.RESULT_OK && resultData != null) {
                    projectionManager?.getMediaProjection(resultCode, resultData)
                } else null

                if (projection != null) {
                    org.snow.capabilities.ScreenCaptureHandler.activeMediaProjection = projection
                    org.snow.capabilities.ScreenCaptureHandler.isConsentGranted = true
                    org.snow.security.SafeLog.i("SnowForegroundService", "MediaProjection one-time consent active and service elevated.")

                    val host = client.currentTargetHost.ifBlank { "127.0.0.1" }
                    val handler = org.snow.capabilities.ScreenCaptureHandler(applicationContext) { transferClient }
                    serviceScope.launch {
                        try {
                            handler.captureScreen(host, 8766)
                        } finally {
                            org.snow.capabilities.ScreenCaptureHandler.resetConsent()
                            demoteScreenShareNotification()
                        }
                    }
                } else {
                    org.snow.security.SafeLog.w("SnowForegroundService", "Failed obtaining MediaProjection for one-time capture.")
                    org.snow.capabilities.ScreenCaptureHandler.resetConsent()
                    demoteScreenShareNotification()
                }
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
                        if (!userDisconnected) {
                            discoveryManager.startListening()
                        }
                        // When disconnected, remove the ongoing foreground notification completely.
                        ServiceCompat.stopForeground(this@SnowForegroundService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                        manager.cancel(NOTIFICATION_ID)
                    }
                    ConnectionState.CONNECTING -> {
                        updateNotification("Connecting...")
                    }
                    ConnectionState.CONNECTED -> {
                        discoveryManager.stopListening()
                        updateNotification("Connected to desktop")
                    }
                    ConnectionState.RECONNECTING -> {
                        discoveryManager.startListening()
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

    internal fun handleDisconnect() {
        userDisconnected = true
        isUserDisconnected = true
        getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PREF_USER_DISCONNECTED, true)
            .apply()
        autoConnectJob?.cancel()
        autoConnectJob = null

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

    private fun executeAutoConnectCascade() {
        autoConnectJob?.cancel()
        autoConnectJob = serviceScope.launch {
            SafeLog.i("SnowForegroundService", "Starting auto-connect cascade...")

            val autoConnectEnabled = getSharedPreferences(SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
                .getBoolean(SnowUiRepository.PREF_KEY_AUTO_CONNECT_ENABLED, true)
            if (!autoConnectEnabled) {
                SafeLog.i("SnowForegroundService", "Auto-connect cascade suppressed: Auto-Connect Nearby is disabled.")
                return@launch
            }

            if (client.connectionState.value == ConnectionState.CONNECTED) {
                return@launch
            }

            // Step 1: USB Loopback (127.0.0.1:8765)
            SafeLog.i("SnowForegroundService", "AutoConnect Step 1: Probing USB loopback 127.0.0.1:8765...")
            client.connect("127.0.0.1", Constants.DEFAULT_PORT)
            val usbConnected = withTimeoutOrNull(1500) {
                client.connectionState.first { it == ConnectionState.CONNECTED }
            }
            if (usbConnected != null) {
                SafeLog.i("SnowForegroundService", "Connected via USB loopback.")
                return@launch
            }

            if (userDisconnected) return@launch

            // Step 2: Saved trusted Wi-Fi endpoint from PREFS_ENDPOINT
            val prefs = getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
            val savedHost = prefs.getString(PREF_SAVED_HOST, null)
            val savedPort = prefs.getInt(PREF_SAVED_PORT, Constants.DEFAULT_PORT)
            if (!savedHost.isNullOrBlank() && savedHost != "127.0.0.1" && savedHost != "localhost") {
                SafeLog.i("SnowForegroundService", "AutoConnect Step 2: Connecting to saved endpoint $savedHost:$savedPort...")
                client.connect(savedHost, savedPort)
                val wifiConnected = withTimeoutOrNull(2500) {
                    client.connectionState.first { it == ConnectionState.CONNECTED }
                }
                if (wifiConnected != null) {
                    SafeLog.i("SnowForegroundService", "Connected via saved Wi-Fi endpoint.")
                    return@launch
                }
            }

            if (userDisconnected) return@launch

            // Step 3: Bounded UDP discovery burst (12s)
            SafeLog.i("SnowForegroundService", "AutoConnect Step 3: Starting bounded UDP discovery (12s)...")
            discoveryManager.startListening()
            val discoveryConnected = withTimeoutOrNull(12000) {
                while (isActive) {
                    val candidate = discoveryManager.getCandidateForPairedDesktop()
                    if (candidate != null) {
                        SafeLog.i("SnowForegroundService", "AutoConnect: Discovered desktop candidate ${candidate.ipAddress}:${candidate.port}")
                        client.connect(candidate.ipAddress, candidate.port)
                        val connected = withTimeoutOrNull(3000) {
                            client.connectionState.first { it == ConnectionState.CONNECTED }
                        }
                        if (connected != null) return@withTimeoutOrNull true
                    }
                    delay(1000)
                }
                false
            }
            if (discoveryConnected == true) {
                SafeLog.i("SnowForegroundService", "Connected via UDP discovery.")
                return@launch
            }

            if (userDisconnected) return@launch

            // Step 4: Saved Remote Relay endpoint fallback
            val settingsPrefs = getSharedPreferences(SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
            val relayEnabled = settingsPrefs.getBoolean("remote_relay_enabled", false)
            val relayEndpoint = settingsPrefs.getString("remote_relay_endpoint", null)
            val relayTokenStorage = SharedPreferencesTokenStorage(applicationContext, prefName = "snow_relay_security")
            val relayTicket = relayTokenStorage.getToken()

            if (relayEnabled && !relayEndpoint.isNullOrBlank() && !relayTicket.isNullOrBlank()) {
                SafeLog.i("SnowForegroundService", "AutoConnect Step 4: Falling back to saved Remote Relay endpoint $relayEndpoint...")
                startRelay(relayEndpoint)
            } else {
                SafeLog.i("SnowForegroundService", "AutoConnect Step 4: No remote relay configured or enabled.")
            }

            // Passive NetworkCallback remains registered (via registerNetworkCallback in onCreate)
            SafeLog.i("SnowForegroundService", "AutoConnect cascade completed; passive network callback active.")
        }
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
        unregisterNetworkCallback()
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
        const val PREF_USER_DISCONNECTED = "user_disconnected"

        const val CHANNEL_ID = "snow_connection_channel"
        const val NOTIFICATION_ID = 1001

        const val ACTION_CONNECT = "org.snow.action.CONNECT"
        const val ACTION_AUTO_CONNECT = "org.snow.action.AUTO_CONNECT"
        const val ACTION_DISCONNECT = "org.snow.action.DISCONNECT"
        const val ACTION_START_SCREEN_SHARE = "org.snow.action.START_SCREEN_SHARE"
        const val ACTION_STOP_SCREEN_SHARE = "org.snow.action.STOP_SCREEN_SHARE"
        const val ACTION_ONE_TIME_SCREEN_CAPTURE = "org.snow.action.ONE_TIME_SCREEN_CAPTURE"
        const val ACTION_START_PEER_HOST = "org.snow.action.START_PEER_HOST"
        const val ACTION_STOP_PEER_HOST = "org.snow.action.STOP_PEER_HOST"
        const val EXTRA_HOST = "org.snow.extra.HOST"
        const val EXTRA_PORT = "org.snow.extra.PORT"
        const val EXTRA_RESULT_CODE = "org.snow.extra.RESULT_CODE"
        const val EXTRA_RESULT_DATA = "org.snow.extra.RESULT_DATA"

        @Volatile
        var isUserDisconnected: Boolean = false

        fun isDisconnectedByUser(context: Context): Boolean {
            val prefs = context.getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
            return isUserDisconnected || prefs.getBoolean(PREF_USER_DISCONNECTED, false)
        }

        fun startAutoConnect(context: Context) {
            val intent = Intent(context, SnowForegroundService::class.java).apply {
                action = ACTION_AUTO_CONNECT
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

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

        fun startOneTimeScreenCapture(context: Context, resultCode: Int, data: Intent) {
            val intent = Intent(context, SnowForegroundService::class.java).apply {
                action = ACTION_ONE_TIME_SCREEN_CAPTURE
                putExtra(EXTRA_RESULT_CODE, resultCode)
                putExtra(EXTRA_RESULT_DATA, data)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }
}
