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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
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
        val autoConnect = getSharedPreferences(org.snow.ui.SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
            .getBoolean(org.snow.ui.SnowUiRepository.PREF_KEY_AUTO_CONNECT_ENABLED, true)
        SnowWebSocketClient(
            certPinStorage = certPinStorage,
            tokenStorage = tokenStorage,
            identity = identity,
            useTls = true,
            context = applicationContext
        ).apply {
            autoReconnectEnabled = autoConnect
            onDeviceRevoked = { _ ->
                userDisconnected = true
                isUserDisconnected = true
                _isServiceRunningFlow.value = false
                setDisconnectedByUser(applicationContext, true)
                cancelAutoConnect()
                discoveryManager.stopListening()
                ServiceCompat.stopForeground(this@SnowForegroundService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                val manager = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
                manager?.cancel(NOTIFICATION_ID)
            }
        }
    }

    val discoveryManager: DiscoveryManager by lazy {
        val identity = org.snow.security.DeviceIdentity.getOrCreate(applicationContext)
        val certPinStorage = EncryptedCertPinStorage(applicationContext)
        val tokenStorage = SharedPreferencesTokenStorage(applicationContext)
        DiscoveryManager(
            certPinStorage = certPinStorage,
            tokenStorage = tokenStorage,
            localDeviceId = identity.deviceId,
            onWakeTargetMatched = { peer ->
                if (!userDisconnected && client.autoReconnectEnabled &&
                    client.connectionState.value == ConnectionState.DISCONNECTED
                ) {
                    SafeLog.i("SnowForegroundService", "Wake beacon matched for ${peer.ipAddress}:${peer.port}; reconnecting...")
                    client.connect(peer.ipAddress, peer.port)
                }
            }
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
            useTls = true,
            targetDeviceIdProvider = { client.activeTargetDeviceId() }
        ).apply {
            transportOrchestrator = this@SnowForegroundService.transportOrchestrator
            usbMappingVerifiedProvider = {
                org.snow.network.TransportClassifier.isLoopbackHost(client.currentTargetHost) &&
                    client.connectionState.value == ConnectionState.CONNECTED
            }
            fallbackTargetProvider = { failedHost, failedRoute ->
                buildTransferFallbackTargets(failedHost, failedRoute, client.activeTargetDeviceId())
            }
        }
    }

    fun buildTransferFallbackTargets(
        failedHost: String,
        failedRoute: org.snow.network.TransportRoute,
        targetDeviceId: String? = null
    ): Pair<String, Int>? {
        val peerId = targetDeviceId?.trim()?.takeIf { it.isNotBlank() }
            ?: client.activeTargetDeviceId()
            ?: failedHost
        transportOrchestrator.selectTransferFallbackTarget(
            deviceId = peerId,
            failedHost = failedHost,
            failedRoute = failedRoute
        )?.let { return it }

        val repo = org.snow.ui.SnowUiRepository.getInstance(applicationContext)
        val mode = transportOrchestrator.getMode(peerId)
        if (mode.isSingleRouteOverride() && mode.targetRouteOrNull() == failedRoute) {
            return null
        }
        val matchedSaved = repo.savedDevices.value.firstOrNull { it.deviceId.equals(peerId, ignoreCase = true) }
        val fallbackTransferPort = matchedSaved?.transferPort?.takeIf { it in 1..65535 } ?: 8766
        val epPrefs = getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
        if (failedRoute == org.snow.network.TransportRoute.USB) {
            val nonLoopback = resolveUsbFallbackTarget(
                lastWifiHost = epPrefs.getString(PREF_LAST_WIFI_HOST, null),
                lastWifiPort = fallbackTransferPort,
                savedHost = epPrefs.getString(PREF_SAVED_HOST, null),
                savedPort = fallbackTransferPort
            )
            if (nonLoopback != null) {
                return nonLoopback.first to fallbackTransferPort
            }
        }
        val cleanSaved = matchedSaved?.host?.trim()?.takeIf {
            it.isNotBlank() &&
                !it.equals(failedHost.trim(), ignoreCase = true) &&
                !it.equals("relay", ignoreCase = true)
        }
        return cleanSaved?.let { it to fallbackTransferPort }
    }

    val capabilityDispatcher: AndroidCapabilityDispatcher by lazy {
        AndroidCapabilityDispatcher(
            context = applicationContext,
            transferClientProvider = { transferClient }
        ).apply {
            transferStatusReporter = { payload ->
                client.sendRequest("file_transfer_update", payload) {}
            }
        }
    }

    val liveScreenHandler: org.snow.capabilities.LiveScreenStreamHandler by lazy {
        org.snow.capabilities.LiveScreenStreamHandler(
            context = applicationContext,
            transferClientProvider = { transferClient }
        )
    }

    val peerHostManager: org.snow.network.AndroidPeerHostManager by lazy {
        org.snow.network.AndroidPeerHostManager(applicationContext)
    }

    var relayClient: org.snow.network.RelayClient? = null
    val transportOrchestrator: org.snow.network.TransportOrchestrator by lazy {
        org.snow.network.TransportOrchestrator()
    }
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile internal var userDisconnected = false
    private var autoConnectJob: Job? = null

    fun cancelAutoConnect() {
        autoConnectJob?.cancel()
        autoConnectJob = null
    }

    @Volatile
    private var lastUsbProbeAttemptMs: Long = 0L

    private var usbPromotionJob: kotlinx.coroutines.Job? = null
    private var usbFallbackJob: kotlinx.coroutines.Job? = null

    internal var clockMsProvider: () -> Long = { System.currentTimeMillis() }

    internal var usbReachableProbe: suspend () -> Boolean = {
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                java.net.Socket().use { sock ->
                    sock.connect(java.net.InetSocketAddress("127.0.0.1", Constants.DEFAULT_PORT), 350)
                    true
                }
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun createConfiguredRelayClient(
        endpoint: String,
        targetDeviceId: String? = null
    ): Pair<org.snow.network.RelayClient?, String?> {
        val effectiveEndpoint = resolveEffectiveRelayEndpoint(endpoint)
        if (effectiveEndpoint.isBlank() ||
            (!effectiveEndpoint.startsWith("wss://") && !effectiveEndpoint.startsWith("ws://"))
        ) {
            return null to "Remote relay endpoint is not configured or invalid."
        }
        val deviceId = org.snow.security.DeviceIdentity.getOrCreate(applicationContext).deviceId
        val certPinStorage = EncryptedCertPinStorage(applicationContext)
        val relaySecurityPrefs = getSharedPreferences("snow_relay_security", Context.MODE_PRIVATE)
        val relayTokenStorage = SharedPreferencesTokenStorage(
            applicationContext,
            prefName = "snow_relay_security"
        )
        val authMaterial = resolveEffectiveRelayAuth(
            ticket = relayTokenStorage.getToken(),
            bootstrapToken = relaySecurityPrefs.getString(PREF_RELAY_BOOTSTRAP_TOKEN, null),
            hubToken = relaySecurityPrefs.getString(PREF_RELAY_HUB_TOKEN, null)
        )
        if (authMaterial == null) {
            SafeLog.i("SnowForegroundService", "Remote relay standby: awaiting Render Hub rendezvous or Desktop relay credentials.")
            return null to "No usable relay credentials available (awaiting Render Hub session or pairing credentials)."
        }
        val prefs = getSharedPreferences(org.snow.ui.SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
        val savedNetId = relaySecurityPrefs.getString(PREF_RELAY_NETWORK_ID, null)
            ?: prefs.getString("last_known_network_id", null)
            ?: ""
        val groupId = prefs.getString("remote_relay_group_id", null)
            ?: savedNetId.takeIf { it.isNotBlank() }
            ?: "default_group"
        val configuredTargetPeer = prefs.getString("remote_relay_target_peer", null)?.trim()
        val targetPeerId = targetDeviceId?.trim()?.takeIf { it.isNotBlank() }
            ?: configuredTargetPeer?.takeIf { it.isNotBlank() }
            ?: "desktop-core"
        val expectedFingerprint = resolveRelayTargetFingerprint(certPinStorage, targetPeerId)
        if (expectedFingerprint.isNullOrBlank()) {
            SafeLog.w("SnowForegroundService", "Refusing startRelay without pinned TLS certificate fingerprint for peer $targetPeerId.")
            return null to "No pinned TLS certificate fingerprint for target device '$targetPeerId'."
        }
        val repo = org.snow.ui.SnowUiRepository.getInstance(applicationContext)
        val matchedSaved = repo.savedDevices.value.find { it.deviceId.equals(targetPeerId, ignoreCase = true) }
        val defaultTransferPort = resolveRelayTransferPort(matchedSaved?.deviceType)
        val usePublicCaOuter = effectiveEndpoint.startsWith("wss://") &&
            !effectiveEndpoint.contains("127.0.0.1") &&
            !effectiveEndpoint.contains("localhost")
        val isClientMode = (deviceId < targetPeerId)
        val localKeyManagers: Array<javax.net.ssl.KeyManager>? = try {
            org.snow.security.AndroidSelfSignedCertGenerator.loadOrCreate(
                org.snow.security.EncryptedFilePeerHostCertStorage(applicationContext)
            ).keyManagers
        } catch (e: Exception) {
            if (!isClientMode) {
                SafeLog.e("SnowForegroundService", "Refusing startRelay server role without valid TLS keyManagers: ${e.message}")
                return null to "Missing local TLS key material for relay handshake: ${e.message}"
            }
            null
        }
        if (!isClientMode && (localKeyManagers == null || localKeyManagers.isEmpty())) {
            SafeLog.e("SnowForegroundService", "Refusing startRelay server role: keyManagers empty.")
            return null to "Empty TLS key managers for relay server role."
        }

        val configured = org.snow.network.RelayClient(
            relayUrl = effectiveEndpoint,
            deviceId = deviceId,
            groupId = groupId,
            ticket = authMaterial.ticket,
            targetPeerId = targetPeerId,
            certPinStorage = certPinStorage,
            expectedPeerFingerprint = expectedFingerprint,
            isClientMode = isClientMode,
            bootstrapToken = authMaterial.bootstrapToken,
            hubToken = authMaterial.hubToken,
            networkId = savedNetId,
            usePublicCaForOuterRelay = usePublicCaOuter
        ).apply {
            keyManagers = localKeyManagers
            requestDispatcher = { action, data ->
                capabilityDispatcher.dispatch(
                    action = action,
                    data = data,
                    serverHost = effectiveEndpoint,
                    defaultTransferPort = defaultTransferPort
                )
            }
            mediaFrameHandler = { sourceId, meta, jpegBytes ->
                org.snow.ui.SnowUiRepository.getInstance(applicationContext)
                    .onIncomingRelayScreenFrame(sourceId, meta, jpegBytes)
            }
        }
        return configured to null
    }

    fun startRelay(endpoint: String) {
        stopRelay()
        val (configured, _) = createConfiguredRelayClient(endpoint)
        if (configured == null) return
        relayClient = configured
        configured.connect()
    }

    /**
     * Start Remote Relay and await real authenticated hub registration (`ONLINE_RELAYED`) plus E2E TLS handshake.
     * Fails closed on missing credentials, missing fingerprint, auth rejection, closed socket, or timeout.
     */
    suspend fun startRelayAndVerify(
        endpoint: String,
        targetDeviceId: String? = null,
        timeoutMs: Long = 8_000L
    ): Pair<Boolean, String> {
        stopRelay()
        val (configured, prepErr) = createConfiguredRelayClient(endpoint, targetDeviceId)
        if (configured == null) {
            return false to (prepErr ?: "Remote relay could not be initialized.")
        }

        val resultDeferred = kotlinx.coroutines.CompletableDeferred<Pair<Boolean, String>>()
        val expectedTarget = configured.targetPeerId

        fun evaluateReady() {
            if (configured.reachabilityState.value == org.snow.network.ReachabilityState.ONLINE_RELAYED &&
                configured.tunnelEstablished.value
            ) {
                val targetMatches = targetDeviceId.isNullOrBlank() ||
                    configured.targetPeerId.equals(expectedTarget, ignoreCase = true)
                if (targetMatches && !resultDeferred.isCompleted) {
                    resultDeferred.complete(true to "Remote relay authenticated and verified.")
                } else if (!targetMatches && !resultDeferred.isCompleted) {
                    resultDeferred.complete(false to "Relay target identity mismatch.")
                }
            }
        }

        configured.onTunnelEstablished = { evaluateReady() }
        configured.onTunnelFailed = { err ->
            if (!resultDeferred.isCompleted) {
                resultDeferred.complete(false to err.ifBlank { "Remote relay authentication failed." })
            }
        }

        relayClient = configured
        val observerJob = serviceScope.launch {
            configured.tunnelEstablished.collectLatest { established ->
                if (established) {
                    evaluateReady()
                }
            }
        }

        return try {
            configured.connect()
            evaluateReady()
            val outcome = kotlinx.coroutines.withTimeoutOrNull(timeoutMs.coerceAtLeast(250L)) {
                resultDeferred.await()
            } ?: (false to (configured.lastErrorMessage?.takeIf { it.isNotBlank() }
                ?: "Timed out waiting for authenticated Remote Relay handshake."))
            if (!outcome.first) {
                stopRelay()
            }
            outcome
        } finally {
            observerJob.cancel()
        }
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
                    discoveryManager.startListening()
                    val prefs = getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                    val savedHost = prefs.getString(PREF_SAVED_HOST, null)
                    val savedPort = prefs.getInt(PREF_SAVED_PORT, Constants.DEFAULT_PORT)
                    if (!savedHost.isNullOrBlank()) {
                        SafeLog.i("SnowForegroundService", "Network restored: triggering reconnect to $savedHost:$savedPort")
                        client.onNetworkRestored(savedHost, savedPort)
                    }
                } else if (relayClient != null || DiscoveryManager.isRelayEndpoint(client.currentTargetHost)) {
                    // Network transition while on Remote Relay: scan briefly for local promotion without dropping relay first.
                    discoveryManager.startListening()
                    promoteLocalRouteFromDiscoveryIfAvailable()
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
        val identity = DeviceIdentity.getOrCreate(applicationContext)
        val repo = SnowUiRepository.getInstance(applicationContext)
        val snowId = try {
            repo.getPermanentDeviceKeyIdentity().snowId
        } catch (_: Exception) {
            SnowUiRepository.deriveCanonicalSnowId(identity.deviceId)
        }
        val tokenStorage = SharedPreferencesTokenStorage(
            applicationContext,
            prefName = SharedPreferencesTokenStorage.PEER_HOST_PREFS_NAME
        )
        val transferDir = java.io.File(applicationContext.filesDir, "peer_transfers").apply { mkdirs() }
        val success = peerHostManager.enableHostMode(
            port = org.snow.network.AndroidPeerHostManager.DEFAULT_HOST_PORT,
            tokenStorage = tokenStorage,
            dispatcher = capabilityDispatcher,
            localDeviceId = identity.deviceId,
            manifestProvider = { org.snow.network.DeviceNode.buildAndroidManifest(applicationContext).toMap() },
            parentScope = serviceScope,
            mediaPort = org.snow.network.AndroidPeerHostManager.DEFAULT_MEDIA_PORT,
            snowId = snowId,
            networkId = repo.getEffectiveNetworkId(),
            transferStorageDir = transferDir,
            perDeviceProfileProvider = { peerDevId ->
                repo.savedDevices.value.find { it.deviceId.equals(peerDevId, ignoreCase = true) }?.permissionProfile
                    ?: capabilityDispatcher.activePermissionProfile
            },
            onHostNetworkUpdated = { netId ->
                repo.applyHostNegotiatedNetworkId(netId)
            }
        )
        if (success) {
            val hs = peerHostManager.hostState.value
            discoveryManager.startPeerHostBeacon(
                deviceId = identity.deviceId,
                deviceName = identity.deviceName,
                port = peerHostManager.activePort,
                transferPort = peerHostManager.activeMediaPort,
                certFingerprint = hs.certFingerprint,
                snowId = snowId,
                candidateIpsProvider = { peerHostManager.enumerateLocalIpv4Candidates() }
            )
            updateNotification("Peer Host Active on Port ${peerHostManager.activePort}")
        }
    }

    fun stopPeerHost() {
        discoveryManager.stopPeerHostBeacon()
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
        activeInstance = this
        _isServiceRunningFlow.value = true
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
        androidRemoteMcpController.startIfEnabled()
    }

    val androidRemoteMcpController: org.snow.mcp.AndroidRemoteMcpController by lazy {
        val repo = org.snow.ui.SnowUiRepository.getInstance(applicationContext)
        org.snow.mcp.AndroidRemoteMcpController(
            appContext = applicationContext,
            capabilityDispatcher = capabilityDispatcher,
            settingsPrefsName = org.snow.ui.SnowUiRepository.PREFS_SETTINGS,
            deviceKeyProvider = { repo.getPermanentDeviceKeyIdentity() },
            hubHttpUrlProvider = { repo.getDefaultHubUrl(allowDevLoopback = false) },
            networkIdProvider = { repo.getEffectiveNetworkId() },
            peerDirectoryProvider = { buildMcpPeerDirectory(repo) },
            peerActionForwarder = { targetId, action, params, _ ->
                executePeerActionForward(repo, targetId, action, params)
            },
            onLocalApprovalsUpdated = {
                repo.syncMergedPendingApprovals()
            }
        )
    }

    private fun buildMcpPeerDirectory(repo: org.snow.ui.SnowUiRepository): List<org.snow.mcp.McpPeerDescriptor> {
        val saved = repo.savedDevices.value
        val authHostPeers = peerHostManager.listAuthenticatedPeers().toSet()
        val clientAuth = client.authState.value as? AuthState.Authenticated
        val activeClientPeer = if (client.connectionState.value == ConnectionState.CONNECTED && clientAuth != null) {
            clientAuth.peerDeviceId?.takeIf { it.isNotBlank() } ?: client.activeTargetDeviceId()
        } else {
            null
        }
        val activeRelay = relayClient?.takeIf { it.isSessionAndTunnelVerified() }
        val descriptors = linkedMapOf<String, org.snow.mcp.McpPeerDescriptor>()

        for (dev in saved) {
            val matchedClient = activeClientPeer != null && (
                dev.deviceId.equals(activeClientPeer, ignoreCase = true) ||
                    dev.host.equals(client.currentTargetHost, ignoreCase = true)
                )
            val matchedHostPeer = authHostPeers.any { it.equals(dev.deviceId, ignoreCase = true) }
            val matchedRelay = activeRelay != null && activeRelay.targetPeerId.equals(dev.deviceId, ignoreCase = true)
            val isOnline = matchedClient || matchedHostPeer || matchedRelay
            val transport = when {
                matchedClient -> org.snow.network.TransportClassifier.classifyRoute(host = client.currentTargetHost).wireName
                matchedHostPeer -> "peer_host"
                matchedRelay -> "remote_relay"
                else -> "offline"
            }
            descriptors[dev.deviceId] = org.snow.mcp.McpPeerDescriptor(
                deviceId = dev.deviceId,
                snowId = dev.snowId ?: "",
                deviceName = dev.deviceName,
                deviceType = dev.deviceType,
                networkId = dev.networkId ?: "",
                isOnline = isOnline,
                transport = transport,
                isFederated = dev.relationship.equals("federated", ignoreCase = true)
            )
        }
        for (pid in authHostPeers) {
            if (!descriptors.containsKey(pid)) {
                descriptors[pid] = org.snow.mcp.McpPeerDescriptor(
                    deviceId = pid,
                    deviceName = pid,
                    deviceType = "android",
                    networkId = repo.getEffectiveNetworkId() ?: "",
                    isOnline = true,
                    transport = "peer_host"
                )
            }
        }
        return descriptors.values.toList()
    }

    private suspend fun executePeerActionForward(
        repo: org.snow.ui.SnowUiRepository,
        targetId: String,
        action: String,
        params: Map<String, Any?>
    ): Pair<Map<String, Any?>?, String?> {
        val matchedSaved = repo.savedDevices.value.firstOrNull {
            it.deviceId.equals(targetId, ignoreCase = true) ||
                (!it.snowId.isNullOrBlank() && it.snowId.equals(targetId, ignoreCase = true))
        }
        val resolvedId = matchedSaved?.deviceId ?: targetId
        val localNet = repo.getEffectiveNetworkId()?.trim()?.uppercase().orEmpty()
        val targetNet = matchedSaved?.networkId?.trim()?.uppercase().orEmpty()
        if (localNet.isNotEmpty() && targetNet.isNotEmpty() && localNet != targetNet &&
            matchedSaved?.relationship?.equals("federated", ignoreCase = true) != true
        ) {
            return null to "PERMISSION_DENIED: Cross-network execution blocked between '$localNet' and '$targetNet'."
        }

        // 1. Direct authenticated incoming peer on Android Peer Host
        if (peerHostManager.listAuthenticatedPeers().any { it.equals(resolvedId, ignoreCase = true) }) {
            return peerHostManager.sendRequestToPeer(resolvedId, action, params)
        }

        // 2. Direct authenticated WebSocket client session to PC or Peer Host
        val clientAuth = client.authState.value as? AuthState.Authenticated
        if (client.connectionState.value == ConnectionState.CONNECTED && clientAuth != null) {
            val peerId = clientAuth.peerDeviceId ?: client.activeTargetDeviceId()
            val isDirectTarget = peerId?.equals(resolvedId, ignoreCase = true) == true ||
                (matchedSaved != null && matchedSaved.host.equals(client.currentTargetHost, ignoreCase = true))
            val deferred = kotlinx.coroutines.CompletableDeferred<Pair<Map<String, Any?>?, String?>>()
            if (isDirectTarget) {
                client.sendRequest(action = action, data = params) { msg ->
                    deferred.complete(unwrapPeerReply(msg, unwrapRelayEnvelope = false))
                }
            } else {
                client.sendRequest(
                    action = "peer_relay_request",
                    data = mapOf(
                        "target_device_id" to resolvedId,
                        "action" to action,
                        "data" to params,
                        "hop_limit" to 2
                    )
                ) { msg ->
                    deferred.complete(unwrapPeerReply(msg, unwrapRelayEnvelope = true))
                }
            }
            return kotlinx.coroutines.withTimeoutOrNull(22_000L) { deferred.await() }
                ?: (null to "TIMEOUT: Peer '$resolvedId' timed out executing '$action'.")
        }

        // 3. Verified end-to-end encrypted Remote Relay tunnel
        val rc = relayClient
        if (rc != null && rc.isSessionAndTunnelVerified()) {
            val isDirectTarget = rc.targetPeerId.equals(resolvedId, ignoreCase = true)
            val deferred = kotlinx.coroutines.CompletableDeferred<Pair<Map<String, Any?>?, String?>>()
            val sendOk = if (isDirectTarget) {
                rc.sendRequest(action = action, data = params) { msg ->
                    deferred.complete(unwrapPeerReply(msg, unwrapRelayEnvelope = false))
                }
            } else {
                rc.sendRequest(
                    action = "peer_relay_request",
                    data = mapOf(
                        "target_device_id" to resolvedId,
                        "action" to action,
                        "data" to params,
                        "hop_limit" to 2
                    )
                ) { msg ->
                    deferred.complete(unwrapPeerReply(msg, unwrapRelayEnvelope = true))
                }
            }
            if (!sendOk) {
                return null to "DEVICE_OFFLINE: Failed dispatching via remote relay tunnel."
            }
            return kotlinx.coroutines.withTimeoutOrNull(22_000L) { deferred.await() }
                ?: (null to "TIMEOUT: Remote peer '$resolvedId' timed out executing '$action'.")
        }

        return null to "DEVICE_OFFLINE: Target device '$resolvedId' is unreachable on all transports."
    }

    private fun unwrapPeerReply(
        msg: org.snow.protocol.SnowMessage,
        unwrapRelayEnvelope: Boolean
    ): Pair<Map<String, Any?>?, String?> {
        if (!msg.isSuccess) {
            val errTxt = msg.error?.let { "${it.code}: ${it.message}" }
                ?: (msg.payload?.get("error")?.toString() ?: "Peer returned error.")
            return null to errTxt
        }
        val payload = msg.payload ?: emptyMap()
        if (!unwrapRelayEnvelope) {
            return payload to null
        }
        val status = (payload["status"] as? String)?.lowercase().orEmpty()
        if (status != "success" && status.isNotEmpty()) {
            val err = (payload["error"] as? String) ?: status.uppercase()
            return null to "$status: $err"
        }
        @Suppress("UNCHECKED_CAST")
        val inner = payload["data"] as? Map<String, Any?> ?: payload
        return inner to null
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
                _isServiceRunningFlow.value = true
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
                _isServiceRunningFlow.value = true
                userDisconnected = false
                isUserDisconnected = false
                getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean(PREF_USER_DISCONNECTED, false)
                    .apply()
                autoConnectJob?.cancel()
                val host = intent.getStringExtra(EXTRA_HOST) ?: "127.0.0.1"
                val port = intent.getIntExtra(EXTRA_PORT, Constants.DEFAULT_PORT)
                val targetDeviceId = intent.getStringExtra(EXTRA_DEVICE_ID)
                val handshakeModeName = intent.getStringExtra(EXTRA_HANDSHAKE_MODE)
                val handshakeMode = handshakeModeName?.let {
                    try {
                        org.snow.network.ConnectionHandshakeMode.valueOf(it)
                    } catch (_: Exception) {
                        null
                    }
                } ?: org.snow.network.ConnectionHandshakeMode.STANDARD_OR_AUTO

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
                client.connect(host, port, targetDeviceId, handshakeMode)
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
                    val targetIds = intent.getStringArrayListExtra(EXTRA_TARGET_IDS)?.toList().orEmpty()
                    liveScreenHandler.onRevoked = {
                        demoteScreenShareNotification()
                    }
                    val devIdentity = DeviceIdentity.getOrCreate(applicationContext)
                    liveScreenHandler.relayMediaSender = { meta, jpegBytes ->
                        val rc = relayClient
                        if (rc != null && rc.reachabilityState.value == org.snow.network.ReachabilityState.ONLINE_RELAYED &&
                            (client.connectionState.value != ConnectionState.CONNECTED ||
                                DiscoveryManager.isRelayEndpoint(client.currentTargetHost))
                        ) {
                            rc.sendScreenFrame(meta, jpegBytes)
                        } else false
                    }
                    val host = client.currentTargetHost.ifBlank { "127.0.0.1" }
                    if (client.connectionState.value == ConnectionState.CONNECTED &&
                        client.authState.value is AuthState.Authenticated
                    ) {
                        client.sendRequest(
                            action = "screen_stream_start",
                            data = mapOf(
                                "sender_name" to (android.os.Build.MODEL ?: devIdentity.deviceName),
                                "sender_platform" to "android",
                                "target_device_ids" to targetIds
                            )
                        ) {}
                    }
                    liveScreenHandler.startStreaming(
                        projection = projection,
                        serverHost = host,
                        transferPort = 8766,
                        targetIds = targetIds,
                        senderDeviceId = devIdentity.deviceId,
                        senderName = (android.os.Build.MODEL ?: devIdentity.deviceName),
                        initialViewerCount = 1
                    )
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
                if (intent == null && !isDisconnectedByUser(this)) {
                    // Sticky OS restart after process/memory reclaim: re-elevate foreground and resume auto-connect
                    ServiceCompat.startForeground(
                        this,
                        NOTIFICATION_ID,
                        buildNotification("Standing by for SNOW desktop..."),
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                    )
                    discoveryManager.startListening()
                    startObservingState()
                    startObservingDiscovery()
                    startObservingAuth()
                    executeAutoConnectCascade()
                } else {
                    // Defensive fallback: fulfill OS foreground contract immediately then cleanly stop.
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
        }
        return if (isDisconnectedByUser(this) && !peerHostManager.isHostModeActive()) {
            START_NOT_STICKY
        } else {
            START_STICKY
        }
    }

    private fun startObservingState() {
        stateObserverJob?.cancel()
        stateObserverJob = serviceScope.launch {
            combine(client.connectionState, client.authState) { state, auth -> state to auth }
                .collectLatest { (state, auth) ->
                when (state) {
                    ConnectionState.DISCONNECTED -> {
                        if (!userDisconnected && client.autoReconnectEnabled) {
                            discoveryManager.startListening()
                        }
                        if (userDisconnected && !peerHostManager.isHostModeActive()) {
                            // Only remove the foreground notification when the user explicitly disconnected
                            ServiceCompat.stopForeground(this@SnowForegroundService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                            manager.cancel(NOTIFICATION_ID)
                        } else {
                            val label = if (peerHostManager.isHostModeActive()) {
                                "Peer Host Active on Port ${peerHostManager.activePort}"
                            } else {
                                "Waiting for SNOW desktop..."
                            }
                            updateNotification(label)
                        }
                    }
                    ConnectionState.CONNECTING -> {
                        updateNotification("Connecting...")
                    }
                    ConnectionState.CONNECTED -> {
                        if (DiscoveryManager.shouldPauseDiscovery(state, auth, client.currentTargetHost)) {
                            discoveryManager.stopListening()
                            if (relayClient != null) {
                                SafeLog.i("SnowForegroundService", "Local route authenticated; retiring redundant relay tunnel.")
                                stopRelay()
                            }
                            updateNotification("Connected to desktop")
                        } else if (auth is AuthState.ConnectedUnauthenticated) {
                            updateNotification("Connected — awaiting pairing...")
                        } else if (auth is AuthState.Authenticated) {
                            updateNotification("Connected via remote relay")
                        } else {
                            updateNotification("Authenticating...")
                        }
                    }
                    ConnectionState.RECONNECTING -> {
                        if (client.autoReconnectEnabled) {
                            discoveryManager.startListening()
                        }
                        updateNotification("Reconnecting...")
                    }
                }
            }
        }
    }

    internal fun getTargetConnectionMode(): String {
        return try {
            val targetId = client.activeTargetDeviceId() ?: ""
            val repo = org.snow.ui.SnowUiRepository.getInstance(applicationContext)
            if (targetId.isNotBlank()) {
                repo.savedDevices.value.find { it.deviceId.equals(targetId, ignoreCase = true) }?.connectionMode ?: "auto"
            } else {
                repo.savedDevices.value.firstOrNull {
                    it.host.equals(client.currentTargetHost, ignoreCase = true)
                }?.connectionMode ?: "auto"
            }
        } catch (_: Throwable) {
            "auto"
        }
    }

    internal suspend fun tryPromoteUsbIfReachable(force: Boolean = false): Boolean {
        val isConn = client.connectionState.value == ConnectionState.CONNECTED
        val isAuth = client.authState.value is AuthState.Authenticated
        val devKey = client.activeTargetDeviceId() ?: (client.authState.value as? AuthState.Authenticated)?.peerDeviceId ?: ""
        if (devKey.isNotBlank() && transportOrchestrator.hasActivePinnedTransfer(devKey)) {
            SafeLog.i("SnowForegroundService", "Skipping background USB promotion: large transfer pinned for [$devKey].")
            return false
        }
        val nowMs = clockMsProvider()
        val effectiveLastAttempt = if (force) Long.MIN_VALUE / 2 else lastUsbProbeAttemptMs
        if (!shouldProbeUsbPromotion(
                connectionMode = getTargetConnectionMode(),
                userDisconnected = userDisconnected,
                isConnected = isConn,
                isAuthenticated = isAuth,
                currentHost = client.currentTargetHost,
                nowMs = nowMs,
                lastAttemptMs = effectiveLastAttempt
            )
        ) {
            return false
        }
        lastUsbProbeAttemptMs = nowMs
        if (devKey.isNotBlank()) {
            transportOrchestrator.registerDiscovered(devKey, org.snow.network.TransportRoute.USB, "127.0.0.1", Constants.DEFAULT_PORT)
            transportOrchestrator.markProbing(devKey, org.snow.network.TransportRoute.USB)
        }
        if (!usbReachableProbe()) {
            if (devKey.isNotBlank()) {
                transportOrchestrator.markUnavailable(devKey, org.snow.network.TransportRoute.USB, "USB loopback tunnel unreachable.")
            }
            return false
        }
        // Preserve active Wi-Fi/Hotspot host before Make-Before-Break cutover to USB 127.0.0.1
        val currentHost = client.currentTargetHost.trim()
        val currentPort = client.currentTargetPort
        if (currentHost.isNotBlank() && !isLoopbackHost(currentHost) && !DiscoveryManager.isRelayEndpoint(currentHost)) {
            getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                .edit()
                .putString(PREF_LAST_WIFI_HOST, currentHost)
                .putInt(PREF_LAST_WIFI_PORT, currentPort)
                .apply()
        }
        SafeLog.i("SnowForegroundService", "USB reverse tunnel detected on 127.0.0.1:${Constants.DEFAULT_PORT}; probing Make-Before-Break promotion...")
        if (devKey.isNotBlank()) {
            transportOrchestrator.setSwitching(devKey, true, "Probing USB • Zero Data")
        }
        val promo = client.probeAndPromoteEndpoint(
            newHost = "127.0.0.1",
            newPort = Constants.DEFAULT_PORT,
            targetDeviceId = client.activeTargetDeviceId(),
            timeoutMs = 2_500L,
            verifyPing = true
        )
        if (devKey.isNotBlank()) {
            if (promo.promoted) {
                transportOrchestrator.markVerified(
                    deviceId = devKey,
                    route = org.snow.network.TransportRoute.USB,
                    host = "127.0.0.1",
                    port = Constants.DEFAULT_PORT,
                    isActive = true
                )
            } else {
                transportOrchestrator.markUnavailable(
                    deviceId = devKey,
                    route = org.snow.network.TransportRoute.USB,
                    reason = promo.error ?: "USB standby verification failed."
                )
            }
            transportOrchestrator.setSwitching(devKey, false)
        }
        return promo.promoted
    }

    private fun startUsbPromotionLoop() {
        usbPromotionJob?.cancel()
        usbPromotionJob = serviceScope.launch {
            while (kotlinx.coroutines.currentCoroutineContext()[kotlinx.coroutines.Job]?.isActive == true && !userDisconnected) {
                delay(USB_PROBE_INTERVAL_MS)
                if (userDisconnected) break
                try {
                    tryPromoteUsbIfReachable(force = false)
                } catch (_: Exception) {
                }
            }
        }

        if (usbFallbackJob?.isActive != true) {
            usbFallbackJob = serviceScope.launch {
                var wasLoopbackConnected = isLoopbackHost(client.currentTargetHost) &&
                    client.connectionState.value != ConnectionState.DISCONNECTED
                client.connectionState.collectLatest { state ->
                    val currentHost = client.currentTargetHost
                    if (isLoopbackHost(currentHost) &&
                        (state == ConnectionState.CONNECTED || state == ConnectionState.CONNECTING)
                    ) {
                        wasLoopbackConnected = true
                    } else if (state == ConnectionState.DISCONNECTED && wasLoopbackConnected && !userDisconnected) {
                        wasLoopbackConnected = false
                        val devKey = client.activeTargetDeviceId() ?: ""
                        if (devKey.isNotBlank()) {
                            transportOrchestrator.handleTransportLoss(
                                deviceId = devKey,
                                lostRoute = org.snow.network.TransportRoute.USB,
                                reason = "USB cable or ADB tunnel disconnected."
                            )
                        }
                        val effMode = org.snow.network.TransportMode.normalize(getTargetConnectionMode())
                            ?: org.snow.network.TransportMode.AUTO
                        if (effMode == org.snow.network.TransportMode.USB) {
                            SafeLog.w("SnowForegroundService", "USB disconnected while pinned to manual USB mode; failing closed.")
                            updateNotification("Manual USB route unavailable")
                        } else if (effMode != org.snow.network.TransportMode.REMOTE_ONLY &&
                            effMode != org.snow.network.TransportMode.REMOTE_RELAY
                        ) {
                            val prefs = getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                            val discCandidate = discoveryManager.getCandidateForPairedDesktop()
                            val savedPair = resolveUsbFallbackTarget(
                                lastWifiHost = prefs.getString(PREF_LAST_WIFI_HOST, null),
                                lastWifiPort = prefs.getInt(PREF_LAST_WIFI_PORT, Constants.DEFAULT_PORT),
                                savedHost = prefs.getString(PREF_SAVED_HOST, null),
                                savedPort = prefs.getInt(PREF_SAVED_PORT, Constants.DEFAULT_PORT)
                            )
                            val fallback = when {
                                discCandidate != null && org.snow.network.TransportClassifier.isHotspotHostOrHint(discCandidate.ipAddress) ->
                                    discCandidate.ipAddress to discCandidate.port
                                savedPair != null && org.snow.network.TransportClassifier.isHotspotHostOrHint(savedPair.first) ->
                                    savedPair
                                discCandidate != null -> discCandidate.ipAddress to discCandidate.port
                                else -> savedPair
                            }
                            if (fallback != null && (
                                    !effMode.isSingleRouteOverride() ||
                                        effMode.targetRouteOrNull() == org.snow.network.TransportClassifier.classifyRoute(host = fallback.first)
                                    )
                            ) {
                                val fbBadge = org.snow.network.TransportClassifier.classifyTransportBadge(host = fallback.first)
                                SafeLog.i("SnowForegroundService", "USB disconnected; failing over to $fbBadge (${fallback.first}:${fallback.second}).")
                                prefs.edit()
                                    .putString(PREF_SAVED_HOST, fallback.first)
                                    .putInt(PREF_SAVED_PORT, fallback.second)
                                    .apply()
                                client.connect(fallback.first, fallback.second, client.activeTargetDeviceId())
                            } else {
                                executeAutoConnectCascade()
                            }
                        } else if (effMode == org.snow.network.TransportMode.REMOTE_ONLY ||
                            effMode == org.snow.network.TransportMode.REMOTE_RELAY
                        ) {
                            executeAutoConnectCascade()
                        }
                    }
                }
            }
        }
    }

    fun promoteLocalRouteFromDiscoveryIfAvailable(): Boolean {
        if (userDisconnected) return false
        val effMode = org.snow.network.TransportMode.normalize(getTargetConnectionMode())
            ?: org.snow.network.TransportMode.AUTO
        if (effMode == org.snow.network.TransportMode.REMOTE_ONLY ||
            effMode == org.snow.network.TransportMode.REMOTE_RELAY
        ) {
            return false
        }
        val devKey = client.activeTargetDeviceId() ?: ""
        if (devKey.isNotBlank() && transportOrchestrator.hasActivePinnedTransfer(devKey)) {
            return false
        }
        val currentHost = client.currentTargetHost.trim().lowercase()
        if (isLoopbackHost(currentHost)) {
            return false
        }
        // Kick off immediate USB loopback check alongside LAN/Hotspot discovery promotion
        if (effMode == org.snow.network.TransportMode.AUTO ||
            effMode == org.snow.network.TransportMode.LOCAL_ONLY ||
            effMode == org.snow.network.TransportMode.USB
        ) {
            serviceScope.launch {
                tryPromoteUsbIfReachable(force = true)
            }
        }
        val candidate = discoveryManager.getCandidateForPairedDesktop() ?: return false
        val candRoute = org.snow.network.TransportClassifier.classifyRoute(host = candidate.ipAddress)
        if (effMode.isSingleRouteOverride() && effMode.targetRouteOrNull() != candRoute) {
            return false
        }
        val curRoute = org.snow.network.TransportClassifier.classifyRoute(host = client.currentTargetHost)
        val isLocalAuth = client.connectionState.value == ConnectionState.CONNECTED &&
            client.authState.value is AuthState.Authenticated &&
            !DiscoveryManager.isRelayEndpoint(client.currentTargetHost) &&
            (curRoute.priority < candRoute.priority ||
                (client.currentTargetHost == candidate.ipAddress && client.currentTargetPort == candidate.port))
        if (isLocalAuth) {
            return false
        }
        val orchId = devKey.ifBlank { candidate.deviceId }
        transportOrchestrator.registerDiscovered(orchId, candRoute, candidate.ipAddress, candidate.port, candidate.transferPort)
        // Make-Before-Break: when already connected (e.g. Relay or lower-priority Wi-Fi), probe standby socket first!
        if (client.connectionState.value == ConnectionState.CONNECTED &&
            client.authState.value is AuthState.Authenticated
        ) {
            serviceScope.launch {
                transportOrchestrator.setSwitching(orchId, true, "Probing ${candRoute.badge}")
                val res = client.probeAndPromoteEndpoint(
                    newHost = candidate.ipAddress,
                    newPort = candidate.port,
                    targetDeviceId = candidate.deviceId,
                    timeoutMs = 2_500L,
                    verifyPing = true
                )
                if (res.promoted) {
                    transportOrchestrator.markVerified(orchId, candRoute, candidate.ipAddress, candidate.port, isActive = true)
                } else {
                    transportOrchestrator.markUnavailable(orchId, candRoute, res.error ?: "Standby verification failed.")
                }
                transportOrchestrator.setSwitching(orchId, false)
            }
        } else {
            client.connect(candidate.ipAddress, candidate.port, candidate.deviceId)
        }
        return true
    }

    private fun startObservingDiscovery() {
        discoveryObserverJob?.cancel()
        discoveryObserverJob = serviceScope.launch {
            discoveryManager.peers.collectLatest { _ ->
                if (!DiscoveryManager.shouldPauseDiscovery(
                        client.connectionState.value,
                        client.authState.value,
                        client.currentTargetHost
                    )
                ) {
                    promoteLocalRouteFromDiscoveryIfAvailable()
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
                    val devKey = auth.peerDeviceId?.takeIf { it.isNotBlank() } ?: client.activeTargetDeviceId() ?: ""
                    if (host.isNotBlank()) {
                        val prefs = getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                        val editor = prefs.edit()
                        if (!isLoopbackHost(host)) {
                            editor.putString(PREF_SAVED_HOST, host)
                                .putInt(PREF_SAVED_PORT, port)
                            if (!DiscoveryManager.isRelayEndpoint(host)) {
                                editor.putString(PREF_LAST_WIFI_HOST, host)
                                    .putInt(PREF_LAST_WIFI_PORT, port)
                            }
                        }
                        editor.apply()
                        if (devKey.isNotBlank()) {
                            val activeRoute = org.snow.network.TransportClassifier.classifyRoute(host = host)
                            transportOrchestrator.markVerified(
                                deviceId = devKey,
                                route = activeRoute,
                                host = host,
                                port = port,
                                isActive = true
                            )
                        }
                    }
                    startUsbPromotionLoop()
                }
            }
        }
    }

    internal fun handleDisconnect() {
        userDisconnected = true
        isUserDisconnected = true
        _isServiceRunningFlow.value = false
        getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PREF_USER_DISCONNECTED, true)
            .apply()
        autoConnectJob?.cancel()
        autoConnectJob = null
        usbPromotionJob?.cancel()
        usbPromotionJob = null
        usbFallbackJob?.cancel()
        usbFallbackJob = null

        // 0. Stop live screen sharing & discovery beacon if active
        liveScreenHandler.stopStreaming(client.currentTargetHost, 8766)
        discoveryManager.stopPeerHostBeacon()

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

            if (client.connectionState.value == ConnectionState.CONNECTED &&
                client.authState.value is AuthState.Authenticated
            ) {
                return@launch
            }

            val effMode = org.snow.network.TransportMode.normalize(getTargetConnectionMode())
                ?: org.snow.network.TransportMode.AUTO

            // Step 1: USB Loopback (127.0.0.1:8765) when allowed by mode
            if (effMode in setOf(
                    org.snow.network.TransportMode.AUTO,
                    org.snow.network.TransportMode.LOCAL_ONLY,
                    org.snow.network.TransportMode.USB
                )
            ) {
                SafeLog.i("SnowForegroundService", "AutoConnect Step 1: Probing USB loopback 127.0.0.1:8765...")
                client.connect("127.0.0.1", Constants.DEFAULT_PORT)
                val usbAuth = withTimeoutOrNull(1800) {
                    client.authState.first { it is AuthState.Authenticated }
                }
                if (usbAuth != null) {
                    SafeLog.i("SnowForegroundService", "Connected & authenticated via USB loopback.")
                    return@launch
                }
                if (effMode == org.snow.network.TransportMode.USB) {
                    SafeLog.w("SnowForegroundService", "AutoConnect stopped: pinned to manual USB mode and loopback unavailable.")
                    return@launch
                }
            }

            if (userDisconnected) return@launch

            val prefs = getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
            val savedHost = prefs.getString(PREF_SAVED_HOST, null)
            val savedPort = prefs.getInt(PREF_SAVED_PORT, Constants.DEFAULT_PORT)
            val lastWifiHost = prefs.getString(PREF_LAST_WIFI_HOST, null)
            val lastWifiPort = prefs.getInt(PREF_LAST_WIFI_PORT, Constants.DEFAULT_PORT)

            // Step 2: Saved local Hotspot / Wi-Fi endpoint prioritized strictly (Hotspot before Wi-Fi LAN)
            if (effMode !in setOf(org.snow.network.TransportMode.REMOTE_ONLY, org.snow.network.TransportMode.REMOTE_RELAY)) {
                val localSaved = listOfNotNull(
                    lastWifiHost?.trim()?.takeIf { it.isNotBlank() && !isLoopbackHost(it) && !DiscoveryManager.isRelayEndpoint(it) }?.let { it to lastWifiPort },
                    savedHost?.trim()?.takeIf { it.isNotBlank() && !isLoopbackHost(it) && !DiscoveryManager.isRelayEndpoint(it) }?.let { it to savedPort }
                ).distinctBy { "${it.first}:${it.second}" }
                    .sortedBy { (h, _) -> org.snow.network.TransportClassifier.classifyRoutePriority(host = h) }
                    .filter { (h, _) ->
                        !effMode.isSingleRouteOverride() ||
                            effMode.targetRouteOrNull() == org.snow.network.TransportClassifier.classifyRoute(host = h)
                    }

                for ((candHost, candPort) in localSaved) {
                    if (userDisconnected) return@launch
                    val candBadge = org.snow.network.TransportClassifier.classifyTransportBadge(host = candHost)
                    SafeLog.i("SnowForegroundService", "AutoConnect Step 2: Connecting to $candBadge ($candHost:$candPort)...")
                    client.connect(candHost, candPort)
                    val localAuth = withTimeoutOrNull(2500) {
                        client.authState.first { it is AuthState.Authenticated }
                    }
                    if (localAuth != null) {
                        SafeLog.i("SnowForegroundService", "Connected & authenticated via $candBadge.")
                        return@launch
                    }
                }
            }

            if (userDisconnected) return@launch

            // Step 3: Bounded UDP discovery burst (12s), preferring Hotspot over Wi-Fi LAN
            if (effMode !in setOf(org.snow.network.TransportMode.REMOTE_ONLY, org.snow.network.TransportMode.REMOTE_RELAY)) {
                SafeLog.i("SnowForegroundService", "AutoConnect Step 3: Starting bounded UDP discovery (12s)...")
                discoveryManager.startListening()
                val discoveryConnected = withTimeoutOrNull(12000) {
                    while (isActive) {
                        val candidate = discoveryManager.getCandidateForPairedDesktop()
                        if (candidate != null) {
                            val candRoute = org.snow.network.TransportClassifier.classifyRoute(host = candidate.ipAddress)
                            if (!effMode.isSingleRouteOverride() || effMode.targetRouteOrNull() == candRoute) {
                                SafeLog.i("SnowForegroundService", "AutoConnect: Discovered ${candRoute.badge} ${candidate.ipAddress}:${candidate.port}")
                                client.connect(candidate.ipAddress, candidate.port, candidate.deviceId)
                                val connected = withTimeoutOrNull(3000) {
                                    client.authState.first { it is AuthState.Authenticated }
                                }
                                if (connected != null) return@withTimeoutOrNull true
                            }
                        }
                        delay(1000)
                    }
                    false
                }
                if (discoveryConnected == true) {
                    SafeLog.i("SnowForegroundService", "Connected & authenticated via UDP discovery.")
                    return@launch
                }
                discoveryManager.stopListening()
                if (effMode.isSingleRouteOverride() || effMode == org.snow.network.TransportMode.LOCAL_ONLY) {
                    SafeLog.w("SnowForegroundService", "AutoConnect stopped: mode=${effMode.wireName} forbids remote relay fallback.")
                    return@launch
                }
            }

            if (userDisconnected) return@launch

            // Step 4: Saved Remote Relay or Built-in Render Hub fallback
            val settingsPrefs = getSharedPreferences(SnowUiRepository.PREFS_SETTINGS, Context.MODE_PRIVATE)
            val relayEnabled = settingsPrefs.getBoolean("remote_relay_enabled", false)
            val relayEndpoint = resolveEffectiveRelayEndpoint(settingsPrefs.getString("remote_relay_endpoint", null))
            val relaySecurityPrefs = getSharedPreferences("snow_relay_security", Context.MODE_PRIVATE)
            val relayTokenStorage = SharedPreferencesTokenStorage(applicationContext, prefName = "snow_relay_security")
            val authMaterial = resolveEffectiveRelayAuth(
                ticket = relayTokenStorage.getToken(),
                bootstrapToken = relaySecurityPrefs.getString(PREF_RELAY_BOOTSTRAP_TOKEN, null),
                hubToken = relaySecurityPrefs.getString(PREF_RELAY_HUB_TOKEN, null)
            )

            if ((relayEnabled || effMode == org.snow.network.TransportMode.REMOTE_ONLY || effMode == org.snow.network.TransportMode.REMOTE_RELAY) &&
                relayEndpoint.isNotBlank() && authMaterial != null
            ) {
                SafeLog.i("SnowForegroundService", "AutoConnect Step 4: Falling back to Render Hub / Remote Relay endpoint $relayEndpoint...")
                startRelay(relayEndpoint)
            } else {
                SafeLog.i("SnowForegroundService", "AutoConnect Step 4: Remote relay disabled or awaiting hub credentials.")
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
        if (activeInstance === this) {
            activeInstance = null
        }
        _isServiceRunningFlow.value = false
        super.onDestroy()
        unregisterNetworkCallback()
        liveScreenHandler.stopStreaming()
        androidRemoteMcpController.stop()
        org.snow.ui.SnowUiRepository.getInstance(applicationContext).unbindService()
        discoveryManager.stopPeerHostBeacon()
        peerHostManager.disableHostMode()
        stateObserverJob?.cancel()
        stateObserverJob = null
        discoveryObserverJob?.cancel()
        discoveryObserverJob = null
        authObserverJob?.cancel()
        authObserverJob = null
        usbPromotionJob?.cancel()
        usbPromotionJob = null
        usbFallbackJob?.cancel()
        usbFallbackJob = null
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
        } else if (!userDisconnected || peerHostManager.isHostModeActive()) {
            val label = if (peerHostManager.isHostModeActive()) {
                "Peer Host Active on Port ${peerHostManager.activePort}"
            } else {
                "Waiting for SNOW desktop..."
            }
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                buildNotification(label),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        }
    }

    data class RelayAuthMaterial(
        val ticket: String = "",
        val bootstrapToken: String = "",
        val hubToken: String = ""
    )

    companion object {
        const val PREFS_ENDPOINT = "snow_endpoint_prefs"
        const val PREF_SAVED_HOST = "saved_host"
        const val PREF_SAVED_PORT = "saved_port"
        const val PREF_LAST_WIFI_HOST = "last_wifi_host"
        const val PREF_LAST_WIFI_PORT = "last_wifi_port"
        const val PREF_USER_DISCONNECTED = "user_disconnected"

        const val PREF_RELAY_BOOTSTRAP_TOKEN = "relay_bootstrap_token"
        const val PREF_RELAY_HUB_TOKEN = "relay_hub_token"
        const val PREF_RELAY_NETWORK_ID = "relay_network_id"

        const val USB_PROMOTION_COOLDOWN_MS = 5000L
        const val USB_PROBE_INTERVAL_MS = 4000L

        @JvmStatic
        fun isLoopbackHost(host: String?): Boolean {
            val clean = host?.trim()?.lowercase() ?: return false
            return clean in setOf("127.0.0.1", "localhost", "::1")
        }

        @JvmStatic
        fun shouldProbeUsbPromotion(
            connectionMode: String?,
            userDisconnected: Boolean,
            isConnected: Boolean,
            isAuthenticated: Boolean,
            currentHost: String?,
            nowMs: Long,
            lastAttemptMs: Long,
            cooldownMs: Long = USB_PROMOTION_COOLDOWN_MS
        ): Boolean {
            if (userDisconnected) return false
            val normMode = connectionMode?.trim()?.lowercase() ?: "auto"
            if (normMode in setOf("remote_only", "remote_relay", "hotspot", "wifi_lan")) return false
            if (!isConnected || !isAuthenticated) return false
            if (isLoopbackHost(currentHost)) return false
            if (lastAttemptMs != Long.MIN_VALUE / 2 && (nowMs - lastAttemptMs) < cooldownMs) return false
            return true
        }

        @JvmStatic
        fun resolveUsbFallbackTarget(
            lastWifiHost: String?,
            lastWifiPort: Int,
            savedHost: String?,
            savedPort: Int
        ): Pair<String, Int>? {
            val cleanLastWifi = lastWifiHost?.trim()?.takeIf { it.isNotBlank() && !isLoopbackHost(it) }
            if (cleanLastWifi != null) {
                return cleanLastWifi to (if (lastWifiPort in 1..65535) lastWifiPort else Constants.DEFAULT_PORT)
            }
            val cleanSaved = savedHost?.trim()?.takeIf { it.isNotBlank() && !isLoopbackHost(it) }
            if (cleanSaved != null) {
                return cleanSaved to (if (savedPort in 1..65535) savedPort else Constants.DEFAULT_PORT)
            }
            return null
        }

        @JvmStatic
        fun resolveEffectiveRelayEndpoint(
            savedEndpoint: String?,
            defaultHubUrl: String = SnowUiRepository.DEFAULT_BUILTIN_HUB_URL
        ): String {
            val cleanSaved = savedEndpoint?.trim().orEmpty()
            if (cleanSaved.isNotBlank()) {
                return SnowUiRepository.normalizeRelayUrl(cleanSaved)
            }
            return SnowUiRepository.normalizeRelayUrl(defaultHubUrl)
        }

        @JvmStatic
        fun resolveEffectiveRelayAuth(
            ticket: String?,
            bootstrapToken: String?,
            hubToken: String?
        ): RelayAuthMaterial? {
            val cleanHub = hubToken?.trim().orEmpty()
            if (cleanHub.isNotBlank()) return RelayAuthMaterial(hubToken = cleanHub)
            val cleanBootstrap = bootstrapToken?.trim().orEmpty()
            if (cleanBootstrap.isNotBlank()) return RelayAuthMaterial(bootstrapToken = cleanBootstrap)
            val cleanTicket = ticket?.trim().orEmpty()
            if (cleanTicket.isNotBlank()) return RelayAuthMaterial(ticket = cleanTicket)
            return null
        }

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
        const val EXTRA_DEVICE_ID = "org.snow.extra.DEVICE_ID"
        const val EXTRA_HANDSHAKE_MODE = "org.snow.extra.HANDSHAKE_MODE"
        const val EXTRA_RESULT_CODE = "org.snow.extra.RESULT_CODE"
        const val EXTRA_RESULT_DATA = "org.snow.extra.RESULT_DATA"
        const val EXTRA_TARGET_IDS = "org.snow.extra.TARGET_IDS"

        @Volatile
        var isUserDisconnected: Boolean = false

        private val _isServiceRunningFlow = MutableStateFlow(false)

        @JvmStatic
        val isServiceRunningFlow: StateFlow<Boolean> = _isServiceRunningFlow.asStateFlow()

        @JvmStatic
        fun isServiceRunning(): Boolean = _isServiceRunningFlow.value

        internal fun setServiceRunningForTest(running: Boolean) {
            _isServiceRunningFlow.value = running
        }

        @Volatile
        private var activeInstance: SnowForegroundService? = null

        @JvmStatic
        fun getActiveInstance(): SnowForegroundService? = activeInstance

        @JvmStatic
        fun setDisconnectedByUser(context: Context, disconnected: Boolean) {
            isUserDisconnected = disconnected
            activeInstance?.let { instance ->
                instance.userDisconnected = disconnected
                if (disconnected) {
                    instance.autoConnectJob?.cancel()
                    instance.autoConnectJob = null
                }
            }
            context.getSharedPreferences(PREFS_ENDPOINT, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(PREF_USER_DISCONNECTED, disconnected)
                .apply()
        }

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

        @JvmOverloads
        fun startConnect(
            context: Context,
            host: String,
            port: Int,
            targetDeviceId: String? = null,
            handshakeMode: org.snow.network.ConnectionHandshakeMode = org.snow.network.ConnectionHandshakeMode.STANDARD_OR_AUTO
        ) {
            val intent = Intent(context, SnowForegroundService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_HOST, host)
                putExtra(EXTRA_PORT, port)
                if (!targetDeviceId.isNullOrBlank()) {
                    putExtra(EXTRA_DEVICE_ID, targetDeviceId)
                }
                putExtra(EXTRA_HANDSHAKE_MODE, handshakeMode.name)
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

        fun startScreenShare(
            context: Context,
            resultCode: Int,
            data: Intent,
            targetDeviceIds: List<String> = emptyList()
        ) {
            val intent = Intent(context, SnowForegroundService::class.java).apply {
                action = ACTION_START_SCREEN_SHARE
                putExtra(EXTRA_RESULT_CODE, resultCode)
                putExtra(EXTRA_RESULT_DATA, data)
                if (targetDeviceIds.isNotEmpty()) {
                    putStringArrayListExtra(EXTRA_TARGET_IDS, ArrayList(targetDeviceIds))
                }
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

        internal fun resolveRelayTargetFingerprint(
            certPinStorage: org.snow.security.CertPinStorage,
            targetPeerId: String
        ): String? {
            val cleanTarget = targetPeerId.trim()
            if (cleanTarget.isNotBlank()) {
                val perDevice = certPinStorage.getPinnedFingerprintForDevice(cleanTarget)
                    ?.replace(":", "")?.replace(" ", "")?.trim()?.takeIf { it.isNotBlank() }
                if (perDevice != null) return perDevice
            }
            return if (certPinStorage.listPinnedDeviceIds().isEmpty()) {
                certPinStorage.getPinnedFingerprint()
                    ?.replace(":", "")?.replace(" ", "")?.trim()?.takeIf { it.isNotBlank() }
            } else {
                null
            }
        }

        internal fun resolveRelayTransferPort(deviceType: String?): Int {
            val clean = deviceType?.trim()?.lowercase()
            return if (clean == "phone" || clean == "android") {
                org.snow.network.AndroidPeerHostManager.DEFAULT_MEDIA_PORT
            } else {
                8766
            }
        }
    }
}
