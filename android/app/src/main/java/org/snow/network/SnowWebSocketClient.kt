package org.snow.network

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.snow.protocol.Constants
import org.snow.protocol.ErrorCode
import org.snow.protocol.JsonSerialization
import org.snow.protocol.MessageType
import org.snow.protocol.ProtocolValidationError
import org.snow.protocol.ProtocolValidator
import org.snow.protocol.SnowError
import org.snow.protocol.SnowMessage
import org.snow.security.CertPinStorage
import org.snow.security.CertificateMismatchException
import org.snow.security.DeviceIdentity
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.SafeLog
import org.snow.security.SnowTrustManager
import org.snow.security.TlsConfig
import org.snow.security.TokenStorage
import org.snow.security.UnconfirmedCertificateException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Authentication and authorization states for the SNOW connection lifecycle.
 */
sealed class AuthState {
    object Disconnected : AuthState()
    object Connecting : AuthState()
    object ConnectedUnauthenticated : AuthState()
    data class Authenticated(
        val sessionId: String,
        val trustTier: String = "peer",
        val peerDeviceName: String? = null,
        val peerDeviceType: String? = null,
        val peerDeviceId: String? = null,
        val peerSnowId: String? = null,
        val permissionProfile: String? = null,
        val peerNetworkId: String? = null
    ) : AuthState()
    data class AuthFailed(val reason: String) : AuthState()
    data class FingerprintConfirmationRequired(val fingerprint: String) : AuthState()
    data class FingerprintMismatch(val pinned: String, val presented: String) : AuthState()
}

/**
 * WebSocket client implementing SNOW Device Protocol v1 with single connection lifecycle,
 * exponential backoff reconnection, WSS/TLS transport with SHA-256 certificate pinning,
 * and automatic post-connection authentication handshake.
 */
class SnowWebSocketClient(
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    private val backoffPolicy: BackoffPolicy = BackoffPolicy.batterySchedule(maxJitterMs = 0L),
    var certPinStorage: CertPinStorage? = null,
    var tokenStorage: TokenStorage? = null,
    var identity: DeviceIdentity? = null,
    var useTls: Boolean = true,
    var onUnconfirmedFingerprint: ((String) -> Unit)? = null,
    var onCertificateMismatch: ((String, String) -> Unit)? = null,
    var context: Context? = null
) {
    companion object {
        private const val TAG = "SnowWebSocketClient"
        const val MAX_CONNECT_RETRIES = 3
        const val MAX_PENDING_REQUESTS = 100
        const val DEFAULT_REQUEST_TIMEOUT_SECONDS = 30L

        internal fun parseAuthenticatedState(data: Map<*, *>?): AuthState.Authenticated {
            val sessionId = data?.get("session_id") as? String ?: "active"
            val trustTier = data?.get("trust_tier") as? String ?: "peer"
            val permissionProfile = data?.get("permission_profile") as? String
            val manifest = data?.get("manifest") as? Map<*, *>
            val peerName = (data?.get("device_name") as? String)
                ?: (manifest?.get("device_name") as? String)
            val peerType = (data?.get("device_type") as? String)
                ?: (data?.get("platform") as? String)
                ?: (manifest?.get("platform") as? String)
                ?: (manifest?.get("device_type") as? String)
            val peerDeviceId = (data?.get("server_device_id") as? String)
                ?: (manifest?.get("device_id") as? String)
            val peerSnowId = (data?.get("snow_id") as? String)
                ?: (manifest?.get("snow_id") as? String)
            val peerNetworkId = ((data?.get("network_id") as? String)
                ?: (manifest?.get("network_id") as? String))
                ?.trim()?.uppercase()?.takeIf { it.isNotBlank() }
            return AuthState.Authenticated(
                sessionId = sessionId,
                trustTier = trustTier,
                peerDeviceName = peerName,
                peerDeviceType = peerType,
                peerDeviceId = peerDeviceId,
                peerSnowId = peerSnowId,
                permissionProfile = permissionProfile,
                peerNetworkId = peerNetworkId
            )
        }
    }

    private var okHttpClient: OkHttpClient? = null
    private val timeoutScheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "SnowWsClientTimeout").apply { isDaemon = true }
    }

    private val socketGeneration = AtomicLong(0L)
    internal val currentGeneration: Long
        get() = socketGeneration.get()

    internal var webSocketFactory: ((Request, WebSocketListener) -> WebSocket)? = null

    private var webSocket: WebSocket? = null
    private var reconnectJob: Job? = null
    private var heartbeatJob: Job? = null

    private var targetHost: String = ""
    private var targetPort: Int = Constants.DEFAULT_PORT

    private val userInitiatedDisconnect = AtomicBoolean(false)
    private val missedHeartbeatAcks = AtomicInteger(0)
    @Volatile
    var autoReconnectEnabled: Boolean = true
    var heartbeatIntervalMs: Long = Constants.HEARTBEAT_INTERVAL_MS
    var heartbeatTimeoutMs: Long = Constants.HEARTBEAT_TIMEOUT_MS
    @Volatile
    internal var requestTimeoutMs: Long = DEFAULT_REQUEST_TIMEOUT_SECONDS * 1000L
    var onDeviceRevoked: ((String?) -> Unit)? = null
    @Volatile
    private var pendingHeartbeatId: String? = null
    @Volatile
    private var lastAckTimestamp: Long = 0L

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _authState = MutableStateFlow<AuthState>(AuthState.Disconnected)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    fun setAuthenticated(
        sessionId: String,
        trustTier: String = "peer",
        peerDeviceName: String? = null,
        peerDeviceType: String? = null,
        peerDeviceId: String? = null,
        peerSnowId: String? = null,
        permissionProfile: String? = null,
        peerNetworkId: String? = null
    ) {
        synchronized(this) {
            val canonicalPeerId = peerDeviceId?.trim()?.takeIf { it.isNotBlank() }
            if (canonicalPeerId != null) {
                resolvedTargetDeviceId = canonicalPeerId
                currentTrustManager?.lastPresentedFingerprint?.let { fp ->
                    if (certPinStorage?.getPinnedFingerprintForDevice(canonicalPeerId) == null) {
                        certPinStorage?.pinFingerprintForDevice(canonicalPeerId, fp)
                    }
                }
            }
            backoffPolicy.reset()
            _authState.value = AuthState.Authenticated(
                sessionId,
                trustTier,
                peerDeviceName,
                peerDeviceType,
                peerDeviceId,
                peerSnowId,
                permissionProfile,
                peerNetworkId
            )
        }
    }

    private val _logs = MutableSharedFlow<String>(replay = 50, extraBufferCapacity = 100)
    val logs: SharedFlow<String> = _logs.asSharedFlow()

    private data class PendingRequestEntry(
        val generation: Long,
        val callback: (SnowMessage) -> Unit
    )

    private val pendingRequests = ConcurrentHashMap<String, PendingRequestEntry>()
    @Volatile
    private var currentTrustManager: SnowTrustManager? = null

    @Volatile
    var expectedTargetDeviceId: String? = null
    @Volatile
    var resolvedTargetDeviceId: String? = null
    var targetDeviceLookupByEndpoint: ((String, Int) -> String?)? = null

    var requestDispatcher: (suspend (action: String, data: Map<String, Any?>?) -> Pair<Map<String, Any?>?, SnowError?>)? = null
    val currentTargetHost: String get() = targetHost
    val currentTargetPort: Int get() = targetPort

    fun activeTargetDeviceId(): String? {
        return resolvedTargetDeviceId?.trim()?.takeIf { it.isNotBlank() }
            ?: expectedTargetDeviceId?.trim()?.takeIf { it.isNotBlank() }
            ?: currentTrustManager?.lastMatchedDeviceId?.trim()?.takeIf { it.isNotBlank() }
            ?: targetDeviceLookupByEndpoint?.invoke(targetHost, targetPort)?.trim()?.takeIf { it.isNotBlank() }
    }

    private fun isLoopbackTargetHost(): Boolean =
        targetHost == "127.0.0.1" || targetHost == "localhost" || targetHost == "::1"

    private fun resolveScopedPinnedFingerprint(presentedFp: String? = null): String? {
        val storage = certPinStorage ?: return null
        val targetDev = activeTargetDeviceId()
        if (targetDev != null) {
            storage.getPinnedFingerprintForDevice(targetDev)?.let { return it }
            if (storage.listPinnedDeviceIds().isEmpty()) {
                return storage.getPinnedFingerprint()
            }
            return null
        }
        if (isLoopbackTargetHost() && presentedFp != null) {
            val matchedDev = storage.findDeviceIdByFingerprint(presentedFp)
            if (matchedDev != null) {
                return storage.getPinnedFingerprintForDevice(matchedDev)
            }
            if (storage.listPinnedDeviceIds().isEmpty()) {
                return storage.getPinnedFingerprint()
            }
            return null
        }
        return storage.getPinnedFingerprint()
    }

    private fun resolveStoredTokenForActiveTarget(): String? {
        val storage = tokenStorage ?: return null
        val targetDev = activeTargetDeviceId()
        if (targetDev != null) {
            storage.getTokenForDevice(targetDev)?.let { return it }
            if (storage.listStoredDeviceIds().isEmpty()) {
                return storage.getToken()
            }
            return null
        }
        if (isLoopbackTargetHost()) {
            // Do not blindly send another peer's token if device was not identified yet
            if (storage.listStoredDeviceIds().isEmpty()) {
                return storage.getToken()
            }
            return null
        }
        return storage.getToken()
    }

    private fun clearStoredTokenForActiveTarget() {
        val storage = tokenStorage ?: return
        val targetDev = activeTargetDeviceId()
        if (targetDev != null) {
            storage.clearTokenForDevice(targetDev)
            if (storage.listStoredDeviceIds().isEmpty()) {
                storage.clearToken()
            }
        } else {
            storage.clearToken()
        }
    }

    private fun log(message: String) {
        val entry = "[${SnowMessage.currentIsoTimestamp()}] $message"
        _logs.tryEmit(entry)
    }

    /**
     * Explicitly confirm and pin a server certificate SHA-256 fingerprint (Trust-On-First-Use).
     */
    @JvmOverloads
    @Synchronized
    fun confirmAndPinCertificate(fingerprint: String, targetDeviceId: String? = null) {
        val normalized = TlsConfig.formatFingerprint(fingerprint)
        val scopedId = targetDeviceId?.trim()?.takeIf { it.isNotBlank() } ?: activeTargetDeviceId()
        if (scopedId != null) {
            certPinStorage?.pinFingerprintForDevice(scopedId, normalized)
            expectedTargetDeviceId = scopedId
        } else {
            certPinStorage?.pinFingerprint(normalized)
        }
        log("Certificate pinned${scopedId?.let { " for [$it]" } ?: ""}: $normalized. Reconnecting...")
        backoffPolicy.reset()
        if (targetHost.isNotBlank()) {
            initiateConnection()
        }
    }

    /**
     * Clear the pinned certificate fingerprint for the active device (or all if unspecified).
     */
    @JvmOverloads
    @Synchronized
    fun resetCertificateTrust(targetDeviceId: String? = null) {
        val scopedId = targetDeviceId?.trim()?.takeIf { it.isNotBlank() } ?: activeTargetDeviceId()
        if (scopedId != null) {
            certPinStorage?.clearPinnedFingerprintForDevice(scopedId)
        } else {
            certPinStorage?.clearPinnedFingerprint()
        }
        log("Certificate trust reset. Next connection will require re-confirmation.")
    }

    /**
     * Connect to the SNOW host at wss://host:port (or ws:// if useTls is false).
     */
    @JvmOverloads
    fun connect(host: String, port: Int = Constants.DEFAULT_PORT, targetDeviceId: String? = null) {
        val stalePending: List<PendingRequestEntry>
        synchronized(this) {
            targetHost = host.trim()
            targetPort = port
            expectedTargetDeviceId = targetDeviceId?.trim()?.takeIf { it.isNotBlank() }
            resolvedTargetDeviceId = null
            userInitiatedDisconnect.set(false)
            backoffPolicy.reset()

            stalePending = if (_connectionState.value == ConnectionState.CONNECTED ||
                _connectionState.value == ConnectionState.CONNECTING ||
                webSocket != null
            ) {
                log("Disconnecting prior session before deliberate connect().")
                disconnectLocked(advanceGeneration = true)
            } else {
                reconnectJob?.cancel()
                reconnectJob = null
                emptyList()
            }

            initiateConnection()
        }
        deliverPendingError(stalePending, "Client reconnecting via explicit connect().")
    }

    /**
     * Recover connection when OS network connectivity is restored, resetting exhausted backoff.
     */
    @JvmOverloads
    fun onNetworkRestored(
        host: String = targetHost,
        port: Int = targetPort,
        targetDeviceId: String? = expectedTargetDeviceId
    ): Boolean {
        val stalePending: List<PendingRequestEntry>
        val cleanHost = host.trim()
        val initiated: Boolean
        synchronized(this) {
            if (userInitiatedDisconnect.get()) return false
            backoffPolicy.reset()
            if (!autoReconnectEnabled || cleanHost.isBlank()) return false

            val endpointMatches = cleanHost == targetHost && port == targetPort
            if (_connectionState.value == ConnectionState.CONNECTED && webSocket != null && endpointMatches) {
                return false
            }

            targetHost = cleanHost
            targetPort = port
            if (!targetDeviceId.isNullOrBlank()) {
                expectedTargetDeviceId = targetDeviceId.trim()
            }
            resolvedTargetDeviceId = null
            log("Network restored: backoff reset, initiating recovery connection to $cleanHost:$port ...")
            stalePending = disconnectLocked(advanceGeneration = true)
            initiateConnection()
            initiated = true
        }
        deliverPendingError(stalePending, "Client reconnecting after network restoration.")
        return initiated
    }

    /**
     * Update target endpoint dynamically (e.g. from LAN discovery beacon or USB promotion).
     */
    @JvmOverloads
    fun updateTargetEndpoint(host: String, port: Int = Constants.DEFAULT_PORT, targetDeviceId: String? = null): Boolean {
        val cleanHost = host.trim()
        if (cleanHost.isBlank()) return false

        val stalePending: List<PendingRequestEntry>
        val result: Boolean
        synchronized(this) {
            val cleanDev = targetDeviceId?.trim()?.takeIf { it.isNotBlank() }
            if (cleanDev != null) {
                expectedTargetDeviceId = cleanDev
            }
            val endpointChanged = cleanHost != targetHost || port != targetPort
            val currentState = _connectionState.value

            if (endpointChanged) {
                log("Target endpoint changed from $targetHost:$targetPort to $cleanHost:$port. Initiating reconnect...")
                targetHost = cleanHost
                targetPort = port
                resolvedTargetDeviceId = null
                userInitiatedDisconnect.set(false)
                backoffPolicy.reset()
                stalePending = disconnectLocked(advanceGeneration = true)
                initiateConnection()
                result = true
            } else if (currentState == ConnectionState.CONNECTED || currentState == ConnectionState.CONNECTING) {
                stalePending = emptyList()
                result = false
            } else if (!userInitiatedDisconnect.get()) {
                log("Target endpoint confirmed ($cleanHost:$port) while state=$currentState. Accelerating reconnect...")
                backoffPolicy.reset()
                reconnectJob?.cancel()
                reconnectJob = null
                stalePending = emptyList()
                initiateConnection()
                result = true
            } else {
                stalePending = emptyList()
                result = false
            }
        }
        deliverPendingError(stalePending, "Endpoint updated; previous requests aborted.")
        return result
    }

    internal fun isCurrentGeneration(expectedGeneration: Long, incomingSocket: WebSocket? = null): Boolean {
        synchronized(this) {
            if (expectedGeneration != socketGeneration.get()) return false
            if (incomingSocket != null && this.webSocket !== incomingSocket) return false
            return true
        }
    }

    internal fun handleUnconfirmedFingerprintCallback(expectedGeneration: Long, fingerprint: String) {
        val active = synchronized(this) {
            if (expectedGeneration != socketGeneration.get() || userInitiatedDisconnect.get()) {
                false
            } else {
                _authState.value = AuthState.FingerprintConfirmationRequired(fingerprint)
                true
            }
        }
        if (!active) {
            log("Ignoring stale unconfirmed-fingerprint callback from generation=$expectedGeneration (active=${socketGeneration.get()}).")
            return
        }
        onUnconfirmedFingerprint?.invoke(fingerprint)
    }

    private fun buildClientForGeneration(generation: Long): Pair<OkHttpClient, SnowTrustManager?> {
        val baseClient = okHttpClient ?: OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .pingInterval(0, TimeUnit.SECONDS)
            .build()
            .also { okHttpClient = it }

        if (!useTls) {
            return baseClient to null
        }

        val storage = certPinStorage ?: InMemoryCertPinStorage()
        val trustManager = SnowTrustManager(
            pinStorage = storage,
            onUnconfirmedFingerprint = { fp ->
                handleUnconfirmedFingerprintCallback(generation, fp)
            },
            targetDeviceIdProvider = { activeTargetDeviceId() },
            allowAnyPinnedMatchProvider = { isLoopbackTargetHost() }
        )
        val sslContext = TlsConfig.createSslContext(trustManager)
        val scopedClient = baseClient.newBuilder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .hostnameVerifier(
                TlsConfig.createHostnameVerifier(
                    pinStorage = storage,
                    targetDeviceIdProvider = { activeTargetDeviceId() },
                    allowAnyPinnedMatchProvider = { isLoopbackTargetHost() }
                )
            )
            .build()
        return scopedClient to trustManager
    }

    @Synchronized
    private fun initiateConnection() {
        if (userInitiatedDisconnect.get()) return
        if (_connectionState.value == ConnectionState.CONNECTED && webSocket != null) {
            log("Already connected to desktop core. Skipping redundant initiateConnection().")
            return
        }

        val newGeneration = socketGeneration.incrementAndGet()
        heartbeatJob?.cancel()
        heartbeatJob = null
        pendingHeartbeatId = null
        missedHeartbeatAcks.set(0)

        // Clean up previous socket instance before opening a new one to prevent connection leaks
        val previousWs = webSocket
        webSocket = null
        if (previousWs != null) {
            try {
                previousWs.close(1000, "Opening new connection")
            } catch (_: Exception) {
                previousWs.cancel()
            }
        }

        val scheme = if (useTls) "wss" else "ws"
        val wsUrl = "$scheme://$targetHost:$targetPort"
        log("Connecting to $wsUrl (gen=$newGeneration) ...")
        _connectionState.value = ConnectionState.CONNECTING
        _authState.value = AuthState.Connecting

        val request = Request.Builder()
            .url(wsUrl)
            .build()

        val (client, genTrustManager) = buildClientForGeneration(newGeneration)
        currentTrustManager = genTrustManager
        val listener = SnowListener(newGeneration, genTrustManager)
        val createdWs = webSocketFactory?.invoke(request, listener) ?: client.newWebSocket(request, listener)
        if (socketGeneration.get() == newGeneration && !userInitiatedDisconnect.get()) {
            webSocket = createdWs
        } else {
            try {
                createdWs.cancel()
            } catch (_: Exception) {}
        }
    }

    private fun drainPendingRequestsLocked(): List<PendingRequestEntry> {
        if (pendingRequests.isEmpty()) return emptyList()
        val entries = pendingRequests.values.toList()
        pendingRequests.clear()
        return entries
    }

    private fun deliverPendingError(entries: List<PendingRequestEntry>, errorMessage: String) {
        if (entries.isEmpty()) return
        val errResponse = SnowMessage.createError(
            code = ErrorCode.INTERNAL_ERROR,
            message = errorMessage
        )
        for (entry in entries) {
            try {
                entry.callback.invoke(errResponse)
            } catch (e: Exception) {
                SafeLog.e(TAG, "Error notifying pending request callback: ${e.message}", e)
            }
        }
    }

    private fun failPendingRequests(errorMessage: String) {
        deliverPendingError(drainPendingRequestsLocked(), errorMessage)
    }

    /**
     * Gracefully disconnect the client and prevent automatic reconnection.
     */
    fun disconnect() {
        val pending: List<PendingRequestEntry>
        synchronized(this) {
            userInitiatedDisconnect.set(true)
            pending = disconnectLocked(advanceGeneration = true)
            backoffPolicy.reset()
            _connectionState.value = ConnectionState.DISCONNECTED
            _authState.value = AuthState.Disconnected
            log("Client disconnected by user.")
        }
        deliverPendingError(pending, "Client disconnected.")
    }

    @Synchronized
    private fun disconnectLocked(advanceGeneration: Boolean = true): List<PendingRequestEntry> {
        if (advanceGeneration) {
            socketGeneration.incrementAndGet()
        }
        heartbeatJob?.cancel()
        heartbeatJob = null
        reconnectJob?.cancel()
        reconnectJob = null

        val prevWs = webSocket
        webSocket = null
        if (prevWs != null) {
            try {
                prevWs.close(1000, "User disconnect")
            } catch (_: Exception) {
                prevWs.cancel()
            }
        }
        val drained = drainPendingRequestsLocked()
        pendingHeartbeatId = null
        missedHeartbeatAcks.set(0)
        return drained
    }

    private fun disconnectInternal() {
        val drained = synchronized(this) { disconnectLocked(advanceGeneration = true) }
        deliverPendingError(drained, "Client disconnected.")
    }

    /**
     * Terminate the client completely, shut down HTTP connection pool and background timeout scheduler.
     */
    fun teardown() {
        disconnect()
        okHttpClient?.dispatcher?.executorService?.shutdown()
        okHttpClient?.connectionPool?.evictAll()
        okHttpClient = null
        try {
            timeoutScheduler.shutdownNow()
        } catch (_: Exception) {}
    }

    internal fun createListenerForTest(generation: Long, trustManager: SnowTrustManager? = null): WebSocketListener {
        return SnowListener(generation, trustManager)
    }

    internal fun getTrustManagerForTest(): SnowTrustManager? = currentTrustManager

    internal fun attachSocketForTest(socket: WebSocket, generation: Long = socketGeneration.incrementAndGet()) {
        synchronized(this) {
            socketGeneration.set(generation)
            userInitiatedDisconnect.set(false)
            webSocket = socket
            _connectionState.value = ConnectionState.CONNECTED
        }
    }

    /**
     * Send a request action to the server.
     */
    fun sendRequest(
        action: String,
        data: Map<String, Any?>? = null,
        onResponse: ((SnowMessage) -> Unit)? = null
    ) {
        sendRequestInternal(
            expectedGeneration = null,
            expectedSocket = null,
            action = action,
            data = data,
            onResponse = onResponse
        )
    }

    private fun sendRequestForGeneration(
        expectedGeneration: Long,
        expectedSocket: WebSocket,
        action: String,
        data: Map<String, Any?>? = null,
        onResponse: ((SnowMessage) -> Unit)? = null
    ) {
        sendRequestInternal(
            expectedGeneration = expectedGeneration,
            expectedSocket = expectedSocket,
            action = action,
            data = data,
            onResponse = onResponse
        )
    }

    private fun sendRequestInternal(
        expectedGeneration: Long?,
        expectedSocket: WebSocket?,
        action: String,
        data: Map<String, Any?>?,
        onResponse: ((SnowMessage) -> Unit)?
    ) {
        val currentWs: WebSocket?
        val activeGen: Long
        synchronized(this) {
            val ws = webSocket
            val gen = socketGeneration.get()
            if (_connectionState.value != ConnectionState.CONNECTED ||
                ws == null ||
                (expectedGeneration != null && expectedGeneration != gen) ||
                (expectedSocket != null && ws !== expectedSocket)
            ) {
                currentWs = null
                activeGen = -1L
            } else {
                currentWs = ws
                activeGen = gen
            }
        }

        if (currentWs == null) {
            log("Cannot send request: Not connected.")
            onResponse?.invoke(
                SnowMessage.createError(
                    code = ErrorCode.INTERNAL_ERROR,
                    message = "Cannot send request: Client is not connected to desktop."
                )
            )
            return
        }

        val requestMessage = SnowMessage.createRequest(action = action, data = data)
        var safeCallback: ((SnowMessage) -> Unit)? = null
        var timeoutFuture: ScheduledFuture<*>? = null

        if (onResponse != null) {
            if (pendingRequests.size >= MAX_PENDING_REQUESTS) {
                log("Cannot send request: Pending request capacity ($MAX_PENDING_REQUESTS) exceeded.")
                onResponse.invoke(
                    SnowMessage.createError(
                        code = ErrorCode.INTERNAL_ERROR,
                        message = "Request rejected: pending request queue capacity ($MAX_PENDING_REQUESTS) exceeded."
                    )
                )
                return
            }

            val invoked = AtomicBoolean(false)
            val timeoutFutureRef = AtomicReference<ScheduledFuture<*>?>()

            val cb: (SnowMessage) -> Unit = { response ->
                if (invoked.compareAndSet(false, true)) {
                    timeoutFutureRef.get()?.cancel(false)
                    pendingRequests.remove(requestMessage.id)
                    onResponse.invoke(response)
                }
            }
            safeCallback = cb
            pendingRequests[requestMessage.id] = PendingRequestEntry(activeGen, cb)

            val activeTimeoutMs = requestTimeoutMs
            timeoutFuture = timeoutScheduler.schedule({
                cb.invoke(
                    SnowMessage.createError(
                        code = ErrorCode.INTERNAL_ERROR,
                        message = "Request timed out after ${activeTimeoutMs}ms [action='$action']",
                        correlationId = requestMessage.id
                    )
                )
            }, activeTimeoutMs, TimeUnit.MILLISECONDS)

            timeoutFutureRef.set(timeoutFuture)
            if (invoked.get()) {
                timeoutFuture.cancel(false)
            }
        }

        if (!isCurrentGeneration(activeGen, currentWs)) {
            safeCallback?.invoke(
                SnowMessage.createError(
                    code = ErrorCode.INTERNAL_ERROR,
                    message = "Cannot send request: connection generation changed.",
                    correlationId = requestMessage.id
                )
            )
            return
        }

        val json = JsonSerialization.toJson(requestMessage)
        val sent = try {
            currentWs.send(json)
        } catch (_: Exception) {
            false
        }
        if (sent) {
            log("Sent request action='$action' id=${requestMessage.id}")
        } else {
            log("Failed to send request id=${requestMessage.id}")
            timeoutFuture?.cancel(false)
            safeCallback?.invoke(
                SnowMessage.createError(
                    code = ErrorCode.INTERNAL_ERROR,
                    message = "Failed to send WebSocket frame to desktop.",
                    correlationId = requestMessage.id
                )
            )
        }
    }

    /**
     * Send a raw SnowMessage directly.
     */
    fun sendMessage(message: SnowMessage): Boolean {
        val currentWs = synchronized(this) { webSocket } ?: return false
        val json = JsonSerialization.toJson(message)
        return try {
            currentWs.send(json)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Send a live capability manifest update to the desktop core.
     */
    fun sendManifestUpdate(
        manifest: CapabilityManifest,
        onResponse: ((SnowMessage) -> Unit)? = null
    ) {
        val devId = identity?.deviceId
        if (devId.isNullOrBlank()) {
            log("Cannot send manifest update: device identity missing")
            return
        }
        val manifestMap = manifest.toMap()
        sendRequest(
            action = "manifest_update",
            data = mapOf(
                "device_id" to devId,
                "manifest" to manifestMap
            ),
            onResponse = onResponse
        )
    }

    @Synchronized
    private fun scheduleReconnection(expectedGeneration: Long = socketGeneration.get()) {
        if (expectedGeneration != socketGeneration.get()) {
            return
        }
        if (userInitiatedDisconnect.get() || !autoReconnectEnabled) {
            if (!autoReconnectEnabled) {
                log("Auto-reconnect disabled; staying disconnected.")
                _connectionState.value = ConnectionState.DISCONNECTED
            }
            return
        }

        // Prevent duplicate concurrent reconnect loops within the same generation
        if (reconnectJob?.isActive == true) {
            return
        }

        // If the failure was due to an unconfirmed certificate or fingerprint mismatch,
        // do not hammer the server with rapid auto-reconnects until user acts
        val currentAuth = _authState.value
        if (currentAuth is AuthState.FingerprintConfirmationRequired ||
            currentAuth is AuthState.FingerprintMismatch
        ) {
            log("Auto-reconnection paused awaiting certificate verification.")
            return
        }

        val maxAttempts = maxOf(MAX_CONNECT_RETRIES, backoffPolicy.scheduleStepCount())
        if (backoffPolicy.currentAttempt >= maxAttempts) {
            log("Maximum connection retries ($maxAttempts) reached. Stopping auto-reconnect.")
            _connectionState.value = ConnectionState.DISCONNECTED
            _authState.value = AuthState.AuthFailed("Connection retry limit reached ($maxAttempts attempts).")
            reconnectJob?.cancel()
            reconnectJob = null
            return
        }

        _connectionState.value = ConnectionState.RECONNECTING
        val delayMs = backoffPolicy.nextDelayMs()
        log("Reconnecting in ${delayMs}ms (attempt #${backoffPolicy.currentAttempt}/$maxAttempts, gen=$expectedGeneration) ...")

        reconnectJob?.cancel()
        lateinit var launchedJob: Job
        launchedJob = scope.launch {
            delay(delayMs)
            synchronized(this@SnowWebSocketClient) {
                if (!isActive ||
                    userInitiatedDisconnect.get() ||
                    !autoReconnectEnabled ||
                    reconnectJob !== launchedJob ||
                    expectedGeneration != socketGeneration.get()
                ) {
                    return@launch
                }
                reconnectJob = null
                initiateConnection()
            }
        }
        reconnectJob = launchedJob
    }

    internal fun handleHeartbeatFailure(
        reason: String = "Missed consecutive heartbeat acknowledgements",
        expectedSocket: WebSocket? = null,
        expectedGeneration: Long? = null
    ) {
        val pending: List<PendingRequestEntry>
        val prevWs: WebSocket?
        val reconnectGen: Long
        val shouldScheduleReconnect: Boolean
        synchronized(this) {
            val gen = socketGeneration.get()
            if (expectedGeneration != null && expectedGeneration != gen) {
                log("Ignoring stale heartbeat failure from gen=$expectedGeneration (active=$gen).")
                return
            }
            if (expectedSocket != null && this.webSocket !== expectedSocket) {
                log("Ignoring heartbeat failure for non-active socket.")
                return
            }

            reconnectGen = socketGeneration.incrementAndGet()
            prevWs = webSocket
            webSocket = null
            heartbeatJob?.cancel()
            heartbeatJob = null
            pendingHeartbeatId = null
            missedHeartbeatAcks.set(0)
            pending = drainPendingRequestsLocked()
            _authState.value = AuthState.Disconnected
            _connectionState.value = ConnectionState.DISCONNECTED
            log("Heartbeat timeout! $reason. Stale session cleared.")
            shouldScheduleReconnect = autoReconnectEnabled && !userInitiatedDisconnect.get()
            if (shouldScheduleReconnect) {
                scheduleReconnection(reconnectGen)
            }
        }
        try {
            prevWs?.cancel()
        } catch (_: Exception) {}
        deliverPendingError(pending, "Heartbeat timeout: $reason")
    }

    internal fun startHeartbeatLoop(
        socketRef: WebSocket? = webSocket,
        generation: Long = socketGeneration.get()
    ) {
        val capturedSocket = socketRef ?: return
        synchronized(this) {
            if (generation != socketGeneration.get() || this.webSocket !== capturedSocket) {
                return
            }
            heartbeatJob?.cancel()
            lastAckTimestamp = System.currentTimeMillis()
            pendingHeartbeatId = null
            missedHeartbeatAcks.set(0)

            lateinit var launchedHeartbeat: Job
            launchedHeartbeat = scope.launch {
                try {
                    while (isActive && isCurrentGeneration(generation, capturedSocket) &&
                        _connectionState.value == ConnectionState.CONNECTED
                    ) {
                        delay(heartbeatIntervalMs)
                        if (!isActive || !isCurrentGeneration(generation, capturedSocket) ||
                            _connectionState.value != ConnectionState.CONNECTED
                        ) {
                            break
                        }

                        var timedOutMissed: Int? = null
                        var jsonPayload: String? = null
                        var sentHeartbeatId: String? = null

                        synchronized(this@SnowWebSocketClient) {
                            if (generation != socketGeneration.get() ||
                                this@SnowWebSocketClient.webSocket !== capturedSocket ||
                                _connectionState.value != ConnectionState.CONNECTED ||
                                heartbeatJob !== launchedHeartbeat
                            ) {
                                return@launch
                            }
                            if (pendingHeartbeatId != null) {
                                val missed = missedHeartbeatAcks.incrementAndGet()
                                val now = System.currentTimeMillis()
                                if (missed >= 2 || (now - lastAckTimestamp) > heartbeatTimeoutMs) {
                                    timedOutMissed = missed
                                } else {
                                    log("Heartbeat ack missed ($missed/2); sending follow-up heartbeat.")
                                }
                            }
                            if (timedOutMissed == null) {
                                val heartbeat = SnowMessage.createHeartbeat()
                                sentHeartbeatId = heartbeat.id
                                jsonPayload = JsonSerialization.toJson(heartbeat)
                                pendingHeartbeatId = heartbeat.id
                            }
                        }

                        if (timedOutMissed != null) {
                            handleHeartbeatFailure(
                                reason = "Missed $timedOutMissed consecutive heartbeat_ack frames.",
                                expectedSocket = capturedSocket,
                                expectedGeneration = generation
                            )
                            break
                        }

                        if (!isCurrentGeneration(generation, capturedSocket)) {
                            break
                        }

                        val sent = try {
                            capturedSocket.send(jsonPayload!!)
                        } catch (_: Exception) {
                            false
                        }
                        if (sent) {
                            log("Heartbeat sent id=$sentHeartbeatId")
                        } else {
                            log("Failed sending heartbeat id=$sentHeartbeatId")
                        }
                    }
                } finally {
                    synchronized(this@SnowWebSocketClient) {
                        if (heartbeatJob === launchedHeartbeat) {
                            heartbeatJob = null
                        }
                    }
                }
            }
            heartbeatJob = launchedHeartbeat
        }
    }

    private inner class SnowListener(
        private val generation: Long,
        private val listenerTrustManager: SnowTrustManager?
    ) : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            val shouldStart = synchronized(this@SnowWebSocketClient) {
                if (userInitiatedDisconnect.get()) {
                    false
                } else if (generation != socketGeneration.get() ||
                    this@SnowWebSocketClient.webSocket !== webSocket
                ) {
                    log("Ignoring onOpen from obsolete generation=$generation (active=${socketGeneration.get()}).")
                    false
                } else {
                    reconnectJob?.cancel()
                    reconnectJob = null
                    _connectionState.value = ConnectionState.CONNECTED
                    val scheme = if (useTls) "wss" else "ws"
                    log("Connected to $scheme://$targetHost:$targetPort (gen=$generation, awaiting auth before resetting backoff)")
                    lastAckTimestamp = System.currentTimeMillis()
                    startHeartbeatLoop(webSocket, generation)
                    true
                }
            }

            if (!shouldStart) {
                try {
                    webSocket.close(1000, "Stale or disconnected")
                } catch (_: Exception) {
                    webSocket.cancel()
                }
                return
            }

            // Automatic post-connection authentication handshake bound strictly to (webSocket, generation)
            performPostConnectionHandshake(webSocket, generation)
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            if (!isCurrentGeneration(generation, webSocket)) {
                log("Ignoring onMessage from stale generation=$generation.")
                return
            }
            handleIncomingMessage(webSocket, text, expectedGeneration = generation)
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            if (isCurrentGeneration(generation, webSocket)) {
                log("Server closing connection (gen=$generation): $code - $reason")
            }
            try {
                webSocket.close(code, reason)
            } catch (_: Exception) {}
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            val drained: List<PendingRequestEntry>
            synchronized(this@SnowWebSocketClient) {
                if (generation != socketGeneration.get() || this@SnowWebSocketClient.webSocket !== webSocket) {
                    log("Ignoring onClosed from stale socket (gen=$generation, code=$code).")
                    return
                }
                log("Connection closed: $code - $reason")
                val nextGen = socketGeneration.incrementAndGet()
                heartbeatJob?.cancel()
                heartbeatJob = null
                pendingHeartbeatId = null
                missedHeartbeatAcks.set(0)
                _authState.value = AuthState.Disconnected
                drained = drainPendingRequestsLocked()
                this@SnowWebSocketClient.webSocket = null
                if (!userInitiatedDisconnect.get()) {
                    scheduleReconnection(nextGen)
                } else {
                    _connectionState.value = ConnectionState.DISCONNECTED
                }
            }
            deliverPendingError(drained, "Connection closed ($code: $reason)")
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            val drained: List<PendingRequestEntry>
            var unconfirmedFpToNotify: String? = null
            var mismatchToNotify: Pair<String, String>? = null

            synchronized(this@SnowWebSocketClient) {
                if (generation != socketGeneration.get() || this@SnowWebSocketClient.webSocket !== webSocket) {
                    log("Ignoring onFailure from stale socket (gen=$generation): ${t.message}")
                    return
                }
                socketGeneration.incrementAndGet()
                heartbeatJob?.cancel()
                heartbeatJob = null
                pendingHeartbeatId = null
                missedHeartbeatAcks.set(0)
                drained = drainPendingRequestsLocked()
                this@SnowWebSocketClient.webSocket = null

                val trustMgr = listenerTrustManager ?: currentTrustManager

                // 1. Check for specific TLS certificate verification exceptions in cause chain
                var certException: Throwable? = t
                var handledTls = false
                while (certException != null) {
                    if (certException is UnconfirmedCertificateException) {
                        val fp = certException.presentedFingerprint
                        _authState.value = AuthState.FingerprintConfirmationRequired(fp)
                        log("Server certificate not yet confirmed by user. Fingerprint: $fp")
                        _connectionState.value = ConnectionState.DISCONNECTED
                        trustMgr?.resetLastPresentedFingerprint()
                        unconfirmedFpToNotify = fp
                        handledTls = true
                        break
                    }
                    if (certException is CertificateMismatchException) {
                        val pinned = certException.pinnedFingerprint
                        val presented = certException.presentedFingerprint
                        _authState.value = AuthState.FingerprintMismatch(pinned, presented)
                        log("Untrusted server certificate! Mismatch detected. Pinned: $pinned, Presented: $presented")
                        _connectionState.value = ConnectionState.DISCONNECTED
                        trustMgr?.resetLastPresentedFingerprint()
                        mismatchToNotify = pinned to presented
                        handledTls = true
                        break
                    }
                    certException = certException.cause
                }

                if (!handledTls) {
                    // 2. Fallback check: inspect scoped TrustManager for this generation
                    val presentedFp = trustMgr?.lastPresentedFingerprint
                    val pinnedFp = resolveScopedPinnedFingerprint(presentedFp)

                    if (presentedFp != null) {
                        if (pinnedFp == null) {
                            _authState.value = AuthState.FingerprintConfirmationRequired(presentedFp)
                            log("Server certificate not yet confirmed by user (via trust manager). Fingerprint: $presentedFp")
                            _connectionState.value = ConnectionState.DISCONNECTED
                            trustMgr.resetLastPresentedFingerprint()
                            unconfirmedFpToNotify = presentedFp
                            handledTls = true
                        } else if (!TlsConfig.fingerprintsMatch(pinnedFp, presentedFp)) {
                            _authState.value = AuthState.FingerprintMismatch(pinnedFp, presentedFp)
                            log("Untrusted server certificate! Mismatch detected. Pinned: $pinnedFp, Presented: $presentedFp")
                            _connectionState.value = ConnectionState.DISCONNECTED
                            trustMgr.resetLastPresentedFingerprint()
                            mismatchToNotify = pinnedFp to presentedFp
                            handledTls = true
                        }
                    }
                }

                if (!handledTls) {
                    log("Connection error: ${t.message ?: t.javaClass.simpleName}")
                    _authState.value = AuthState.Disconnected
                    if (!userInitiatedDisconnect.get()) {
                        scheduleReconnection(socketGeneration.get())
                    } else {
                        _connectionState.value = ConnectionState.DISCONNECTED
                    }
                }
            }

            deliverPendingError(drained, "Connection failed: ${t.message}")
            unconfirmedFpToNotify?.let { fp -> onUnconfirmedFingerprint?.invoke(fp) }
            mismatchToNotify?.let { (pinned, presented) -> onCertificateMismatch?.invoke(pinned, presented) }
        }
    }

    private fun performPostConnectionHandshake(socketRef: WebSocket, generation: Long) {
        if (!isCurrentGeneration(generation, socketRef)) return
        val devId = identity?.deviceId
        val token = resolveStoredTokenForActiveTarget()

        if (!devId.isNullOrBlank() && !token.isNullOrBlank()) {
            log("Initiating automatic authentication handshake (device_id=${devId.take(8)}...)...")
            val manifestMap = DeviceNode.buildAndroidManifest(context).toMap()
            val isLoopback = targetHost == "127.0.0.1" || targetHost == "localhost" || targetHost == "::1"
            sendRequestForGeneration(
                expectedGeneration = generation,
                expectedSocket = socketRef,
                action = "auth_request",
                data = mapOf(
                    "device_id" to devId,
                    "auth_token" to token,
                    "manifest" to manifestMap,
                    "connection_mode" to if (isLoopback) "usb_adb" else "wifi_lan",
                    "transport_mode" to if (isLoopback) "usb_adb" else "wifi_lan"
                )
            ) { response ->
                if (!isCurrentGeneration(generation, socketRef)) {
                    log("Ignoring stale auth_request response for obsolete gen=$generation.")
                    return@sendRequestForGeneration
                }
                if (response.type == MessageType.RESPONSE && response.payload?.get("status") == "success") {
                    val data = (response.payload["data"] as? Map<*, *>) ?: response.payload
                    val authState = parseAuthenticatedState(data)
                    synchronized(this) {
                        if (generation != socketGeneration.get() || this.webSocket !== socketRef) {
                            log("Ignoring stale auth success immediately before state write (gen=$generation).")
                            return@sendRequestForGeneration
                        }
                        val canonicalPeerId = authState.peerDeviceId?.trim()?.takeIf { it.isNotBlank() }
                            ?: activeTargetDeviceId()
                        if (canonicalPeerId != null) {
                            resolvedTargetDeviceId = canonicalPeerId
                            (tokenStorage as? org.snow.security.SharedPreferencesTokenStorage)
                                ?.migrateLegacyTokenToDeviceIfKnown(canonicalPeerId)
                            (certPinStorage as? org.snow.security.EncryptedCertPinStorage)
                                ?.migrateLegacyPinToDeviceIfKnown(canonicalPeerId)
                            currentTrustManager?.lastPresentedFingerprint?.let { fp ->
                                if (certPinStorage?.getPinnedFingerprintForDevice(canonicalPeerId) == null) {
                                    certPinStorage?.pinFingerprintForDevice(canonicalPeerId, fp)
                                }
                            }
                            if (tokenStorage?.getTokenForDevice(canonicalPeerId) == null && !token.isNullOrBlank()) {
                                tokenStorage?.saveTokenForDevice(canonicalPeerId, token)
                            }
                        }
                        backoffPolicy.reset()
                        _authState.value = authState
                    }
                    log("Authenticated successfully with peer core [session=${authState.sessionId}, tier=${authState.trustTier}, profile=${authState.permissionProfile ?: "unset"}, type=${authState.peerDeviceType ?: "unknown"}]")
                } else {
                    val errCode = response.error?.code ?: ErrorCode.UNAUTHORIZED
                    val errMsg = response.error?.message ?: "Authentication rejected."
                    log("Authentication failed: $errMsg (code=$errCode)")

                    if (errCode == ErrorCode.DEVICE_NOT_FOUND) {
                        log("Server reported device not paired (revoked). Clearing token and disabling auto-reconnect.")
                        handleRemoteRevocation("Device pairing revoked on desktop host.", expectedGeneration = generation, expectedSocket = socketRef)
                    } else if (errCode == ErrorCode.UNAUTHORIZED && errMsg.startsWith("MANUAL_DISCONNECT", ignoreCase = true)) {
                        log("Host manually disconnected session; keeping pairing token intact and pausing auto-reconnect.")
                        val drained: List<PendingRequestEntry>
                        synchronized(this) {
                            if (generation != socketGeneration.get() || this.webSocket !== socketRef) return@sendRequestForGeneration
                            userInitiatedDisconnect.set(true)
                            drained = disconnectLocked(advanceGeneration = true)
                            backoffPolicy.reset()
                            _authState.value = AuthState.Disconnected
                            _connectionState.value = ConnectionState.DISCONNECTED
                        }
                        deliverPendingError(drained, "Manual disconnect by host.")
                    } else if (errCode == ErrorCode.UNAUTHORIZED) {
                        log("Stored token is invalid. Clearing stale token and awaiting user pairing...")
                        synchronized(this) {
                            if (generation != socketGeneration.get() || this.webSocket !== socketRef) return@sendRequestForGeneration
                            clearStoredTokenForActiveTarget()
                            _authState.value = AuthState.ConnectedUnauthenticated
                        }

                        // Immunize connection from timeout and register unauthenticated pending pairing
                        val manifestMap = DeviceNode.buildAndroidManifest(context).toMap()
                        val isLoopback = targetHost == "127.0.0.1" || targetHost == "localhost" || targetHost == "::1"
                        sendRequestForGeneration(
                            expectedGeneration = generation,
                            expectedSocket = socketRef,
                            action = "pair_request",
                            data = mapOf(
                                "device_id" to devId,
                                "device_name" to (identity?.deviceName ?: "Android-Device"),
                                "manifest" to manifestMap,
                                "connection_mode" to if (isLoopback) "usb_adb" else "wifi_lan",
                                "transport_mode" to if (isLoopback) "usb_adb" else "wifi_lan"
                            )
                        ) { pairResp ->
                            if (isCurrentGeneration(generation, socketRef)) {
                                log("Desktop pairing registration updated (status=${pairResp.payload?.get("status")})")
                            }
                        }
                    } else {
                        synchronized(this) {
                            if (generation == socketGeneration.get() && this.webSocket === socketRef) {
                                _authState.value = AuthState.AuthFailed(errMsg)
                            }
                        }
                    }
                }
            }
        } else {
            val shouldPair = synchronized(this) {
                if (generation != socketGeneration.get() || this.webSocket !== socketRef) {
                    false
                } else {
                    _authState.value = AuthState.ConnectedUnauthenticated
                    true
                }
            }
            if (!shouldPair) return
            log("Connected over WSS. Device is not paired; initializing pairing on desktop...")
            if (!devId.isNullOrBlank()) {
                val manifestMap = DeviceNode.buildAndroidManifest(context).toMap()
                val isLoopback = targetHost == "127.0.0.1" || targetHost == "localhost" || targetHost == "::1"
                sendRequestForGeneration(
                    expectedGeneration = generation,
                    expectedSocket = socketRef,
                    action = "pair_request",
                    data = mapOf(
                        "device_id" to devId,
                        "device_name" to (identity?.deviceName ?: "Android-Device"),
                        "manifest" to manifestMap,
                        "connection_mode" to if (isLoopback) "usb_adb" else "wifi_lan",
                        "transport_mode" to if (isLoopback) "usb_adb" else "wifi_lan"
                    )
                ) { response ->
                    if (isCurrentGeneration(generation, socketRef)) {
                        log("Desktop core pairing initialized (status=${response.payload?.get("status")})")
                    }
                }
            }
        }
    }

    internal fun handleRemoteRevocation(
        reason: String? = null,
        expectedGeneration: Long? = null,
        expectedSocket: WebSocket? = null
    ) {
        val drained: List<PendingRequestEntry>
        synchronized(this) {
            if (expectedGeneration != null && expectedGeneration != socketGeneration.get()) return
            if (expectedSocket != null && this.webSocket != null && this.webSocket !== expectedSocket) return
            clearStoredTokenForActiveTarget()
            userInitiatedDisconnect.set(true)
            drained = disconnectLocked(advanceGeneration = true)
            backoffPolicy.reset()
            _authState.value = AuthState.AuthFailed(reason ?: "Device access revoked by host.")
            _connectionState.value = ConnectionState.DISCONNECTED
        }
        deliverPendingError(drained, "Device access revoked by host.")
        onDeviceRevoked?.invoke(reason)
    }

    internal fun handleIncomingMessage(
        incomingSocket: WebSocket,
        rawText: String,
        expectedGeneration: Long? = null
    ) {
        // Guard against stale socket / obsolete generation deliveries
        synchronized(this) {
            val activeGen = socketGeneration.get()
            if (expectedGeneration != null) {
                if (expectedGeneration != activeGen || this.webSocket !== incomingSocket) {
                    log("Dropping incoming message from obsolete gen=$expectedGeneration (active=$activeGen).")
                    return
                }
            } else if (this.webSocket != null && this.webSocket !== incomingSocket) {
                log("Dropping incoming message from non-active socket.")
                return
            }
        }

        val capturedGeneration = expectedGeneration ?: socketGeneration.get()
        val message = try {
            ProtocolValidator.validateRawMessage(rawText)
        } catch (e: ProtocolValidationError) {
            log("Received invalid message: ${e.message}")
            if (e.correlationId != null && (expectedGeneration == null || isCurrentGeneration(capturedGeneration, incomingSocket))) {
                val err = SnowMessage.createError(
                    code = e.code,
                    message = e.message,
                    correlationId = e.correlationId
                )
                incomingSocket.send(JsonSerialization.toJson(err))
            }
            return
        }

        when (message.type) {
            MessageType.HEARTBEAT -> {
                if (expectedGeneration != null && !isCurrentGeneration(capturedGeneration, incomingSocket)) return
                log("Received heartbeat from server id=${message.id}. Sending ack.")
                val ack = SnowMessage.createHeartbeatAck(correlationId = message.id)
                incomingSocket.send(JsonSerialization.toJson(ack))
            }

            MessageType.HEARTBEAT_ACK -> {
                synchronized(this) {
                    if (expectedGeneration != null && (capturedGeneration != socketGeneration.get() || this.webSocket !== incomingSocket)) {
                        return
                    }
                    if (message.correlationId == pendingHeartbeatId) {
                        lastAckTimestamp = System.currentTimeMillis()
                        pendingHeartbeatId = null
                        missedHeartbeatAcks.set(0)
                        backoffPolicy.reset()
                        log("Received heartbeat_ack for ${message.correlationId}. Connection healthy.")
                    } else {
                        log("Received heartbeat_ack with unexpected correlation_id=${message.correlationId}")
                    }
                }
            }

            MessageType.RESPONSE -> {
                log("Received response id=${message.id} corr=${message.correlationId}")
                message.correlationId?.let { corrId ->
                    val entry = pendingRequests[corrId]
                    if (entry != null &&
                        (expectedGeneration == null || (entry.generation == capturedGeneration && isCurrentGeneration(capturedGeneration, incomingSocket)))
                    ) {
                        if (pendingRequests.remove(corrId, entry)) {
                            entry.callback.invoke(message)
                        }
                    }
                }
            }

            MessageType.ERROR -> {
                log("Received error from server: code=${message.error?.code} msg=${message.error?.message} corr=${message.correlationId}")
                message.correlationId?.let { corrId ->
                    val entry = pendingRequests[corrId]
                    if (entry != null &&
                        (expectedGeneration == null || (entry.generation == capturedGeneration && isCurrentGeneration(capturedGeneration, incomingSocket)))
                    ) {
                        if (pendingRequests.remove(corrId, entry)) {
                            entry.callback.invoke(message)
                        }
                    }
                }
            }

            MessageType.REQUEST -> {
                val action = message.payload?.get("action") as? String
                val data = message.payload?.get("data") as? Map<String, Any?>
                log("Received request from server action='$action' id=${message.id}")
                if (action == "device_revoked") {
                    val reason = (data?.get("reason") as? String) ?: "Device revoked by desktop host."
                    log("Received device_revoked from server: $reason")
                    val ackResp = SnowMessage.createResponse(
                        correlationId = message.id,
                        payload = mapOf("status" to "success", "action" to "device_revoked", "acknowledged" to true)
                    )
                    try {
                        incomingSocket.send(JsonSerialization.toJson(ackResp))
                    } catch (_: Exception) {}
                    handleRemoteRevocation(
                        reason = reason,
                        expectedGeneration = expectedGeneration,
                        expectedSocket = if (expectedGeneration != null) incomingSocket else null
                    )
                } else if (action == "session_disconnect") {
                    val reason = (data?.get("reason") as? String) ?: "Disconnected by desktop host."
                    log("Received session_disconnect from server: $reason")
                    val ackResp = SnowMessage.createResponse(
                        correlationId = message.id,
                        payload = mapOf("status" to "success", "action" to "session_disconnect", "acknowledged" to true)
                    )
                    try {
                        incomingSocket.send(JsonSerialization.toJson(ackResp))
                    } catch (_: Exception) {}
                    val drained = synchronized(this) {
                        if (expectedGeneration != null && (capturedGeneration != socketGeneration.get() || this.webSocket !== incomingSocket)) {
                            return
                        }
                        userInitiatedDisconnect.set(true)
                        val pending = disconnectLocked(advanceGeneration = true)
                        backoffPolicy.reset()
                        _authState.value = AuthState.Disconnected
                        _connectionState.value = ConnectionState.DISCONNECTED
                        pending
                    }
                    deliverPendingError(drained, "Disconnected by desktop host.")
                } else if (action == "ping") {
                    if (expectedGeneration != null && !isCurrentGeneration(capturedGeneration, incomingSocket)) return
                    val respPayload = mapOf<String, Any?>(
                        "status" to "success",
                        "action" to "pong"
                    )
                    val response = SnowMessage.createResponse(
                        correlationId = message.id,
                        payload = respPayload
                    )
                    incomingSocket.send(JsonSerialization.toJson(response))
                    log("Replied to ping request with status 'success', action 'pong'")
                } else if (action != null && requestDispatcher != null) {
                    scope.launch {
                        val (respPayload, error) = try {
                            requestDispatcher?.invoke(action, data)
                                ?: Pair(null, SnowError(ErrorCode.UNSUPPORTED_ACTION, "No request dispatcher registered."))
                        } catch (e: Exception) {
                            Pair(null, SnowError(ErrorCode.INTERNAL_ERROR, "Error handling action '$action': ${e.message}"))
                        }
                        if (!isActive || (expectedGeneration != null && !isCurrentGeneration(capturedGeneration, incomingSocket))) {
                            return@launch
                        }
                        if (error != null) {
                            val errMessage = SnowMessage.createError(
                                code = error.code,
                                message = error.message,
                                correlationId = message.id
                            )
                            incomingSocket.send(JsonSerialization.toJson(errMessage))
                            log("Replied to request id=${message.id} with error: ${error.code} - ${error.message}")
                        } else {
                            val response = SnowMessage.createResponse(
                                correlationId = message.id,
                                payload = respPayload ?: emptyMap()
                            )
                            incomingSocket.send(JsonSerialization.toJson(response))
                            log("Replied to request id=${message.id} with success")
                        }
                    }
                } else {
                    if (expectedGeneration != null && !isCurrentGeneration(capturedGeneration, incomingSocket)) return
                    val err = SnowMessage.createError(
                        code = ErrorCode.UNSUPPORTED_ACTION,
                        message = "Unsupported action '$action' on Android client.",
                        correlationId = message.id
                    )
                    incomingSocket.send(JsonSerialization.toJson(err))
                }
            }
        }
    }
}
