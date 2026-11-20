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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Authentication and authorization states for the SNOW connection lifecycle.
 */
sealed class AuthState {
    object Disconnected : AuthState()
    object Connecting : AuthState()
    object ConnectedUnauthenticated : AuthState()
    data class Authenticated(val sessionId: String, val trustTier: String = "peer") : AuthState()
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
    private val backoffPolicy: BackoffPolicy = BackoffPolicy(),
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
    }

    private var webSocket: WebSocket? = null
    private var reconnectJob: Job? = null
    private var heartbeatJob: Job? = null

    private var targetHost: String = ""
    private var targetPort: Int = Constants.DEFAULT_PORT

    private val userInitiatedDisconnect = AtomicBoolean(false)
    private var pendingHeartbeatId: String? = null
    private var lastAckTimestamp: Long = 0L

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _authState = MutableStateFlow<AuthState>(AuthState.Disconnected)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    fun setAuthenticated(sessionId: String) {
        _authState.value = AuthState.Authenticated(sessionId)
    }

    private val _logs = MutableSharedFlow<String>(replay = 50, extraBufferCapacity = 100)
    val logs: SharedFlow<String> = _logs.asSharedFlow()

    private val pendingRequests = ConcurrentHashMap<String, (SnowMessage) -> Unit>()
    private var currentTrustManager: SnowTrustManager? = null

    var requestDispatcher: (suspend (action: String, data: Map<String, Any?>?) -> Pair<Map<String, Any?>?, SnowError?>)? = null
    val currentTargetHost: String get() = targetHost
    val currentTargetPort: Int get() = targetPort

    private fun log(message: String) {
        val entry = "[${SnowMessage.currentIsoTimestamp()}] $message"
        _logs.tryEmit(entry)
    }

    /**
     * Explicitly confirm and pin a server certificate SHA-256 fingerprint (Trust-On-First-Use).
     *
     * Saves the verified fingerprint to encrypted storage and immediately triggers connection.
     */
    fun confirmAndPinCertificate(fingerprint: String) {
        val normalized = TlsConfig.formatFingerprint(fingerprint)
        certPinStorage?.pinFingerprint(normalized)
        log("Certificate pinned: $normalized. Reconnecting...")
        backoffPolicy.reset()
        if (targetHost.isNotBlank()) {
            initiateConnection()
        }
    }

    /**
     * Clear the pinned certificate fingerprint (trust reset / certificate rotation).
     */
    fun resetCertificateTrust() {
        certPinStorage?.clearPinnedFingerprint()
        log("Certificate trust reset. Next connection will require re-confirmation.")
    }

    /**
     * Connect to the desktop SNOW core server at wss://host:port (or ws:// if useTls is false).
     */
    @Synchronized
    fun connect(host: String, port: Int = Constants.DEFAULT_PORT) {
        targetHost = host.trim()
        targetPort = port
        userInitiatedDisconnect.set(false)

        if (_connectionState.value == ConnectionState.CONNECTED || _connectionState.value == ConnectionState.CONNECTING) {
            log("Already connected or connecting. Disconnecting prior session first.")
            disconnectInternal()
        }

        reconnectJob?.cancel()
        reconnectJob = null

        initiateConnection()
    }

    /**
     * Update target endpoint dynamically (e.g. from LAN discovery beacon).
     *
     * Triggers immediate reconnection if host/port changed or if in RECONNECTING/DISCONNECTED
     * state without creating connection storms.
     *
     * @return True if a reconnection or connection attempt was initiated; False if no-op.
     */
    @Synchronized
    fun updateTargetEndpoint(host: String, port: Int = Constants.DEFAULT_PORT): Boolean {
        val cleanHost = host.trim()
        if (cleanHost.isBlank()) return false

        val endpointChanged = cleanHost != targetHost || port != targetPort
        val currentState = _connectionState.value

        if (endpointChanged) {
            log("Target endpoint changed from $targetHost:$targetPort to $cleanHost:$port. Initiating reconnect...")
            targetHost = cleanHost
            targetPort = port
            userInitiatedDisconnect.set(false)
            backoffPolicy.reset()
            reconnectJob?.cancel()
            reconnectJob = null
            disconnectInternal()
            initiateConnection()
            return true
        }

        // Endpoint is identical. Avoid reconnect storms if already CONNECTED or CONNECTING.
        if (currentState == ConnectionState.CONNECTED || currentState == ConnectionState.CONNECTING) {
            return false
        }

        // If RECONNECTING or DISCONNECTED (and not explicitly user-stopped), fast-reconnect.
        if (!userInitiatedDisconnect.get()) {
            log("Target endpoint confirmed ($cleanHost:$port) while state=$currentState. Accelerating reconnect...")
            backoffPolicy.reset()
            reconnectJob?.cancel()
            reconnectJob = null
            initiateConnection()
            return true
        }

        return false
    }

    private fun buildOkHttpClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .pingInterval(0, TimeUnit.SECONDS)

        if (useTls) {
            val storage = certPinStorage ?: InMemoryCertPinStorage()
            val trustManager = SnowTrustManager(
                pinStorage = storage,
                onUnconfirmedFingerprint = { fp ->
                    _authState.value = AuthState.FingerprintConfirmationRequired(fp)
                    onUnconfirmedFingerprint?.invoke(fp)
                }
            )
            currentTrustManager = trustManager
            val sslContext = TlsConfig.createSslContext(trustManager)
            builder.sslSocketFactory(sslContext.socketFactory, trustManager)
            builder.hostnameVerifier(TlsConfig.createHostnameVerifier(storage))
        }

        return builder.build()
    }

    @Synchronized
    private fun initiateConnection() {
        if (userInitiatedDisconnect.get()) return
        if (_connectionState.value == ConnectionState.CONNECTED && webSocket != null) {
            log("Already connected to desktop core. Skipping redundant initiateConnection().")
            return
        }

        // Clean up previous socket instance before opening a new one to prevent connection leaks
        try {
            webSocket?.close(1000, "Opening new connection")
        } catch (_: Exception) {
            webSocket?.cancel()
        }
        webSocket = null

        val scheme = if (useTls) "wss" else "ws"
        val wsUrl = "$scheme://$targetHost:$targetPort"
        log("Connecting to $wsUrl ...")
        _connectionState.value = ConnectionState.CONNECTING
        _authState.value = AuthState.Connecting

        val request = Request.Builder()
            .url(wsUrl)
            .build()

        val client = buildOkHttpClient()
        webSocket = client.newWebSocket(request, SnowListener())
    }

    private fun failPendingRequests(errorMessage: String) {
        if (pendingRequests.isEmpty()) return
        val errResponse = SnowMessage.createError(
            code = ErrorCode.INTERNAL_ERROR,
            message = errorMessage
        )
        val callbacks = pendingRequests.values.toList()
        pendingRequests.clear()
        for (cb in callbacks) {
            try {
                cb.invoke(errResponse)
            } catch (e: Exception) {
                SafeLog.e(TAG, "Error notifying pending request callback: ${e.message}", e)
            }
        }
    }

    /**
     * Gracefully disconnect the client and prevent automatic reconnection.
     */
    @Synchronized
    fun disconnect() {
        userInitiatedDisconnect.set(true)
        disconnectInternal()
        backoffPolicy.reset()
        _connectionState.value = ConnectionState.DISCONNECTED
        _authState.value = AuthState.Disconnected
        log("Client disconnected by user.")
    }

    private fun disconnectInternal() {
        heartbeatJob?.cancel()
        heartbeatJob = null
        reconnectJob?.cancel()
        reconnectJob = null

        try {
            webSocket?.close(1000, "User disconnect")
        } catch (_: Exception) {
            webSocket?.cancel()
        }
        webSocket = null
        failPendingRequests("Client disconnected.")
        pendingHeartbeatId = null
    }

    /**
     * Send a request action to the server.
     */
    fun sendRequest(
        action: String,
        data: Map<String, Any?>? = null,
        onResponse: ((SnowMessage) -> Unit)? = null
    ) {
        val currentWs = webSocket
        if (_connectionState.value != ConnectionState.CONNECTED || currentWs == null) {
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
        if (onResponse != null) {
            pendingRequests[requestMessage.id] = onResponse
        }

        val json = JsonSerialization.toJson(requestMessage)
        val sent = currentWs.send(json)
        if (sent) {
            log("Sent request action='$action' id=${requestMessage.id}")
        } else {
            log("Failed to send request id=${requestMessage.id}")
            pendingRequests.remove(requestMessage.id)
            onResponse?.invoke(
                SnowMessage.createError(
                    code = ErrorCode.INTERNAL_ERROR,
                    message = "Failed to send WebSocket frame to desktop."
                )
            )
        }
    }

    /**
     * Send a raw SnowMessage directly.
     */
    fun sendMessage(message: SnowMessage): Boolean {
        val currentWs = webSocket ?: return false
        val json = JsonSerialization.toJson(message)
        return currentWs.send(json)
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

    private fun scheduleReconnection() {
        if (userInitiatedDisconnect.get()) return

        // If the failure was due to an unconfirmed certificate or fingerprint mismatch,
        // do not hammer the server with rapid auto-reconnects until user acts
        val currentAuth = _authState.value
        if (currentAuth is AuthState.FingerprintConfirmationRequired ||
            currentAuth is AuthState.FingerprintMismatch
        ) {
            log("Auto-reconnection paused awaiting certificate verification.")
            return
        }

        if (backoffPolicy.currentAttempt >= MAX_CONNECT_RETRIES) {
            log("Maximum connection retries ($MAX_CONNECT_RETRIES) reached. Stopping auto-reconnect.")
            _connectionState.value = ConnectionState.DISCONNECTED
            _authState.value = AuthState.AuthFailed("Connection retry limit reached ($MAX_CONNECT_RETRIES attempts).")
            reconnectJob?.cancel()
            reconnectJob = null
            return
        }

        _connectionState.value = ConnectionState.RECONNECTING
        val delayMs = backoffPolicy.nextDelayMs()
        log("Reconnecting in ${delayMs}ms (attempt #${backoffPolicy.currentAttempt}/$MAX_CONNECT_RETRIES) ...")

        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            delay(delayMs)
            if (!userInitiatedDisconnect.get() && isActive) {
                initiateConnection()
            }
        }
    }

    private fun startHeartbeatLoop() {
        heartbeatJob?.cancel()
        lastAckTimestamp = System.currentTimeMillis()
        pendingHeartbeatId = null

        heartbeatJob = scope.launch {
            while (isActive && _connectionState.value == ConnectionState.CONNECTED) {
                delay(Constants.HEARTBEAT_INTERVAL_MS)
                if (!isActive) break

                val now = System.currentTimeMillis()
                if (now - lastAckTimestamp > Constants.HEARTBEAT_TIMEOUT_MS) {
                    log("Heartbeat timeout! Server did not acknowledge within ${Constants.HEARTBEAT_TIMEOUT_MS}ms.")
                    webSocket?.cancel()
                    scheduleReconnection()
                    break
                }

                val heartbeat = SnowMessage.createHeartbeat()
                pendingHeartbeatId = heartbeat.id
                val json = JsonSerialization.toJson(heartbeat)
                val sent = webSocket?.send(json) == true
                if (sent) {
                    log("Heartbeat sent id=${heartbeat.id}")
                }
            }
        }
    }

    private inner class SnowListener : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            if (userInitiatedDisconnect.get()) {
                webSocket.close(1000, "Disconnected")
                return
            }

            _connectionState.value = ConnectionState.CONNECTED
            backoffPolicy.reset()
            val scheme = if (useTls) "wss" else "ws"
            log("Connected to $scheme://$targetHost:$targetPort")
            lastAckTimestamp = System.currentTimeMillis()
            startHeartbeatLoop()

            // Automatic post-connection authentication handshake
            performPostConnectionHandshake()
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            handleIncomingMessage(webSocket, text)
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            log("Server closing connection: $code - $reason")
            webSocket.close(code, reason)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            if (this@SnowWebSocketClient.webSocket !== webSocket) {
                log("Ignoring onClosed from stale socket (code=$code).")
                return
            }
            log("Connection closed: $code - $reason")
            heartbeatJob?.cancel()
            _authState.value = AuthState.Disconnected
            failPendingRequests("Connection closed ($code: $reason)")
            this@SnowWebSocketClient.webSocket = null
            if (!userInitiatedDisconnect.get()) {
                scheduleReconnection()
            } else {
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            if (this@SnowWebSocketClient.webSocket !== webSocket) {
                log("Ignoring onFailure from stale socket: ${t.message}")
                return
            }
            heartbeatJob?.cancel()
            failPendingRequests("Connection failed: ${t.message}")
            this@SnowWebSocketClient.webSocket = null

            // 1. Check for specific TLS certificate verification exceptions in cause chain
            var certException: Throwable? = t
            while (certException != null) {
                if (certException is UnconfirmedCertificateException) {
                    val fp = certException.presentedFingerprint
                    _authState.value = AuthState.FingerprintConfirmationRequired(fp)
                    onUnconfirmedFingerprint?.invoke(fp)
                    log("Server certificate not yet confirmed by user. Fingerprint: $fp")
                    _connectionState.value = ConnectionState.DISCONNECTED
                    currentTrustManager?.resetLastPresentedFingerprint()
                    return
                }
                if (certException is CertificateMismatchException) {
                    val pinned = certException.pinnedFingerprint
                    val presented = certException.presentedFingerprint
                    _authState.value = AuthState.FingerprintMismatch(pinned, presented)
                    onCertificateMismatch?.invoke(pinned, presented)
                    log("Untrusted server certificate! Mismatch detected. Pinned: $pinned, Presented: $presented")
                    _connectionState.value = ConnectionState.DISCONNECTED
                    currentTrustManager?.resetLastPresentedFingerprint()
                    return
                }
                certException = certException.cause
            }

            // 2. Fallback check: If Conscrypt wrapped or stripped the custom exception,
            // check currentTrustManager's lastPresentedFingerprint against pinned storage.
            val trustMgr = currentTrustManager
            val storage = certPinStorage ?: InMemoryCertPinStorage()
            val presentedFp = trustMgr?.lastPresentedFingerprint
            val pinnedFp = storage.getPinnedFingerprint()

            if (presentedFp != null) {
                if (pinnedFp == null) {
                    _authState.value = AuthState.FingerprintConfirmationRequired(presentedFp)
                    onUnconfirmedFingerprint?.invoke(presentedFp)
                    log("Server certificate not yet confirmed by user (via trust manager). Fingerprint: $presentedFp")
                    _connectionState.value = ConnectionState.DISCONNECTED
                    trustMgr.resetLastPresentedFingerprint()
                    return
                } else if (!TlsConfig.fingerprintsMatch(pinnedFp, presentedFp)) {
                    _authState.value = AuthState.FingerprintMismatch(pinnedFp, presentedFp)
                    onCertificateMismatch?.invoke(pinnedFp, presentedFp)
                    log("Untrusted server certificate! Mismatch detected. Pinned: $pinnedFp, Presented: $presentedFp")
                    _connectionState.value = ConnectionState.DISCONNECTED
                    trustMgr.resetLastPresentedFingerprint()
                    return
                }
            }

            log("Connection error: ${t.message ?: t.javaClass.simpleName}")
            _authState.value = AuthState.Disconnected
            if (!userInitiatedDisconnect.get()) {
                scheduleReconnection()
            } else {
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }
    }

    private fun performPostConnectionHandshake() {
        val devId = identity?.deviceId
        val token = tokenStorage?.getToken()

        if (!devId.isNullOrBlank() && !token.isNullOrBlank()) {
            log("Initiating automatic authentication handshake (device_id=${devId.take(8)}...)...")
            val manifestMap = DeviceNode.buildAndroidManifest(context).toMap()
            val isLoopback = targetHost == "127.0.0.1" || targetHost == "localhost" || targetHost == "::1"
            sendRequest(
                action = "auth_request",
                data = mapOf(
                    "device_id" to devId,
                    "auth_token" to token,
                    "manifest" to manifestMap,
                    "connection_mode" to if (isLoopback) "usb_adb" else "wifi_lan",
                    "transport_mode" to if (isLoopback) "usb_adb" else "wifi_lan"
                )
            ) { response ->
                if (response.type == MessageType.RESPONSE && response.payload?.get("status") == "success") {
                    val data = response.payload["data"] as? Map<*, *>
                    val sessionId = data?.get("session_id") as? String ?: "active"
                    val trustTier = data?.get("trust_tier") as? String ?: "peer"
                    _authState.value = AuthState.Authenticated(sessionId, trustTier)
                    log("Authenticated successfully with desktop core [session=$sessionId, tier=$trustTier]")
                } else {
                    val errCode = response.error?.code ?: ErrorCode.UNAUTHORIZED
                    val errMsg = response.error?.message ?: "Authentication rejected."
                    log("Authentication failed: $errMsg (code=$errCode)")

                    if (errCode == ErrorCode.UNAUTHORIZED || errCode == ErrorCode.DEVICE_NOT_FOUND) {
                        log("Stored token is invalid or revoked. Clearing stale token and prompting PIN pairing...")
                        tokenStorage?.clearToken()
                        _authState.value = AuthState.ConnectedUnauthenticated

                        // Immunize connection from timeout and register unauthenticated pending pairing
                        val manifestMap = DeviceNode.buildAndroidManifest(context).toMap()
                        val isLoopback = targetHost == "127.0.0.1" || targetHost == "localhost" || targetHost == "::1"
                        sendRequest(
                            action = "pair_request",
                            data = mapOf(
                                "device_id" to devId,
                                "device_name" to (identity?.deviceName ?: "Android-Device"),
                                "manifest" to manifestMap,
                                "connection_mode" to if (isLoopback) "usb_adb" else "wifi_lan",
                                "transport_mode" to if (isLoopback) "usb_adb" else "wifi_lan"
                            )
                        ) { pairResp ->
                            log("Desktop pairing registration updated (status=${pairResp.payload?.get("status")})")
                        }
                    } else {
                        _authState.value = AuthState.AuthFailed(errMsg)
                    }
                }
            }
        } else {
            _authState.value = AuthState.ConnectedUnauthenticated
            log("Connected over WSS. Device is not paired; initializing pairing on desktop...")
            if (!devId.isNullOrBlank()) {
                // Immunize connection from handshake timeout and register with desktop pairing manager
                val manifestMap = DeviceNode.buildAndroidManifest(context).toMap()
                val isLoopback = targetHost == "127.0.0.1" || targetHost == "localhost" || targetHost == "::1"
                sendRequest(
                    action = "pair_request",
                    data = mapOf(
                        "device_id" to devId,
                        "device_name" to (identity?.deviceName ?: "Android-Device"),
                        "manifest" to manifestMap,
                        "connection_mode" to if (isLoopback) "usb_adb" else "wifi_lan",
                        "transport_mode" to if (isLoopback) "usb_adb" else "wifi_lan"
                    )
                ) { response ->
                    log("Desktop core pairing initialized (status=${response.payload?.get("status")})")
                }
            }
        }
    }

    private fun handleIncomingMessage(incomingSocket: WebSocket, rawText: String) {
        val message = try {
            ProtocolValidator.validateRawMessage(rawText)
        } catch (e: ProtocolValidationError) {
            log("Received invalid message: ${e.message}")
            if (e.correlationId != null) {
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
                log("Received heartbeat from server id=${message.id}. Sending ack.")
                val ack = SnowMessage.createHeartbeatAck(correlationId = message.id)
                incomingSocket.send(JsonSerialization.toJson(ack))
            }

            MessageType.HEARTBEAT_ACK -> {
                if (message.correlationId == pendingHeartbeatId) {
                    lastAckTimestamp = System.currentTimeMillis()
                    pendingHeartbeatId = null
                    backoffPolicy.reset()
                    log("Received heartbeat_ack for ${message.correlationId}. Connection healthy.")
                } else {
                    log("Received heartbeat_ack with unexpected correlation_id=${message.correlationId}")
                }
            }

            MessageType.RESPONSE -> {
                log("Received response id=${message.id} corr=${message.correlationId}")
                message.correlationId?.let { corrId ->
                    val callback = pendingRequests.remove(corrId)
                    callback?.invoke(message)
                }
            }

            MessageType.ERROR -> {
                log("Received error from server: code=${message.error?.code} msg=${message.error?.message} corr=${message.correlationId}")
                message.correlationId?.let { corrId ->
                    val callback = pendingRequests.remove(corrId)
                    callback?.invoke(message)
                }
            }

            MessageType.REQUEST -> {
                val action = message.payload?.get("action") as? String
                val data = message.payload?.get("data") as? Map<String, Any?>
                log("Received request from server action='$action' id=${message.id}")
                if (action == "ping") {
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
