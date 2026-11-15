package org.snow.network

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
import org.snow.protocol.SnowMessage
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * WebSocket client implementing SNOW Device Protocol v1 with single connection lifecycle,
 * exponential backoff reconnection, and application-level heartbeats.
 */
class SnowWebSocketClient(
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    private val backoffPolicy: BackoffPolicy = BackoffPolicy()
) {
    private val okHttpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS) // WebSocket requires no read timeout
        .pingInterval(0, TimeUnit.SECONDS) // Use application-level heartbeats
        .build()

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

    private val _logs = MutableSharedFlow<String>(replay = 50, extraBufferCapacity = 100)
    val logs: SharedFlow<String> = _logs.asSharedFlow()

    private val pendingRequests = ConcurrentHashMap<String, (SnowMessage) -> Unit>()

    private fun log(message: String) {
        val entry = "[${SnowMessage.currentIsoTimestamp()}] $message"
        _logs.tryEmit(entry)
    }

    /**
     * Connect to the desktop SNOW core server at ws://host:port.
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

    private fun initiateConnection() {
        val wsUrl = "ws://$targetHost:$targetPort"
        log("Connecting to $wsUrl ...")
        _connectionState.value = ConnectionState.CONNECTING

        val request = Request.Builder()
            .url(wsUrl)
            .build()

        webSocket = okHttpClient.newWebSocket(request, SnowListener())
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
        log("Client disconnected by user.")
    }

    private fun disconnectInternal() {
        heartbeatJob?.cancel()
        heartbeatJob = null
        reconnectJob?.cancel()
        reconnectJob = null

        try {
            webSocket?.close(1000, "User disconnect")
        } catch (e: Exception) {
            webSocket?.cancel()
        }
        webSocket = null
        pendingRequests.clear()
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
        }
    }

    /**
     * Send a raw SnowMessage directly.
     */
    fun sendMessage(message: SnowMessage): Boolean {
        val currentWs = webSocket
        if (currentWs == null) return false
        val json = JsonSerialization.toJson(message)
        return currentWs.send(json)
    }

    private fun scheduleReconnection() {
        if (userInitiatedDisconnect.get()) return

        _connectionState.value = ConnectionState.RECONNECTING
        val delayMs = backoffPolicy.nextDelayMs()
        log("Reconnecting in ${delayMs}ms (attempt #${backoffPolicy.currentAttempt}) ...")

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
            log("Connected to ws://$targetHost:$targetPort")
            lastAckTimestamp = System.currentTimeMillis()
            startHeartbeatLoop()
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            handleIncomingMessage(webSocket, text)
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            log("Server closing connection: $code - $reason")
            webSocket.close(code, reason)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            log("Connection closed: $code - $reason")
            heartbeatJob?.cancel()
            if (!userInitiatedDisconnect.get()) {
                scheduleReconnection()
            } else {
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            log("Connection error: ${t.message ?: t.javaClass.simpleName}")
            heartbeatJob?.cancel()
            if (!userInitiatedDisconnect.get()) {
                scheduleReconnection()
            } else {
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }
    }

    private fun handleIncomingMessage(incomingSocket: WebSocket, rawText: String) {
        val message = try {
            ProtocolValidator.validateRawMessage(rawText)
        } catch (e: ProtocolValidationError) {
            log("Received invalid message: ${e.message}")
            // Reply with error if correlation_id is present
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
                // Respond with heartbeat_ack
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
