package org.snow.network

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.java_websocket.WebSocket
import org.java_websocket.handshake.ClientHandshake
import org.java_websocket.server.DefaultSSLWebSocketServerFactory
import org.java_websocket.server.WebSocketServer
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.protocol.ErrorCode
import org.snow.protocol.JsonSerialization
import org.snow.protocol.MessageType
import org.snow.protocol.SnowError
import org.snow.protocol.SnowMessage
import org.snow.security.SafeLog
import org.snow.security.TokenStorage
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext

/**
 * Lightweight RFC 6455 WebSocket peer host server for Android-to-Android and Python-to-Android peer mesh.
 *
 * Security & Lifecycle Invariants:
 * 1. Runs exclusively in the foreground under user control and active Foreground Service.
 * 2. Never acts as a permanent background listener.
 * 3. Requires valid token-based peer authentication before executing capability requests.
 * 4. Dispatches all operations through [AndroidCapabilityDispatcher], strictly enforcing
 *    Android 17 OS execution contracts (BACKGROUND_SAFE vs FOREGROUND_USER_INTERACTION_REQUIRED).
 * 5. Bounded memory and frame sizes (max 64KB per frame).
 * 6. Supports TLS 1.2+ via [DefaultSSLWebSocketServerFactory].
 */
class AndroidPeerHostServer(
    val requestedPort: Int = 8767,
    private val tokenStorage: TokenStorage,
    private val dispatcher: AndroidCapabilityDispatcher,
    private val localDeviceId: String,
    private val manifestProvider: () -> Map<String, Any?> = { emptyMap() },
    private val peerTokenValidator: ((String) -> Boolean)? = null,
    private val pinVerifier: ((String) -> Boolean)? = null,
    private val parentScope: CoroutineScope? = null,
    private val sslContext: SSLContext? = null,
    private val handshakeTokenVerifier: ((String, String?) -> Boolean)? = null,
    private val hostSnowId: String? = null,
    private val hostNetworkId: String? = null
) {
    companion object {
        private const val TAG = "AndroidPeerHostServer"
        const val MAX_FRAME_SIZE = 65536
    }

    private data class PeerSession(
        var isAuthenticated: Boolean = false,
        var peerDeviceId: String? = null,
        var sessionId: String? = null
    )

    private val isRunning = AtomicBoolean(false)
    private var wsServer: WebSocketServer? = null
    private val serverScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    var boundPort: Int = requestedPort
        private set

    /**
     * Start listening for incoming peer connections on the requested port using RFC 6455 WebSocket protocol.
     */
    @Synchronized
    fun start(): Boolean {
        if (isRunning.get()) {
            SafeLog.i(TAG, "AndroidPeerHostServer is already running on port $boundPort")
            return true
        }

        if (sslContext == null) {
            SafeLog.e(TAG, "Cannot start AndroidPeerHostServer without SSLContext: mandatory TLS is enforced.")
            return false
        }

        return try {
            val startLatch = CountDownLatch(1)
            val address = InetSocketAddress(requestedPort)
            val server = object : WebSocketServer(address) {
                override fun onStart() {
                    startLatch.countDown()
                    SafeLog.i(TAG, "WebSocket peer host listening on port $boundPort")
                }

                override fun onOpen(conn: WebSocket, handshake: ClientHandshake) {
                    conn.setAttachment(PeerSession())
                    SafeLog.i(TAG, "Inbound peer WebSocket connection opened: ${conn.remoteSocketAddress}")
                }

                override fun onClose(conn: WebSocket, code: Int, reason: String, remote: Boolean) {
                    SafeLog.i(TAG, "Peer WebSocket closed: code=$code reason=$reason remote=$remote")
                }

                override fun onMessage(conn: WebSocket, message: String) {
                    handleIncomingMessage(conn, message)
                }

                override fun onError(conn: WebSocket?, ex: Exception?) {
                    SafeLog.w(TAG, "WebSocket peer host error: ${ex?.message}")
                }
            }

            server.isReuseAddr = true
            server.maxPendingConnections = 10
            if (sslContext != null) {
                server.setWebSocketFactory(DefaultSSLWebSocketServerFactory(sslContext))
            }

            server.start()

            // Wait until onStart() has fired and server socket is bound
            val started = startLatch.await(2000, TimeUnit.MILLISECONDS)
            if (!started) {
                SafeLog.w(TAG, "AndroidPeerHostServer startLatch timed out waiting for onStart on port $requestedPort")
            }

            boundPort = if (server.port > 0) server.port else requestedPort
            wsServer = server
            isRunning.set(true)
            SafeLog.i(TAG, "AndroidPeerHostServer started on port $boundPort")
            true
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed to start AndroidPeerHostServer on port $requestedPort: ${e.message}", e)
            stop()
            false
        }
    }

    /**
     * Stop the WebSocket server and disconnect all active peer sessions cleanly.
     */
    @Synchronized
    fun stop() {
        if (!isRunning.getAndSet(false)) {
            return
        }
        SafeLog.i(TAG, "Stopping AndroidPeerHostServer on port $boundPort...")
        try {
            wsServer?.stop()
        } catch (e: Exception) {
            SafeLog.w(TAG, "Error stopping WebSocketServer: ${e.message}")
        }
        wsServer = null
        SafeLog.i(TAG, "AndroidPeerHostServer stopped cleanly.")
    }

    fun isListening(): Boolean = isRunning.get() && wsServer != null

    fun getActiveConnectionCount(): Int = wsServer?.connections?.size ?: 0

    private fun handleIncomingMessage(conn: WebSocket, rawMessage: String) {
        if (rawMessage.length > MAX_FRAME_SIZE) {
            val err = SnowMessage.createError(
                code = ErrorCode.OVERSIZED_MESSAGE,
                message = "Message exceeds maximum size of $MAX_FRAME_SIZE bytes."
            )
            conn.send(JsonSerialization.toJson(err))
            conn.close(1009, "Message too big")
            return
        }

        val message = try {
            JsonSerialization.fromJson(rawMessage)
        } catch (pe: Exception) {
            val err = SnowMessage.createError(
                code = ErrorCode.INVALID_JSON,
                message = "Malformed JSON message: ${pe.message}"
            )
            conn.send(JsonSerialization.toJson(err))
            return
        }

        val session = conn.getAttachment<PeerSession>() ?: PeerSession().also { conn.setAttachment(it) }

        if (message.type == MessageType.HEARTBEAT) {
            val ack = SnowMessage.createHeartbeatAck(correlationId = message.id)
            conn.send(JsonSerialization.toJson(ack))
            return
        }

        if (message.type != MessageType.REQUEST) {
            return
        }

        val action = message.payload?.get("action") as? String
        @Suppress("UNCHECKED_CAST")
        val data = message.payload?.get("data") as? Map<String, Any?> ?: emptyMap()

        if (action == "pair_request") {
            val rawHandshakeToken = data["handshake_token"] as? String
            val presentedNetworkId = (data["network_id"] as? String)?.trim()?.uppercase()
            val pin = (data["pin"] as? String) ?: (data["pairing_pin"] as? String)
            val peerId = (data["device_id"] as? String)?.trim()

            if (peerId.isNullOrBlank()) {
                val err = SnowMessage.createError(
                    code = ErrorCode.INVALID_PAYLOAD,
                    message = "Missing valid device_id in pairing request.",
                    correlationId = message.id
                )
                conn.send(JsonSerialization.toJson(err))
                conn.close(1008, "Invalid pairing request")
                return
            }

            // Mutual exclusion matching Desktop Core: when handshake_token is supplied, verify ONLY it.
            val isAuthorized = if (rawHandshakeToken != null) {
                handshakeTokenVerifier?.invoke(rawHandshakeToken, presentedNetworkId) == true
            } else {
                pin != null && pinVerifier != null && pinVerifier.invoke(pin)
            }

            if (isAuthorized) {
                val newToken = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "")
                tokenStorage.saveTokenForDevice(peerId, newToken)
                val newSessionId = UUID.randomUUID().toString()
                session.isAuthenticated = true
                session.peerDeviceId = peerId
                session.sessionId = newSessionId

                val respPayload = mutableMapOf<String, Any?>(
                    "status" to "success",
                    "action" to "pair_response",
                    "session_id" to newSessionId,
                    "device_id" to localDeviceId,
                    "server_device_id" to localDeviceId,
                    "device_type" to "android",
                    "device_name" to (android.os.Build.MODEL ?: "Android Peer"),
                    "auth_token" to newToken,
                    "permission_profile" to dispatcher.activePermissionProfile,
                    "manifest" to manifestProvider()
                )
                if (!hostSnowId.isNullOrBlank()) respPayload["snow_id"] = hostSnowId
                if (!hostNetworkId.isNullOrBlank()) respPayload["network_id"] = hostNetworkId

                val resp = SnowMessage.createResponse(
                    correlationId = message.id,
                    payload = respPayload
                )
                conn.send(JsonSerialization.toJson(resp))
                SafeLog.i(TAG, "Peer paired (${if (rawHandshakeToken != null) "QR handshake" else "PIN"}): device_id=$peerId session=$newSessionId")
            } else {
                val errCode = if (rawHandshakeToken != null) ErrorCode.UNAUTHORIZED else ErrorCode.UNAUTHORIZED
                val errMsg = if (rawHandshakeToken != null) {
                    "Invalid, expired, or already used QR handshake token."
                } else {
                    "Invalid or expired pairing PIN."
                }
                val err = SnowMessage.createError(
                    code = errCode,
                    message = errMsg,
                    correlationId = message.id
                )
                conn.send(JsonSerialization.toJson(err))
                conn.close(1008, "Pairing unauthorized")
                SafeLog.w(TAG, "Peer pairing rejected for device_id=$peerId")
            }
        } else if (action == "auth_request") {
            val presentedToken = data["auth_token"] as? String
            val rawPeerId = (data["device_id"] as? String)?.trim()
            val storedDeviceIds = tokenStorage.listStoredDeviceIds()
            val peerId = if (!rawPeerId.isNullOrBlank()) {
                rawPeerId
            } else if (storedDeviceIds.isEmpty()) {
                // Legacy single-device/validator callers that omit device_id before per-device pairing
                "legacy-peer"
            } else {
                null
            }

            val storedToken = if (!peerId.isNullOrBlank()) {
                tokenStorage.getTokenForDevice(peerId)
                    ?: if (storedDeviceIds.isEmpty()) tokenStorage.getToken() else null
            } else {
                null
            }
            val isValid = when {
                storedToken != null && presentedToken != null -> {
                    MessageDigest.isEqual(
                        presentedToken.toByteArray(Charsets.UTF_8),
                        storedToken.toByteArray(Charsets.UTF_8)
                    )
                }
                peerTokenValidator != null && presentedToken != null -> {
                    peerTokenValidator.invoke(presentedToken)
                }
                else -> false
            }

            if (isValid && !peerId.isNullOrBlank()) {
                val newSessionId = UUID.randomUUID().toString()
                session.isAuthenticated = true
                session.peerDeviceId = peerId
                session.sessionId = newSessionId

                val respPayload = mutableMapOf<String, Any?>(
                    "status" to "success",
                    "session_id" to newSessionId,
                    "device_id" to localDeviceId,
                    "server_device_id" to localDeviceId,
                    "device_type" to "android",
                    "device_name" to (android.os.Build.MODEL ?: "Android Peer"),
                    "permission_profile" to dispatcher.activePermissionProfile,
                    "manifest" to manifestProvider()
                )
                if (!hostSnowId.isNullOrBlank()) respPayload["snow_id"] = hostSnowId
                if (!hostNetworkId.isNullOrBlank()) respPayload["network_id"] = hostNetworkId

                val resp = SnowMessage.createResponse(
                    correlationId = message.id,
                    payload = respPayload
                )
                conn.send(JsonSerialization.toJson(resp))
                SafeLog.i(TAG, "Peer authenticated successfully: device_id=$peerId session=$newSessionId")
            } else {
                val err = SnowMessage.createError(
                    code = ErrorCode.UNAUTHORIZED,
                    message = "Invalid or unverified peer authorization token.",
                    correlationId = message.id
                )
                conn.send(JsonSerialization.toJson(err))
                conn.close(1008, "Unauthorized")
                SafeLog.w(TAG, "Peer authentication rejected for device_id=$peerId")
            }
        } else if (action == "ping") {
            val resp = SnowMessage.createResponse(
                correlationId = message.id,
                payload = mapOf(
                    "status" to "success",
                    "action" to "pong"
                )
            )
            conn.send(JsonSerialization.toJson(resp))
        } else {
            if (!session.isAuthenticated) {
                val err = SnowMessage.createError(
                    code = ErrorCode.UNAUTHORIZED,
                    message = "Session not authenticated. Please authenticate first.",
                    correlationId = message.id
                )
                conn.send(JsonSerialization.toJson(err))
                return
            }

            if (action == null) {
                val err = SnowMessage.createError(
                    code = ErrorCode.INVALID_PAYLOAD,
                    message = "Missing request action.",
                    correlationId = message.id
                )
                conn.send(JsonSerialization.toJson(err))
                return
            }

            (parentScope ?: serverScope).launch(Dispatchers.IO) {
                val peerHost = conn.remoteSocketAddress?.address?.hostAddress ?: "127.0.0.1"
                SafeLog.i(TAG, "Dispatching capability: action=$action peer=${session.peerDeviceId}")

                val (resultPayload, error) = try {
                    dispatcher.dispatch(
                        action = action,
                        data = data,
                        serverHost = peerHost,
                        defaultTransferPort = 8766
                    )
                } catch (e: Exception) {
                    Pair(null, SnowError(ErrorCode.INTERNAL_ERROR, "Execution failed: ${e.message}"))
                }

                if (error != null) {
                    val err = SnowMessage.createError(
                        code = error.code,
                        message = error.message,
                        correlationId = message.id
                    )
                    conn.send(JsonSerialization.toJson(err))
                } else {
                    val resp = SnowMessage.createResponse(
                        correlationId = message.id,
                        payload = resultPayload ?: mapOf("status" to "success")
                    )
                    conn.send(JsonSerialization.toJson(resp))
                }
            }
        }
    }
}
