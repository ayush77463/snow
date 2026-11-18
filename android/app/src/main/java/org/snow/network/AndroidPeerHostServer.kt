package org.snow.network

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.protocol.ErrorCode
import org.snow.protocol.JsonSerialization
import org.snow.protocol.MessageType
import org.snow.protocol.SnowError
import org.snow.protocol.SnowMessage
import org.snow.security.SafeLog
import org.snow.security.TokenStorage
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.Collections
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Lightweight, foreground-only TCP/WebSocket server for Android-to-Android peer host mode.
 *
 * Security & Lifecycle Invariants:
 * 1. Runs exclusively in the foreground under user control and active Foreground Service.
 * 2. Never acts as a permanent background listener.
 * 3. Requires valid token-based peer authentication before executing capability requests.
 * 4. Dispatches all operations through [AndroidCapabilityDispatcher], strictly enforcing
 *    Android 17 OS execution contracts (BACKGROUND_SAFE vs FOREGROUND_USER_INTERACTION_REQUIRED).
 * 5. Bounded memory and frame sizes (max 64KB per frame).
 */
class AndroidPeerHostServer(
    val requestedPort: Int = 8767,
    private val tokenStorage: TokenStorage,
    private val dispatcher: AndroidCapabilityDispatcher,
    private val localDeviceId: String,
    private val manifestProvider: () -> Map<String, Any?> = { emptyMap() },
    private val peerTokenValidator: ((String) -> Boolean)? = null,
    private val parentScope: CoroutineScope? = null
) {
    companion object {
        private const val TAG = "AndroidPeerHostServer"
        const val MAX_FRAME_SIZE = 65536
    }

    private val isRunning = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var serverJob: Job? = null
    private val activeSockets = Collections.synchronizedSet(mutableSetOf<Socket>())
    private val serverScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    var boundPort: Int = requestedPort
        private set

    /**
     * Start listening for incoming peer connections on the requested port.
     */
    @Synchronized
    fun start(): Boolean {
        if (isRunning.get()) {
            SafeLog.i(TAG, "AndroidPeerHostServer is already running on port $boundPort")
            return true
        }

        return try {
            val ss = ServerSocket(requestedPort)
            serverSocket = ss
            boundPort = ss.localPort
            isRunning.set(true)
            SafeLog.i(TAG, "AndroidPeerHostServer started on port $boundPort")

            serverJob = (parentScope ?: serverScope).launch(Dispatchers.IO) {
                acceptLoop(ss)
            }
            true
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed to start AndroidPeerHostServer on port $requestedPort: ${e.message}", e)
            stop()
            false
        }
    }

    /**
     * Stop the server socket and disconnect all active peer sessions cleanly.
     */
    @Synchronized
    fun stop() {
        if (!isRunning.getAndSet(false)) {
            return
        }
        SafeLog.i(TAG, "Stopping AndroidPeerHostServer on port $boundPort...")

        serverJob?.cancel()
        serverJob = null

        try {
            serverSocket?.close()
        } catch (_: Exception) {}
        serverSocket = null

        synchronized(activeSockets) {
            for (sock in activeSockets) {
                try {
                    sock.close()
                } catch (_: Exception) {}
            }
            activeSockets.clear()
        }
        SafeLog.i(TAG, "AndroidPeerHostServer stopped cleanly.")
    }

    fun isListening(): Boolean = isRunning.get() && serverSocket != null && !serverSocket!!.isClosed

    private suspend fun acceptLoop(ss: ServerSocket) {
        while (isRunning.get() && !ss.isClosed) {
            try {
                val clientSocket = ss.accept()
                activeSockets.add(clientSocket)
                (parentScope ?: serverScope).launch(Dispatchers.IO) {
                    handleClientConnection(clientSocket)
                }
            } catch (e: SocketException) {
                // Expected when serverSocket.close() is called
                break
            } catch (e: Exception) {
                if (isRunning.get()) {
                    SafeLog.w(TAG, "Error in acceptLoop: ${e.message}")
                }
            }
        }
    }

    private suspend fun handleClientConnection(socket: Socket) {
        var isAuthenticated = false
        var authenticatedPeerId: String? = null

        try {
            socket.soTimeout = 30000 // 30s read timeout
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))
            val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))

            while (isRunning.get() && !socket.isClosed) {
                val line = reader.readLine() ?: break
                if (line.length > MAX_FRAME_SIZE) {
                    val err = SnowMessage.createError(
                        code = ErrorCode.OVERSIZED_MESSAGE,
                        message = "Message exceeds maximum size of $MAX_FRAME_SIZE bytes."
                    )
                    writer.write(JsonSerialization.toJson(err) + "\n")
                    writer.flush()
                    break
                }

                val message = try {
                    JsonSerialization.fromJson(line)
                } catch (pe: Exception) {
                    val err = SnowMessage.createError(
                        code = ErrorCode.INVALID_JSON,
                        message = "Malformed JSON message: ${pe.message}"
                    )
                    writer.write(JsonSerialization.toJson(err) + "\n")
                    writer.flush()
                    continue
                }

                if (message.type == MessageType.HEARTBEAT) {
                    val ack = SnowMessage.createHeartbeatAck(correlationId = message.id)
                    writer.write(JsonSerialization.toJson(ack) + "\n")
                    writer.flush()
                    continue
                }

                if (message.type != MessageType.REQUEST) {
                    continue
                }

                val action = message.payload?.get("action") as? String
                @Suppress("UNCHECKED_CAST")
                val data = message.payload?.get("data") as? Map<String, Any?> ?: emptyMap()

                if (action == "auth_request") {
                    val presentedToken = data["auth_token"] as? String
                    val peerId = data["device_id"] as? String

                    val storedToken = tokenStorage.getToken()
                    val isValid = when {
                        storedToken != null && presentedToken != null -> {
                            java.security.MessageDigest.isEqual(
                                presentedToken.toByteArray(Charsets.UTF_8),
                                storedToken.toByteArray(Charsets.UTF_8)
                            )
                        }
                        peerTokenValidator != null && presentedToken != null -> {
                            peerTokenValidator.invoke(presentedToken)
                        }
                        else -> false
                    }

                    if (isValid) {
                        isAuthenticated = true
                        authenticatedPeerId = peerId
                        val resp = SnowMessage.createResponse(
                            correlationId = message.id,
                            payload = mapOf(
                                "status" to "success",
                                "session_id" to UUID.randomUUID().toString(),
                                "device_id" to localDeviceId,
                                "manifest" to manifestProvider()
                            )
                        )
                        writer.write(JsonSerialization.toJson(resp) + "\n")
                        writer.flush()
                        SafeLog.i(TAG, "Peer authenticated successfully: device_id=$peerId")
                    } else {
                        val err = SnowMessage.createError(
                            code = ErrorCode.UNAUTHORIZED,
                            message = "Invalid or unverified peer authorization token.",
                            correlationId = message.id
                        )
                        writer.write(JsonSerialization.toJson(err) + "\n")
                        writer.flush()
                        SafeLog.w(TAG, "Peer authentication rejected for device_id=$peerId")
                        break
                    }
                } else if (action == "ping") {
                    val resp = SnowMessage.createResponse(
                        correlationId = message.id,
                        payload = mapOf(
                            "status" to "success",
                            "action" to "pong"
                        )
                    )
                    writer.write(JsonSerialization.toJson(resp) + "\n")
                    writer.flush()
                } else {
                    if (!isAuthenticated) {
                        val err = SnowMessage.createError(
                            code = ErrorCode.UNAUTHORIZED,
                            message = "Session not authenticated. Please authenticate first.",
                            correlationId = message.id
                        )
                        writer.write(JsonSerialization.toJson(err) + "\n")
                        writer.flush()
                        continue
                    }

                    if (action == null) {
                        val err = SnowMessage.createError(
                            code = ErrorCode.INVALID_PAYLOAD,
                            message = "Missing request action.",
                            correlationId = message.id
                        )
                        writer.write(JsonSerialization.toJson(err) + "\n")
                        writer.flush()
                        continue
                    }

                    // Dispatch action through AndroidCapabilityDispatcher (which validates execution contract)
                    SafeLog.i(TAG, "Dispatching capability: action=$action peer=$authenticatedPeerId")
                    val peerHost = socket.inetAddress?.hostAddress ?: "127.0.0.1"
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
                        writer.write(JsonSerialization.toJson(err) + "\n")
                    } else {
                        val resp = SnowMessage.createResponse(
                            correlationId = message.id,
                            payload = resultPayload ?: mapOf("status" to "success")
                        )
                        writer.write(JsonSerialization.toJson(resp) + "\n")
                    }
                    writer.flush()
                }
            }
        } catch (e: Exception) {
            SafeLog.i(TAG, "Peer connection ended: ${e.message}")
        } finally {
            activeSockets.remove(socket)
            try {
                socket.close()
            } catch (_: Exception) {}
        }
    }
}
