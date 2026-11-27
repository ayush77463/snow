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
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext

enum class PinVerificationStatus {
    SUCCESS,
    INVALID_PIN,
    EXPIRED,
    LOCKED
}

data class PinVerificationResult(
    val status: PinVerificationStatus,
    val remainingAttempts: Int = 0,
    val lockoutSeconds: Long = 0L,
    val message: String = ""
)

data class NetworkNegotiationOutcome(
    val peerDeviceId: String,
    val peerDeviceName: String,
    val relationship: String,
    val networkAction: String,
    val networkConflict: Boolean,
    val effectiveHostNetworkId: String?,
    val peerNetworkId: String?,
    val mergeTxId: String? = null,
    val survivingNetworkId: String? = null
)

data class NetworkMergeCommandResult(
    val success: Boolean,
    val committed: Boolean = false,
    val networkAction: String? = null,
    val networkId: String? = null,
    val relationship: String? = null,
    val errorCode: String? = null,
    val errorMessage: String? = null
)

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
    private val hostNetworkId: String? = null,
    private val defaultMediaPort: Int = AndroidPeerHostManager.DEFAULT_MEDIA_PORT,
    private val hostNetworkIdProvider: (() -> String?)? = null,
    private val pinDetailedVerifier: ((String) -> PinVerificationResult)? = null,
    private val onNetworkNegotiated: ((NetworkNegotiationOutcome) -> Unit)? = null,
    private val mergeDecisionHandler: ((txId: String, decision: String, actingDeviceId: String) -> NetworkMergeCommandResult)? = null
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
    @Volatile
    private var dynamicHostNetworkId: String? = hostNetworkId?.trim()?.uppercase()?.takeIf {
        AndroidPeerHostManager.isValidCanonicalNetworkId(it)
    }
    private data class InMemoryMergeProposal(
        val txId: String,
        val sourceNetworkId: String,
        val targetNetworkId: String,
        val survivingNetworkId: String,
        val sourceOwnerDeviceId: String,
        val targetOwnerDeviceId: String,
        var sourceApproved: Boolean = false,
        var targetApproved: Boolean = false,
        var status: String = "PENDING"
    )
    private val fallbackMergeProposals = ConcurrentHashMap<String, InMemoryMergeProposal>()
    private val mergeRandom = SecureRandom()

    private fun currentHostNetworkId(): String? {
        val provided = hostNetworkIdProvider?.invoke()?.trim()?.uppercase()
        if (AndroidPeerHostManager.isValidCanonicalNetworkId(provided)) return provided
        return dynamicHostNetworkId?.takeIf { AndroidPeerHostManager.isValidCanonicalNetworkId(it) }
    }

    private fun nextMergeTxId(): String {
        val bytes = ByteArray(6)
        mergeRandom.nextBytes(bytes)
        return "mrg-" + bytes.joinToString("") { "%02x".format(it) }
    }

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
            val peerName = (data["device_name"] as? String)?.trim()?.takeIf { it.isNotBlank() } ?: peerId ?: "Android Peer"

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

            var detailedPinResult: PinVerificationResult? = null
            // Mutual exclusion matching Desktop Core: when handshake_token is supplied, verify ONLY it.
            val isAuthorized = if (rawHandshakeToken != null) {
                handshakeTokenVerifier?.invoke(rawHandshakeToken, presentedNetworkId) == true
            } else if (pinDetailedVerifier != null) {
                if (pin != null) {
                    detailedPinResult = pinDetailedVerifier.invoke(pin)
                    detailedPinResult.status == PinVerificationStatus.SUCCESS
                } else {
                    false
                }
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

                val hostNetId = currentHostNetworkId()
                val rawClientNet = (data["client_network_id"] as? String)?.trim()?.uppercase()
                val clientNetId = rawClientNet?.takeIf { AndroidPeerHostManager.isValidCanonicalNetworkId(it) }
                val decision = (data["network_decision"] as? String)?.trim()?.lowercase()
                val reqTxId = (data["merge_tx_id"] as? String)?.trim()?.takeIf { it.isNotBlank() }
                val clientMergeApproved = (data["client_merge_approved"] as? Boolean) == true
                val hostOwnerApproved = (data["host_owner_approved"] as? Boolean) == true
                val assignedTier = ((data["trust_tier"] as? String) ?: "owner").trim().lowercase()

                var relationship = "member"
                var netAction = "FORMED"
                var networkConflict = false
                var outMergeTxId: String? = null
                var respNetworkId: String?
                var effectiveHostNetworkId = hostNetId
                var pairedNetId: String?

                if (hostNetId == null && clientNetId == null) {
                    val formedId = AndroidPeerHostManager.generateCanonicalNetworkId()
                    effectiveHostNetworkId = formedId
                    dynamicHostNetworkId = formedId
                    respNetworkId = formedId
                    pairedNetId = formedId
                    netAction = "FORMED"
                } else if (hostNetId != null && clientNetId == null) {
                    respNetworkId = hostNetId
                    pairedNetId = hostNetId
                    netAction = "JOINED"
                } else if (hostNetId == null && clientNetId != null) {
                    effectiveHostNetworkId = clientNetId
                    dynamicHostNetworkId = clientNetId
                    respNetworkId = clientNetId
                    pairedNetId = clientNetId
                    netAction = "ADOPTED"
                } else if (hostNetId == clientNetId) {
                    respNetworkId = hostNetId
                    pairedNetId = hostNetId
                    netAction = "SAME_NETWORK"
                } else {
                    val safeHostNet = hostNetId!!
                    val safeClientNet = clientNetId!!
                    val survivingCandidate = (data["surviving_network_id"] as? String)?.trim()?.uppercase()
                    val surviving = if (survivingCandidate == safeHostNet || survivingCandidate == safeClientNet) {
                        survivingCandidate!!
                    } else {
                        safeHostNet
                    }
                    if (decision == "keep_separate") {
                        relationship = "external_network"
                        netAction = "KEEP_SEPARATE"
                        networkConflict = false
                        respNetworkId = safeHostNet
                        pairedNetId = safeClientNet
                    } else {
                        val txId = reqTxId ?: nextMergeTxId()
                        outMergeTxId = txId
                        relationship = "external_network"
                        networkConflict = true
                        netAction = "DECISION_REQUIRED"
                        respNetworkId = safeHostNet
                        pairedNetId = safeClientNet

                        val existing = fallbackMergeProposals[txId] ?: InMemoryMergeProposal(
                            txId = txId,
                            sourceNetworkId = safeHostNet,
                            targetNetworkId = safeClientNet,
                            survivingNetworkId = surviving,
                            sourceOwnerDeviceId = localDeviceId,
                            targetOwnerDeviceId = peerId
                        ).also { fallbackMergeProposals[txId] = it }

                        if (decision == "merge" && assignedTier == "owner" && clientMergeApproved) {
                            existing.targetApproved = true
                            if (hostOwnerApproved) {
                                existing.sourceApproved = true
                                existing.status = "COMMITTED"
                                relationship = "member"
                                networkConflict = false
                                effectiveHostNetworkId = existing.survivingNetworkId
                                dynamicHostNetworkId = existing.survivingNetworkId
                                respNetworkId = existing.survivingNetworkId
                                pairedNetId = existing.survivingNetworkId
                                netAction = "MERGED"
                            } else {
                                netAction = "MERGE_APPROVAL_REQUIRED"
                            }
                        }
                    }
                }

                onNetworkNegotiated?.invoke(
                    NetworkNegotiationOutcome(
                        peerDeviceId = peerId,
                        peerDeviceName = peerName,
                        relationship = relationship,
                        networkAction = netAction,
                        networkConflict = networkConflict,
                        effectiveHostNetworkId = effectiveHostNetworkId,
                        peerNetworkId = pairedNetId,
                        mergeTxId = outMergeTxId,
                        survivingNetworkId = respNetworkId
                    )
                )

                val respPayload = mutableMapOf<String, Any?>(
                    "status" to "success",
                    "action" to "pair_response",
                    "session_id" to newSessionId,
                    "device_id" to localDeviceId,
                    "server_device_id" to localDeviceId,
                    "device_type" to "android",
                    "device_name" to (android.os.Build.MODEL ?: "Android Peer"),
                    "auth_token" to newToken,
                    "trust_tier" to assignedTier,
                    "permission_profile" to dispatcher.activePermissionProfile,
                    "relationship" to relationship,
                    "network_action" to netAction,
                    "network_conflict" to networkConflict,
                    "manifest" to manifestProvider()
                )
                if (!hostSnowId.isNullOrBlank()) respPayload["snow_id"] = hostSnowId
                if (!respNetworkId.isNullOrBlank()) respPayload["network_id"] = respNetworkId
                if (!hostNetId.isNullOrBlank()) respPayload["host_network_id"] = hostNetId
                if (!clientNetId.isNullOrBlank()) respPayload["client_network_id"] = clientNetId
                if (!outMergeTxId.isNullOrBlank()) respPayload["merge_tx_id"] = outMergeTxId

                val resp = SnowMessage.createResponse(
                    correlationId = message.id,
                    payload = respPayload
                )
                conn.send(JsonSerialization.toJson(resp))
                SafeLog.i(TAG, "Peer paired (${if (rawHandshakeToken != null) "QR handshake" else "PIN"}): device_id=$peerId session=$newSessionId netAction=$netAction")
            } else {
                val (errCode, errMsg) = when {
                    rawHandshakeToken != null -> ErrorCode.UNAUTHORIZED to "Invalid, expired, or already used QR handshake token."
                    detailedPinResult != null -> when (detailedPinResult.status) {
                        PinVerificationStatus.EXPIRED -> ErrorCode.PIN_EXPIRED to detailedPinResult.message.ifBlank {
                            "Pairing PIN expired. Generate a fresh QR code or PIN on host."
                        }
                        PinVerificationStatus.LOCKED -> ErrorCode.PAIRING_LOCKED to detailedPinResult.message.ifBlank {
                            "Pairing temporarily locked due to repeated invalid PIN attempts."
                        }
                        PinVerificationStatus.INVALID_PIN -> ErrorCode.INVALID_PIN to detailedPinResult.message.ifBlank {
                            "Invalid pairing PIN (${detailedPinResult.remainingAttempts} attempts remaining)."
                        }
                        PinVerificationStatus.SUCCESS -> ErrorCode.UNAUTHORIZED to "Pairing rejected."
                    }
                    else -> ErrorCode.UNAUTHORIZED to "Invalid or expired pairing PIN."
                }
                val err = SnowMessage.createError(
                    code = errCode,
                    message = errMsg,
                    correlationId = message.id
                )
                conn.send(JsonSerialization.toJson(err))
                conn.close(1008, "Pairing unauthorized")
                SafeLog.w(TAG, "Peer pairing rejected for device_id=$peerId code=$errCode")
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
                val liveNetId = currentHostNetworkId()
                if (!liveNetId.isNullOrBlank()) respPayload["network_id"] = liveNetId

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
        } else if (action == "network_merge_decision") {
            if (!session.isAuthenticated) {
                val err = SnowMessage.createError(
                    code = ErrorCode.UNAUTHORIZED,
                    message = "Session not authenticated. Please authenticate first.",
                    correlationId = message.id
                )
                conn.send(JsonSerialization.toJson(err))
                return
            }
            val txId = (data["tx_id"] as? String)?.trim().orEmpty()
            val decision = (data["decision"] as? String)?.trim()?.lowercase().orEmpty()
            val actingDevId = session.peerDeviceId ?: (data["device_id"] as? String)?.trim().orEmpty()
            if (txId.isBlank() || decision !in listOf("merge", "keep_separate", "reject")) {
                val err = SnowMessage.createError(
                    code = ErrorCode.INVALID_PAYLOAD,
                    message = "Requires 'tx_id' and decision in ('merge', 'keep_separate', 'reject').",
                    correlationId = message.id
                )
                conn.send(JsonSerialization.toJson(err))
                return
            }
            val cmdRes = if (mergeDecisionHandler != null) {
                mergeDecisionHandler.invoke(txId, decision, actingDevId)
            } else {
                val prop = fallbackMergeProposals[txId]
                if (prop == null) {
                    NetworkMergeCommandResult(
                        success = false,
                        errorCode = ErrorCode.INVALID_PAYLOAD,
                        errorMessage = "Merge transaction '$txId' not found."
                    )
                } else if (decision == "keep_separate" || decision == "reject") {
                    prop.status = "REJECTED"
                    NetworkMergeCommandResult(
                        success = true,
                        committed = false,
                        networkAction = "KEEP_SEPARATE",
                        networkId = prop.sourceNetworkId,
                        relationship = "external_network"
                    )
                } else {
                    if (actingDevId != prop.sourceOwnerDeviceId && actingDevId != prop.targetOwnerDeviceId) {
                        NetworkMergeCommandResult(
                            success = false,
                            errorCode = ErrorCode.UNAUTHORIZED,
                            errorMessage = "Only network owners can approve merge transactions."
                        )
                    } else {
                        if (actingDevId == prop.sourceOwnerDeviceId) prop.sourceApproved = true
                        if (actingDevId == prop.targetOwnerDeviceId) prop.targetApproved = true
                        if (prop.sourceApproved && prop.targetApproved) {
                            prop.status = "COMMITTED"
                            dynamicHostNetworkId = prop.survivingNetworkId
                            NetworkMergeCommandResult(
                                success = true,
                                committed = true,
                                networkAction = "MERGED",
                                networkId = prop.survivingNetworkId,
                                relationship = "member"
                            )
                        } else {
                            NetworkMergeCommandResult(
                                success = true,
                                committed = false,
                                networkAction = "MERGE_APPROVAL_REQUIRED",
                                networkId = prop.sourceNetworkId,
                                relationship = "external_network"
                            )
                        }
                    }
                }
            }

            if (!cmdRes.success) {
                val err = SnowMessage.createError(
                    code = cmdRes.errorCode ?: ErrorCode.INVALID_PAYLOAD,
                    message = cmdRes.errorMessage ?: "Network merge decision failed.",
                    correlationId = message.id
                )
                conn.send(JsonSerialization.toJson(err))
                return
            }

            val dataMap = mutableMapOf<String, Any?>(
                "tx_id" to txId,
                "committed" to cmdRes.committed
            )
            cmdRes.networkAction?.let { dataMap["network_action"] = it }
            cmdRes.networkId?.let { dataMap["network_id"] = it }
            cmdRes.relationship?.let { dataMap["relationship"] = it }
            val resp = SnowMessage.createResponse(
                correlationId = message.id,
                payload = mapOf(
                    "status" to "success",
                    "action" to "network_merge_decision",
                    "data" to dataMap
                )
            )
            conn.send(JsonSerialization.toJson(resp))
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
                        defaultTransferPort = defaultMediaPort
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
