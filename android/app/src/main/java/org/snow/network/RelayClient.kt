package org.snow.network

import android.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import org.snow.protocol.ErrorCode
import org.snow.protocol.JsonSerialization
import org.snow.protocol.SnowError
import org.snow.protocol.SnowMessage
import org.snow.security.CertPinStorage
import org.snow.security.SafeLog
import org.snow.security.SnowTrustManager
import org.snow.security.TlsConfig
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext

/**
 * Determine deterministic TLS role for end-to-end encrypted relay tunnels.
 * The node with lexicographically greater device_id acts as server.
 */
fun isTlsServerRole(localId: String, remoteId: String): Boolean = localId > remoteId

/**
 * Android client managing connection to an untrusted SNOW Remote Relay
 * and maintaining an End-to-End TLS 1.3 tunnel to the Desktop Core.
 */
class RelayClient @JvmOverloads constructor(
    val relayUrl: String,
    val deviceId: String,
    val groupId: String,
    val ticket: String,
    val targetPeerId: String,
    var certPinStorage: CertPinStorage? = null,
    val expectedPeerFingerprint: String? = null,
    val isClientMode: Boolean = (deviceId < targetPeerId),
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    val bootstrapToken: String = "",
    val hubToken: String = "",
    val networkId: String = ""
) {
    companion object {
        private const val TAG = "RelayClient"
        private val TUNNEL_INIT_SIGNAL = "SNOW_TUNNEL_INIT".toByteArray(Charsets.UTF_8)
        private val MEDIA_FRAME_MAGIC = "SNOW_MEDIA_JPG\u0000".toByteArray(Charsets.UTF_8)
        const val MAX_RELAY_MEDIA_FRAME_BYTES = 524288

        /**
         * Build Render Hub / legacy relay `hello` authentication payload.
         * Prefers Ed25519 hubToken or rendezvous bootstrapToken over legacy static HMAC tickets.
         */
        @JvmStatic
        fun buildHelloPayload(
            deviceId: String,
            groupId: String,
            ticket: String = "",
            bootstrapToken: String = "",
            hubToken: String = "",
            networkId: String = ""
        ): JSONObject {
            return JSONObject().apply {
                put("type", "hello")
                val effectiveNetId = networkId.trim().ifEmpty { groupId.trim() }
                when {
                    hubToken.isNotBlank() -> {
                        put("hub_token", hubToken.trim())
                        if (effectiveNetId.isNotEmpty()) put("network_id", effectiveNetId)
                        put("device_id", deviceId)
                    }
                    bootstrapToken.isNotBlank() -> {
                        put("bootstrap_token", bootstrapToken.trim())
                        if (effectiveNetId.isNotEmpty()) put("network_id", effectiveNetId)
                        put("device_id", deviceId)
                    }
                    else -> {
                        put("ticket", ticket)
                    }
                }
            }
        }
    }

    private var webSocket: WebSocket? = null
    private var tunnel: E2eRelayTunnel? = null

    private val _reachabilityState = MutableStateFlow(ReachabilityState.UNREACHABLE_OFFLINE)
    val reachabilityState: StateFlow<ReachabilityState> = _reachabilityState.asStateFlow()

    var requestDispatcher: (suspend (action: String, data: Map<String, Any?>?) -> Pair<Map<String, Any?>?, SnowError?>)? = null
    var mediaFrameHandler: ((sourceId: String, meta: Map<String, Any?>, jpegBytes: ByteArray) -> Unit)? = null

    @Volatile
    private var shouldReconnect = false
    private var reconnectAttempts = 0
    private var reconnectJob: Job? = null

    val isServer: Boolean = !isClientMode

    private val okHttpClient: OkHttpClient by lazy {
        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .pingInterval(30, TimeUnit.SECONDS)

        if (relayUrl.startsWith("wss://")) {
            val storage = certPinStorage
            if (storage != null) {
                val trustManager = SnowTrustManager(storage)
                val sslContext = TlsConfig.createSslContext(trustManager)
                builder.sslSocketFactory(sslContext.socketFactory, trustManager)
                builder.hostnameVerifier(TlsConfig.createHostnameVerifier(storage))
            }
        }
        builder.build()
    }

    var keyManagers: Array<javax.net.ssl.KeyManager>? = null

    fun createTunnelSslContext(isServerRole: Boolean = isServer): SSLContext {
        val storage = certPinStorage
        val trustManager = if (storage != null) SnowTrustManager(storage) else object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
        }
        val sslContext = SSLContext.getInstance("TLS")
        val km = if (isServerRole) keyManagers else null
        sslContext.init(km, arrayOf(trustManager), java.security.SecureRandom())
        return sslContext
    }

    fun connect() {
        if (_reachabilityState.value == ReachabilityState.ONLINE_RELAYED) {
            return
        }

        shouldReconnect = true
        reconnectJob?.cancel()

        try {
            webSocket?.close(1000, "Reconnecting")
        } catch (_: Exception) {}
        webSocket = null
        tunnel = null

        _reachabilityState.value = ReachabilityState.CONNECTED_SESSION

        try {
            val innerSslContext = createTunnelSslContext(isServer)
            val expectedFp = expectedPeerFingerprint ?: certPinStorage?.getPinnedFingerprint()
            tunnel = E2eRelayTunnel(
                sslContext = innerSslContext,
                isServer = isServer,
                expectedPeerFingerprint = expectedFp
            )

            val req = Request.Builder()
                .url(relayUrl)
                .build()

            webSocket = okHttpClient.newWebSocket(req, RelayWebSocketListener())
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed to initiate relay connection: ${e.message}", e)
            _reachabilityState.value = ReachabilityState.UNREACHABLE_OFFLINE
            scheduleReconnect()
        }
    }

    fun disconnect() {
        shouldReconnect = false
        reconnectJob?.cancel()
        _reachabilityState.value = ReachabilityState.UNREACHABLE_OFFLINE
        try {
            webSocket?.close(1000, "Normal disconnect")
        } catch (_: Exception) {}
        webSocket = null
        tunnel = null
    }

    @Synchronized
    private fun scheduleReconnect() {
        if (!shouldReconnect) return
        if (reconnectJob?.isActive == true) return
        val backoffSchedule = BackoffPolicy.STAGE6C_BATTERY_SCHEDULE_MS
        val backoffMs = backoffSchedule[minOf(reconnectAttempts, backoffSchedule.lastIndex)]
        reconnectAttempts++
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            SafeLog.i(TAG, "Scheduling relay reconnect in ${backoffMs}ms (attempt $reconnectAttempts)...")
            delay(backoffMs)
            if (shouldReconnect) {
                connect()
            }
        }
    }

    fun sendRelayMessage(message: SnowMessage): Boolean {
        val tun = tunnel ?: return false
        val ws = webSocket ?: return false
        if (!tun.handshakeDone) return false

        return try {
            val plaintext = JsonSerialization.toJson(message).toByteArray(Charsets.UTF_8)
            val ciphertext = tun.encryptApplicationData(plaintext)
            val payloadB64 = Base64.encodeToString(ciphertext, Base64.NO_WRAP)

            val frame = JSONObject().apply {
                put("type", "relay_frame")
                put("target", targetPeerId)
                put("payload_b64", payloadB64)
            }
            ws.send(frame.toString())
        } catch (e: Exception) {
            SafeLog.e(TAG, "Error sending encrypted message via relay: ${e.message}", e)
            false
        }
    }

    fun sendScreenFrame(meta: Map<String, Any?>, jpegBytes: ByteArray): Boolean {
        if (jpegBytes.isEmpty() || jpegBytes.size > MAX_RELAY_MEDIA_FRAME_BYTES) return false
        val tun = tunnel ?: return false
        val ws = webSocket ?: return false
        if (!tun.handshakeDone) return false
        return try {
            val metaJson = JSONObject(meta).toString().toByteArray(Charsets.UTF_8)
            val plaintext = ByteArray(MEDIA_FRAME_MAGIC.size + metaJson.size + 1 + jpegBytes.size)
            System.arraycopy(MEDIA_FRAME_MAGIC, 0, plaintext, 0, MEDIA_FRAME_MAGIC.size)
            System.arraycopy(metaJson, 0, plaintext, MEDIA_FRAME_MAGIC.size, metaJson.size)
            plaintext[MEDIA_FRAME_MAGIC.size + metaJson.size] = 0
            System.arraycopy(jpegBytes, 0, plaintext, MEDIA_FRAME_MAGIC.size + metaJson.size + 1, jpegBytes.size)

            val ciphertext = tun.encryptApplicationData(plaintext)
            val payloadB64 = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
            val frame = JSONObject().apply {
                put("type", "relay_frame")
                put("target", targetPeerId)
                put("payload_b64", payloadB64)
            }
            ws.send(frame.toString())
        } catch (e: Exception) {
            SafeLog.w(TAG, "Error sending E2E screen frame: ${e.message}")
            false
        }
    }

    private inner class RelayWebSocketListener : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            SafeLog.i(TAG, "Relay WebSocket open. Sending hello authentication...")
            val hello = buildHelloPayload(
                deviceId = deviceId,
                groupId = groupId,
                ticket = ticket,
                bootstrapToken = bootstrapToken,
                hubToken = hubToken,
                networkId = networkId
            )
            webSocket.send(hello.toString())
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            try {
                val data = JSONObject(text)
                when (data.optString("type")) {
                    "hello_ack" -> {
                        val success = data.optBoolean("success", false)
                        if (success) {
                            reconnectAttempts = 0
                            SafeLog.i(TAG, "Relay authenticated successfully as [$deviceId]")
                            _reachabilityState.value = ReachabilityState.ONLINE_RELAYED

                            val tun = tunnel
                            if (tun != null) {
                                if (isClientMode) {
                                    val (_, outBytes) = tun.driveHandshake()
                                    if (outBytes.isNotEmpty()) {
                                        sendRelayFrame(webSocket, targetPeerId, outBytes)
                                    }
                                } else {
                                    // Server mode: proactively prompt client with init signal
                                    sendRelayFrame(webSocket, targetPeerId, TUNNEL_INIT_SIGNAL)
                                }
                            }
                        } else {
                            SafeLog.w(TAG, "Relay hello authentication failed: ${data.optString("error")}")
                            _reachabilityState.value = ReachabilityState.UNREACHABLE_OFFLINE
                            disconnect()
                        }
                    }
                    "relay_frame" -> {
                        val source = data.optString("source")
                        val payloadB64 = data.optString("payload_b64")
                        if (payloadB64.isNotBlank()) {
                            val rawBytes = Base64.decode(payloadB64, Base64.NO_WRAP)
                            handleIncomingRelayBytes(webSocket, source, rawBytes)
                        }
                    }
                    "relay_error" -> {
                        SafeLog.w(TAG, "Relay reported error: ${data.optString("message")} (${data.optString("error_code")})")
                    }
                }
            } catch (e: Exception) {
                SafeLog.e(TAG, "Failed processing relay message: ${e.message}", e)
            }
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            SafeLog.w(TAG, "Relay WebSocket failure: ${t.message}")
            _reachabilityState.value = ReachabilityState.UNREACHABLE_OFFLINE
            scheduleReconnect()
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            SafeLog.i(TAG, "Relay WebSocket closed: code=$code, reason=$reason")
            _reachabilityState.value = ReachabilityState.UNREACHABLE_OFFLINE
            if (code != 1000) {
                scheduleReconnect()
            }
        }
    }

    private fun handleIncomingRelayBytes(ws: WebSocket, source: String, rawBytes: ByteArray) {
        // Check for out-of-band tunnel init signal
        if (rawBytes.contentEquals(TUNNEL_INIT_SIGNAL)) {
            if (isClientMode) {
                val tun = tunnel ?: E2eRelayTunnel(
                    createTunnelSslContext(isServerRole = false),
                    isServer = false,
                    expectedPeerFingerprint = expectedPeerFingerprint ?: certPinStorage?.getPinnedFingerprint()
                ).also { tunnel = it }
                val (_, outBytes) = tun.driveHandshake()
                if (outBytes.isNotEmpty()) {
                    sendRelayFrame(ws, source, outBytes)
                }
            }
            return
        }

        val tun = tunnel ?: return
        try {
            tun.feedNetworkData(rawBytes)

            if (!tun.handshakeDone) {
                val (done, outBytes) = tun.driveHandshake()
                if (outBytes.isNotEmpty()) {
                    sendRelayFrame(ws, source, outBytes)
                }
                if (done) {
                    SafeLog.i(TAG, "E2E TLS 1.3 inner tunnel established with peer [$source]")
                }
            }

            if (tun.handshakeDone) {
                val decrypted = tun.decryptApplicationData()
                if (decrypted.isNotEmpty()) {
                    if (decrypted.size > MEDIA_FRAME_MAGIC.size &&
                        decrypted.copyOfRange(0, MEDIA_FRAME_MAGIC.size).contentEquals(MEDIA_FRAME_MAGIC)
                    ) {
                        var sepIdx = -1
                        for (i in MEDIA_FRAME_MAGIC.size until decrypted.size) {
                            if (decrypted[i] == 0.toByte()) {
                                sepIdx = i
                                break
                            }
                        }
                        if (sepIdx > MEDIA_FRAME_MAGIC.size && sepIdx + 1 < decrypted.size) {
                            val headerStr = String(decrypted, MEDIA_FRAME_MAGIC.size, sepIdx - MEDIA_FRAME_MAGIC.size, Charsets.UTF_8)
                            val jpegBytes = decrypted.copyOfRange(sepIdx + 1, decrypted.size)
                            if (jpegBytes.size <= MAX_RELAY_MEDIA_FRAME_BYTES) {
                                val metaObj = JSONObject(headerStr)
                                val metaMap = mutableMapOf<String, Any?>()
                                val keys = metaObj.keys()
                                while (keys.hasNext()) {
                                    val k = keys.next()
                                    metaMap[k] = metaObj.opt(k)
                                }
                                mediaFrameHandler?.invoke(source, metaMap, jpegBytes)
                            }
                        }
                        return
                    }
                    val rawJson = String(decrypted, Charsets.UTF_8)
                    val message = JsonSerialization.fromJson(rawJson)
                    handleDecryptedMessage(source, message)
                }
            }
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed handling incoming relay bytes: ${e.message}", e)
        }
    }

    private fun handleDecryptedMessage(source: String, message: SnowMessage) {
        val payloadMap = message.payload
        val action = payloadMap?.get("action") as? String
        @Suppress("UNCHECKED_CAST")
        val data = payloadMap?.get("data") as? Map<String, Any?>
        val dispatcher = requestDispatcher

        if (action != null && dispatcher != null) {
            scope.launch {
                val (respPayload, error) = try {
                    dispatcher.invoke(action, data)
                } catch (e: Exception) {
                    Pair(null, SnowError(ErrorCode.INTERNAL_ERROR, "Error handling action '$action': ${e.message}"))
                }

                val replyMessage = if (error != null) {
                    SnowMessage.createError(
                        code = error.code,
                        message = error.message,
                        correlationId = message.id
                    )
                } else {
                    val respData = mutableMapOf<String, Any?>("action" to action)
                    if (respPayload != null) {
                        respData["data"] = respPayload
                    }
                    SnowMessage.createResponse(
                        correlationId = message.id,
                        payload = respData
                    )
                }
                sendRelayMessage(replyMessage)
            }
        }
    }

    private fun sendRelayFrame(ws: WebSocket, target: String, rawBytes: ByteArray) {
        val payloadB64 = Base64.encodeToString(rawBytes, Base64.NO_WRAP)
        val frame = JSONObject().apply {
            put("type", "relay_frame")
            put("target", target)
            put("payload_b64", payloadB64)
        }
        ws.send(frame.toString())
    }
}
