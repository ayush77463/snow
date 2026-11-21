package org.snow.network

import android.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
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
 * Android client managing connection to an untrusted SNOW Remote Relay
 * and maintaining an End-to-End TLS 1.3 tunnel to the Desktop Core.
 */
class RelayClient(
    val relayUrl: String,
    val deviceId: String,
    val groupId: String,
    val ticket: String,
    val targetPeerId: String,
    var certPinStorage: CertPinStorage? = null,
    val expectedPeerFingerprint: String? = null,
    val isClientMode: Boolean = true,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
) {
    companion object {
        private const val TAG = "RelayClient"
    }

    private var webSocket: WebSocket? = null
    private var tunnel: E2eRelayTunnel? = null

    private val _reachabilityState = MutableStateFlow(ReachabilityState.UNREACHABLE_OFFLINE)
    val reachabilityState: StateFlow<ReachabilityState> = _reachabilityState.asStateFlow()

    var requestDispatcher: (suspend (action: String, data: Map<String, Any?>?) -> Pair<Map<String, Any?>?, SnowError?>)? = null

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

    private fun createTunnelSslContext(): SSLContext {
        val storage = certPinStorage
        val trustManager = if (storage != null) SnowTrustManager(storage) else object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
        }
        return TlsConfig.createSslContext(trustManager)
    }

    fun connect() {
        if (_reachabilityState.value == ReachabilityState.ONLINE_RELAYED) {
            return
        }

        disconnect()
        _reachabilityState.value = ReachabilityState.CONNECTED_SESSION

        try {
            val innerSslContext = createTunnelSslContext()
            val expectedFp = expectedPeerFingerprint ?: certPinStorage?.getPinnedFingerprint()
            tunnel = E2eRelayTunnel(
                sslContext = innerSslContext,
                isServer = !isClientMode,
                expectedPeerFingerprint = expectedFp
            )

            val req = Request.Builder()
                .url(relayUrl)
                .build()

            webSocket = okHttpClient.newWebSocket(req, RelayWebSocketListener())
        } catch (e: Exception) {
            SafeLog.e(TAG, "Failed to initiate relay connection: ${e.message}", e)
            _reachabilityState.value = ReachabilityState.UNREACHABLE_OFFLINE
        }
    }

    fun disconnect() {
        _reachabilityState.value = ReachabilityState.UNREACHABLE_OFFLINE
        try {
            webSocket?.close(1000, "Normal disconnect")
        } catch (_: Exception) {}
        webSocket = null
        tunnel = null
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

    private inner class RelayWebSocketListener : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            SafeLog.i(TAG, "Relay WebSocket open. Sending hello ticket...")
            val hello = JSONObject().apply {
                put("type", "hello")
                put("ticket", ticket)
                put("device_id", deviceId)
                put("group_id", groupId)
            }
            webSocket.send(hello.toString())
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            try {
                val data = JSONObject(text)
                when (data.optString("type")) {
                    "hello_ack" -> {
                        val success = data.optBoolean("success", false)
                        if (success) {
                            SafeLog.i(TAG, "Relay authenticated successfully as [$deviceId]")
                            _reachabilityState.value = ReachabilityState.ONLINE_RELAYED

                            val tun = tunnel
                            if (tun != null && isClientMode) {
                                val (_, outBytes) = tun.driveHandshake()
                                if (outBytes.isNotEmpty()) {
                                    sendRelayFrame(webSocket, targetPeerId, outBytes)
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
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            SafeLog.i(TAG, "Relay WebSocket closed: code=$code, reason=$reason")
            _reachabilityState.value = ReachabilityState.UNREACHABLE_OFFLINE
        }
    }

    private fun handleIncomingRelayBytes(ws: WebSocket, source: String, rawBytes: ByteArray) {
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
