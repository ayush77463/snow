package org.snow.mcp

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import org.snow.security.DeviceKeyIdentity
import org.snow.security.SafeLog
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

data class RelayMcpForwarderState(
    val enabled: Boolean,
    val connected: Boolean,
    val registeredSnowId: String = "",
    val mcpEndpointUrl: String = "",
    val sessionGeneration: Long = 0L,
    val lastError: String? = null
)

/**
 * Standalone outbound WebSocket forwarder running on Android that connects directly to the
 * SNOW Render Hub (`/v1/tunnel`), authenticates using Android's permanent Ed25519
 * [DeviceKeyIdentity], registers `/u/<android_snow_id>/mcp`, and streams incoming
 * `mcp_http_request` envelopes into [AndroidMcpResponder] with bounded concurrency.
 *
 * Works completely independently without Windows PC online.
 */
class AndroidMcpRelayForwarder(
    private val hubHttpUrlProvider: () -> String,
    private val deviceIdProvider: () -> String,
    private val deviceKeyProvider: () -> DeviceKeyIdentity,
    private val networkIdProvider: () -> String? = { null },
    private val responder: AndroidMcpResponder,
    private val enabledProvider: () -> Boolean = { true },
    private val allowInsecureLocalhostForTest: Boolean = false,
    private val autoReconnect: Boolean = true,
    private val baseBackoffMs: Long = 1_500L,
    private val maxBackoffMs: Long = 30_000L,
    private val maxConcurrentForwards: Int = 16,
    private val maxForwardBodyBytes: Int = 256 * 1024,
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .pingInterval(25, TimeUnit.SECONDS)
        .build(),
    private val webSocketFactory: ((Request, WebSocketListener) -> WebSocket)? = null,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    private val onStateChanged: ((RelayMcpForwarderState) -> Unit)? = null
) {
    companion object {
        private const val TAG = "AndroidMcpRelayFwd"
        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
        private val ALLOWED_METHODS = setOf("GET", "POST", "DELETE")
        private val HOP_BY_HOP_HEADERS = setOf(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "transfer-encoding", "upgrade", "content-length"
        )
        private val random = SecureRandom()
    }

    private val lock = Any()
    private val manuallyStopped = AtomicBoolean(false)
    private val generationCounter = AtomicLong(0L)
    private val requestSemaphore = Semaphore(maxConcurrentForwards.coerceIn(1, 64))

    @Volatile
    private var activeWebSocket: WebSocket? = null

    @Volatile
    private var connectJob: Job? = null

    @Volatile
    private var reconnectJob: Job? = null

    @Volatile
    private var reconnectAttempts = 0

    @Volatile
    private var isConnecting = false

    @Volatile
    private var isConnected = false

    private val _state = MutableStateFlow(
        RelayMcpForwarderState(
            enabled = enabledProvider(),
            connected = false
        )
    )
    val state: StateFlow<RelayMcpForwarderState> = _state.asStateFlow()

    fun isConnected(): Boolean = isConnected && activeWebSocket != null

    fun currentEndpointUrl(): String {
        val cleanHub = resolveValidatedHubBaseUrl() ?: return ""
        val snowId = try {
            deviceKeyProvider().snowId
        } catch (_: Exception) {
            ""
        }
        return if (snowId.isNotBlank()) "$cleanHub/u/$snowId/mcp" else ""
    }

    fun start(recoveryTakeover: Boolean = false) {
        if (!enabledProvider()) {
            SafeLog.i(TAG, "Android Remote MCP forwarder is disabled by user preference.")
            emitState(
                RelayMcpForwarderState(
                    enabled = false,
                    connected = false,
                    registeredSnowId = safeSnowId(),
                    mcpEndpointUrl = currentEndpointUrl(),
                    sessionGeneration = generationCounter.get(),
                    lastError = null
                )
            )
            return
        }
        synchronized(lock) {
            manuallyStopped.set(false)
            if (isConnected || isConnecting) {
                return
            }
            reconnectJob?.cancel()
            reconnectJob = null
            isConnecting = true
        }
        connectJob?.cancel()
        connectJob = scope.launch {
            runConnectAttempt(recoveryTakeover = recoveryTakeover)
        }
    }

    fun stop() {
        val wsToClose: WebSocket?
        synchronized(lock) {
            manuallyStopped.set(true)
            generationCounter.incrementAndGet()
            isConnecting = false
            isConnected = false
            reconnectJob?.cancel()
            reconnectJob = null
            connectJob?.cancel()
            connectJob = null
            wsToClose = activeWebSocket
            activeWebSocket = null
        }
        try {
            wsToClose?.close(1000, "Manual stop")
        } catch (_: Exception) {
            try {
                wsToClose?.cancel()
            } catch (_: Exception) {}
        }
        emitState(
            RelayMcpForwarderState(
                enabled = enabledProvider(),
                connected = false,
                registeredSnowId = safeSnowId(),
                mcpEndpointUrl = currentEndpointUrl(),
                sessionGeneration = generationCounter.get(),
                lastError = null
            )
        )
    }

    private suspend fun runConnectAttempt(recoveryTakeover: Boolean) {
        if (manuallyStopped.get() || !enabledProvider()) {
            synchronized(lock) { isConnecting = false }
            return
        }

        val cleanHub = resolveValidatedHubBaseUrl()
        if (cleanHub == null) {
            failAttemptAndMaybeRetry("Invalid Render Hub URL for Android MCP tunnel.")
            return
        }

        val devKey = try {
            deviceKeyProvider()
        } catch (e: Exception) {
            failAttemptAndMaybeRetry("Device cryptographic identity unavailable: ${e.message}")
            return
        }

        val devId = deviceIdProvider().trim().ifEmpty { devKey.snowId }
        val netId = networkIdProvider()?.trim()?.uppercase(Locale.ROOT)?.takeIf { it.isNotEmpty() }.orEmpty()

        val sessionToken = try {
            authenticateDeviceHubSession(
                hubBase = cleanHub,
                devKey = devKey,
                deviceId = devId,
                networkId = netId
            )
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            failAttemptAndMaybeRetry(e.message ?: "Device Render Hub challenge failed.")
            return
        }

        if (manuallyStopped.get() || !enabledProvider()) {
            synchronized(lock) { isConnecting = false }
            return
        }

        val gen = generationCounter.incrementAndGet()
        val wsUrl = toTunnelWsUrl(cleanHub)
        val ackDeferred = CompletableDeferred<Pair<Boolean, String?>>()

        val req = Request.Builder().url(wsUrl).build()
        val listener = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (manuallyStopped.get() || gen != generationCounter.get()) {
                    webSocket.close(1000, "Stale generation")
                    return
                }
                val hello = JSONObject().apply {
                    put("type", "hello")
                    put("hub_token", sessionToken)
                    put("snow_id", devKey.snowId)
                    put("device_id", devId)
                    if (netId.isNotEmpty()) put("network_id", netId)
                    put("mcp_tunnel", true)
                    put("session_generation", gen)
                    if (recoveryTakeover) put("recovery_takeover", true)
                }
                webSocket.send(hello.toString())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (manuallyStopped.get() || gen != generationCounter.get()) return
                val obj = try {
                    JSONObject(text)
                } catch (_: Exception) {
                    return
                }
                when (obj.optString("type")) {
                    "hello_ack" -> {
                        val ok = obj.optBoolean("success", false)
                        val ackSnowId = obj.optString("snow_id", "").trim().uppercase(Locale.ROOT)
                        if (ok && ackSnowId == devKey.snowId) {
                            ackDeferred.complete(true to null)
                        } else {
                            val err = obj.optString("error", "").ifBlank { "Hub rejected hello_ack for ${devKey.snowId}." }
                            ackDeferred.complete(false to err)
                        }
                    }
                    "ping" -> {
                        webSocket.send(JSONObject().put("type", "pong").toString())
                    }
                    "mcp_http_request" -> {
                        scope.launch {
                            handleHttpForwardEnvelope(webSocket, gen, obj, devKey.snowId)
                        }
                    }
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(code, reason)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                handleSocketClosed(gen, code, reason)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (!ackDeferred.isCompleted) {
                    ackDeferred.complete(false to (t.message ?: "WebSocket connection failed"))
                }
                handleSocketClosed(gen, 1006, t.message ?: "WebSocket failure")
            }
        }

        val ws = try {
            webSocketFactory?.invoke(req, listener) ?: httpClient.newWebSocket(req, listener)
        } catch (e: Exception) {
            failAttemptAndMaybeRetry("Failed opening Render Hub WebSocket: ${e.message}")
            return
        }

        synchronized(lock) {
            if (manuallyStopped.get() || gen != generationCounter.get()) {
                ws.close(1000, "Stopped")
                isConnecting = false
                return
            }
            activeWebSocket = ws
        }

        val ackResult = withTimeoutOrNull(10_000L) { ackDeferred.await() }
            ?: (false to "Render Hub hello_ack timed out.")

        if (!ackResult.first) {
            synchronized(lock) {
                if (activeWebSocket === ws) {
                    activeWebSocket = null
                }
                isConnecting = false
                isConnected = false
            }
            try {
                ws.close(1008, "Handshake failed")
            } catch (_: Exception) {
                ws.cancel()
            }
            failAttemptAndMaybeRetry(ackResult.second ?: "Render Hub handshake rejected.")
            return
        }

        synchronized(lock) {
            if (manuallyStopped.get() || gen != generationCounter.get()) {
                ws.close(1000, "Superseded")
                isConnecting = false
                return
            }
            isConnecting = false
            isConnected = true
            reconnectAttempts = 0
        }

        val endpointUrl = "$cleanHub/u/${devKey.snowId}/mcp"
        SafeLog.i(TAG, "Android Native MCP tunnel connected at $endpointUrl (gen=$gen)")
        emitState(
            RelayMcpForwarderState(
                enabled = true,
                connected = true,
                registeredSnowId = devKey.snowId,
                mcpEndpointUrl = endpointUrl,
                sessionGeneration = gen,
                lastError = null
            )
        )
    }

    private suspend fun authenticateDeviceHubSession(
        hubBase: String,
        devKey: DeviceKeyIdentity,
        deviceId: String,
        networkId: String
    ): String = withContext(Dispatchers.IO) {
        val chReqBody = JSONObject().apply {
            put("snow_id", devKey.snowId)
            put("public_key", devKey.publicKeyB64)
            put("device_id", deviceId)
            if (networkId.isNotEmpty()) put("network_id", networkId)
        }
        val chReq = Request.Builder()
            .url("$hubBase/v1/hub/challenge")
            .post(chReqBody.toString().toRequestBody(JSON_MEDIA))
            .build()

        val chJson: JSONObject
        httpClient.newCall(chReq).execute().use { resp ->
            val raw = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                throw IllegalStateException("Hub challenge failed (HTTP ${resp.code})")
            }
            chJson = JSONObject(raw)
        }

        val challengeId = chJson.optString("challenge_id").trim()
        val nonce = chJson.optString("nonce").trim()
        val expiresAt = chJson.optLong("expires_at", 0L)
        val audience = chJson.optString("audience", "render-hub-tunnel").trim()
        if (challengeId.isEmpty() || nonce.isEmpty() || expiresAt <= 0L) {
            throw IllegalStateException("Malformed challenge response from Render Hub.")
        }

        val sigB64 = devKey.signDeviceHubChallenge(
            challengeId = challengeId,
            nonce = nonce,
            expiresAt = expiresAt,
            deviceId = deviceId,
            networkId = networkId,
            audience = audience
        )

        val sessBody = JSONObject().apply {
            put("challenge_id", challengeId)
            put("snow_id", devKey.snowId)
            put("public_key", devKey.publicKeyB64)
            put("signature", sigB64)
            put("device_id", deviceId)
            if (networkId.isNotEmpty()) put("network_id", networkId)
        }
        val sessReq = Request.Builder()
            .url("$hubBase/v1/hub/session")
            .post(sessBody.toString().toRequestBody(JSON_MEDIA))
            .build()

        httpClient.newCall(sessReq).execute().use { resp ->
            val raw = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                throw IllegalStateException("Hub session exchange failed (HTTP ${resp.code})")
            }
            val obj = JSONObject(raw)
            val ackSnow = obj.optString("snow_id", "").trim().uppercase(Locale.ROOT)
            val token = obj.optString("token", "").trim()
            if (token.isEmpty() || (ackSnow.isNotEmpty() && ackSnow != devKey.snowId)) {
                throw IllegalStateException("Hub returned invalid session token or mismatched snow_id.")
            }
            token
        }
    }

    private suspend fun handleHttpForwardEnvelope(
        ws: WebSocket,
        gen: Long,
        envelope: JSONObject,
        snowId: String
    ) {
        val requestId = envelope.optString("request_id", "").trim()
        if (requestId.isEmpty() || requestId.length > 128) return

        val responseObj: McpHttpResponse = requestSemaphore.withPermit {
            val method = envelope.optString("method", "").trim().uppercase(Locale.ROOT)
            if (method !in ALLOWED_METHODS) {
                McpHttpResponse.json(405, JSONObject().put("error", "method_not_allowed"))
            } else {
                val rawBodyB64 = envelope.optString("body_b64", "")
                val decodedBody = if (rawBodyB64.isEmpty()) {
                    ByteArray(0)
                } else {
                    try {
                        Base64.getDecoder().decode(rawBodyB64)
                    } catch (_: Exception) {
                        null
                    }
                }
                if (decodedBody == null) {
                    McpHttpResponse.json(400, JSONObject().put("error", "invalid_encoding"))
                } else if (decodedBody.size > maxForwardBodyBytes) {
                    McpHttpResponse.json(413, JSONObject().put("error", "payload_too_large"))
                } else {
                    val hdrMap = linkedMapOf<String, String>()
                    envelope.optJSONObject("headers")?.let { hdrObj ->
                        val keys = hdrObj.keys()
                        while (keys.hasNext()) {
                            val k = keys.next().lowercase(Locale.ROOT).trim()
                            if (k.isEmpty() || k in HOP_BY_HOP_HEADERS) continue
                            val v = hdrObj.optString(k, "")
                            hdrMap[k] = v
                        }
                    }
                    val cleanSubpath = normalizeForwardedSubpath(envelope.optString("path", "/mcp"), snowId)
                    val query = envelope.optString("query", "")
                    val remoteIp = hdrMap["x-forwarded-for"]?.substringBefore(',')?.trim() ?: "hub"
                    val mcpReq = McpHttpRequest(
                        method = method,
                        subpath = cleanSubpath,
                        query = query,
                        headers = hdrMap,
                        body = decodedBody,
                        remoteIp = remoteIp
                    )
                    try {
                        responder.handleForwardedHttp(mcpReq)
                    } catch (e: Exception) {
                        SafeLog.e(TAG, "Error handling forwarded MCP request: ${e.message}")
                        McpHttpResponse.json(500, JSONObject().put("error", "internal_error"))
                    }
                }
            }
        }

        if (manuallyStopped.get() || gen != generationCounter.get() || activeWebSocket !== ws) {
            return
        }

        val respHeadersJson = JSONObject()
        for ((k, v) in responseObj.headers) {
            if (k.lowercase(Locale.ROOT) !in HOP_BY_HOP_HEADERS) {
                respHeadersJson.put(k, v)
            }
        }
        val outFrame = JSONObject()
            .put("type", "mcp_http_response")
            .put("request_id", requestId)
            .put("status", responseObj.status)
            .put("headers", respHeadersJson)
            .put("body_b64", Base64.getEncoder().encodeToString(responseObj.body))

        ws.send(outFrame.toString())
    }

    private fun handleSocketClosed(gen: Long, code: Int, reason: String) {
        val shouldRetry: Boolean
        synchronized(lock) {
            if (gen != generationCounter.get()) return
            activeWebSocket = null
            isConnecting = false
            isConnected = false
            shouldRetry = !manuallyStopped.get() && autoReconnect && enabledProvider() && code != 4003
        }
        val errText = if (code == 1000) null else "Hub tunnel closed (code=$code): $reason"
        emitState(
            RelayMcpForwarderState(
                enabled = enabledProvider(),
                connected = false,
                registeredSnowId = safeSnowId(),
                mcpEndpointUrl = currentEndpointUrl(),
                sessionGeneration = gen,
                lastError = errText
            )
        )
        if (shouldRetry) {
            scheduleReconnect(errText)
        }
    }

    private fun failAttemptAndMaybeRetry(errorMessage: String) {
        synchronized(lock) {
            isConnecting = false
            isConnected = false
        }
        SafeLog.w(TAG, "Android MCP forwarder attempt failed: $errorMessage")
        emitState(
            RelayMcpForwarderState(
                enabled = enabledProvider(),
                connected = false,
                registeredSnowId = safeSnowId(),
                mcpEndpointUrl = currentEndpointUrl(),
                sessionGeneration = generationCounter.get(),
                lastError = errorMessage
            )
        )
        if (!manuallyStopped.get() && autoReconnect && enabledProvider()) {
            scheduleReconnect(errorMessage)
        }
    }

    private fun scheduleReconnect(lastErr: String?) {
        synchronized(lock) {
            if (manuallyStopped.get() || !autoReconnect || !enabledProvider()) return
            reconnectJob?.cancel()
            val attempt = reconnectAttempts.coerceAtMost(6)
            reconnectAttempts++
            val expDelay = (baseBackoffMs shl attempt).coerceAtMost(maxBackoffMs)
            val jitter = random.nextInt(500).toLong()
            val waitMs = (expDelay + jitter).coerceAtMost(maxBackoffMs)
            reconnectJob = scope.launch {
                delay(waitMs)
                if (!isActive || manuallyStopped.get() || !enabledProvider()) return@launch
                start(recoveryTakeover = false)
            }
        }
        if (!lastErr.isNullOrBlank()) {
            SafeLog.i(TAG, "Scheduled Android MCP tunnel reconnect ($lastErr)")
        }
    }

    internal fun resolveValidatedHubBaseUrl(): String? {
        val raw = hubHttpUrlProvider().trim()
        if (raw.isEmpty()) return null
        val converted = when {
            raw.startsWith("wss://", ignoreCase = true) -> "https://" + raw.substring(6)
            raw.startsWith("ws://", ignoreCase = true) -> "http://" + raw.substring(5)
            else -> raw
        }.trimEnd('/')
        val uri = try {
            URI(converted)
        } catch (_: Exception) {
            return null
        }
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return null
        val host = uri.host?.lowercase(Locale.ROOT) ?: return null
        val isLocalTestHost = host == "127.0.0.1" || host == "localhost" || host == "::1"
        if (scheme == "http" && (!allowInsecureLocalhostForTest || !isLocalTestHost)) {
            return null
        }
        if (scheme != "https" && scheme != "http") return null
        return if (uri.port > 0) "$scheme://${uri.host}:${uri.port}" else "$scheme://${uri.host}"
    }

    private fun toTunnelWsUrl(hubHttpBase: String): String {
        val wsBase = if (hubHttpBase.startsWith("https://")) {
            "wss://" + hubHttpBase.substring(8)
        } else {
            "ws://" + hubHttpBase.substring(7)
        }
        return "$wsBase/v1/tunnel"
    }

    private fun normalizeForwardedSubpath(rawPath: String, snowId: String): String {
        var clean = rawPath.trim().substringBefore('?')
        val prefix = "/u/$snowId"
        if (clean.startsWith(prefix, ignoreCase = true)) {
            clean = clean.substring(prefix.length)
        }
        if (clean.isEmpty()) return "/mcp"
        return if (clean.startsWith("/")) clean else "/$clean"
    }

    private fun safeSnowId(): String = try {
        deviceKeyProvider().snowId
    } catch (_: Exception) {
        ""
    }

    private fun emitState(newState: RelayMcpForwarderState) {
        _state.value = newState
        onStateChanged?.invoke(newState)
    }
}
