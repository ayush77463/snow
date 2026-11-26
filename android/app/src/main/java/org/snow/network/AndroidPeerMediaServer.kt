package org.snow.network

import org.json.JSONArray
import org.json.JSONObject
import org.snow.security.SafeLog
import org.snow.security.TokenStorage
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * Lightweight authenticated TLS HTTPS media endpoint for Direct Phone-to-Phone mode.
 *
 * Accepts bounded JPEG frames (<= 512 KiB) and serves active multi-sender frames
 * on port 8766 over TLS reusing the peer host certificate and token authentication.
 */
class AndroidPeerMediaServer(
    val requestedPort: Int = 8766,
    private val sslContext: SSLContext,
    private val tokenStorage: TokenStorage,
    private val peerTokenValidator: ((String) -> Boolean)? = null,
    private val activeProfileProvider: () -> String = { "full_control" }
) {
    companion object {
        private const val TAG = "AndroidPeerMediaServer"
        const val MAX_SCREEN_FRAME_BYTES = 524288
    }

    data class PeerScreenSlot(
        val senderDeviceId: String,
        val senderName: String,
        val senderPlatform: String,
        val sessionId: String,
        val frameSeq: Long,
        val width: Int,
        val height: Int,
        val fps: Float,
        val targetDeviceIds: List<String>,
        val state: String,
        val timestampMs: Long,
        val frameBytes: ByteArray?
    )

    private val isRunning = AtomicBoolean(false)
    private var serverSocket: SSLServerSocket? = null
    private var acceptThread: Thread? = null
    private val screenSessions = ConcurrentHashMap<String, PeerScreenSlot>()

    var boundPort: Int = requestedPort
        private set

    fun isListening(): Boolean = isRunning.get() && serverSocket != null

    fun setSessionStopped(deviceId: String?) {
        if (deviceId.isNullOrBlank() || deviceId == "all") {
            screenSessions.keys.forEach { k ->
                val prev = screenSessions[k] ?: return@forEach
                screenSessions[k] = prev.copy(state = "STOPPED", frameBytes = null)
            }
        } else {
            val prev = screenSessions[deviceId] ?: return
            screenSessions[deviceId] = prev.copy(state = "STOPPED", frameBytes = null)
        }
    }

    fun getActiveSenders(): List<PeerScreenSlot> {
        return screenSessions.values.filter { it.state == "STREAMING" }
    }

    fun getLatestFrame(senderId: String?): PeerScreenSlot? {
        if (!senderId.isNullOrBlank()) {
            val slot = screenSessions[senderId]
            return if (slot != null && slot.state == "STREAMING" && slot.frameBytes != null) slot else null
        }
        return screenSessions.values.firstOrNull { it.state == "STREAMING" && it.frameBytes != null }
    }

    @Synchronized
    fun start(): Boolean {
        if (isRunning.get()) return true
        return try {
            val factory = sslContext.serverSocketFactory
            val srv = factory.createServerSocket() as SSLServerSocket
            srv.reuseAddress = true
            srv.bind(InetSocketAddress(requestedPort), 16)
            boundPort = srv.localPort
            serverSocket = srv
            isRunning.set(true)

            acceptThread = Thread {
                while (isRunning.get()) {
                    try {
                        val sock = srv.accept() as SSLSocket
                        Thread { handleClient(sock) }.apply {
                            isDaemon = true
                            start()
                        }
                    } catch (_: Exception) {
                        if (!isRunning.get()) break
                    }
                }
            }.apply {
                isDaemon = true
                name = "SnowPeerMediaAccept"
                start()
            }
            SafeLog.i(TAG, "AndroidPeerMediaServer listening on TLS port $boundPort")
            true
        } catch (e: Exception) {
            SafeLog.w(TAG, "Failed starting AndroidPeerMediaServer on port $requestedPort: ${e.message}")
            stop()
            false
        }
    }

    @Synchronized
    fun stop() {
        if (!isRunning.getAndSet(false) && serverSocket == null) return
        try {
            serverSocket?.close()
        } catch (_: Exception) {}
        serverSocket = null
        acceptThread = null
        screenSessions.clear()
    }

    private fun isTokenAuthorized(headers: Map<String, String>): Boolean {
        val authHdr = headers["authorization"] ?: return false
        if (!authHdr.startsWith("Bearer ", ignoreCase = true)) return false
        val presented = authHdr.substring(7).trim()
        if (presented.isBlank()) return false
        val stored = tokenStorage.getToken()
        if (!stored.isNullOrBlank() && MessageDigest.isEqual(presented.toByteArray(), stored.toByteArray())) {
            return true
        }
        return peerTokenValidator?.invoke(presented) == true
    }

    private fun handleClient(socket: SSLSocket) {
        try {
            socket.soTimeout = 5000
            val input = socket.inputStream
            val output = socket.outputStream
            val requestLine = readLine(input) ?: return
            val parts = requestLine.split(" ")
            if (parts.size < 2) return
            val method = parts[0].uppercase()
            val fullTarget = parts[1]
            val qIdx = fullTarget.indexOf('?')
            val path = if (qIdx >= 0) fullTarget.substring(0, qIdx) else fullTarget
            val query = if (qIdx >= 0) fullTarget.substring(qIdx + 1) else ""

            val headers = mutableMapOf<String, String>()
            while (true) {
                val line = readLine(input) ?: break
                if (line.isEmpty()) break
                val colon = line.indexOf(':')
                if (colon > 0) {
                    headers[line.substring(0, colon).trim().lowercase()] = line.substring(colon + 1).trim()
                }
            }

            if (!isTokenAuthorized(headers)) {
                writeJson(output, 401, JSONObject().put("error", "Unauthorized"))
                return
            }
            if (activeProfileProvider().trim().lowercase() != "full_control") {
                writeJson(output, 403, JSONObject().put("error", "PERMISSION_DENIED"))
                return
            }

            val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
            if (contentLength > MAX_SCREEN_FRAME_BYTES) {
                writeJson(output, 413, JSONObject().put("error", "Payload exceeds $MAX_SCREEN_FRAME_BYTES bytes"))
                return
            }
            val body = if (contentLength > 0) readExact(input, contentLength) else ByteArray(0)

            when {
                method == "POST" && path == "/api/v1/screen/frame" -> {
                    val senderId = headers["x-snow-sender-id"] ?: headers["x-snow-device-id"] ?: "peer"
                    val senderName = headers["x-snow-sender-name"] ?: senderId
                    val platform = headers["x-snow-sender-platform"] ?: "android"
                    val sessionId = headers["x-snow-session-id"] ?: UUID.randomUUID().toString().take(8)
                    val seq = headers["x-snow-frame-seq"]?.toLongOrNull() ?: 0L
                    val width = headers["x-snow-frame-width"]?.toIntOrNull() ?: 0
                    val height = headers["x-snow-frame-height"]?.toIntOrNull() ?: 0
                    val fps = headers["x-snow-fps"]?.toFloatOrNull() ?: 2.0f
                    val targets = headers["x-snow-target-device-ids"]?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()
                    screenSessions[senderId] = PeerScreenSlot(
                        senderDeviceId = senderId,
                        senderName = senderName,
                        senderPlatform = platform,
                        sessionId = sessionId,
                        frameSeq = seq,
                        width = width,
                        height = height,
                        fps = fps,
                        targetDeviceIds = targets,
                        state = "STREAMING",
                        timestampMs = System.currentTimeMillis(),
                        frameBytes = body
                    )
                    writeJson(output, 200, JSONObject().put("status", "ACCEPTED").put("frame_size", body.size))
                }
                method == "GET" && path == "/api/v1/screen/senders" -> {
                    val arr = JSONArray()
                    getActiveSenders().forEach { s ->
                        arr.put(
                            JSONObject()
                                .put("sender_device_id", s.senderDeviceId)
                                .put("sender_name", s.senderName)
                                .put("sender_platform", s.senderPlatform)
                                .put("session_id", s.sessionId)
                                .put("frame_seq", s.frameSeq)
                                .put("frame_width", s.width)
                                .put("frame_height", s.height)
                                .put("fps", s.fps.toDouble())
                                .put("route_badge", "Wi-Fi • Zero Data")
                                .put("has_frame", s.frameBytes != null)
                        )
                    }
                    writeJson(output, 200, JSONObject().put("success", true).put("senders", arr))
                }
                method == "GET" && path == "/api/v1/screen/frame" -> {
                    val senderId = extractQueryParam(query, "sender_id") ?: extractQueryParam(query, "device_id")
                    val slot = getLatestFrame(senderId)
                    val bytes = slot?.frameBytes
                    if (slot == null || bytes == null || bytes.isEmpty()) {
                        writeEmpty(output, 204)
                    } else {
                        val hdr = "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: ${bytes.size}\r\nCache-Control: no-store\r\nX-Snow-Session-Id: ${slot.sessionId}\r\nX-Snow-Sender-Id: ${slot.senderDeviceId}\r\nX-Snow-Sender-Name: ${slot.senderName}\r\nX-Snow-Frame-Seq: ${slot.frameSeq}\r\nConnection: close\r\n\r\n"
                        output.write(hdr.toByteArray(Charsets.UTF_8))
                        output.write(bytes)
                        output.flush()
                    }
                }
                method == "POST" && path == "/api/v1/screen/stop" -> {
                    val senderId = headers["x-snow-sender-id"] ?: headers["x-snow-device-id"]
                    setSessionStopped(senderId)
                    writeJson(output, 200, JSONObject().put("status", "STOPPED"))
                }
                method == "POST" && path == "/api/v1/screen/subscribe" -> {
                    writeJson(output, 200, JSONObject().put("success", true))
                }
                else -> {
                    writeJson(output, 404, JSONObject().put("error", "Not found"))
                }
            }
        } catch (_: Exception) {
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {}
        }
    }

    private fun extractQueryParam(query: String, key: String): String? {
        if (query.isBlank()) return null
        return query.split("&").firstNotNullOfOrNull { pair ->
            val idx = pair.indexOf('=')
            if (idx > 0 && pair.substring(0, idx) == key) {
                java.net.URLDecoder.decode(pair.substring(idx + 1), "UTF-8")
            } else null
        }
    }

    private fun readLine(input: InputStream): String? {
        val baos = ByteArrayOutputStream()
        var prev = -1
        while (true) {
            val b = input.read()
            if (b == -1) return if (baos.size() == 0) null else String(baos.toByteArray(), Charsets.UTF_8)
            if (b == '\n'.code) {
                val arr = baos.toByteArray()
                val len = if (prev == '\r'.code && arr.isNotEmpty()) arr.size - 1 else arr.size
                return String(arr, 0, len, Charsets.UTF_8)
            }
            baos.write(b)
            prev = b
        }
    }

    private fun readExact(input: InputStream, count: Int): ByteArray {
        val buf = ByteArray(count)
        var readTotal = 0
        while (readTotal < count) {
            val n = input.read(buf, readTotal, count - readTotal)
            if (n <= 0) break
            readTotal += n
        }
        return if (readTotal == count) buf else buf.copyOf(readTotal)
    }

    private fun writeJson(output: OutputStream, status: Int, json: JSONObject) {
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        val hdr = "HTTP/1.1 $status OK\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        output.write(hdr.toByteArray(Charsets.UTF_8))
        output.write(bytes)
        output.flush()
    }

    private fun writeEmpty(output: OutputStream, status: Int) {
        val hdr = "HTTP/1.1 $status No Content\r\nConnection: close\r\n\r\n"
        output.write(hdr.toByteArray(Charsets.UTF_8))
        output.flush()
    }
}
