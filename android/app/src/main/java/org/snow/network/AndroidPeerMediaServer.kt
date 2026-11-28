package org.snow.network

import org.json.JSONArray
import org.json.JSONObject
import org.snow.security.SafeLog
import org.snow.security.TokenStorage
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/**
 * Explicit lifecycle states for peer-to-peer Android file transfers,
 * aligned with SNOW TransferManager semantics.
 */
enum class PeerTransferState {
    PENDING,
    ACCEPTED,
    TRANSFERRING,
    PAUSED,
    VERIFYING,
    COMPLETED,
    FAILED,
    CANCELLED;

    fun isTerminal(): Boolean = this == COMPLETED || this == FAILED || this == CANCELLED
}

/**
 * Mutable transfer session metadata guarded cleanly during chunked socket streaming.
 */
data class PeerTransferRecord(
    val transferId: String,
    val deviceId: String,
    val direction: String, // "UPLOAD" or "DOWNLOAD"
    val fileName: String,
    val fileSize: Long,
    val sha256: String,
    @Volatile var currentOffset: Long = 0L,
    @Volatile var state: PeerTransferState = PeerTransferState.ACCEPTED,
    @Volatile var errorMessage: String? = null,
    @Volatile var filePath: String? = null,
    val createdAtMs: Long = System.currentTimeMillis(),
    @Volatile var updatedAtMs: Long = System.currentTimeMillis()
) {
    val stateLock = Any()

    fun toJson(): JSONObject = JSONObject().apply {
        put("transfer_id", transferId)
        put("device_id", deviceId)
        put("direction", direction)
        put("file_name", fileName)
        put("file_size", fileSize)
        put("sha256", sha256)
        put("current_offset", currentOffset)
        put("offset", currentOffset)
        put("status", state.name)
        put("state", state.name)
        put("error_message", errorMessage ?: JSONObject.NULL)
    }
}

/**
 * Authenticated TLS HTTPS peer media and resumable large-file transfer server for Direct Phone-to-Phone mode.
 *
 * Security & streaming guarantees:
 * - Enforces per-device token verification via `X-Snow-Device-Id` + `Authorization: Bearer <token>`
 *   using constant-time comparison against `tokenStorage.getTokenForDevice(deviceId)`.
 * - Enforces 5-tier access profiles (`full_control` for screen frames;
 *   `full_control` / `files_and_clipboard` / `files_only` for file transfers).
 * - Streams transfer request and response bodies directly in bounded 64 KiB chunks (`Long` offsets up to 16 GiB)
 *   without whole-file `ByteArray` buffering.
 * - Verifies incremental/final SHA-256 and commits staged `.part` files atomically on completion.
 */
class AndroidPeerMediaServer(
    val requestedPort: Int = 8766,
    private val sslContext: SSLContext,
    private val tokenStorage: TokenStorage,
    private val peerTokenValidator: ((String) -> Boolean)? = null,
    private val activeProfileProvider: () -> String = { "full_control" },
    private val storageRootDir: File? = null,
    private val perDeviceProfileProvider: ((String) -> String)? = null,
    private val freeSpaceProvider: ((File) -> Long)? = null,
    val maxTransferSizeBytes: Long = MAX_SUPPORTED_TRANSFER_SIZE_BYTES
) {
    companion object {
        private const val TAG = "AndroidPeerMediaServer"
        const val MAX_SCREEN_FRAME_BYTES = 524288
        const val MAX_SMALL_JSON_BYTES = 32768
        const val MAX_HEADER_LINE_COUNT = 64
        const val MAX_HEADER_TOTAL_BYTES = 32768
        const val STREAM_CHUNK_SIZE = 64 * 1024 // 64 KiB
        const val MAX_SUPPORTED_TRANSFER_SIZE_BYTES = 16L * 1024L * 1024L * 1024L // 16 GiB
        private val SHA256_HEX_REGEX = Regex("^[a-f0-9]{64}$")
        private val TRANSFER_ID_REGEX = Regex("^[a-zA-Z0-9_\\-]{4,128}$")
        private val FORBIDDEN_FILENAMES = setOf("", ".", "..", "con", "prn", "aux", "nul")
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
    private val transfers = ConcurrentHashMap<String, PeerTransferRecord>()

    val transfersRoot: File = (storageRootDir ?: File(System.getProperty("java.io.tmpdir"), "snow_peer_transfers"))
        .absoluteFile
        .apply { mkdirs() }
    val partsRoot: File = File(transfersRoot, ".parts").apply { mkdirs() }

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

    /**
     * Register a host-initiated download transfer record so a paired peer can download it with HTTP Range resume.
     */
    fun registerDownloadTransfer(
        deviceId: String,
        file: File,
        sha256: String,
        transferId: String = UUID.randomUUID().toString(),
        fileSize: Long = file.length()
    ): PeerTransferRecord {
        require(deviceId.isNotBlank()) { "deviceId must not be blank" }
        val cleanSha = sha256.trim().lowercase()
        require(SHA256_HEX_REGEX.matches(cleanSha)) { "Invalid sha256 hex digest" }
        require(TRANSFER_ID_REGEX.matches(transferId)) { "Invalid transferId" }
        val rec = PeerTransferRecord(
            transferId = transferId,
            deviceId = deviceId.trim(),
            direction = "DOWNLOAD",
            fileName = sanitizeFilename(file.name),
            fileSize = fileSize,
            sha256 = cleanSha,
            currentOffset = 0L,
            state = PeerTransferState.ACCEPTED,
            filePath = file.absolutePath
        )
        transfers[transferId] = rec
        return rec
    }

    fun getTransfer(transferId: String): PeerTransferRecord? = transfers[transferId]

    fun revokeDevice(deviceId: String) {
        val cleanId = deviceId.trim()
        if (cleanId.isEmpty()) return
        for (rec in transfers.values) {
            if (rec.deviceId == cleanId) {
                synchronized(rec.stateLock) {
                    if (!rec.state.isTerminal()) {
                        rec.state = PeerTransferState.CANCELLED
                        rec.errorMessage = "Device access revoked"
                        rec.updatedAtMs = System.currentTimeMillis()
                    }
                }
                deletePartFile(rec.transferId)
            }
        }
        setSessionStopped(cleanId)
    }

    @Synchronized
    fun start(): Boolean {
        if (isRunning.get()) return true
        return try {
            val factory = sslContext.serverSocketFactory
            val srv = factory.createServerSocket() as SSLServerSocket
            srv.reuseAddress = true
            srv.bind(InetSocketAddress(requestedPort), 32)
            boundPort = srv.localPort
            serverSocket = srv
            isRunning.set(true)

            acceptThread = Thread {
                while (isRunning.get()) {
                    try {
                        val sock = srv.accept() as SSLSocket
                        Thread { handleClient(sock) }.apply {
                            isDaemon = true
                            name = "SnowPeerMediaConn"
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

    /**
     * Strict per-device authentication using `X-Snow-Device-Id` + `Authorization: Bearer <token>`.
     * Never silently falls back to a global token for peer requests.
     */
    internal fun authenticateDevice(headers: Map<String, String>): String? {
        val deviceId = headers["x-snow-device-id"]?.trim() ?: return null
        if (deviceId.isEmpty() || deviceId.length > 128) return null
        val authHdr = headers["authorization"] ?: return null
        if (!authHdr.startsWith("Bearer ", ignoreCase = true)) return null
        val presented = authHdr.substring(7).trim()
        if (presented.isEmpty()) return null

        val perDeviceStored = tokenStorage.getTokenForDevice(deviceId)
        if (!perDeviceStored.isNullOrBlank()) {
            val ok = MessageDigest.isEqual(
                presented.toByteArray(Charsets.UTF_8),
                perDeviceStored.toByteArray(Charsets.UTF_8)
            )
            return if (ok) deviceId else null
        }

        // Only allow custom test validator when no per-device token slots have been provisioned.
        if (tokenStorage.listStoredDeviceIds().isEmpty() && peerTokenValidator?.invoke(presented) == true) {
            return deviceId
        }
        return null
    }

    private fun isAuthorizedForRoute(deviceId: String, path: String): Boolean {
        val profile = (perDeviceProfileProvider?.invoke(deviceId) ?: activeProfileProvider())
            .trim()
            .lowercase()
        return when {
            path.startsWith("/api/v1/screen/") -> profile == "full_control"
            path.startsWith("/api/v1/transfers") -> {
                profile == "full_control" || profile == "files_and_clipboard" || profile == "files_only"
            }
            else -> profile == "full_control"
        }
    }

    private fun handleClient(socket: SSLSocket) {
        try {
            socket.soTimeout = 30_000
            val input = BufferedInputStream(socket.inputStream, STREAM_CHUNK_SIZE)
            val output = BufferedOutputStream(socket.outputStream, STREAM_CHUNK_SIZE)

            val requestLine = readLineBounded(input, 4096) ?: return
            val parts = requestLine.split(" ")
            if (parts.size < 2) {
                writeJson(output, 400, JSONObject().put("error", "Malformed HTTP request line"))
                return
            }
            val method = parts[0].uppercase()
            val fullTarget = parts[1]
            val qIdx = fullTarget.indexOf('?')
            val path = if (qIdx >= 0) fullTarget.substring(0, qIdx) else fullTarget
            val query = if (qIdx >= 0) fullTarget.substring(qIdx + 1) else ""

            val headers = mutableMapOf<String, String>()
            var headerLines = 0
            var totalHeaderBytes = 0
            while (true) {
                val line = readLineBounded(input, 8192) ?: break
                if (line.isEmpty()) break
                headerLines++
                totalHeaderBytes += line.length
                if (headerLines > MAX_HEADER_LINE_COUNT || totalHeaderBytes > MAX_HEADER_TOTAL_BYTES) {
                    writeJson(output, 431, JSONObject().put("error", "Headers too large"))
                    return
                }
                val colon = line.indexOf(':')
                if (colon > 0) {
                    headers[line.substring(0, colon).trim().lowercase()] = line.substring(colon + 1).trim()
                }
            }

            val authedDeviceId = authenticateDevice(headers)
            if (authedDeviceId == null) {
                writeJson(output, 401, JSONObject().put("error", "Unauthorized"))
                return
            }
            if (!isAuthorizedForRoute(authedDeviceId, path)) {
                writeJson(output, 403, JSONObject().put("error", "PERMISSION_DENIED"))
                return
            }

            when {
                // ---- Transfer endpoints (streamed, zero whole-body buffering) ----
                method == "POST" && path == "/api/v1/transfers/check-duplicate" -> {
                    handleCheckDuplicate(input, output, headers)
                }
                method == "POST" && path == "/api/v1/transfers/init" -> {
                    handleInitTransfer(input, output, headers, authedDeviceId)
                }
                method == "GET" && path == "/api/v1/transfers" -> {
                    val arr = JSONArray()
                    transfers.values.filter { it.deviceId == authedDeviceId }.forEach { arr.put(it.toJson()) }
                    writeJson(output, 200, JSONObject().put("success", true).put("transfers", arr))
                }
                method == "GET" && path.startsWith("/api/v1/transfers/upload/") && path.endsWith("/status") -> {
                    val tid = path.removePrefix("/api/v1/transfers/upload/").removeSuffix("/status")
                    handleTransferStatus(output, tid, authedDeviceId)
                }
                method == "GET" && path.startsWith("/api/v1/transfers/") && path.endsWith("/status") -> {
                    val tid = path.removePrefix("/api/v1/transfers/").removeSuffix("/status")
                    handleTransferStatus(output, tid, authedDeviceId)
                }
                (method == "POST" || method == "PUT") && path.startsWith("/api/v1/transfers/upload/") -> {
                    val tid = path.removePrefix("/api/v1/transfers/upload/")
                    handleUploadStream(input, output, headers, tid, authedDeviceId)
                }
                method == "GET" && path.startsWith("/api/v1/transfers/download/") -> {
                    val tid = path.removePrefix("/api/v1/transfers/download/")
                    handleDownloadStream(output, headers, tid, authedDeviceId)
                }
                method == "POST" && path.startsWith("/api/v1/transfers/") && path.endsWith("/cancel") -> {
                    val tid = path.removePrefix("/api/v1/transfers/").removeSuffix("/cancel")
                    handleCancelTransfer(output, tid, authedDeviceId)
                }

                // ---- Screen share endpoints (bounded <= 512 KiB JPEG frames) ----
                method == "POST" && path == "/api/v1/screen/frame" -> {
                    val contentLength = headers["content-length"]?.toLongOrNull() ?: 0L
                    if (contentLength < 0L || contentLength > MAX_SCREEN_FRAME_BYTES) {
                        writeJson(output, 413, JSONObject().put("error", "Payload exceeds $MAX_SCREEN_FRAME_BYTES bytes"))
                        return
                    }
                    val body = if (contentLength > 0L) readExact(input, contentLength.toInt()) else ByteArray(0)
                    val senderId = headers["x-snow-sender-id"] ?: headers["x-snow-device-id"] ?: authedDeviceId
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
                method == "GET" && path == "/api/v1/screen/status" -> {
                    val active = getActiveSenders()
                    val arr = JSONArray()
                    active.forEach { s ->
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
                                .put("has_frame", s.frameBytes != null)
                        )
                    }
                    writeJson(
                        output,
                        200,
                        JSONObject()
                            .put("success", true)
                            .put("active", active.isNotEmpty())
                            .put("sender_count", active.size)
                            .put("senders", arr)
                    )
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
                    val senderId = extractQueryParam(query, "sender_id")
                        ?: extractQueryParam(query, "device_id")
                        ?: headers["x-snow-sender-id"]
                        ?: headers["x-snow-device-id"]
                        ?: authedDeviceId
                    setSessionStopped(senderId)
                    writeJson(output, 200, JSONObject().put("status", "STOPPED").put("sender_device_id", senderId))
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

    private fun readSmallJsonBody(input: InputStream, headers: Map<String, String>): JSONObject? {
        val len = headers["content-length"]?.toLongOrNull() ?: return null
        if (len < 0L || len > MAX_SMALL_JSON_BYTES) return null
        val bytes = readExact(input, len.toInt())
        if (bytes.size != len.toInt()) return null
        return try {
            JSONObject(String(bytes, Charsets.UTF_8))
        } catch (_: Exception) {
            null
        }
    }

    private fun handleCheckDuplicate(input: InputStream, output: OutputStream, headers: Map<String, String>) {
        val body = readSmallJsonBody(input, headers)
            ?: return writeJson(output, 400, JSONObject().put("error", "Invalid JSON payload"))
        val rawName = body.optString("file_name", "").trim()
        val expectedSha = body.optString("sha256", "").trim().lowercase()
        val destFile = resolveSafeDestFile(rawName)
            ?: return writeJson(output, 400, JSONObject().put("error", "Invalid file_name"))
        if (!destFile.isFile) {
            writeJson(output, 200, JSONObject().put("already_exists", false).put("is_conflict", false).put("existing_sha256", JSONObject.NULL))
            return
        }
        val actual = computeFileSha256(destFile)
        val same = actual.equals(expectedSha, ignoreCase = true)
        writeJson(
            output,
            200,
            JSONObject()
                .put("already_exists", same)
                .put("is_conflict", !same)
                .put("existing_sha256", actual)
        )
    }

    private fun handleInitTransfer(
        input: InputStream,
        output: OutputStream,
        headers: Map<String, String>,
        deviceId: String
    ) {
        val body = readSmallJsonBody(input, headers)
            ?: return writeJson(output, 400, JSONObject().put("error", "Invalid JSON payload"))
        val rawName = body.optString("file_name", "").trim()
        val fileSize = body.optLong("file_size", -1L)
        val sha256 = body.optString("sha256", "").trim().lowercase()
        val direction = body.optString("direction", "UPLOAD").trim().uppercase()
        val requestedTid = body.optString("transfer_id", "").trim()

        val destFile = resolveSafeDestFile(rawName)
            ?: return writeJson(output, 400, JSONObject().put("error", "Invalid file_name"))
        if (fileSize < 0L || fileSize > maxTransferSizeBytes) {
            return writeJson(
                output,
                if (fileSize > maxTransferSizeBytes) 413 else 400,
                JSONObject().put("error", "Invalid or oversized file_size ($fileSize)")
            )
        }
        if (!SHA256_HEX_REGEX.matches(sha256)) {
            return writeJson(output, 400, JSONObject().put("error", "Invalid 64-char sha256 digest"))
        }
        if (direction != "UPLOAD" && direction != "DOWNLOAD") {
            return writeJson(output, 400, JSONObject().put("error", "direction must be UPLOAD or DOWNLOAD"))
        }

        val freeBytes = freeSpaceProvider?.invoke(transfersRoot) ?: transfersRoot.usableSpace
        if (direction == "UPLOAD" && fileSize > 0L && freeBytes < fileSize) {
            return writeJson(
                output,
                507,
                JSONObject()
                    .put("error", "Insufficient storage: need $fileSize bytes, available $freeBytes bytes")
                    .put("status", "INSUFFICIENT_STORAGE")
            )
        }

        val tid = if (requestedTid.isNotEmpty()) {
            if (!TRANSFER_ID_REGEX.matches(requestedTid)) {
                return writeJson(output, 400, JSONObject().put("error", "Invalid transfer_id format"))
            }
            if (transfers.containsKey(requestedTid)) {
                return writeJson(output, 409, JSONObject().put("error", "transfer_id already exists"))
            }
            requestedTid
        } else {
            UUID.randomUUID().toString()
        }

        val record = PeerTransferRecord(
            transferId = tid,
            deviceId = deviceId,
            direction = direction,
            fileName = destFile.name,
            fileSize = fileSize,
            sha256 = sha256,
            currentOffset = 0L,
            state = PeerTransferState.ACCEPTED
        )
        transfers[tid] = record
        writeJson(
            output,
            200,
            JSONObject()
                .put("transfer_id", tid)
                .put("resume_offset", 0L)
                .put("status", PeerTransferState.ACCEPTED.name)
                .put("state", PeerTransferState.ACCEPTED.name)
        )
    }

    private fun handleTransferStatus(output: OutputStream, tid: String, deviceId: String) {
        val rec = transfers[tid]
        if (rec == null || rec.deviceId != deviceId) {
            writeJson(output, 404, JSONObject().put("error", "Transfer not found"))
            return
        }
        writeJson(output, 200, rec.toJson())
    }

    private fun handleUploadStream(
        input: InputStream,
        output: OutputStream,
        headers: Map<String, String>,
        tid: String,
        deviceId: String
    ) {
        val rec = transfers[tid]
        if (rec == null || rec.deviceId != deviceId) {
            writeJson(output, 404, JSONObject().put("error", "Transfer not found"))
            return
        }
        if (rec.direction != "UPLOAD") {
            writeJson(output, 400, JSONObject().put("error", "Transfer direction is not UPLOAD"))
            return
        }

        val contentLength = headers["content-length"]?.toLongOrNull()
        if (contentLength == null || contentLength < 0L) {
            writeJson(output, 411, JSONObject().put("error", "Missing valid Content-Length header"))
            return
        }
        if (contentLength > maxTransferSizeBytes) {
            writeJson(output, 413, JSONObject().put("error", "Upload exceeds maximum supported transfer size"))
            return
        }

        val contentRange = headers["content-range"]
        val startOffset: Long
        if (!contentRange.isNullOrBlank()) {
            val match = Regex("""^bytes\s+(\d+)-(\d+)/(\d+|\*)$""", RegexOption.IGNORE_CASE).matchEntire(contentRange.trim())
                ?: return writeJson(output, 416, JSONObject().put("error", "Malformed Content-Range"))
            startOffset = match.groupValues[1].toLongOrNull() ?: -1L
            val endOffset = match.groupValues[2].toLongOrNull() ?: -1L
            val declaredTotal = match.groupValues[3].let { if (it == "*") rec.fileSize else it.toLongOrNull() ?: -1L }
            if (startOffset < 0L || endOffset < startOffset || declaredTotal != rec.fileSize || endOffset >= rec.fileSize) {
                return writeJson(output, 416, JSONObject().put("error", "Content-Range bounds mismatch"))
            }
            val expectedSpan = (endOffset - startOffset) + 1L
            if (expectedSpan != contentLength) {
                return writeJson(output, 400, JSONObject().put("error", "Content-Length does not match Content-Range span"))
            }
        } else {
            startOffset = 0L
            if (contentLength != rec.fileSize) {
                return writeJson(output, 400, JSONObject().put("error", "Content-Length mismatch with initialized file_size"))
            }
        }

        val partFile = getPartFile(tid)
        val freeBytes = freeSpaceProvider?.invoke(partsRoot) ?: partsRoot.usableSpace
        if (contentLength > 0L && freeBytes < contentLength) {
            return writeJson(output, 507, JSONObject().put("error", "Insufficient storage for incoming stream"))
        }

        synchronized(rec.stateLock) {
            if (rec.state.isTerminal()) {
                return writeJson(output, 409, JSONObject().put("error", "Transfer already in terminal state ${rec.state}"))
            }
            val existingLen = if (partFile.exists()) partFile.length() else 0L
            if (startOffset > 0L && startOffset != existingLen) {
                return writeJson(output, 409, JSONObject().put("error", "Resume offset mismatch: server has $existingLen bytes"))
            }
            if (startOffset == 0L && partFile.exists()) {
                partFile.delete()
            }
            rec.state = PeerTransferState.TRANSFERRING
            rec.updatedAtMs = System.currentTimeMillis()
        }

        var written = 0L
        var abortedByCancel = false
        var abortedByRevocation = false
        val buffer = ByteArray(STREAM_CHUNK_SIZE)
        try {
            RandomAccessFile(partFile, "rw").use { raf ->
                if (startOffset > 0L) {
                    raf.seek(startOffset)
                } else {
                    raf.setLength(0L)
                }
                while (written < contentLength) {
                    if (rec.state == PeerTransferState.CANCELLED) {
                        abortedByCancel = true
                        break
                    }
                    if (!isDeviceCurrentlyTrusted(deviceId)) {
                        abortedByRevocation = true
                        break
                    }
                    val toRead = minOf(buffer.size.toLong(), contentLength - written).toInt()
                    val n = input.read(buffer, 0, toRead)
                    if (n <= 0) {
                        throw IOException("Unexpected EOF while streaming upload ($written/$contentLength)")
                    }
                    raf.write(buffer, 0, n)
                    written += n
                    val newOffset = startOffset + written
                    rec.currentOffset = newOffset
                    rec.updatedAtMs = System.currentTimeMillis()
                }
                raf.fd.sync()
            }
        } catch (ioe: Exception) {
            synchronized(rec.stateLock) {
                if (!rec.state.isTerminal()) {
                    rec.state = PeerTransferState.PAUSED
                    rec.errorMessage = ioe.message ?: "Stream interrupted"
                    rec.updatedAtMs = System.currentTimeMillis()
                }
            }
            return writeJson(output, 400, JSONObject().put("error", ioe.message ?: "Upload stream interrupted").put("offset", rec.currentOffset))
        }

        if (abortedByCancel) {
            deletePartFile(tid)
            return writeJson(output, 409, JSONObject().put("error", "Transfer cancelled").put("status", PeerTransferState.CANCELLED.name))
        }
        if (abortedByRevocation) {
            revokeDevice(deviceId)
            return writeJson(output, 401, JSONObject().put("error", "Device access revoked"))
        }

        val currentTotal = startOffset + written
        if (currentTotal < rec.fileSize) {
            synchronized(rec.stateLock) {
                if (!rec.state.isTerminal()) {
                    rec.state = PeerTransferState.PAUSED
                    rec.currentOffset = currentTotal
                    rec.updatedAtMs = System.currentTimeMillis()
                }
            }
            return writeJson(
                output,
                206,
                JSONObject()
                    .put("status", PeerTransferState.PAUSED.name)
                    .put("state", PeerTransferState.PAUSED.name)
                    .put("transfer_id", tid)
                    .put("current_offset", currentTotal)
                    .put("offset", currentTotal)
            )
        }

        // Complete upload: verify SHA-256 across the complete .part file before atomic commit
        synchronized(rec.stateLock) {
            if (rec.state == PeerTransferState.CANCELLED) {
                deletePartFile(tid)
                return writeJson(output, 409, JSONObject().put("error", "Transfer cancelled"))
            }
            rec.state = PeerTransferState.VERIFYING
            rec.updatedAtMs = System.currentTimeMillis()
        }

        val actualSha = computeFileSha256(partFile)
        if (!actualSha.equals(rec.sha256, ignoreCase = true)) {
            synchronized(rec.stateLock) {
                rec.state = PeerTransferState.FAILED
                rec.errorMessage = "SHA-256 integrity mismatch"
                rec.updatedAtMs = System.currentTimeMillis()
            }
            deletePartFile(tid)
            return writeJson(output, 422, JSONObject().put("error", "SHA-256 integrity mismatch").put("expected", rec.sha256).put("actual", actualSha))
        }

        val finalDest = resolveConflictSafeDestFile(rec.fileName)
            ?: return writeJson(output, 500, JSONObject().put("error", "Unable to resolve safe destination"))
        finalDest.parentFile?.mkdirs()
        if (!partFile.renameTo(finalDest)) {
            streamMoveFallback(partFile, finalDest)
        }

        synchronized(rec.stateLock) {
            if (rec.state.isTerminal()) {
                return writeJson(output, 409, JSONObject().put("error", "Transfer cancelled before finalization"))
            }
            rec.currentOffset = rec.fileSize
            rec.filePath = finalDest.absolutePath
            rec.state = PeerTransferState.COMPLETED
            rec.errorMessage = null
            rec.updatedAtMs = System.currentTimeMillis()
        }

        writeJson(
            output,
            200,
            JSONObject()
                .put("status", PeerTransferState.COMPLETED.name)
                .put("state", PeerTransferState.COMPLETED.name)
                .put("transfer_id", tid)
                .put("sha256", actualSha)
                .put("bytes_transferred", rec.fileSize)
                .put("file_name", finalDest.name)
        )
    }

    private fun handleDownloadStream(
        output: OutputStream,
        headers: Map<String, String>,
        tid: String,
        deviceId: String
    ) {
        val rec = transfers[tid]
        if (rec == null || rec.deviceId != deviceId) {
            writeJson(output, 404, JSONObject().put("error", "Transfer not found"))
            return
        }
        val targetPath = rec.filePath ?: return writeJson(output, 404, JSONObject().put("error", "File unavailable"))
        val srcFile = File(targetPath)
        if (!srcFile.isFile) {
            return writeJson(output, 404, JSONObject().put("error", "Source file not found"))
        }

        val totalSize = srcFile.length()
        val rangeHdr = headers["range"]
        var isRange = false
        var start = 0L
        var end = if (totalSize > 0L) totalSize - 1L else -1L

        if (!rangeHdr.isNullOrBlank()) {
            val match = Regex("""^bytes=(\d+)-(\d*)$""", RegexOption.IGNORE_CASE).matchEntire(rangeHdr.trim())
                ?: run {
                    output.write("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */$totalSize\r\nConnection: close\r\n\r\n".toByteArray())
                    output.flush()
                    return
                }
            val parsedStart = match.groupValues[1].toLongOrNull() ?: -1L
            val parsedEnd = if (match.groupValues[2].isEmpty()) totalSize - 1L else (match.groupValues[2].toLongOrNull() ?: -1L)
            if (totalSize == 0L || parsedStart < 0L || parsedStart >= totalSize || parsedEnd < parsedStart || parsedEnd >= totalSize) {
                output.write("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */$totalSize\r\nConnection: close\r\n\r\n".toByteArray())
                output.flush()
                return
            }
            start = parsedStart
            end = parsedEnd
            isRange = true
        }

        val bytesToSend = if (totalSize == 0L) 0L else (end - start + 1L)
        synchronized(rec.stateLock) {
            if (rec.state == PeerTransferState.CANCELLED) {
                return writeJson(output, 409, JSONObject().put("error", "Transfer cancelled"))
            }
            if (!rec.state.isTerminal()) {
                rec.state = PeerTransferState.TRANSFERRING
                rec.updatedAtMs = System.currentTimeMillis()
            }
        }

        val hdrBuilder = StringBuilder()
        if (isRange) {
            hdrBuilder.append("HTTP/1.1 206 Partial Content\r\n")
            hdrBuilder.append("Content-Range: bytes $start-$end/$totalSize\r\n")
        } else {
            hdrBuilder.append("HTTP/1.1 200 OK\r\n")
        }
        hdrBuilder.append("Content-Type: application/octet-stream\r\n")
        hdrBuilder.append("Content-Length: $bytesToSend\r\n")
        hdrBuilder.append("Accept-Ranges: bytes\r\n")
        hdrBuilder.append("Cache-Control: no-store\r\n")
        hdrBuilder.append("Connection: close\r\n\r\n")
        output.write(hdrBuilder.toString().toByteArray(Charsets.UTF_8))

        val buffer = ByteArray(STREAM_CHUNK_SIZE)
        var sent = 0L
        if (bytesToSend > 0L) {
            RandomAccessFile(srcFile, "r").use { raf ->
                raf.seek(start)
                while (sent < bytesToSend) {
                    if (rec.state == PeerTransferState.CANCELLED || !isDeviceCurrentlyTrusted(deviceId)) {
                        break
                    }
                    val toRead = minOf(buffer.size.toLong(), bytesToSend - sent).toInt()
                    val n = raf.read(buffer, 0, toRead)
                    if (n <= 0) break
                    output.write(buffer, 0, n)
                    sent += n
                    rec.currentOffset = start + sent
                    rec.updatedAtMs = System.currentTimeMillis()
                }
            }
        }
        output.flush()

        synchronized(rec.stateLock) {
            if (!rec.state.isTerminal() && sent == bytesToSend && (totalSize == 0L || end == totalSize - 1L)) {
                rec.currentOffset = totalSize
                rec.state = PeerTransferState.COMPLETED
                rec.updatedAtMs = System.currentTimeMillis()
            } else if (!rec.state.isTerminal()) {
                rec.state = PeerTransferState.PAUSED
                rec.updatedAtMs = System.currentTimeMillis()
            }
        }
    }

    private fun handleCancelTransfer(output: OutputStream, tid: String, deviceId: String) {
        val rec = transfers[tid]
        if (rec == null || rec.deviceId != deviceId) {
            writeJson(output, 404, JSONObject().put("error", "Transfer not found"))
            return
        }
        val cancelled: Boolean
        synchronized(rec.stateLock) {
            cancelled = if (rec.state.isTerminal()) {
                false
            } else {
                rec.state = PeerTransferState.CANCELLED
                rec.errorMessage = "Cancelled by requester"
                rec.updatedAtMs = System.currentTimeMillis()
                true
            }
        }
        deletePartFile(tid)
        writeJson(
            output,
            200,
            JSONObject()
                .put("status", PeerTransferState.CANCELLED.name)
                .put("state", PeerTransferState.CANCELLED.name)
                .put("transfer_id", tid)
                .put("cancelled", cancelled)
        )
    }

    private fun isDeviceCurrentlyTrusted(deviceId: String): Boolean {
        val perDevice = tokenStorage.getTokenForDevice(deviceId)
        if (!perDevice.isNullOrBlank()) return true
        return tokenStorage.listStoredDeviceIds().isEmpty() && peerTokenValidator != null
    }

    private fun sanitizeFilename(raw: String): String {
        if (raw.contains('/') || raw.contains('\\')) {
            throw IllegalArgumentException("Path separators forbidden")
        }
        val clean = raw.trim().replace(Regex("[^a-zA-Z0-9._\\- ()]"), "_")
        if (clean.isEmpty() || FORBIDDEN_FILENAMES.contains(clean.lowercase()) || clean.startsWith(".")) {
            throw IllegalArgumentException("Unsafe filename")
        }
        return clean
    }

    private fun resolveSafeDestFile(rawName: String): File? {
        return try {
            val clean = sanitizeFilename(rawName)
            val rootCanon = transfersRoot.canonicalPath
            val cand = File(transfersRoot, clean).canonicalFile
            if (!cand.canonicalPath.startsWith(rootCanon + File.separator)) return null
            cand
        } catch (_: Exception) {
            null
        }
    }

    private fun resolveConflictSafeDestFile(cleanName: String): File? {
        val base = resolveSafeDestFile(cleanName) ?: return null
        if (!base.exists()) return base
        val dot = cleanName.lastIndexOf('.')
        val stem = if (dot > 0) cleanName.substring(0, dot) else cleanName
        val ext = if (dot > 0) cleanName.substring(dot) else ""
        for (i in 1..999) {
            val alt = resolveSafeDestFile("${stem}_$i$ext") ?: continue
            if (!alt.exists()) return alt
        }
        return resolveSafeDestFile("${stem}_${UUID.randomUUID().toString().take(8)}$ext")
    }

    private fun getPartFile(transferId: String): File {
        val cleanId = transferId.replace(Regex("[^a-zA-Z0-9_\\-]"), "")
        return File(partsRoot, "$cleanId.part").canonicalFile
    }

    private fun deletePartFile(transferId: String) {
        try {
            getPartFile(transferId).delete()
        } catch (_: Exception) {}
    }

    private fun computeFileSha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(STREAM_CHUNK_SIZE)
        FileInputStream(file).use { fis ->
            while (true) {
                val n = fis.read(buf)
                if (n <= 0) break
                digest.update(buf, 0, n)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun streamMoveFallback(partFile: File, finalDest: File) {
        val tmpDest = File(finalDest.parentFile, ".${finalDest.name}.${UUID.randomUUID().toString().take(6)}.tmp")
        val buf = ByteArray(STREAM_CHUNK_SIZE)
        FileInputStream(partFile).use { input ->
            java.io.FileOutputStream(tmpDest).use { out ->
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    out.write(buf, 0, n)
                }
                out.fd.sync()
            }
        }
        if (!tmpDest.renameTo(finalDest)) {
            if (finalDest.exists()) finalDest.delete()
            if (!tmpDest.renameTo(finalDest)) {
                tmpDest.delete()
                throw IOException("Failed finalizing destination file")
            }
        }
        partFile.delete()
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

    private fun readLineBounded(input: InputStream, maxLen: Int): String? {
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
            if (baos.size() >= maxLen) {
                throw IOException("Header line exceeded $maxLen bytes")
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

    private fun reasonPhrase(status: Int): String = when (status) {
        200 -> "OK"
        204 -> "No Content"
        206 -> "Partial Content"
        400 -> "Bad Request"
        401 -> "Unauthorized"
        403 -> "Forbidden"
        404 -> "Not Found"
        409 -> "Conflict"
        411 -> "Length Required"
        413 -> "Payload Too Large"
        416 -> "Range Not Satisfiable"
        422 -> "Unprocessable Entity"
        431 -> "Request Header Fields Too Large"
        507 -> "Insufficient Storage"
        else -> "Error"
    }

    private fun writeJson(output: OutputStream, status: Int, json: JSONObject) {
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        val hdr = "HTTP/1.1 $status ${reasonPhrase(status)}\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        output.write(hdr.toByteArray(Charsets.UTF_8))
        output.write(bytes)
        output.flush()
    }

    private fun writeEmpty(output: OutputStream, status: Int) {
        val hdr = "HTTP/1.1 $status ${reasonPhrase(status)}\r\nConnection: close\r\n\r\n"
        output.write(hdr.toByteArray(Charsets.UTF_8))
        output.flush()
    }
}
