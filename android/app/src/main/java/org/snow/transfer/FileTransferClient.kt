package org.snow.transfer

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import org.json.JSONObject
import org.snow.security.CertPinStorage
import org.snow.security.EncryptedCertPinStorage
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.SafeLog
import org.snow.security.SnowTrustManager
import org.snow.security.TlsConfig
import org.snow.security.TokenStorage
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Client for reliable, authenticated, bidirectional streaming file transfers between
 * Android and the SNOW Desktop Core.
 *
 * Implements Sub-Milestones 3.1–3.4:
 * - 3.1: Authenticated HTTPS streaming using shared TLS certificates & bearer tokens.
 * - 3.2: 64 KiB streaming SHA-256 calculation and end-to-end integrity verification.
 * - 3.3: Temporary .part file handling and crash recovery.
 * - 3.4: Resumable chunked upload (Content-Range), resumable download (HTTP Range),
 *        and duplicate detection.
 */
open class FileTransferClient(
    private val context: Context,
    private val deviceId: String,
    private val certPinStorage: CertPinStorage? = null,
    private val tokenStorage: TokenStorage? = null,
    private val useTls: Boolean = true,
    customClient: OkHttpClient? = null,
    private val targetDeviceIdProvider: (() -> String?)? = null
) {
    companion object {
        const val TAG = "FileTransferClient"
        const val CHUNK_SIZE = 64 * 1024 // 64 KiB bounded streaming chunks
        private val OCTET_STREAM = "application/octet-stream".toMediaType()
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        /**
         * Compute SHA-256 digest over an InputStream in bounded 64 KiB chunks.
         */
        fun computeSha256(inputStream: InputStream): String {
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(CHUNK_SIZE)
            var bytesRead: Int
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        /**
         * Compute SHA-256 digest over a File in bounded 64 KiB chunks.
         */
        fun computeSha256(file: File): String {
            return FileInputStream(file).use { computeSha256(it) }
        }
    }

    data class TransferProgress(
        val transferId: String,
        val bytesTransferred: Long,
        val totalBytes: Long,
        val percent: Int
    )

    data class DuplicateCheckResult(
        val alreadyExists: Boolean,
        val isConflict: Boolean,
        val existingSha256: String?
    )

    sealed class TransferResult {
        data class Success(val transferId: String, val sha256: String, val file: File) : TransferResult()
        data class Duplicate(val fileName: String, val sha256: String) : TransferResult()
        data class Error(val transferId: String?, val message: String, val code: Int? = null) : TransferResult()
    }

    sealed interface WallpaperResult {
        data class Updated(val bytes: ByteArray, val etag: String?) : WallpaperResult {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is Updated) return false
                return bytes.contentEquals(other.bytes) && etag == other.etag
            }
            override fun hashCode(): Int {
                return 31 * bytes.contentHashCode() + (etag?.hashCode() ?: 0)
            }
        }
        data object NotModified : WallpaperResult
        data object Unavailable : WallpaperResult
    }

    data class AppUpdateInfo(
        val versionCode: Int,
        val versionName: String,
        val sizeBytes: Long,
        val sha256: String,
        val available: Boolean
    )

    private val httpClient: OkHttpClient = customClient ?: buildHttpClient()
    private val activeCall = AtomicReference<Call?>(null)
    private val transferCancelled = AtomicBoolean(false)

    /**
     * Cancel any active in-flight HTTP file upload or download immediately.
     */
    fun cancelActiveTransfer() {
        transferCancelled.set(true)
        activeCall.getAndSet(null)?.cancel()
    }

    private fun buildHttpClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)

        if (useTls) {
            val storage = certPinStorage ?: EncryptedCertPinStorage(context)
            val trustManager = SnowTrustManager(
                pinStorage = storage,
                targetDeviceIdProvider = targetDeviceIdProvider
            )
            val sslContext = TlsConfig.createSslContext(trustManager)
            builder.sslSocketFactory(sslContext.socketFactory, trustManager)
            builder.hostnameVerifier(TlsConfig.createHostnameVerifier(storage, targetDeviceIdProvider))
        }

        return builder.build()
    }

    private fun getAuthToken(): String? {
        val storage = tokenStorage ?: return null
        val targetId = targetDeviceIdProvider?.invoke()?.trim()?.takeIf { it.isNotEmpty() }
        if (targetId != null) {
            storage.getTokenForDevice(targetId)?.let { return it }
            if (storage.listStoredDeviceIds().isEmpty()) {
                return storage.getToken()
            }
            return null
        }
        return storage.getToken()
    }

    private fun getBaseUrl(serverHost: String, transferPort: Int): String {
        val scheme = if (useTls) "https" else "http"
        return "$scheme://${serverHost.trim()}:$transferPort"
    }

    /**
     * Check if a file with the given name and SHA-256 hash already exists on the desktop core.
     */
    suspend fun checkDuplicate(
        serverHost: String,
        transferPort: Int,
        fileName: String,
        sha256: String
    ): DuplicateCheckResult = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val url = "$baseUrl/api/v1/transfers/check-duplicate"

        val jsonBody = JSONObject().apply {
            put("file_name", fileName)
            put("sha256", sha256)
        }.toString()

        val token = getAuthToken() ?: ""
        val request = Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)
            .post(jsonBody.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        try {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    SafeLog.w(TAG, "Duplicate check failed with HTTP ${response.code}")
                    return@withContext DuplicateCheckResult(false, false, null)
                }
                val bodyStr = response.body?.string() ?: "{}"
                val json = JSONObject(bodyStr)
                DuplicateCheckResult(
                    alreadyExists = json.optBoolean("already_exists", false),
                    isConflict = json.optBoolean("is_conflict", false),
                    existingSha256 = json.optString("existing_sha256", "").takeIf { it.isNotBlank() }
                )
            }
        } catch (e: Exception) {
            SafeLog.e(TAG, "Exception during duplicate check: ${e.message}", e)
            DuplicateCheckResult(false, false, null)
        }
    }

    /**
     * Initialize a transfer session on the desktop server.
     */
    suspend fun initTransfer(
        serverHost: String,
        transferPort: Int,
        fileName: String,
        fileSize: Long,
        sha256: String,
        direction: String = "UPLOAD"
    ): Pair<String, Long>? = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val url = "$baseUrl/api/v1/transfers/init"

        val jsonBody = JSONObject().apply {
            put("file_name", fileName)
            put("file_size", fileSize)
            put("sha256", sha256)
            put("direction", direction)
        }.toString()

        val token = getAuthToken() ?: ""
        val request = Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)
            .post(jsonBody.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        try {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    SafeLog.w(TAG, "Transfer initialization failed: HTTP ${response.code}")
                    return@withContext null
                }
                val bodyStr = response.body?.string() ?: "{}"
                val json = JSONObject(bodyStr)
                val transferId = json.getString("transfer_id")
                val resumeOffset = json.optLong("resume_offset", 0L)
                Pair(transferId, resumeOffset)
            }
        } catch (e: Exception) {
            SafeLog.e(TAG, "Exception during transfer init: ${e.message}", e)
            null
        }
    }

    /**
     * Upload a local File to the desktop server with 64 KiB chunk streaming,
     * resume support, and progress reporting.
     */
    open suspend fun uploadFile(
        serverHost: String,
        transferPort: Int,
        file: File,
        onProgress: ((TransferProgress) -> Unit)? = null
    ): TransferResult = withContext(Dispatchers.IO) {
        val fileName = file.name
        val fileSize = file.length()
        val sha256 = computeSha256(file)

        // 1. Check duplicate
        val dupResult = checkDuplicate(serverHost, transferPort, fileName, sha256)
        if (dupResult.alreadyExists) {
            SafeLog.i(TAG, "File '$fileName' already exists on desktop core with matching SHA-256.")
            return@withContext TransferResult.Duplicate(fileName, sha256)
        }

        // 2. Initialize transfer session
        val init = initTransfer(serverHost, transferPort, fileName, fileSize, sha256, "UPLOAD")
            ?: return@withContext TransferResult.Error(null, "Failed to initialize upload session.")
        val (transferId, resumeOffset) = init

        // 3. Prepare streaming request body
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val uploadUrl = "$baseUrl/api/v1/transfers/upload/$transferId"

        val requestBody = object : RequestBody() {
            override fun contentType() = OCTET_STREAM
            override fun contentLength() = fileSize - resumeOffset

            override fun writeTo(sink: BufferedSink) {
                FileInputStream(file).use { input ->
                    if (resumeOffset > 0) {
                        input.skip(resumeOffset)
                    }
                    val buffer = ByteArray(CHUNK_SIZE)
                    var bytesRead: Int
                    var totalWritten = resumeOffset

                    while (input.read(buffer).also { bytesRead = it } != -1) {
                        if (transferCancelled.get() || Thread.currentThread().isInterrupted) {
                            throw IOException("Transfer cancelled")
                        }
                        sink.write(buffer, 0, bytesRead)
                        totalWritten += bytesRead
                        val percent = if (fileSize > 0) ((totalWritten * 100) / fileSize).toInt() else 100
                        onProgress?.invoke(
                            TransferProgress(
                                transferId = transferId,
                                bytesTransferred = totalWritten,
                                totalBytes = fileSize,
                                percent = percent
                            )
                        )
                    }
                }
            }
        }

        val token = getAuthToken() ?: ""
        val reqBuilder = Request.Builder()
            .url(uploadUrl)
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)
            .addHeader("X-Snow-Filename", fileName)
            .addHeader("X-Snow-Filesize", fileSize.toString())
            .addHeader("X-Snow-SHA256", sha256)

        if (resumeOffset > 0) {
            reqBuilder.addHeader("Content-Range", "bytes $resumeOffset-${fileSize - 1}/$fileSize")
        }

        val request = reqBuilder.post(requestBody).build()
        transferCancelled.set(false)
        val call = httpClient.newCall(request)
        activeCall.set(call)

        try {
            call.execute().use { response ->
                if (response.isSuccessful) {
                    val bodyStr = response.body?.string() ?: "{}"
                    val json = JSONObject(bodyStr)
                    val verifiedHash = json.optString("sha256", sha256)
                    SafeLog.i(TAG, "Upload completed successfully. Verified SHA-256: $verifiedHash")
                    TransferResult.Success(transferId, verifiedHash, file)
                } else if (response.code == 422) {
                    SafeLog.e(TAG, "SHA-256 integrity verification rejected by desktop core (422).")
                    TransferResult.Error(transferId, "Integrity verification failed (HTTP 422).", 422)
                } else {
                    SafeLog.w(TAG, "Upload failed with HTTP ${response.code}")
                    TransferResult.Error(transferId, "Upload failed with HTTP ${response.code}", response.code)
                }
            }
        } catch (e: CancellationException) {
            call.cancel()
            throw e
        } catch (e: Exception) {
            if (transferCancelled.get() || call.isCanceled()) {
                SafeLog.i(TAG, "Upload cancelled by user: $fileName")
                TransferResult.Error(transferId, "Transfer cancelled")
            } else {
                SafeLog.e(TAG, "Upload exception: ${e.message}", e)
                TransferResult.Error(transferId, e.message ?: "Upload network exception")
            }
        } finally {
            activeCall.compareAndSet(call, null)
        }
    }

    /**
     * Upload an arbitrary content stream from Android Storage Access Framework (SAF) Uri.
     */
    suspend fun uploadUri(
        serverHost: String,
        transferPort: Int,
        uri: Uri,
        fileName: String,
        fileSize: Long,
        onProgress: ((TransferProgress) -> Unit)? = null
    ): TransferResult = withContext(Dispatchers.IO) {
        // Compute SHA-256
        val sha256 = context.contentResolver.openInputStream(uri)?.use { computeSha256(it) }
            ?: return@withContext TransferResult.Error(null, "Unable to read URI stream for digest.")

        // Duplicate check
        val dupResult = checkDuplicate(serverHost, transferPort, fileName, sha256)
        if (dupResult.alreadyExists) {
            return@withContext TransferResult.Duplicate(fileName, sha256)
        }

        // Init transfer
        val init = initTransfer(serverHost, transferPort, fileName, fileSize, sha256, "UPLOAD")
            ?: return@withContext TransferResult.Error(null, "Failed to initialize upload session.")
        val (transferId, resumeOffset) = init

        val baseUrl = getBaseUrl(serverHost, transferPort)
        val uploadUrl = "$baseUrl/api/v1/transfers/upload/$transferId"

        val requestBody = object : RequestBody() {
            override fun contentType() = OCTET_STREAM
            override fun contentLength() = fileSize - resumeOffset

            override fun writeTo(sink: BufferedSink) {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    if (resumeOffset > 0) {
                        input.skip(resumeOffset)
                    }
                    val buffer = ByteArray(CHUNK_SIZE)
                    var bytesRead: Int
                    var totalWritten = resumeOffset

                    while (input.read(buffer).also { bytesRead = it } != -1) {
                        if (transferCancelled.get() || Thread.currentThread().isInterrupted) {
                            throw IOException("Transfer cancelled")
                        }
                        sink.write(buffer, 0, bytesRead)
                        totalWritten += bytesRead
                        val percent = if (fileSize > 0) ((totalWritten * 100) / fileSize).toInt() else 100
                        onProgress?.invoke(
                            TransferProgress(
                                transferId = transferId,
                                bytesTransferred = totalWritten,
                                totalBytes = fileSize,
                                percent = percent
                            )
                        )
                    }
                }
            }
        }

        val token = getAuthToken() ?: ""
        val reqBuilder = Request.Builder()
            .url(uploadUrl)
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)
            .addHeader("X-Snow-Filename", fileName)
            .addHeader("X-Snow-Filesize", fileSize.toString())
            .addHeader("X-Snow-SHA256", sha256)

        if (resumeOffset > 0) {
            reqBuilder.addHeader("Content-Range", "bytes $resumeOffset-${fileSize - 1}/$fileSize")
        }

        val request = reqBuilder.post(requestBody).build()
        transferCancelled.set(false)
        val call = httpClient.newCall(request)
        activeCall.set(call)

        try {
            call.execute().use { response ->
                if (response.isSuccessful) {
                    val bodyStr = response.body?.string() ?: "{}"
                    val json = JSONObject(bodyStr)
                    val verifiedHash = json.optString("sha256", sha256)
                    TransferResult.Success(transferId, verifiedHash, File(fileName))
                } else if (response.code == 422) {
                    TransferResult.Error(transferId, "Integrity verification failed (HTTP 422).", 422)
                } else {
                    TransferResult.Error(transferId, "Upload failed with HTTP ${response.code}", response.code)
                }
            }
        } catch (e: CancellationException) {
            call.cancel()
            throw e
        } catch (e: Exception) {
            if (transferCancelled.get() || call.isCanceled()) {
                SafeLog.i(TAG, "Upload URI cancelled by user: $fileName")
                TransferResult.Error(transferId, "Transfer cancelled")
            } else {
                SafeLog.e(TAG, "Upload URI exception: ${e.message}", e)
                TransferResult.Error(transferId, e.message ?: "Upload network exception")
            }
        } finally {
            activeCall.compareAndSet(call, null)
        }
    }

    /**
     * Download a file from desktop server with support for HTTP Range resume and
     * SHA-256 verification before atomic commit to final destination.
     */
    suspend fun downloadFile(
        serverHost: String,
        transferPort: Int,
        transferId: String,
        destinationFile: File,
        expectedSha256: String,
        resume: Boolean = true,
        onProgress: ((TransferProgress) -> Unit)? = null
    ): TransferResult = withContext(Dispatchers.IO) {
        val partFile = File(destinationFile.parentFile, "${destinationFile.name}.part")
        destinationFile.parentFile?.mkdirs()

        val resumeOffset = if (resume && partFile.exists()) partFile.length() else 0L

        val baseUrl = getBaseUrl(serverHost, transferPort)
        val downloadUrl = "$baseUrl/api/v1/transfers/download/$transferId"

        val token = getAuthToken() ?: ""
        val reqBuilder = Request.Builder()
            .url(downloadUrl)
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)

        if (resumeOffset > 0) {
            reqBuilder.addHeader("Range", "bytes=$resumeOffset-")
        }

        val request = reqBuilder.get().build()
        transferCancelled.set(false)
        val call = httpClient.newCall(request)
        activeCall.set(call)

        try {
            call.execute().use { response ->
                if (response.code != 200 && response.code != 206) {
                    return@withContext TransferResult.Error(
                        transferId,
                        "Download failed with HTTP ${response.code}",
                        response.code
                    )
                }

                val append = response.code == 206
                val body = response.body ?: return@withContext TransferResult.Error(
                    transferId,
                    "Empty response body"
                )

                val contentLength = body.contentLength()
                val totalExpected = if (append) resumeOffset + contentLength else contentLength

                body.byteStream().use { input ->
                    FileOutputStream(partFile, append).use { output ->
                        val buffer = ByteArray(CHUNK_SIZE)
                        var bytesRead: Int
                        var downloaded = if (append) resumeOffset else 0L

                        while (input.read(buffer).also { bytesRead = it } != -1) {
                            if (transferCancelled.get() || Thread.currentThread().isInterrupted) {
                                throw IOException("Transfer cancelled")
                            }
                            output.write(buffer, 0, bytesRead)
                            downloaded += bytesRead
                            val percent = if (totalExpected > 0) ((downloaded * 100) / totalExpected).toInt() else 100
                            onProgress?.invoke(
                                TransferProgress(
                                    transferId = transferId,
                                    bytesTransferred = downloaded,
                                    totalBytes = totalExpected,
                                    percent = percent
                                )
                            )
                        }
                    }
                }

                // Verify integrity
                val actualSha256 = computeSha256(partFile)
                if (!actualSha256.equals(expectedSha256.trim(), ignoreCase = true)) {
                    partFile.delete()
                    return@withContext TransferResult.Error(
                        transferId,
                        "Downloaded file integrity mismatch: expected $expectedSha256, got $actualSha256",
                        422
                    )
                }

                // Atomic commit to target destination
                if (destinationFile.exists()) {
                    destinationFile.delete()
                }
                if (!partFile.renameTo(destinationFile)) {
                    // Fallback to copy and delete if rename fails
                    partFile.copyTo(destinationFile, overwrite = true)
                    partFile.delete()
                }

                SafeLog.i(TAG, "Download completed and verified: ${destinationFile.name}")
                TransferResult.Success(transferId, actualSha256, destinationFile)
            }
        } catch (e: CancellationException) {
            call.cancel()
            partFile.delete()
            throw e
        } catch (e: Exception) {
            if (transferCancelled.get() || call.isCanceled()) {
                partFile.delete()
                SafeLog.i(TAG, "Download cancelled by user: ${destinationFile.name}")
                TransferResult.Error(transferId, "Transfer cancelled")
            } else {
                SafeLog.e(TAG, "Download exception: ${e.message}", e)
                TransferResult.Error(transferId, e.message ?: "Download exception")
            }
        } finally {
            activeCall.compareAndSet(call, null)
        }
    }

    data class ScreenSenderInfo(
        val senderDeviceId: String,
        val senderName: String,
        val senderPlatform: String,
        val sessionId: String,
        val fps: Float,
        val frameWidth: Int,
        val frameHeight: Int,
        val frameSeq: Long,
        val routeBadge: String,
        val hasFrame: Boolean
    )

    data class ScreenFrameResult(
        val bytes: ByteArray,
        val sessionId: String,
        val senderId: String,
        val senderName: String,
        val frameSeq: Long,
        val timestamp: String
    )

    /**
     * Post a single bounded JPEG screen frame to the desktop HTTP transfer server.
     */
    suspend fun postScreenFrame(
        serverHost: String,
        transferPort: Int,
        frameBytes: ByteArray,
        sessionId: String,
        width: Int,
        height: Int,
        fps: Float,
        senderId: String? = null,
        senderName: String? = null,
        senderPlatform: String = "android",
        frameSeq: Long = 0L,
        targetDeviceIds: List<String> = emptyList()
    ): Boolean = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val url = "$baseUrl/api/v1/screen/frame"
        val token = getAuthToken() ?: ""
        val mediaType = "image/jpeg".toMediaType()
        val reqBody = frameBytes.toRequestBody(mediaType)
        val reqBuilder = Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)
            .addHeader("X-Snow-Sender-Id", senderId ?: deviceId)
            .addHeader("X-Snow-Sender-Platform", senderPlatform)
            .addHeader("X-Snow-Session-Id", sessionId)
            .addHeader("X-Snow-Frame-Width", width.toString())
            .addHeader("X-Snow-Frame-Height", height.toString())
            .addHeader("X-Snow-FPS", fps.toString())
        if (!senderName.isNullOrBlank()) {
            reqBuilder.addHeader("X-Snow-Sender-Name", senderName)
        }
        if (frameSeq > 0L) {
            reqBuilder.addHeader("X-Snow-Frame-Seq", frameSeq.toString())
        }
        if (targetDeviceIds.isNotEmpty()) {
            reqBuilder.addHeader("X-Snow-Target-Device-Ids", targetDeviceIds.joinToString(","))
        }
        val request = reqBuilder.post(reqBody).build()

        try {
            httpClient.newCall(request).execute().use { response ->
                response.isSuccessful
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "Screen frame POST error: ${e.message}")
            false
        }
    }

    /**
     * List active screen senders authorized for this Full Control device.
     */
    suspend fun getScreenSenders(
        serverHost: String,
        transferPort: Int = 8766
    ): List<ScreenSenderInfo> = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val url = "$baseUrl/api/v1/screen/senders"
        val token = getAuthToken() ?: ""
        val req = Request.Builder()
            .url(url)
            .get()
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)
            .build()
        try {
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@withContext emptyList()
                val raw = resp.body?.string() ?: return@withContext emptyList()
                val obj = JSONObject(raw)
                val arr = obj.optJSONArray("senders") ?: return@withContext emptyList()
                val list = mutableListOf<ScreenSenderInfo>()
                for (i in 0 until arr.length()) {
                    val item = arr.optJSONObject(i) ?: continue
                    list.add(
                        ScreenSenderInfo(
                            senderDeviceId = item.optString("sender_device_id", item.optString("device_id", "")),
                            senderName = item.optString("sender_name", "Peer Device"),
                            senderPlatform = item.optString("sender_platform", "unknown"),
                            sessionId = item.optString("session_id", ""),
                            fps = item.optDouble("fps", 2.0).toFloat(),
                            frameWidth = item.optInt("frame_width", 0),
                            frameHeight = item.optInt("frame_height", 0),
                            frameSeq = item.optLong("frame_seq", 0L),
                            routeBadge = item.optString("route_badge", ""),
                            hasFrame = item.optBoolean("has_frame", false)
                        )
                    )
                }
                list
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "getScreenSenders error: ${e.message}")
            emptyList()
        }
    }

    /**
     * Fetch the latest live screen frame for an authorized sender over HTTPS.
     */
    suspend fun getScreenFrame(
        serverHost: String,
        transferPort: Int = 8766,
        senderId: String? = null
    ): ScreenFrameResult? = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val suffix = if (!senderId.isNullOrBlank()) "?sender_id=${java.net.URLEncoder.encode(senderId, "UTF-8")}" else ""
        val url = "$baseUrl/api/v1/screen/frame$suffix"
        val token = getAuthToken() ?: ""
        val req = Request.Builder()
            .url(url)
            .get()
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)
            .build()
        try {
            httpClient.newCall(req).execute().use { resp ->
                if (resp.code != 200) return@withContext null
                val bytes = resp.body?.bytes() ?: return@withContext null
                if (bytes.isEmpty() || bytes.size > 524288) return@withContext null
                ScreenFrameResult(
                    bytes = bytes,
                    sessionId = resp.header("X-Snow-Session-Id") ?: "",
                    senderId = resp.header("X-Snow-Sender-Id") ?: (senderId ?: ""),
                    senderName = resp.header("X-Snow-Sender-Name") ?: "Peer Screen",
                    frameSeq = resp.header("X-Snow-Frame-Seq")?.toLongOrNull() ?: 0L,
                    timestamp = resp.header("X-Snow-Timestamp") ?: ""
                )
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "getScreenFrame error: ${e.message}")
            null
        }
    }

    /**
     * Notify host viewer subscription state so zero viewers stops capture automatically.
     */
    suspend fun postScreenSubscribe(
        serverHost: String,
        transferPort: Int = 8766,
        subscribe: Boolean
    ): Boolean = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val url = "$baseUrl/api/v1/screen/subscribe"
        val token = getAuthToken() ?: ""
        val body = JSONObject().put("action", if (subscribe) "subscribe" else "unsubscribe").toString()
            .toRequestBody(JSON_MEDIA_TYPE)
        val req = Request.Builder()
            .url(url)
            .post(body)
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)
            .build()
        try {
            httpClient.newCall(req).execute().use { it.isSuccessful }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Signal the desktop HTTP transfer server that screen streaming has stopped.
     */
    suspend fun postScreenStreamStop(
        serverHost: String,
        transferPort: Int
    ): Boolean = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val url = "$baseUrl/api/v1/screen/stop"
        val token = getAuthToken() ?: ""
        val emptyBody = "".toRequestBody(JSON_MEDIA_TYPE)
        val request = Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer $token")
            .addHeader("X-Snow-Device-Id", deviceId)
            .post(emptyBody)
            .build()

        try {
            httpClient.newCall(request).execute().use { response ->
                response.isSuccessful
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "Screen stop POST error: ${e.message}")
            false
        }
    }

    /**
     * Retrieve scaled desktop wallpaper preview from the HTTPS transfer server.
     * Supports ETag / If-None-Match for efficient 304 caching.
     */
    suspend fun getDesktopWallpaper(
        serverHost: String,
        transferPort: Int = 8766,
        ifNoneMatch: String? = null
    ): WallpaperResult = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val url = "$baseUrl/api/v1/desktop/wallpaper"
        val reqBuilder = Request.Builder()
            .url(url)
            .get()
            .addHeader("X-Snow-Device-Id", deviceId)

        val token = getAuthToken()
        if (!token.isNullOrBlank()) {
            reqBuilder.addHeader("Authorization", "Bearer $token")
        }
        if (!ifNoneMatch.isNullOrBlank()) {
            reqBuilder.addHeader("If-None-Match", ifNoneMatch)
        }

        try {
            httpClient.newCall(reqBuilder.build()).execute().use { response ->
                val etag = response.header("ETag")
                if (response.code == 304) {
                    return@withContext WallpaperResult.NotModified
                }
                if (!response.isSuccessful) {
                    return@withContext WallpaperResult.Unavailable
                }
                val bodyBytes = response.body?.bytes()
                if (bodyBytes != null && bodyBytes.isNotEmpty()) {
                    WallpaperResult.Updated(bodyBytes, etag)
                } else {
                    WallpaperResult.Unavailable
                }
            }
        } catch (e: Exception) {
            SafeLog.w(TAG, "Wallpaper GET error: ${e.message}")
            WallpaperResult.Unavailable
        }
    }

    /**
     * Query paired desktop for signed APK update metadata.
     */
    suspend fun getAppUpdateInfo(serverHost: String, transferPort: Int = 8766): Result<AppUpdateInfo> = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val url = "$baseUrl/api/v1/app/update-info"
        val reqBuilder = Request.Builder()
            .url(url)
            .get()
            .addHeader("X-Snow-Device-Id", deviceId)

        val token = getAuthToken()
        if (!token.isNullOrBlank()) {
            reqBuilder.addHeader("Authorization", "Bearer $token")
        }

        try {
            httpClient.newCall(reqBuilder.build()).execute().use { response ->
                if (!response.isSuccessful) {
                    return@withContext Result.failure(Exception("Update info request failed with HTTP ${response.code}"))
                }
                val bodyStr = response.body?.string() ?: return@withContext Result.failure(Exception("Empty update info response"))
                val json = JSONObject(bodyStr)
                val info = AppUpdateInfo(
                    versionCode = json.optInt("version_code", 0),
                    versionName = json.optString("version_name", ""),
                    sizeBytes = json.optLong("size_bytes", 0L),
                    sha256 = json.optString("sha256", ""),
                    available = json.optBoolean("available", false)
                )
                Result.success(info)
            }
        } catch (e: Exception) {
            SafeLog.e(TAG, "getAppUpdateInfo error: ${e.message}")
            Result.failure(e)
        }
    }

    /**
     * Download signed APK directly from paired desktop into destFile with streaming SHA-256 verification.
     */
    suspend fun downloadAppApk(
        serverHost: String,
        transferPort: Int = 8766,
        destFile: File,
        expectedSha256: String,
        onProgress: ((Int) -> Unit)? = null
    ): Result<File> = withContext(Dispatchers.IO) {
        val baseUrl = getBaseUrl(serverHost, transferPort)
        val url = "$baseUrl/api/v1/app/apk"
        val reqBuilder = Request.Builder()
            .url(url)
            .get()
            .addHeader("X-Snow-Device-Id", deviceId)

        val token = getAuthToken()
        if (!token.isNullOrBlank()) {
            reqBuilder.addHeader("Authorization", "Bearer $token")
        }

        destFile.parentFile?.mkdirs()
        val tempFile = File(destFile.parentFile, "${destFile.name}.part")
        if (tempFile.exists()) tempFile.delete()

        try {
            httpClient.newCall(reqBuilder.build()).execute().use { response ->
                if (!response.isSuccessful) {
                    return@withContext Result.failure(Exception("APK download failed with HTTP ${response.code}"))
                }
                val body = response.body ?: return@withContext Result.failure(Exception("Empty APK response body"))
                val contentLength = body.contentLength()
                var bytesRead = 0L

                body.byteStream().use { input ->
                    FileOutputStream(tempFile).use { output ->
                        val buffer = ByteArray(CHUNK_SIZE)
                        var read: Int
                        while (input.read(buffer).also { read = it } != -1) {
                            output.write(buffer, 0, read)
                            bytesRead += read
                            if (contentLength > 0 && onProgress != null) {
                                val pct = ((bytesRead * 100) / contentLength).toInt().coerceIn(0, 100)
                                onProgress(pct)
                            }
                        }
                        output.flush()
                    }
                }
            }

            val actualSha256 = computeSha256(tempFile)
            if (expectedSha256.isNotBlank() && !actualSha256.equals(expectedSha256, ignoreCase = true)) {
                tempFile.delete()
                return@withContext Result.failure(SecurityException("SHA-256 mismatch for APK: expected $expectedSha256, got $actualSha256"))
            }

            if (destFile.exists()) destFile.delete()
            if (!tempFile.renameTo(destFile)) {
                tempFile.copyTo(destFile, overwrite = true)
                tempFile.delete()
            }
            Result.success(destFile)
        } catch (e: Exception) {
            SafeLog.e(TAG, "downloadAppApk error: ${e.message}")
            if (tempFile.exists()) tempFile.delete()
            Result.failure(e)
        }
    }
}
