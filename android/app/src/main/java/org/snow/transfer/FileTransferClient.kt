package org.snow.transfer

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

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
    customClient: OkHttpClient? = null
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

    private val httpClient: OkHttpClient = customClient ?: buildHttpClient()

    private fun buildHttpClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)

        if (useTls) {
            val storage = certPinStorage ?: EncryptedCertPinStorage(context)
            val trustManager = SnowTrustManager(pinStorage = storage)
            val sslContext = TlsConfig.createSslContext(trustManager)
            builder.sslSocketFactory(sslContext.socketFactory, trustManager)
            builder.hostnameVerifier(TlsConfig.createHostnameVerifier(storage))
        }

        return builder.build()
    }

    private fun getAuthToken(): String? {
        return tokenStorage?.getToken()
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

        try {
            httpClient.newCall(request).execute().use { response ->
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
        } catch (e: Exception) {
            SafeLog.e(TAG, "Upload exception: ${e.message}", e)
            TransferResult.Error(transferId, e.message ?: "Upload network exception")
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

        try {
            httpClient.newCall(request).execute().use { response ->
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
        } catch (e: Exception) {
            SafeLog.e(TAG, "Upload URI exception: ${e.message}", e)
            TransferResult.Error(transferId, e.message ?: "Upload network exception")
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

        try {
            httpClient.newCall(request).execute().use { response ->
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
        } catch (e: Exception) {
            SafeLog.e(TAG, "Download exception: ${e.message}", e)
            TransferResult.Error(transferId, e.message ?: "Download exception")
        }
    }
}
