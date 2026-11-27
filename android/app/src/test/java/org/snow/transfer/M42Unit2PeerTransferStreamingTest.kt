package org.snow.transfer

import android.content.ContextWrapper
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.network.AndroidPeerMediaServer
import org.snow.network.PeerTransferState
import org.snow.security.AndroidSelfSignedCertGenerator
import org.snow.security.InMemoryCertPinStorage
import org.snow.security.InMemoryTokenStorage
import org.snow.security.SnowTrustManager
import org.snow.security.TlsConfig
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * M4.2 Unit 2 (RC-3): End-to-End Direct Phone-to-Phone Resumable Streaming & Security Matrix Tests
 * exercising real FileTransferClient <-> real TLS AndroidPeerMediaServer over loopback sockets.
 */
class M42Unit2PeerTransferStreamingTest {

    private val hostDeviceId = "phone-host-${UUID.randomUUID().toString().take(8)}"
    private val phoneBId = "phone-client-b-${UUID.randomUUID().toString().take(8)}"
    private val phoneCId = "phone-client-c-${UUID.randomUUID().toString().take(8)}"
    private val tokenB = "peer-token-b-secret-xyz"
    private val tokenC = "peer-token-c-secret-uvw"

    private lateinit var tempRoot: File
    private lateinit var hostStorageDir: File
    private lateinit var clientDownloadDir: File
    private lateinit var serverTokenStorage: InMemoryTokenStorage
    private lateinit var clientPinStorage: InMemoryCertPinStorage
    private lateinit var clientTokenStorage: InMemoryTokenStorage
    private lateinit var certResult: AndroidSelfSignedCertGenerator.GeneratedCertResult
    private lateinit var profilesByDevice: ConcurrentHashMap<String, String>
    private val simulatedFreeBytes = AtomicLong(100L * 1024L * 1024L * 1024L)
    private lateinit var mediaServer: AndroidPeerMediaServer
    private lateinit var transferClient: FileTransferClient
    private lateinit var rawHttpClient: OkHttpClient

    private fun sha256Hex(bytes: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(bytes)
        return d.joinToString("") { "%02x".format(it) }
    }

    private fun buildPinnedHttpClient(): OkHttpClient {
        val tm = SnowTrustManager(
            pinStorage = clientPinStorage,
            targetDeviceIdProvider = { hostDeviceId }
        )
        val sc = TlsConfig.createSslContext(tm)
        return OkHttpClient.Builder()
            .sslSocketFactory(sc.socketFactory, tm)
            .hostnameVerifier(
                TlsConfig.createHostnameVerifier(
                    pinStorage = clientPinStorage,
                    targetDeviceIdProvider = { hostDeviceId }
                )
            )
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(20, TimeUnit.SECONDS)
            .build()
    }

    @Before
    fun setUp() {
        tempRoot = File(System.getProperty("java.io.tmpdir"), "snow_m42_u2_${UUID.randomUUID()}").apply { mkdirs() }
        hostStorageDir = File(tempRoot, "host_transfers").apply { mkdirs() }
        clientDownloadDir = File(tempRoot, "client_downloads").apply { mkdirs() }

        certResult = AndroidSelfSignedCertGenerator.generate()
        serverTokenStorage = InMemoryTokenStorage().apply {
            saveTokenForDevice(phoneBId, tokenB)
            saveTokenForDevice(phoneCId, tokenC)
        }
        clientPinStorage = InMemoryCertPinStorage().apply {
            pinFingerprintForDevice(hostDeviceId, certResult.fingerprint)
        }
        clientTokenStorage = InMemoryTokenStorage().apply {
            saveTokenForDevice(hostDeviceId, tokenB)
        }
        profilesByDevice = ConcurrentHashMap<String, String>().apply {
            put(phoneBId, "full_control")
            put(phoneCId, "files_only")
        }

        mediaServer = AndroidPeerMediaServer(
            requestedPort = 0,
            sslContext = certResult.sslContext,
            tokenStorage = serverTokenStorage,
            activeProfileProvider = { "not_allowed" },
            storageRootDir = hostStorageDir,
            perDeviceProfileProvider = { dev -> profilesByDevice[dev] ?: "not_allowed" },
            freeSpaceProvider = { simulatedFreeBytes.get() }
        )
        assertTrue("Media server must bind TLS ephemeral port", mediaServer.start())

        val dummyCtx = object : ContextWrapper(null) {
            override fun getFilesDir(): File = tempRoot
            override fun getCacheDir(): File = tempRoot
        }
        transferClient = FileTransferClient(
            context = dummyCtx,
            deviceId = phoneBId,
            certPinStorage = clientPinStorage,
            tokenStorage = clientTokenStorage,
            useTls = true,
            maxRetryAttempts = 1,
            retryBaseDelayMs = 20L,
            targetDeviceIdProvider = { hostDeviceId }
        )
        rawHttpClient = buildPinnedHttpClient()
    }

    @After
    fun tearDown() {
        mediaServer.stop()
        rawHttpClient.dispatcher.executorService.shutdown()
        tempRoot.deleteRecursively()
    }

    @Test
    fun testCase1And6_ChunkedStreamingMultiMegabyteUploadAndDownloadWithBoundedHeap() = runBlocking {
        // 12 MiB synthetic payload (192 x 64 KiB chunks) proves chunked streaming + bounded JVM memory
        val sizeBytes = 12 * 1024 * 1024 + 137
        val payload = ByteArray(sizeBytes) { i -> ((i * 31) xor (i ushr 8)).toByte() }
        val expectedSha = sha256Hex(payload)
        val srcFile = File(tempRoot, "video_12mb.bin").apply { writeBytes(payload) }

        System.gc()
        val rt = Runtime.getRuntime()
        val beforeHeap = rt.totalMemory() - rt.freeMemory()

        val upRes = transferClient.uploadFile(
            serverHost = "127.0.0.1",
            transferPort = mediaServer.boundPort,
            file = srcFile
        )
        assertTrue("Expected Success upload, got $upRes", upRes is FileTransferClient.TransferResult.Success)
        val upSuccess = upRes as FileTransferClient.TransferResult.Success
        assertEquals(expectedSha, upSuccess.sha256)

        val storedFile = File(hostStorageDir, "video_12mb.bin")
        assertTrue("Uploaded file must be atomically committed on peer host", storedFile.isFile)
        assertEquals(sizeBytes.toLong(), storedFile.length())
        assertEquals(0, mediaServer.partsRoot.listFiles()?.size ?: 0)

        val rec = mediaServer.getTransfer(upSuccess.transferId)
        assertEquals(PeerTransferState.COMPLETED, rec?.state)

        // Now download back via FileTransferClient and verify exact SHA-256
        mediaServer.registerDownloadTransfer(
            deviceId = phoneBId,
            file = storedFile,
            sha256 = expectedSha,
            transferId = "dl-12mb-001"
        )
        val dlDest = File(clientDownloadDir, "downloaded_12mb.bin")
        val dlRes = transferClient.downloadFile(
            serverHost = "127.0.0.1",
            transferPort = mediaServer.boundPort,
            transferId = "dl-12mb-001",
            destinationFile = dlDest,
            expectedSha256 = expectedSha
        )
        assertTrue("Expected Success download, got $dlRes", dlRes is FileTransferClient.TransferResult.Success)
        assertArrayEquals(payload, dlDest.readBytes())

        System.gc()
        val afterHeap = rt.totalMemory() - rt.freeMemory()
        val heapDeltaBytes = afterHeap - beforeHeap
        assertTrue(
            "Streaming upload/download heap growth ($heapDeltaBytes bytes) should stay bounded",
            heapDeltaBytes < 32L * 1024L * 1024L
        )
    }

    @Test
    fun testCase2_InterruptedUploadResumeAcrossMultipleContentRangeChunks() {
        val totalSize = 180_000
        val payload = ByteArray(totalSize) { i -> (i % 251).toByte() }
        val sha = sha256Hex(payload)
        val baseUrl = "https://127.0.0.1:${mediaServer.boundPort}"

        // Step 1: /init
        val initReq = Request.Builder()
            .url("$baseUrl/api/v1/transfers/init")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .post(
                JSONObject()
                    .put("file_name", "resumed_upload.bin")
                    .put("file_size", totalSize)
                    .put("sha256", sha)
                    .put("direction", "UPLOAD")
                    .toString()
                    .toRequestBody("application/json".toMediaType())
            )
            .build()
        val tid = rawHttpClient.newCall(initReq).execute().use { resp ->
            assertEquals(200, resp.code)
            JSONObject(resp.body!!.string()).getString("transfer_id")
        }

        // Step 2: Upload first chunk (0..65535)
        val split = 65_536
        val part1 = payload.copyOfRange(0, split)
        val req1 = Request.Builder()
            .url("$baseUrl/api/v1/transfers/upload/$tid")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .addHeader("Content-Range", "bytes 0-${split - 1}/$totalSize")
            .post(part1.toRequestBody("application/octet-stream".toMediaType()))
            .build()
        rawHttpClient.newCall(req1).execute().use { resp ->
            assertEquals(206, resp.code)
            assertEquals(split.toLong(), JSONObject(resp.body!!.string()).getLong("current_offset"))
        }

        // Step 3: Query status and verify offset matches server .part length
        val statusReq = Request.Builder()
            .url("$baseUrl/api/v1/transfers/upload/$tid/status")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .get()
            .build()
        rawHttpClient.newCall(statusReq).execute().use { resp ->
            assertEquals(200, resp.code)
            val obj = JSONObject(resp.body!!.string())
            assertEquals("PAUSED", obj.getString("status"))
            assertEquals(split.toLong(), obj.getLong("current_offset"))
        }

        // Step 4: Resume remaining bytes (split..totalSize-1) and commit atomically
        val part2 = payload.copyOfRange(split, totalSize)
        val req2 = Request.Builder()
            .url("$baseUrl/api/v1/transfers/upload/$tid")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .addHeader("Content-Range", "bytes $split-${totalSize - 1}/$totalSize")
            .post(part2.toRequestBody("application/octet-stream".toMediaType()))
            .build()
        rawHttpClient.newCall(req2).execute().use { resp ->
            assertEquals(200, resp.code)
            assertEquals(sha, JSONObject(resp.body!!.string()).getString("sha256"))
        }

        val finalDest = File(hostStorageDir, "resumed_upload.bin")
        assertTrue(finalDest.isFile)
        assertArrayEquals(payload, finalDest.readBytes())
        assertEquals(PeerTransferState.COMPLETED, mediaServer.getTransfer(tid)?.state)
    }

    @Test
    fun testCase3And4_DownloadResumeViaHttpRangeAnd416BoundsCheck() = runBlocking {
        val total = 150_000
        val payload = ByteArray(total) { i -> ((i * 7) and 0xFF).toByte() }
        val sha = sha256Hex(payload)
        val src = File(hostStorageDir, "dl_resume_src.bin").apply { writeBytes(payload) }
        mediaServer.registerDownloadTransfer(phoneBId, src, sha, transferId = "dl-resume-id")

        // Pre-populate .part with first 40,000 bytes so FileTransferClient sends Range: bytes=40000-
        val dest = File(clientDownloadDir, "dl_resume_dest.bin")
        val part = File(clientDownloadDir, "${dest.name}.part")
        part.writeBytes(payload.copyOfRange(0, 40_000))

        val dlRes = transferClient.downloadFile(
            serverHost = "127.0.0.1",
            transferPort = mediaServer.boundPort,
            transferId = "dl-resume-id",
            destinationFile = dest,
            expectedSha256 = sha,
            resume = true
        )
        assertTrue("Resumed Range download must succeed: $dlRes", dlRes is FileTransferClient.TransferResult.Success)
        assertArrayEquals(payload, dest.readBytes())

        // Out-of-bounds Range request must return 416 Range Not Satisfiable
        val badRangeReq = Request.Builder()
            .url("https://127.0.0.1:${mediaServer.boundPort}/api/v1/transfers/download/dl-resume-id")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .addHeader("Range", "bytes=${total + 100}-")
            .get()
            .build()
        rawHttpClient.newCall(badRangeReq).execute().use { resp ->
            assertEquals(416, resp.code)
        }
    }

    @Test
    fun testCase5_LargeFile64BitSparseSeekExceeds2GiBWithoutIntOverflow() {
        val sparseFile = File(hostStorageDir, "sparse_over_2gb.bin")
        val highOffset = 3_500_000_000L // > Integer.MAX_VALUE (2,147,483,647)
        val sentinel = "SNOW-64BIT-LONG-OFFSET-TAIL-OK".toByteArray(Charsets.UTF_8)
        val totalLen = highOffset + sentinel.size

        try {
            FileChannel.open(
                sparseFile.toPath(),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
                StandardOpenOption.SPARSE
            ).use { ch ->
                ch.position(highOffset)
                ch.write(ByteBuffer.wrap(sentinel))
            }
        } catch (_: Exception) {
            // Fallback for filesystems ignoring StandardOpenOption.SPARSE flag
            RandomAccessFile(sparseFile, "rw").use { raf ->
                raf.seek(highOffset)
                raf.write(sentinel)
            }
        }
        assertEquals(totalLen, sparseFile.length())

        mediaServer.registerDownloadTransfer(
            deviceId = phoneBId,
            file = sparseFile,
            sha256 = "f".repeat(64),
            transferId = "tx-sparse-gt-2gb",
            fileSize = totalLen
        )

        val rangeReq = Request.Builder()
            .url("https://127.0.0.1:${mediaServer.boundPort}/api/v1/transfers/download/tx-sparse-gt-2gb")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .addHeader("Range", "bytes=$highOffset-${totalLen - 1L}")
            .get()
            .build()
        rawHttpClient.newCall(rangeReq).execute().use { resp ->
            assertEquals(206, resp.code)
            assertEquals("bytes $highOffset-${totalLen - 1L}/$totalLen", resp.header("Content-Range"))
            assertArrayEquals(sentinel, resp.body!!.bytes())
        }
    }

    @Test
    fun testCase7And8_InsufficientStorage507AndSha256Mismatch422() = runBlocking {
        // Case 7: 507 Insufficient Storage rejects init cleanly
        simulatedFreeBytes.set(100L)
        val baseUrl = "https://127.0.0.1:${mediaServer.boundPort}"
        val smallPayload = ByteArray(1024) { 42 }
        val sha = sha256Hex(smallPayload)
        val init507 = Request.Builder()
            .url("$baseUrl/api/v1/transfers/init")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .post(
                JSONObject()
                    .put("file_name", "too_big.bin")
                    .put("file_size", 4096)
                    .put("sha256", sha)
                    .put("direction", "UPLOAD")
                    .toString()
                    .toRequestBody("application/json".toMediaType())
            )
            .build()
        rawHttpClient.newCall(init507).execute().use { resp ->
            assertEquals(507, resp.code)
        }
        assertFalse(File(hostStorageDir, "too_big.bin").exists())

        // Case 8: 422 SHA-256 mismatch rejects commit and removes .part file
        simulatedFreeBytes.set(100L * 1024L * 1024L * 1024L)
        val wrongSha = "0".repeat(64)
        val init422 = Request.Builder()
            .url("$baseUrl/api/v1/transfers/init")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .post(
                JSONObject()
                    .put("file_name", "bad_sha.bin")
                    .put("file_size", smallPayload.size)
                    .put("sha256", wrongSha)
                    .put("direction", "UPLOAD")
                    .toString()
                    .toRequestBody("application/json".toMediaType())
            )
            .build()
        val tid422 = rawHttpClient.newCall(init422).execute().use { resp ->
            assertEquals(200, resp.code)
            JSONObject(resp.body!!.string()).getString("transfer_id")
        }
        val uploadBad = Request.Builder()
            .url("$baseUrl/api/v1/transfers/upload/$tid422")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .post(smallPayload.toRequestBody("application/octet-stream".toMediaType()))
            .build()
        rawHttpClient.newCall(uploadBad).execute().use { resp ->
            assertEquals(422, resp.code)
        }
        assertFalse(File(hostStorageDir, "bad_sha.bin").exists())
        assertFalse(File(mediaServer.partsRoot, "$tid422.part").exists())
        assertEquals(PeerTransferState.FAILED, mediaServer.getTransfer(tid422)?.state)
    }

    @Test
    fun testCase9And10_PerDeviceAuthTierGatingCancellationAndMidTransferRevocation() = runBlocking {
        val baseUrl = "https://127.0.0.1:${mediaServer.boundPort}"
        val data = ByteArray(4096) { 9 }
        val sha = sha256Hex(data)

        // 10a: Cross-device token impersonation rejected (Phone C token with Phone B deviceId -> 401)
        val spoofReq = Request.Builder()
            .url("$baseUrl/api/v1/transfers/init")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenC")
            .post(
                JSONObject().put("file_name", "a.bin").put("file_size", 4096).put("sha256", sha).put("direction", "UPLOAD")
                    .toString().toRequestBody("application/json".toMediaType())
            ).build()
        rawHttpClient.newCall(spoofReq).execute().use { assertEquals(401, it.code) }

        // 10b: Missing X-Snow-Device-Id rejected -> 401
        val noDevReq = Request.Builder()
            .url("$baseUrl/api/v1/transfers/init")
            .addHeader("Authorization", "Bearer $tokenB")
            .post("{}".toRequestBody("application/json".toMediaType())).build()
        rawHttpClient.newCall(noDevReq).execute().use { assertEquals(401, it.code) }

        // 10c: Access profile enforcement: clipboard_only & not_allowed blocked (403); files_only blocks screen but allows transfers
        profilesByDevice[phoneCId] = "clipboard_only"
        val clipBlocked = Request.Builder()
            .url("$baseUrl/api/v1/transfers/init")
            .addHeader("X-Snow-Device-Id", phoneCId)
            .addHeader("Authorization", "Bearer $tokenC")
            .post(
                JSONObject().put("file_name", "blocked.bin").put("file_size", 4096).put("sha256", sha).put("direction", "UPLOAD")
                    .toString().toRequestBody("application/json".toMediaType())
            ).build()
        rawHttpClient.newCall(clipBlocked).execute().use { assertEquals(403, it.code) }

        profilesByDevice[phoneCId] = "files_only"
        val screenBlockedForFilesOnly = Request.Builder()
            .url("$baseUrl/api/v1/screen/senders")
            .addHeader("X-Snow-Device-Id", phoneCId)
            .addHeader("Authorization", "Bearer $tokenC")
            .get().build()
        rawHttpClient.newCall(screenBlockedForFilesOnly).execute().use { assertEquals(403, it.code) }

        val filesAllowedForFilesOnly = Request.Builder()
            .url("$baseUrl/api/v1/transfers")
            .addHeader("X-Snow-Device-Id", phoneCId)
            .addHeader("Authorization", "Bearer $tokenC")
            .get().build()
        rawHttpClient.newCall(filesAllowedForFilesOnly).execute().use { assertEquals(200, it.code) }

        // 9: Cancellation cleans up partial staging and rejects late upload chunk
        val initCancel = Request.Builder()
            .url("$baseUrl/api/v1/transfers/init")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .post(
                JSONObject().put("file_name", "cancel_me.bin").put("file_size", data.size).put("sha256", sha).put("direction", "UPLOAD")
                    .toString().toRequestBody("application/json".toMediaType())
            ).build()
        val cancelTid = rawHttpClient.newCall(initCancel).execute().use { resp ->
            assertEquals(200, resp.code)
            JSONObject(resp.body!!.string()).getString("transfer_id")
        }
        val partChunk = Request.Builder()
            .url("$baseUrl/api/v1/transfers/upload/$cancelTid")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .addHeader("Content-Range", "bytes 0-1023/${data.size}")
            .post(data.copyOfRange(0, 1024).toRequestBody("application/octet-stream".toMediaType())).build()
        rawHttpClient.newCall(partChunk).execute().use { assertEquals(206, it.code) }
        assertTrue(File(mediaServer.partsRoot, "$cancelTid.part").exists())

        val cancelCall = Request.Builder()
            .url("$baseUrl/api/v1/transfers/$cancelTid/cancel")
            .addHeader("X-Snow-Device-Id", phoneBId)
            .addHeader("Authorization", "Bearer $tokenB")
            .post("{}".toRequestBody("application/json".toMediaType())).build()
        rawHttpClient.newCall(cancelCall).execute().use { resp ->
            assertEquals(200, resp.code)
            assertTrue(JSONObject(resp.body!!.string()).getBoolean("cancelled"))
        }
        assertFalse(File(mediaServer.partsRoot, "$cancelTid.part").exists())
        assertEquals(PeerTransferState.CANCELLED, mediaServer.getTransfer(cancelTid)?.state)

        // 10d: Revocation aborts active device access immediately
        serverTokenStorage.clearTokenForDevice(phoneCId)
        mediaServer.revokeDevice(phoneCId)
        val afterRevoke = Request.Builder()
            .url("$baseUrl/api/v1/transfers")
            .addHeader("X-Snow-Device-Id", phoneCId)
            .addHeader("Authorization", "Bearer $tokenC")
            .get().build()
        rawHttpClient.newCall(afterRevoke).execute().use { assertEquals(401, it.code) }
    }
}
