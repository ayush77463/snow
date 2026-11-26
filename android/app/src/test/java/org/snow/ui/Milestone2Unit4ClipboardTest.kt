package org.snow.ui

import android.content.ClipData
import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.capabilities.ClipboardHandler
import org.snow.security.InMemoryTokenStorage
import org.snow.transfer.FileTransferClient
import org.snow.ui.files.SafFolderManager
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Milestone 2 — Unit 2.4 Android Universal Clipboard tests:
 * - 15-item history parsing & ordering without OS clipboard overwrite
 * - Separated history sync vs latest-only non-self unacked apply check
 * - <= 64 KiB text enforcement & ack only after clipboard set succeeds
 * - PNG/JPEG download over HTTP/8766 with SHA-256 verification, 15 MiB bound, FileProvider ClipData
 * - Single-file & 5-file bundle SAF/Downloads/SNOW delivery, SHA-256 fail-closed, retry without duplicates
 * - Echo suppression and revoked-SAF failure without false ack
 */
@OptIn(ExperimentalCoroutinesApi::class)
class Milestone2Unit4ClipboardTest {

    private class MemoryPrefs : SharedPreferences {
        private val map = ConcurrentHashMap<String, Any?>()
        override fun getAll(): MutableMap<String, *> = map
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String?, defValue: Int): Int = (map[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (map[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (map[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (map[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = map.containsKey(key)
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val ops = mutableMapOf<String, Any?>()
            private var clearAll = false
            override fun putString(key: String?, value: String?) = apply { if (key != null) ops[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply { if (key != null) ops[key] = values }
            override fun putInt(key: String?, value: Int) = apply { if (key != null) ops[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) ops[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) ops[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) ops[key] = value }
            override fun remove(key: String?) = apply { if (key != null) ops[key] = null }
            override fun clear() = apply { clearAll = true }
            override fun commit(): Boolean {
                if (clearAll) map.clear()
                ops.forEach { (k, v) -> if (v == null) map.remove(k) else map[k] = v }
                return true
            }
            override fun apply() {
                commit()
            }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private class TestContext(private val rootDir: File) : ContextWrapper(null) {
        private val prefsByName = ConcurrentHashMap<String, MemoryPrefs>()
        private val cacheRoot = File(rootDir, "cache").apply { mkdirs() }
        private val filesRoot = File(rootDir, "files").apply { mkdirs() }

        override fun getPackageName(): String = "org.snow"
        override fun getApplicationContext(): Context = this
        override fun getCacheDir(): File = cacheRoot
        override fun getFilesDir(): File = filesRoot
        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
            prefsByName.computeIfAbsent(name ?: "default") { MemoryPrefs() }
        override fun getSystemService(name: String): Any? = null
    }

    private lateinit var tempDir: File
    private lateinit var ctx: TestContext
    private lateinit var downloadsDir: File
    private lateinit var repo: SnowUiRepository

    private fun resetRepoSingleton() {
        val field = SnowUiRepository::class.java.getDeclaredField("instance")
        field.isAccessible = true
        field.set(null, null)
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
    }

    @Before
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        resetRepoSingleton()
        tempDir = kotlin.io.path.createTempDirectory("snow_m2_u4_test_").toFile()
        ctx = TestContext(tempDir)
        downloadsDir = File(tempDir, "Downloads_SNOW").apply { mkdirs() }
        repo = SnowUiRepository.getInstance(ctx)
    }

    @After
    fun tearDown() {
        resetRepoSingleton()
        Dispatchers.resetMain()
        tempDir.deleteRecursively()
    }

    @Test
    fun test_01_fifteen_item_history_parsing_ordering_and_manifest_sanitization() {
        val rawItems = (1..18).map { idx ->
            mapOf(
                "item_id" to "cb_${idx.toString().padStart(12, '0')}_abcdef",
                "content_type" to if (idx == 18) "file_bundle" else "text",
                "origin_device_id" to "desktop_windows",
                "source_device" to "desktop_windows",
                "preview" to "Item #$idx",
                "size_bytes" to idx * 100L,
                "timestamp" to (1700000000.0 + idx),
                "pinned" to (idx <= 3),
                "event_id" to "evt-$idx",
                "seq" to idx.toLong(),
                "sha256" to "a".repeat(64),
                "file_manifest" to if (idx == 18) {
                    listOf(
                        mapOf("index" to 0, "name" to "good.pdf", "size_bytes" to 1024L, "mime_type" to "application/pdf", "sha256" to "b".repeat(64)),
                        mapOf("index" to 1, "name" to "../evil.txt", "size_bytes" to 10L, "mime_type" to "text/plain", "sha256" to "c".repeat(64))
                    )
                } else emptyList<Any>()
            )
        }

        val parsed = SnowUiRepository.parseClipboardBufferItems(rawItems)
        assertEquals(15, parsed.size)
        assertEquals(18L, parsed.first().seq)
        assertEquals("file_bundle", parsed.first().type)
        // Traversal filename "../evil.txt" rejected by sanitizeClipboardFileName
        assertEquals(1, parsed.first().fileManifest.size)
        assertEquals("good.pdf", parsed.first().fileManifest.first().name)
        assertEquals(4L, parsed.last().seq)
    }

    @Test
    fun test_02_separated_history_vs_latest_only_and_zero_echo() {
        val selfId = repo.identity.deviceId
        assertFalse(
            SnowUiRepository.shouldApplyRemoteClipboardEvent(
                originDeviceId = selfId,
                selfDeviceId = selfId,
                eventId = "evt-self",
                seq = 10L,
                lastAckedSeq = 5L
            )
        )
        assertFalse(
            SnowUiRepository.shouldApplyRemoteClipboardEvent(
                originDeviceId = "desktop_windows",
                selfDeviceId = selfId,
                eventId = "evt-old",
                seq = 5L,
                lastAckedSeq = 5L
            )
        )
        assertTrue(
            SnowUiRepository.shouldApplyRemoteClipboardEvent(
                originDeviceId = "desktop_windows",
                selfDeviceId = selfId,
                eventId = "evt-new",
                seq = 6L,
                lastAckedSeq = 5L
            )
        )

        // Incoming echo recording prevents re-upload of applied text
        repo.recordIncomingClipboardText("Synchronized from Windows")
        assertTrue(repo.isDuplicateClipboard("Synchronized from Windows"))
        assertFalse(repo.isDuplicateClipboard("Fresh phone copy"))
    }

    @Test
    fun test_03_text_size_bound_and_ack_only_after_clipboard_apply_succeeds() = runBlocking {
        val dispatcher = AndroidCapabilityDispatcher(ctx) { null }
        val sentAcks = CopyOnWriteArrayList<Pair<Long, String>>()
        repo.clipboardAckObserverForTest = { seq, eid -> sentAcks.add(Pair(seq, eid)) }

        // Oversized > 64 KiB text MUST fail and NOT ack
        val hugeText = "A".repeat(65537)
        val (errRes, errObj) = dispatcher.handleIncomingClipboardPush(
            data = mapOf("type" to "text", "text" to hugeText, "seq" to 10L, "event_id" to "evt-huge", "origin_device_id" to "desktop_windows"),
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766,
            transferClient = null,
            repoOverride = repo
        )
        assertEquals(null, errRes)
        assertNotNull(errObj)
        assertTrue(sentAcks.isEmpty())

        // Clipboard failure (no setter / null system ClipboardManager on TestContext) MUST NOT ack
        val (failRes, failErr) = dispatcher.handleIncomingClipboardPush(
            data = mapOf("type" to "text", "text" to "Valid text", "seq" to 11L, "event_id" to "evt-fail", "origin_device_id" to "desktop_windows"),
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766,
            transferClient = null,
            repoOverride = repo
        )
        assertEquals(null, failRes)
        assertNotNull(failErr)
        assertTrue(sentAcks.isEmpty())

        // Valid <= 64 KiB text succeeds & sends ack once primary clip is set
        val appliedTexts = CopyOnWriteArrayList<String>()
        val workingClipboardHandler = ClipboardHandler(ctx) { txt -> appliedTexts.add(txt) }
        val (okRes, okErr) = dispatcher.handleIncomingClipboardPush(
            data = mapOf("type" to "text", "text" to "Hello V7 Android", "seq" to 12L, "event_id" to "evt-12", "origin_device_id" to "desktop_windows"),
            serverHost = "127.0.0.1",
            defaultTransferPort = 8766,
            transferClient = null,
            repoOverride = repo,
            clipboardHandlerOverride = workingClipboardHandler
        )
        assertEquals(null, okErr)
        assertEquals("success", okRes?.get("status"))
        assertEquals(listOf("Hello V7 Android"), appliedTexts.toList())
        assertEquals(listOf(Pair(12L, "evt-12")), sentAcks.toList())
    }

    private class LoopbackHttpServer(
        private val routes: (String) -> Pair<Int, ByteArray>
    ) {
        private val serverSocket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        private val running = AtomicBoolean(true)
        val port: Int get() = serverSocket.localPort

        private val acceptThread = thread(isDaemon = true, name = "m2-u4-loopback-http") {
            while (running.get()) {
                val sock = try {
                    serverSocket.accept()
                } catch (_: Exception) {
                    break
                }
                try {
                    sock.use { s ->
                        val reader = BufferedReader(InputStreamReader(s.getInputStream()))
                        val requestLine = reader.readLine() ?: return@use
                        while (true) {
                            val hdr = reader.readLine() ?: break
                            if (hdr.isEmpty()) break
                        }
                        val path = requestLine.split(" ").getOrNull(1) ?: "/"
                        val (code, body) = routes(path)
                        val reason = when (code) {
                            200 -> "OK"
                            503 -> "Service Unavailable"
                            else -> "Not Found"
                        }
                        val header = "HTTP/1.1 $code $reason\r\n" +
                            "Content-Length: ${body.size}\r\n" +
                            "Connection: close\r\n\r\n"
                        val out = s.getOutputStream()
                        out.write(header.toByteArray(Charsets.US_ASCII))
                        if (body.isNotEmpty()) {
                            out.write(body)
                        }
                        out.flush()
                    }
                } catch (_: Exception) {
                }
            }
        }

        fun stop() {
            running.set(false)
            try {
                serverSocket.close()
            } catch (_: Exception) {
            }
            acceptThread.join(1000)
        }
    }

    @Test
    fun test_04_image_download_sha256_verification_15mib_guard_and_ack_gating() = runBlocking {
        val pngBytes = byteArrayOf(
            0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52
        ) + "PNG_DATA_OK".toByteArray()
        val goodSha = sha256Hex(pngBytes)

        val server = LoopbackHttpServer { path ->
            when (path) {
                "/api/v1/transfers/download/img-good" -> 200 to pngBytes
                "/api/v1/transfers/download/img-corrupt" -> 200 to "CORRUPT_PNG".toByteArray()
                else -> 404 to ByteArray(0)
            }
        }

        try {
            val port = server.port
            val tokens = InMemoryTokenStorage().apply { saveToken("tok") }
            val transferClient = FileTransferClient(
                context = ctx,
                deviceId = repo.identity.deviceId,
                tokenStorage = tokens,
                useTls = false,
                customClient = OkHttpClient()
            )
            val dispatcher = AndroidCapabilityDispatcher(ctx) { transferClient }
            val sentAcks = CopyOnWriteArrayList<Pair<Long, String>>()
            repo.clipboardAckObserverForTest = { seq, eid -> sentAcks.add(Pair(seq, eid)) }

            // 1. Over 15 MiB image rejected before download
            val (overRes, overErr) = dispatcher.handleIncomingClipboardPush(
                data = mapOf(
                    "type" to "image",
                    "transfer_id" to "img-good",
                    "sha256" to goodSha,
                    "size" to (15L * 1024L * 1024L + 1L),
                    "seq" to 20L,
                    "event_id" to "evt-over-img",
                    "origin_device_id" to "desktop_windows"
                ),
                serverHost = "127.0.0.1",
                defaultTransferPort = port,
                transferClient = transferClient,
                repoOverride = repo
            )
            assertEquals(null, overRes)
            assertNotNull(overErr)
            assertTrue(sentAcks.isEmpty())

            // 2. Corrupt SHA-256 download fails verification -> MUST NOT ack
            val (badRes, badErr) = dispatcher.handleIncomingClipboardPush(
                data = mapOf(
                    "type" to "image",
                    "transfer_id" to "img-corrupt",
                    "sha256" to goodSha,
                    "size" to pngBytes.size.toLong(),
                    "transfer_port" to port,
                    "seq" to 21L,
                    "event_id" to "evt-bad-img",
                    "origin_device_id" to "desktop_windows"
                ),
                serverHost = "127.0.0.1",
                defaultTransferPort = port,
                transferClient = transferClient,
                repoOverride = repo
            )
            assertEquals(null, badRes)
            assertNotNull(badErr)
            assertTrue(sentAcks.isEmpty())

            // 3. Valid PNG download -> verified file applied -> ack sent ONLY after clip set succeeds
            val capturedImages = CopyOnWriteArrayList<Pair<File, String>>()
            val (okRes, okErr) = dispatcher.handleIncomingClipboardPush(
                data = mapOf(
                    "type" to "image",
                    "transfer_id" to "img-good",
                    "sha256" to goodSha,
                    "mime_type" to "image/png",
                    "size" to pngBytes.size.toLong(),
                    "transfer_port" to port,
                    "seq" to 22L,
                    "event_id" to "evt-good-img",
                    "origin_device_id" to "desktop_windows"
                ),
                serverHost = "127.0.0.1",
                defaultTransferPort = port,
                transferClient = transferClient,
                repoOverride = repo,
                imageClipApplierOverride = { f, mime -> capturedImages.add(Pair(f, mime)) }
            )
            assertEquals(null, okErr)
            assertEquals("success", okRes?.get("status"))
            assertEquals(1, capturedImages.size)
            assertEquals("image/png", capturedImages[0].second)
            assertTrue(capturedImages[0].first.exists())
            assertEquals(listOf(Pair(22L, "evt-good-img")), sentAcks.toList())
        } finally {
            server.stop()
        }
    }

    @Test
    fun test_05_multi_file_bundle_sha256_all_or_nothing_retry_no_duplicates_and_saf_fail_closed() = runBlocking {
        val f1Bytes = "file-one-payload".toByteArray()
        val f2Bytes = "file-two-payload".toByteArray()
        val f3Bytes = "file-three-payload".toByteArray()
        val sha1 = sha256Hex(f1Bytes)
        val sha2 = sha256Hex(f2Bytes)
        val sha3 = sha256Hex(f3Bytes)

        val failFile2 = AtomicBoolean(true)
        val server = LoopbackHttpServer { path ->
            when (path) {
                "/api/v1/transfers/download/f-1" -> 200 to f1Bytes
                "/api/v1/transfers/download/f-2" -> if (failFile2.get()) 503 to ByteArray(0) else 200 to f2Bytes
                "/api/v1/transfers/download/f-3" -> 200 to f3Bytes
                else -> 404 to ByteArray(0)
            }
        }

        try {
            val port = server.port
            val tokens = InMemoryTokenStorage().apply { saveToken("tok") }
            val transferClient = FileTransferClient(
                context = ctx,
                deviceId = repo.identity.deviceId,
                tokenStorage = tokens,
                useTls = false,
                customClient = OkHttpClient()
            )
            val safManager = SafFolderManager(ctx, fallbackDownloadDirOverride = downloadsDir)
            val sentAcks = CopyOnWriteArrayList<Pair<Long, String>>()
            repo.clipboardAckObserverForTest = { seq, eid -> sentAcks.add(Pair(seq, eid)) }

            val pushPayload = mapOf(
                "type" to "file_bundle",
                "event_id" to "evt-bundle-30",
                "seq" to 30L,
                "origin_device_id" to "desktop_windows",
                "transfer_port" to port,
                "files" to listOf(
                    mapOf("index" to 0, "transfer_id" to "f-1", "name" to "alpha.txt", "size_bytes" to f1Bytes.size.toLong(), "mime_type" to "text/plain", "sha256" to sha1, "transfer_port" to port),
                    mapOf("index" to 1, "transfer_id" to "f-2", "name" to "beta.txt", "size_bytes" to f2Bytes.size.toLong(), "mime_type" to "text/plain", "sha256" to sha2, "transfer_port" to port),
                    mapOf("index" to 2, "transfer_id" to "f-3", "name" to "gamma.txt", "size_bytes" to f3Bytes.size.toLong(), "mime_type" to "text/plain", "sha256" to sha3, "transfer_port" to port)
                )
            )

            // 1. Reject > 5 files & > 15 MiB aggregate manifest cleanly
            val tooMany = SnowUiRepository.validateIncomingFileBundlePayload(
                (0..5).map { idx ->
                    mapOf("name" to "n$idx.txt", "size_bytes" to 10L, "mime_type" to "text/plain", "sha256" to sha1, "transfer_id" to "t-$idx")
                }
            )
            assertTrue(tooMany.isFailure)

            // 2. Mid-bundle failure on file 2 -> ZERO files saved into Downloads/SNOW and ZERO acks!
            val resFail = repo.handleIncomingClipboardFilePush(
                data = pushPayload,
                transferClient = transferClient,
                serverHost = "127.0.0.1",
                defaultTransferPort = port,
                safManagerOverride = safManager,
                notifyUser = false
            )
            assertTrue(resFail.isFailure)
            assertEquals(0, downloadsDir.listFiles()?.size ?: 0)
            assertTrue(sentAcks.isEmpty())

            // 3. Reconnect retry succeeds -> commits all 3 files ONCE (zero duplicates) and sends ack!
            failFile2.set(false)
            val resRetry = repo.handleIncomingClipboardFilePush(
                data = pushPayload,
                transferClient = transferClient,
                serverHost = "127.0.0.1",
                defaultTransferPort = port,
                safManagerOverride = safManager,
                notifyUser = false
            )
            assertTrue(resRetry.isSuccess)
            val committedFiles = downloadsDir.listFiles()?.map { it.name }?.sorted() ?: emptyList()
            assertEquals(listOf("alpha.txt", "beta.txt", "gamma.txt"), committedFiles)
            assertEquals(listOf(Pair(30L, "evt-bundle-30")), sentAcks.toList())

            // 4. Redelivery retry of already-committed event -> re-sends ack WITHOUT creating alpha (1).txt duplicates!
            val resRedeliver = repo.handleIncomingClipboardFilePush(
                data = pushPayload,
                transferClient = transferClient,
                serverHost = "127.0.0.1",
                defaultTransferPort = port,
                safManagerOverride = safManager,
                notifyUser = false
            )
            assertTrue(resRedeliver.isSuccess)
            val filesAfterRedeliver = downloadsDir.listFiles()?.map { it.name }?.sorted() ?: emptyList()
            assertEquals(listOf("alpha.txt", "beta.txt", "gamma.txt"), filesAfterRedeliver)
            assertEquals(2, sentAcks.size)

            // 5. Revoked custom SAF tree URI -> fails closed without silent fallback and NEVER sends ack!
            ctx.getSharedPreferences("snow_saf_prefs", Context.MODE_PRIVATE)
                .edit()
                .putString("saf_destination_uri", "content://com.android.externalstorage.documents/tree/primary%3ARevoked")
                .apply()
            val revokedSafPayload = mapOf(
                "type" to "file",
                "event_id" to "evt-revoked-saf",
                "seq" to 31L,
                "origin_device_id" to "desktop_windows",
                "transfer_port" to port,
                "files" to listOf(
                    mapOf("index" to 0, "transfer_id" to "f-1", "name" to "revoked.txt", "size_bytes" to f1Bytes.size.toLong(), "mime_type" to "text/plain", "sha256" to sha1, "transfer_port" to port)
                )
            )
            val acksBeforeRevoked = sentAcks.size
            val resRevoked = repo.handleIncomingClipboardFilePush(
                data = revokedSafPayload,
                transferClient = transferClient,
                serverHost = "127.0.0.1",
                defaultTransferPort = port,
                safManagerOverride = safManager,
                notifyUser = false
            )
            assertTrue(resRevoked.isFailure)
            assertEquals(acksBeforeRevoked, sentAcks.size)
            assertFalse(File(downloadsDir, "revoked.txt").exists())
        } finally {
            server.stop()
        }
    }
}
