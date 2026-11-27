package org.snow.capabilities

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.transfer.FileTransferClient
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.SnowMessage
import org.snow.ui.SnowUiRepository
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

@OptIn(ExperimentalCoroutinesApi::class)
class M41Unit4ClipboardCanonicalTest {

    private class MemPrefs : SharedPreferences {
        private val map = mutableMapOf<String, Any?>()
        override fun getAll(): MutableMap<String, *> = map.toMutableMap()
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String?, defValue: Int): Int = map[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = map[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = map[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = map[key] as? Boolean ?: defValue
        override fun contains(key: String?): Boolean = map.containsKey(key)
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val pending = mutableMapOf<String, Any?>()
            private var clearAll = false
            override fun putString(key: String?, value: String?): SharedPreferences.Editor = apply { if (key != null) pending[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = this
            override fun putInt(key: String?, value: Int): SharedPreferences.Editor = apply { if (key != null) pending[key] = value }
            override fun putLong(key: String?, value: Long): SharedPreferences.Editor = apply { if (key != null) pending[key] = value }
            override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = apply { if (key != null) pending[key] = value }
            override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = apply { if (key != null) pending[key] = value }
            override fun remove(key: String?): SharedPreferences.Editor = apply { if (key != null) pending[key] = null }
            override fun clear(): SharedPreferences.Editor = apply { clearAll = true }
            override fun commit(): Boolean {
                if (clearAll) map.clear()
                pending.forEach { (k, v) -> if (v == null) map.remove(k) else map[k] = v }
                return true
            }
            override fun apply() { commit() }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private val prefsByName = mutableMapOf<String, MemPrefs>()
    private lateinit var tempDir: File
    private lateinit var context: Context
    private val testDispatcher = UnconfinedTestDispatcher()

    private fun resetRepoSingleton() {
        val f = SnowUiRepository::class.java.getDeclaredField("instance")
        f.isAccessible = true
        f.set(null, null)
    }

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        ClipboardHandler.resetForegroundTracking()
        CanonicalImageDigest.fileDecoderOverrideForTest = null
        prefsByName.clear()
        tempDir = File(System.getProperty("java.io.tmpdir"), "snow_m41_u4_${UUID.randomUUID()}").apply { mkdirs() }
        context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = tempDir
            override fun getCacheDir(): File = tempDir
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
                prefsByName.getOrPut(name ?: "default") { MemPrefs() }
            override fun getSystemService(name: String): Any? = null
            override fun startService(service: Intent?): android.content.ComponentName? = null
            override fun startForegroundService(service: Intent?): android.content.ComponentName? = null
        }
        resetRepoSingleton()
    }

    @After
    fun tearDown() {
        CanonicalImageDigest.fileDecoderOverrideForTest = null
        ClipboardHandler.resetForegroundTracking()
        resetRepoSingleton()
        tempDir.deleteRecursively()
        Dispatchers.resetMain()
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    @Test
    fun canonicalDigestMatchesPythonPixelSpecificationAndArgbConversion() {
        // 2x1 pixels: Pixel 0 = RGBA(0x11, 0x22, 0x33, 0xFF), Pixel 1 = RGBA(0xAA, 0xBB, 0xCC, 0x80)
        val rgba = byteArrayOf(
            0x11.toByte(), 0x22.toByte(), 0x33.toByte(), 0xFF.toByte(),
            0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0x80.toByte()
        )
        val argb = intArrayOf(
            (0xFF shl 24) or (0x11 shl 16) or (0x22 shl 8) or 0x33,
            (0x80 shl 24) or (0xAA shl 16) or (0xBB shl 8) or 0xCC
        )

        val expectedPayload = ByteArrayOutputStream().apply {
            write("2x1:".toByteArray(Charsets.US_ASCII))
            write(rgba)
        }.toByteArray()
        val expectedHex = sha256Hex(expectedPayload)

        assertEquals(expectedHex, CanonicalImageDigest.computeFromRgbaPixels(2, 1, rgba))
        assertEquals(expectedHex, CanonicalImageDigest.computeFromArgbInts(2, 1, argb))
    }

    @Test
    fun oversizedInvalidAndCorruptImagesFailClosedWithoutCrash() {
        val singlePixel = byteArrayOf(1, 2, 3, 4)
        assertNull(CanonicalImageDigest.computeFromRgbaPixels(0, 1, singlePixel))
        assertNull(CanonicalImageDigest.computeFromRgbaPixels(1, -2, singlePixel))
        assertNull(CanonicalImageDigest.computeFromRgbaPixels(8193, 1, ByteArray(0)))
        assertNull(CanonicalImageDigest.computeFromRgbaPixels(1, 8193, ByteArray(0)))
        assertNull(CanonicalImageDigest.computeFromRgbaPixels(8192, 4097, ByteArray(0))) // > 33,554,432 pixels
        assertNull(CanonicalImageDigest.computeFromRgbaPixels(2, 2, singlePixel)) // byte count mismatch
        assertNull(CanonicalImageDigest.computeFromArgbInts(2, 2, intArrayOf(1, 2)))

        val missing = File(tempDir, "does_not_exist.png")
        assertNull(CanonicalImageDigest.computeFromFile(missing))
        val corrupt = File(tempDir, "corrupt.jpg").apply { writeBytes(byteArrayOf(1, 2, 3, 4, 5)) }
        assertNull(CanonicalImageDigest.computeFromFile(corrupt))
        assertNull(CanonicalImageDigest.computeFromBytes(byteArrayOf(0x00, 0x01, 0x02)))
    }

    @Test
    fun zeroEchoAcrossJpegPngTranscodingForForegroundAndScreenshotPushAndExplicitSendBypasses() = runTest {
        val repo = SnowUiRepository.getInstance(context)
        repo.resetImageClipboardEchoGuard()

        val pngBytes = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 10, 20, 30)
        val jpgBytes = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte(), 40, 50, 60)
        val distinctBytes = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 99, 88, 77)

        val pngSha = sha256Hex(pngBytes)
        val jpgSha = sha256Hex(jpgBytes)
        val distinctSha = sha256Hex(distinctBytes)
        assertNotEquals(pngSha, jpgSha)

        val sharedPixels = CanonicalImageDigest.DecodedRgbaImage(
            width = 2,
            height = 2,
            rgbaBytes = ByteArray(16) { idx -> (idx * 13 + 7).toByte() }
        )
        val distinctPixels = CanonicalImageDigest.DecodedRgbaImage(
            width = 2,
            height = 2,
            rgbaBytes = ByteArray(16) { idx -> (idx * 5 + 100).toByte() }
        )
        val sharedCanon = CanonicalImageDigest.computeFromRgbaPixels(sharedPixels.width, sharedPixels.height, sharedPixels.rgbaBytes)!!
        val distinctCanon = CanonicalImageDigest.computeFromRgbaPixels(distinctPixels.width, distinctPixels.height, distinctPixels.rgbaBytes)!!
        assertNotEquals(sharedCanon, distinctCanon)

        CanonicalImageDigest.fileDecoderOverrideForTest = CanonicalImageDigest.ImagePixelDecoder { file ->
            when {
                file.name.contains("distinct") -> distinctPixels
                else -> sharedPixels
            }
        }

        // Serve PNG via local fake HTTP server for handleIncomingClipboardPush
        val server = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        val t = thread(isDaemon = true) {
            try {
                server.use { srv ->
                    val sock = srv.accept()
                    sock.use { s ->
                        val reader = s.getInputStream().bufferedReader()
                        while (true) {
                            val line = reader.readLine() ?: break
                            if (line.isEmpty()) break
                        }
                        val header = "HTTP/1.1 200 OK\r\nContent-Length: ${pngBytes.size}\r\nConnection: close\r\n\r\n"
                        s.getOutputStream().write(header.toByteArray(Charsets.US_ASCII))
                        s.getOutputStream().write(pngBytes)
                        s.getOutputStream().flush()
                    }
                }
            } catch (_: Exception) {
            }
        }

        val transferClient = FileTransferClient(
            context = context,
            deviceId = "android-m41-u4",
            useTls = false
        )
        val dispatcher = AndroidCapabilityDispatcher(
            context = context,
            transferClientProvider = { transferClient }
        )

        val (res, err) = try {
            dispatcher.handleIncomingClipboardPush(
                data = mapOf(
                    "type" to "image",
                    "transfer_id" to "tr-png-canon",
                    "sha256" to pngSha,
                    "canonical_sha256" to sharedCanon,
                    "mime_type" to "image/png",
                    "size" to pngBytes.size
                ),
                serverHost = "127.0.0.1",
                defaultTransferPort = server.localPort,
                transferClient = transferClient,
                repoOverride = repo,
                imageClipApplierOverride = { _, _ -> }
            )
        } finally {
            try { server.close() } catch (_: Exception) {}
            t.join(3000)
        }
        assertNull("Incoming push failed: $err", err)
        assertNotNull(res)
        assertEquals(pngSha, repo.getLastImageClipboardSha256())
        assertEquals(sharedCanon, repo.getLastImageClipboardCanonicalSha256())

        // Now Android sees a re-encoded JPEG with SAME canonical pixel hash -> automatic foreground & screenshot push MUST NOT upload!
        val jpgClipboardFile = File(tempDir, "reencoded_clip.jpg").apply { writeBytes(jpgBytes) }
        val jpgScreenshotFile = File(tempDir, "Screenshot_reencoded.jpg").apply { writeBytes(jpgBytes) }
        val distinctFile = File(tempDir, "distinct_new.png").apply { writeBytes(distinctBytes) }

        val uploadCount = AtomicInteger(0)
        val wsRequests = mutableListOf<Pair<String, Map<String, Any?>>>()
        val fakeTransfer = object : FileTransferClient(
            context = context,
            deviceId = "android-m41-u4",
            useTls = false
        ) {
            override suspend fun uploadFile(
                serverHost: String,
                transferPort: Int,
                file: File,
                onProgress: ((TransferProgress) -> Unit)?
            ): TransferResult {
                uploadCount.incrementAndGet()
                return TransferResult.Success("tr-up-${uploadCount.get()}", sha256Hex(file.readBytes()), file)
            }
        }
        val fakeClient = SnowWebSocketClient(useTls = false)
        repo.clipboardRequestDispatchOverrideForTest = { action, payload, cb ->
            wsRequests.add(action to payload)
            cb(SnowMessage.createResponse(correlationId = "c-u4", payload = mapOf("status" to "success")))
        }

        // 1) Automatic foreground push of transcoded JPEG -> suppressed!
        val fgLatch = CountDownLatch(1)
        var fgOk = false
        repo.pushStagedImageFileToDesktop(jpgClipboardFile, fakeTransfer, "127.0.0.1", fakeClient, userInitiated = false) { ok, _ ->
            fgOk = ok
            fgLatch.countDown()
        }
        assertTrue(fgLatch.await(2, TimeUnit.SECONDS))
        assertTrue(fgOk)
        assertEquals(0, uploadCount.get())
        assertTrue(wsRequests.isEmpty())

        // 2) Automatic screenshot observer push of transcoded JPEG -> suppressed!
        val ssLatch = CountDownLatch(1)
        var ssOk = false
        repo.uploadStagedScreenshotFile(jpgScreenshotFile, fakeTransfer, "127.0.0.1", fakeClient, userInitiated = false) { ok, _ ->
            ssOk = ok
            ssLatch.countDown()
        }
        assertTrue(ssLatch.await(2, TimeUnit.SECONDS))
        assertTrue(ssOk)
        assertEquals(0, uploadCount.get())
        assertTrue(wsRequests.isEmpty())

        // 3) Class 3 explicit user action on same transcoded JPEG -> NOT swallowed, forwards user_initiated = true!
        val expLatch = CountDownLatch(1)
        var expOk = false
        repo.pushStagedImageFileToDesktop(jpgClipboardFile, fakeTransfer, "127.0.0.1", fakeClient, userInitiated = true) { ok, _ ->
            expOk = ok
            expLatch.countDown()
        }
        assertTrue(expLatch.await(2, TimeUnit.SECONDS))
        assertTrue(expOk)
        assertEquals(1, uploadCount.get())
        assertEquals(1, wsRequests.size)
        assertEquals(sharedCanon, wsRequests.last().second["canonical_sha256"])
        assertEquals(true, wsRequests.last().second["user_initiated"])

        // 4) Genuine distinct image pushes normally with its canonical digest
        val distLatch = CountDownLatch(1)
        var distOk = false
        repo.pushStagedImageFileToDesktop(distinctFile, fakeTransfer, "127.0.0.1", fakeClient, userInitiated = false) { ok, _ ->
            distOk = ok
            distLatch.countDown()
        }
        assertTrue(distLatch.await(2, TimeUnit.SECONDS))
        assertTrue(distOk)
        assertEquals(2, uploadCount.get())
        assertEquals(2, wsRequests.size)
        assertEquals(distinctSha, wsRequests.last().second["sha256"])
        assertEquals(distinctCanon, wsRequests.last().second["canonical_sha256"])
    }
}
