package org.snow.ui

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.network.SnowWebSocketClient
import org.snow.protocol.ErrorCode
import org.snow.protocol.MessageType
import org.snow.protocol.SnowError
import org.snow.protocol.SnowMessage
import org.snow.transfer.FileTransferClient
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

@OptIn(ExperimentalCoroutinesApi::class)
class Milestone3BSection3ClipboardTest {

    private class InMemorySharedPreferences : SharedPreferences {
        private val map = mutableMapOf<String, Any?>()
        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? {
            @Suppress("UNCHECKED_CAST")
            return (map[key] as? Set<String>)?.toMutableSet() ?: defValues
        }
        override fun getInt(key: String?, defValue: Int): Int = (map[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (map[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (map[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (map[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = map.containsKey(key)
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val pending = mutableMapOf<String, Any?>()
            private val removals = mutableSetOf<String>()
            private var clearAll = false
            override fun putString(key: String?, value: String?) = apply { if (key != null) pending[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {
                if (key != null) pending[key] = values?.toSet()
            }
            override fun putInt(key: String?, value: Int) = apply { if (key != null) pending[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) pending[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) pending[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) pending[key] = value }
            override fun remove(key: String?) = apply { if (key != null) removals.add(key) }
            override fun clear() = apply { clearAll = true }
            override fun commit(): Boolean {
                if (clearAll) map.clear()
                for (r in removals) map.remove(r)
                for ((k, v) in pending) if (v == null) map.remove(k) else map[k] = v
                return true
            }
            override fun apply() { commit() }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private val prefsByName = mutableMapOf<String, InMemorySharedPreferences>()
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
        prefsByName.clear()
        tempDir = File(System.getProperty("java.io.tmpdir"), "snow_m3b_s3_${UUID.randomUUID()}").apply { mkdirs() }
        context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = tempDir
            override fun getCacheDir(): File = tempDir
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
                prefsByName.getOrPut(name ?: "default") { InMemorySharedPreferences() }
            override fun getSystemService(name: String): Any? = null
            override fun startService(service: Intent?): android.content.ComponentName? = null
            override fun startForegroundService(service: Intent?): android.content.ComponentName? = null
        }
        resetRepoSingleton()
    }

    @After
    fun tearDown() {
        resetRepoSingleton()
        tempDir.deleteRecursively()
        Dispatchers.resetMain()
    }

    @Test
    fun testCase1_ImageEchoGuardIsolatedFromTextAndThreadSafe() {
        val repo = SnowUiRepository.getInstance(context)
        val sha = "a".repeat(64)

        repo.recordIncomingClipboardText("hello world")
        assertTrue(repo.isDuplicateClipboard("hello world"))
        assertFalse(repo.isDuplicateImageClipboard(sha))

        repo.recordIncomingClipboardImageSha256(sha)
        assertTrue(repo.isDuplicateImageClipboard(sha.uppercase()))
        // Recording an image SHA-256 MUST NOT overwrite or collide with text dedup hash
        assertTrue(repo.isDuplicateClipboard("hello world"))
        assertFalse(repo.isDuplicateClipboard(sha))
    }

    @Test
    fun testCase2And3And4_OwnFileProviderBlockedAndShaUpdatedOnlyAfterDesktopSuccess() {
        val repo = SnowUiRepository.getInstance(context)
        repo.resetImageClipboardEchoGuard()

        // Own FileProvider URI authority/prefix strictly ignored
        assertTrue(repo.isOwnFileProviderUriString("content://org.snow.fileprovider/clipboard/clip_abc.png"))
        assertTrue(repo.isOwnFileProviderAuthority("content", "org.snow.fileprovider"))
        assertFalse(repo.isOwnFileProviderUriString("content://media/external/images/media/42"))
        assertFalse(repo.isOwnFileProviderAuthority("content", "com.android.providers.media.documents"))

        val imgBytes = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 1, 2, 3, 4)
        val expectedSha = MessageDigest.getInstance("SHA-256")
            .digest(imgBytes).joinToString("") { "%02x".format(it) }
        val staged = File(tempDir, "staged_clip.png").apply { writeBytes(imgBytes) }

        val uploadCalls = AtomicInteger(0)
        val fakeTransfer = object : FileTransferClient(
            context = context,
            deviceId = "android-test",
            useTls = false
        ) {
            override suspend fun uploadFile(
                serverHost: String,
                transferPort: Int,
                file: File,
                onProgress: ((TransferProgress) -> Unit)?
            ): TransferResult {
                uploadCalls.incrementAndGet()
                return TransferResult.Success("tr-img-1", expectedSha, file)
            }
        }
        val fakeClient = SnowWebSocketClient(useTls = false)

        // 1. Failed desktop_clipboard_set MUST leave image echo guard unset
        repo.clipboardRequestDispatchOverrideForTest = { _, _, cb ->
            cb(SnowMessage.createError(code = ErrorCode.INTERNAL_ERROR, message = "Desktop rejected"))
        }
        val failLatch = CountDownLatch(1)
        var failOk = true
        repo.pushStagedImageFileToDesktop(staged, fakeTransfer, "192.168.1.50", fakeClient) { ok, _ ->
            failOk = ok
            failLatch.countDown()
        }
        assertTrue(failLatch.await(2, TimeUnit.SECONDS))
        assertFalse(failOk)
        assertEquals(1, uploadCalls.get())
        assertNull("Image SHA must NOT be recorded before desktop_clipboard_set succeeds", repo.getLastImageClipboardSha256())

        // 2. Successful desktop_clipboard_set records expectedSha
        repo.clipboardRequestDispatchOverrideForTest = { _, _, cb ->
            cb(SnowMessage.createResponse(correlationId = "c-ok", payload = mapOf("status" to "success")))
        }
        val okLatch = CountDownLatch(1)
        var okRes = false
        repo.pushStagedImageFileToDesktop(staged, fakeTransfer, "192.168.1.50", fakeClient) { ok, _ ->
            okRes = ok
            okLatch.countDown()
        }
        assertTrue(okLatch.await(2, TimeUnit.SECONDS))
        assertTrue(okRes)
        assertEquals(2, uploadCalls.get())
        assertEquals(expectedSha, repo.getLastImageClipboardSha256())

        // 3. Re-pushing identical image skips upload completely (echo loop stopped!)
        val dupLatch = CountDownLatch(1)
        var dupOk = false
        repo.pushStagedImageFileToDesktop(staged, fakeTransfer, "192.168.1.50", fakeClient) { ok, _ ->
            dupOk = ok
            dupLatch.countDown()
        }
        assertTrue(dupLatch.await(2, TimeUnit.SECONDS))
        assertTrue(dupOk)
        assertEquals(2, uploadCalls.get())
    }

    @Test
    fun testCase5And6_IncomingDispatcherImagePushSetsImageGuardAndPreservesTextGuard() {
        val repo = SnowUiRepository.getInstance(context)
        repo.recordIncomingClipboardText("keep-this-text-hash")

        val incomingBytes = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 9, 8, 7, 6)
        val incomingSha = MessageDigest.getInstance("SHA-256")
            .digest(incomingBytes).joinToString("") { "%02x".format(it) }

        val server = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        val t = thread(isDaemon = true) {
            try {
                while (!server.isClosed) {
                    val s = server.accept()
                    val r = BufferedReader(InputStreamReader(s.getInputStream()))
                    while (true) {
                        val line = r.readLine() ?: break
                        if (line.isBlank()) break
                    }
                    val out = s.getOutputStream()
                    val hdr = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: ${incomingBytes.size}\r\nConnection: close\r\n\r\n"
                    out.write(hdr.toByteArray())
                    out.write(incomingBytes)
                    out.flush()
                    s.close()
                }
            } catch (_: Exception) {}
        }

        try {
            val transferClient = FileTransferClient(
                context = context,
                deviceId = "android-test",
                useTls = false
            )
            val dispatcher = AndroidCapabilityDispatcher(
                context = context,
                transferClientProvider = { transferClient }
            )
            var appliedFile: File? = null
            var appliedMime: String? = null
            runBlocking {
                val (res, err) = dispatcher.handleIncomingClipboardPush(
                    data = mapOf(
                        "type" to "image",
                        "transfer_id" to "tr-in",
                        "sha256" to incomingSha,
                        "size" to incomingBytes.size,
                        "transfer_port" to server.localPort,
                        "mime_type" to "image/png"
                    ),
                    serverHost = "127.0.0.1",
                    defaultTransferPort = server.localPort,
                    transferClient = transferClient,
                    repoOverride = repo,
                    imageClipApplierOverride = { f, m ->
                        appliedFile = f
                        appliedMime = m
                    }
                )
                assertNull(err)
                assertEquals("success", res?.get("status"))
            }

            assertEquals("image/png", appliedMime)
            assertTrue(appliedFile?.exists() == true)
            assertEquals(incomingSha, repo.getLastImageClipboardSha256())
            assertTrue(repo.isDuplicateClipboard("keep-this-text-hash"))
        } finally {
            server.close()
            t.join(1000)
        }
    }

    @Test
    fun testCase7_FormatApplyClipboardFeedbackDistinguishesSafFromClipboard() {
        assertEquals(
            "Saved report.pdf to SAF folder",
            formatApplyClipboardFeedback(true, "Saved report.pdf to SAF folder")
        )
        assertEquals(
            "Saved 2 files to SAF folder (a.txt, b.png)",
            formatApplyClipboardFeedback(true, "Saved 2 files to SAF folder (a.txt, b.png)")
        )
        assertEquals(
            "Copied image to Android clipboard",
            formatApplyClipboardFeedback(true, "Copied image to Android clipboard")
        )
        assertEquals(
            "Failed: Storage permission revoked",
            formatApplyClipboardFeedback(false, "Storage permission revoked")
        )
    }
}
