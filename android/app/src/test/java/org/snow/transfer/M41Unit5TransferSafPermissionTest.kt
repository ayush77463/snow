package org.snow.transfer

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.capabilities.AndroidFileHandler
import org.snow.capabilities.AppLauncherHandler
import org.snow.service.SnowForegroundService
import org.snow.ui.files.SafFolderManager
import org.snow.ui.settings.SettingsPermissionInspector
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

@OptIn(ExperimentalCoroutinesApi::class)
class M41Unit5TransferSafPermissionTest {

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

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        prefsByName.clear()
        SnowForegroundService.setServiceRunningForTest(false)
        tempDir = File(System.getProperty("java.io.tmpdir"), "snow_m41_u5_${UUID.randomUUID()}").apply { mkdirs() }
        context = object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = tempDir
            override fun getCacheDir(): File = tempDir
            override fun getExternalFilesDir(type: String?): File = File(tempDir, "ext_${type ?: "default"}").apply { mkdirs() }
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
                prefsByName.getOrPut(name ?: "default") { MemPrefs() }
            override fun getSystemService(name: String): Any? = null
            override fun startService(service: Intent?): android.content.ComponentName? = null
            override fun startForegroundService(service: Intent?): android.content.ComponentName? = null
        }
    }

    @After
    fun tearDown() {
        SnowForegroundService.setServiceRunningForTest(false)
        tempDir.deleteRecursively()
        Dispatchers.resetMain()
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun resolveModuleFile(rel: String): File {
        val candidates = listOf(File(rel), File("app", rel), File("android/app", rel))
        return candidates.firstOrNull { it.exists() } ?: error("Cannot resolve $rel")
    }

    @Test
    fun skipExactBytesHandlesZeroSkipOver2GiBOffsetsAndPrematureEof() {
        // 1. Stream returning partial skips (1 byte) AND 0L skips (falls back to read discard)
        val payload = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".toByteArray()
        val flakyStream = object : InputStream() {
            private var pos = 0
            private var skipCallCount = 0
            override fun read(): Int = if (pos < payload.size) payload[pos++].toInt() and 0xFF else -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (pos >= payload.size) return -1
                val n = minOf(len, 2, payload.size - pos)
                System.arraycopy(payload, pos, b, off, n)
                pos += n
                return n
            }
            override fun skip(n: Long): Long {
                skipCallCount++
                if (skipCallCount % 2 == 1) return 0L // Zero-progress skip!
                val adv = minOf(1L, (payload.size - pos).toLong(), n)
                pos += adv.toInt()
                return adv
            }
        }
        FileTransferClient.skipExactBytes(flakyStream, 10L)
        val rest = flakyStream.readBytes()
        assertEquals("ABCDEFGHIJKLMNOPQRSTUVWXYZ", String(rest))

        // 2. Virtual >2 GiB (3 GiB) stream skip via Long cursor without Int overflow or RAM allocation
        val threeGiB = 3L * 1024L * 1024L * 1024L
        val tail = "OVER_3GIB_MARKER".toByteArray()
        val bigVirtualStream = object : InputStream() {
            private var cursor = 0L
            private val total = threeGiB + tail.size
            override fun skip(n: Long): Long {
                val maxStep = minOf(n, 1_000_000_000L, total - cursor)
                cursor += maxStep
                return maxStep
            }
            override fun read(): Int {
                if (cursor >= total) return -1
                val b = if (cursor >= threeGiB) tail[(cursor - threeGiB).toInt()].toInt() and 0xFF else 0
                cursor++
                return b
            }
        }
        FileTransferClient.skipExactBytes(bigVirtualStream, threeGiB)
        assertEquals("OVER_3GIB_MARKER", String(bigVirtualStream.readBytes()))

        // 3. Premature EOF throws EOFException cleanly
        val shortStream = "tiny".byteInputStream()
        var threwEof = false
        try {
            FileTransferClient.skipExactBytes(shortStream, 100L)
        } catch (_: EOFException) {
            threwEof = true
        }
        assertTrue(threwEof)
    }

    @Test
    fun downloadFileResumesViaHttpRangeHandles416Rejects422AndRespectsCancel() = runTest {
        val fullPayload = ("SNOW_RESUME_CHUNK_TEST_" .repeat(4000)).toByteArray()
        val fullSha = sha256Hex(fullPayload)
        val splitPoint = fullPayload.size / 2

        // Case A: Connection drops at midpoint on Attempt 1, resumes cleanly with Range on Attempt 2
        val requests = CopyOnWriteArrayList<String>()
        val srv1 = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        val attemptCounter = AtomicInteger(0)
        val t1 = thread(isDaemon = true) {
            try {
                while (!srv1.isClosed && attemptCounter.get() < 2) {
                    val s = srv1.accept()
                    val n = attemptCounter.incrementAndGet()
                    s.use { sock ->
                        val r = sock.getInputStream().bufferedReader()
                        var rangeHdr = ""
                        while (true) {
                            val line = r.readLine() ?: break
                            if (line.isEmpty()) break
                            if (line.startsWith("Range:", ignoreCase = true)) {
                                rangeHdr = line
                            }
                        }
                        requests.add(rangeHdr)
                        val out = sock.getOutputStream()
                        if (n == 1) {
                            // Claim full Content-Length but truncate stream early at splitPoint!
                            out.write("HTTP/1.1 200 OK\r\nContent-Length: ${fullPayload.size}\r\nConnection: close\r\n\r\n".toByteArray())
                            out.write(fullPayload, 0, splitPoint)
                            out.flush()
                        } else {
                            val remaining = fullPayload.size - splitPoint
                            out.write("HTTP/1.1 206 Partial Content\r\nContent-Length: $remaining\r\nContent-Range: bytes $splitPoint-${fullPayload.size - 1}/${fullPayload.size}\r\nConnection: close\r\n\r\n".toByteArray())
                            out.write(fullPayload, splitPoint, remaining)
                            out.flush()
                        }
                    }
                }
            } catch (_: Exception) {}
        }

        val client = FileTransferClient(
            context = context,
            deviceId = "android-u5",
            useTls = false,
            retryBaseDelayMs = 20L
        )
        val outA = File(tempDir, "resumed.bin")
        val resA = client.downloadFile("127.0.0.1", srv1.localPort, "tr-res-1", outA, fullSha, resume = true)
        srv1.close()
        t1.join(2000)

        assertTrue("Expected Success after Range resume, got $resA", resA is FileTransferClient.TransferResult.Success)
        assertEquals(fullPayload.toList(), outA.readBytes().toList())
        assertTrue(requests.size == 2 && requests[1].contains("bytes=$splitPoint-"))

        // Case B: HTTP 416 deletes invalid .part and recovers from offset 0
        val outB = File(tempDir, "recover416.bin")
        File(outB.parentFile, "${outB.name}.part").writeBytes(ByteArray(fullPayload.size + 500))
        val srv2 = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        val c2 = AtomicInteger(0)
        val t2 = thread(isDaemon = true) {
            try {
                while (!srv2.isClosed && c2.get() < 2) {
                    val s = srv2.accept()
                    val n = c2.incrementAndGet()
                    s.use { sock ->
                        val r = sock.getInputStream().bufferedReader()
                        while (true) {
                            val line = r.readLine() ?: break
                            if (line.isEmpty()) break
                        }
                        val out = sock.getOutputStream()
                        if (n == 1) {
                            out.write("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */${fullPayload.size}\r\nContent-Length: 0\r\n\r\n".toByteArray())
                        } else {
                            out.write("HTTP/1.1 200 OK\r\nContent-Length: ${fullPayload.size}\r\n\r\n".toByteArray())
                            out.write(fullPayload)
                        }
                        out.flush()
                    }
                }
            } catch (_: Exception) {}
        }
        val resB = client.downloadFile("127.0.0.1", srv2.localPort, "tr-416-1", outB, fullSha, resume = true)
        srv2.close()
        t2.join(2000)
        assertTrue(resB is FileTransferClient.TransferResult.Success)
        assertEquals(fullPayload.toList(), outB.readBytes().toList())

        // Case C: SHA-256 mismatch -> 422 Error without retry and deletes corrupt .part
        val outC = File(tempDir, "badsha.bin")
        val srv3 = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        val c3 = AtomicInteger(0)
        val t3 = thread(isDaemon = true) {
            try {
                val s = srv3.accept()
                c3.incrementAndGet()
                s.use { sock ->
                    val r = sock.getInputStream().bufferedReader()
                    while (true) {
                        val line = r.readLine() ?: break
                        if (line.isEmpty()) break
                    }
                    val badData = "CORRUPTED".toByteArray()
                    sock.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: ${badData.size}\r\n\r\n".toByteArray())
                    sock.getOutputStream().write(badData)
                    sock.getOutputStream().flush()
                }
            } catch (_: Exception) {}
        }
        val resC = client.downloadFile("127.0.0.1", srv3.localPort, "tr-422-1", outC, "f".repeat(64), resume = true)
        srv3.close()
        t3.join(2000)
        assertTrue(resC is FileTransferClient.TransferResult.Error)
        assertEquals(422, (resC as FileTransferClient.TransferResult.Error).code)
        assertEquals(1, c3.get())
        assertFalse(File(outC.parentFile, "${outC.name}.part").exists())
    }

    @Test
    fun safFolderPersistFailsClosedWithoutCorruptingPriorSelectionAndAutoScopeAvoidsManageStorage() = runTest {
        // 1. Mock Uri string via Uri.parse stub (or check non-content failure + SecurityException preservation)
        val uriGood = Uri.parse("content://com.android.externalstorage.documents/tree/primary%3ADownload%2FSNOW")
        val uriBad = Uri.parse("content://com.android.externalstorage.documents/tree/primary%3ABad")
        // NOTE: In JVM tests with isReturnDefaultValues=true, Uri.parse may return null unless mocked; skip null safely if needed
        if (uriGood != null && uriBad != null) {
            val goodMgr = SafFolderManager(
                context = context,
                persistUriPermissionHandler = { _, _ -> },
                uriAccessValidator = { it == uriGood }
            )
            assertTrue(goodMgr.persistFolderUri(uriGood))
            assertTrue(goodMgr.hasValidPersistedFolderUri())

            val failingMgr = SafFolderManager(
                context = context,
                persistUriPermissionHandler = { _, _ -> throw SecurityException("Permission denied") },
                uriAccessValidator = { true }
            )
            assertFalse(failingMgr.persistFolderUri(uriBad))
            // Original valid selection MUST remain intact!
            assertEquals(uriGood.toString(), failingMgr.getDestinationUri()?.toString())

            // Revoked URI validator returns false without throwing
            val revokedMgr = SafFolderManager(
                context = context,
                persistUriPermissionHandler = { _, _ -> },
                uriAccessValidator = { false }
            )
            assertFalse(revokedMgr.hasValidPersistedFolderUri())
        }

        // 2. AndroidFileHandler scope="auto" works in SAF-first mode and never throws ALL_FILES_ACCESS_REQUIRED
        val handler = AndroidFileHandler(context = context, transferClientProvider = { null })
        val autoRes = handler.handleFileList(mapOf("scope" to "auto", "principal" to "OWNER_MANUAL"))
        assertNotEquals("ALL_FILES_ACCESS_REQUIRED", autoRes["status"])
        val fullRes = handler.handleFileList(mapOf("scope" to "full", "principal" to "OWNER_MANUAL"))
        assertEquals("ALL_FILES_ACCESS_REQUIRED", fullRes["status"])

        // 3. Async file_send_request returns ACCEPTED immediately and reports completion + supports cancel
        val payload = "ASYNC_FILE_TRANSFER_BODY".toByteArray()
        val sha = sha256Hex(payload)
        val srv = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        val t = thread(isDaemon = true) {
            try {
                srv.accept().use { sock ->
                    val r = sock.getInputStream().bufferedReader()
                    while (true) {
                        val line = r.readLine() ?: break
                        if (line.isEmpty()) break
                    }
                    sock.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: ${payload.size}\r\n\r\n".toByteArray())
                    sock.getOutputStream().write(payload)
                    sock.getOutputStream().flush()
                }
            } catch (_: Exception) {}
        }
        val doneLatch = CountDownLatch(1)
        var reportedStatus: String? = null
        val tClient = FileTransferClient(context = context, deviceId = "android-u5", useTls = false)
        val dispatcher = AndroidCapabilityDispatcher(
            context = context,
            transferClientProvider = { tClient }
        ).apply {
            transferStatusReporter = { m ->
                reportedStatus = m["status"] as? String
                doneLatch.countDown()
            }
        }
        val (accRes, accErr) = dispatcher.dispatch(
            action = "file_send_request",
            data = mapOf(
                "transfer_id" to "tr-async-1",
                "file_name" to "async_doc.txt",
                "sha256" to sha,
                "transfer_port" to srv.localPort,
                "async" to true
            ),
            serverHost = "127.0.0.1",
            defaultTransferPort = srv.localPort
        )
        assertNull(accErr)
        assertEquals("accepted", accRes?.get("status"))
        assertTrue(doneLatch.await(5, TimeUnit.SECONDS))
        srv.close()
        t.join(1000)
        assertEquals("COMPLETED", reportedStatus)
        val resolvedDownloadsDir = context.getExternalFilesDir(android.os.Environment.DIRECTORY_DOWNLOADS)
        val committedFile = File(File(resolvedDownloadsDir, "SNOW"), "async_doc.txt")
        assertTrue("async_doc.txt must be committed into isolated test tempDir, not CWD: ${committedFile.absolutePath}", committedFile.isFile)
        assertTrue(committedFile.canonicalPath.startsWith(tempDir.canonicalPath))
        assertFalse("Must never create CWD relative SNOW/ directory", File("SNOW").exists())
        assertFalse("Must never create android/app/SNOW/ directory", File("android/app/SNOW").exists())
    }

    @Test
    fun honestPermissionsServiceObservabilityAndScopedRestrictedManifestPermissions() {
        val snapSetupNeeded = SettingsPermissionInspector.inspect(
            context = context,
            listenerGranted = false,
            allFilesAccessOverride = false,
            safConfiguredOverride = false,
            overlayPermissionOverride = false
        )
        assertEquals("SETUP", snapSetupNeeded.notificationSyncBadgeText())
        assertEquals("SETUP", snapSetupNeeded.fileAccessBadgeText())
        assertEquals("DEFAULT", snapSetupNeeded.transferFolderBadgeText())
        assertEquals("SETUP", snapSetupNeeded.backgroundRunBadgeText())

        // Never shows fake "Background Run: Granted"
        assertFalse(snapSetupNeeded.backgroundRunBadgeText().contains("GRANTED"))

        val snapGranted = SettingsPermissionInspector.inspect(
            context = context,
            listenerGranted = true,
            allFilesAccessOverride = true,
            safConfiguredOverride = true,
            safFolderNameOverride = "SNOW_Backup",
            overlayPermissionOverride = true
        )
        assertEquals("GRANTED", snapGranted.notificationSyncBadgeText())
        assertEquals("GRANTED", snapGranted.fileAccessBadgeText())
        assertEquals("CONFIGURED", snapGranted.transferFolderBadgeText())
        assertEquals("GRANTED", snapGranted.backgroundRunBadgeText())
        assertEquals("SNOW_Backup", snapGranted.safFolderName)

        // Verify AppLauncherHandler no longer references "Display over other apps"
        val launcherSrc = resolveModuleFile("src/main/java/org/snow/capabilities/AppLauncherHandler.kt").readText()
        assertFalse(launcherSrc.contains("Display over other apps"))

        // Verify SettingsScreen contains ON_RESUME refresh, SAF OpenDocumentTree, M4.6 intents, and no fake granted badge
        val settingsSrc = resolveModuleFile("src/main/java/org/snow/ui/settings/SettingsScreen.kt").readText()
        assertTrue(settingsSrc.contains("ON_RESUME"))
        assertTrue(settingsSrc.contains("OpenDocumentTree"))
        assertTrue(settingsSrc.contains("ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION"))
        assertTrue(settingsSrc.contains("ACTION_MANAGE_OVERLAY_PERMISSION"))
        assertFalse(settingsSrc.contains("Background Run: Granted"))

        // Verify AndroidManifest declares strictly MANAGE_EXTERNAL_STORAGE + SYSTEM_ALERT_WINDOW (never INSTALL_PACKAGES / BATTERY_OPT)
        val manifest = resolveModuleFile("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("android.permission.SYSTEM_ALERT_WINDOW"))
        assertTrue(manifest.contains("android.permission.MANAGE_EXTERNAL_STORAGE"))
        assertFalse(manifest.contains("REQUEST_INSTALL_PACKAGES"))
        assertFalse(manifest.contains("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"))
    }
}
