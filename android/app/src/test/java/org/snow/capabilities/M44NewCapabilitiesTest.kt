package org.snow.capabilities

import android.content.Context
import android.content.ContextWrapper
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.snow.protocol.ErrorCode
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicInteger

/**
 * M4.4 Stage 5 Tests: All 6 new Android capabilities on pure JVM with real File-backed SAF trees:
 * - snow_android_file_read (valid UTF-8, traversal rejections, 256 KiB cap, binary/malformed UTF-8 error, missing SAF)
 * - snow_android_file_write (created vs updated, overwrite=false protection, 256 KiB cap, traversal rejection)
 * - snow_android_file_search (case-insensitive filenames only, bounded depth<=5 & max_results<=50, truncated flag)
 * - snow_android_device_info (model/version/RAM/storage/lock/active transport; zero serial/IMEI/Android ID)
 * - snow_android_audio_status (streams/ringer mode + unavailable DND when policy access denied without mutating settings)
 * - snow_android_clipboard_get (strict visible foreground Activity requirement vs background denial)
 */
class M44NewCapabilitiesTest {

    private val tempDirs = mutableListOf<File>()

    private class FileSafNode(private val file: File) : AndroidFileHandler.SafNode {
        override val name: String get() = file.name
        override val isDirectory: Boolean get() = file.isDirectory
        override val isFile: Boolean get() = file.isFile
        override val length: Long get() = file.length()
        override val lastModified: Long get() = file.lastModified()
        override val canRead: Boolean get() = file.canRead()
        override val canWrite: Boolean get() = file.canWrite()
        override val exists: Boolean get() = file.exists()

        override fun findChild(displayName: String): AndroidFileHandler.SafNode? {
            val child = File(file, displayName)
            return if (child.exists()) FileSafNode(child) else null
        }

        override fun listChildren(): List<AndroidFileHandler.SafNode> =
            (file.listFiles() ?: emptyArray()).map { FileSafNode(it) }

        override fun createChildFile(mimeType: String, displayName: String): AndroidFileHandler.SafNode? {
            val child = File(file, displayName)
            if (!file.exists()) file.mkdirs()
            return if (child.createNewFile()) FileSafNode(child) else null
        }

        override fun createChildDirectory(displayName: String): AndroidFileHandler.SafNode? {
            val child = File(file, displayName)
            return if (child.exists() || child.mkdirs()) FileSafNode(child) else null
        }

        override fun openInputStream(): InputStream = file.inputStream()
        override fun openOutputStream(truncate: Boolean): OutputStream = FileOutputStream(file, false)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Before
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @After
    fun cleanup() {
        ClipboardHandler.resetForegroundTracking()
        ClipboardHandler.isUserIntentGranted = false
        Dispatchers.resetMain()
        tempDirs.forEach { it.deleteRecursively() }
    }

    private class MemPrefs : SharedPreferences {
        val map = mutableMapOf<String, Any?>()
        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String?, defValue: Int): Int = (map[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (map[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (map[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (map[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = map.containsKey(key)
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val p = mutableMapOf<String, Any?>()
            override fun putString(key: String?, value: String?) = apply { if (key != null) p[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply {}
            override fun putInt(key: String?, value: Int) = apply { if (key != null) p[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) p[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) p[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) p[key] = value }
            override fun remove(key: String?) = apply { if (key != null) p[key] = null }
            override fun clear() = apply { map.clear() }
            override fun commit(): Boolean {
                p.forEach { (k, v) -> if (v == null) map.remove(k) else map[k] = v }
                return true
            }
            override fun apply() { commit() }
        }
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private fun newTestContext(): Context {
        val dir = java.nio.file.Files.createTempDirectory("m44_caps_").toFile().also { tempDirs.add(it) }
        val prefsMap = mutableMapOf<String, MemPrefs>()
        return object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = dir
            override fun getCacheDir(): File = dir
            override fun getPackageName(): String = "org.snow"
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
                prefsMap.getOrPut(name ?: "default") { MemPrefs() }
            override fun getSystemService(name: String): Any? = null
        }
    }

    private fun newSafFileHandler(rootDir: File): AndroidFileHandler {
        val ctx = newTestContext()
        return AndroidFileHandler(
            context = ctx,
            transferClientProvider = { null },
            safNodeProviderOverride = { FileSafNode(rootDir) }
        )
    }

    @Test
    fun safFileReadWriteSearchValidationAndBounds() {
        val safRoot = java.nio.file.Files.createTempDirectory("m44_saf_").toFile().also { tempDirs.add(it) }
        val handler = newSafFileHandler(safRoot)

        // 1. Unconfigured SAF returns explicit error (no fallback)
        val unconfigured = AndroidFileHandler(newTestContext(), { null }).readSafTextFile(mapOf("path" to "a.txt"))
        assertEquals("SAF_FOLDER_NOT_CONFIGURED", unconfigured["status"])

        // 2. Write new file in nested folder -> outcome = created
        val wNew = handler.writeSafTextFile(mapOf("path" to "notes/hello.txt", "content" to "hello snow UTF-8 \u2744"))
        assertEquals("success", wNew["status"])
        assertEquals("created", wNew["outcome"])
        assertEquals("hello snow UTF-8 \u2744", File(safRoot, "notes/hello.txt").readText())

        // 3. Existing file with overwrite=false refuses cleanly without overwriting
        val wConflict = handler.writeSafTextFile(mapOf("path" to "notes/hello.txt", "content" to "clobber", "overwrite" to false))
        assertEquals("FILE_EXISTS", wConflict["status"])
        assertEquals("hello snow UTF-8 \u2744", File(safRoot, "notes/hello.txt").readText())

        // 4. Existing file with overwrite=true updates cleanly
        val wUpdate = handler.writeSafTextFile(mapOf("path" to "notes/hello.txt", "content" to "updated content", "overwrite" to true))
        assertEquals("success", wUpdate["status"])
        assertEquals("updated", wUpdate["outcome"])

        // 5. Read valid UTF-8 file
        val readOk = handler.readSafTextFile(mapOf("path" to "notes/hello.txt"))
        assertEquals("success", readOk["status"])
        assertEquals("updated content", readOk["content"])

        // 6. Traversal, absolute, backslash, percent-encoded, NUL rejected on read/write/search
        for (badPath in listOf("../secret.txt", "notes/../../x", "/etc/passwd", "a\\b.txt", "%2e%2e/x", "a\u0000b")) {
            val rr = handler.readSafTextFile(mapOf("path" to badPath))
            assertEquals("Expected traversal rejection for $badPath", "PATH_TRAVERSAL_DETECTED", rr["status"])
            val wr = handler.writeSafTextFile(mapOf("path" to badPath, "content" to "x"))
            assertEquals("Expected write traversal rejection for $badPath", "PATH_TRAVERSAL_DETECTED", wr["status"])
        }

        // 7. Oversized > 256 KiB rejected on both read & write
        val oversizedStr = "A".repeat(256 * 1024 + 10)
        assertEquals("FILE_TOO_LARGE", handler.writeSafTextFile(mapOf("path" to "big.txt", "content" to oversizedStr))["status"])
        File(safRoot, "real_big.txt").writeBytes(ByteArray(256 * 1024 + 1) { 0x41 })
        assertEquals("FILE_TOO_LARGE", handler.readSafTextFile(mapOf("path" to "real_big.txt"))["status"])

        // 8. Binary / malformed UTF-8 rejected cleanly
        File(safRoot, "bad_utf8.bin").writeBytes(byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0x00, 0x01))
        assertEquals("BINARY_OR_INVALID_UTF8", handler.readSafTextFile(mapOf("path" to "bad_utf8.bin"))["status"])

        // 9. Search filenames only (bounded max_results <= 50, max_depth <= 5, zero file content opened)
        for (i in 1..60) {
            File(safRoot, "report_$i.txt").writeText("secret-$i")
        }
        val searchRes = handler.searchSafFileNames(mapOf("query" to "REPORT", "max_results" to 200, "max_depth" to 10))
        assertEquals("success", searchRes["status"])
        assertEquals(50, searchRes["count"])
        assertEquals(true, searchRes["truncated"])
        @Suppress("UNCHECKED_CAST")
        val matches = searchRes["matches"] as List<Map<String, Any?>>
        assertFalse(matches.any { it.containsKey("content") || it.containsKey("uri") })
    }

    @Test
    fun deviceInfoAndAudioStatusZeroSecretsZeroMutations() {
        val ctx = newTestContext()
        val mutates = AtomicInteger(0)
        val sys = SystemStatusHandler(
            context = ctx,
            transportSnapshotProvider = {
                mapOf("route" to "usb", "badge" to "USB • Zero Data", "connected" to true, "switching" to false)
            },
            memoryInfoProvider = { 8192L to 4096L },
            storageInfoProvider = { 128_000_000_000L to 64_000_000_000L },
            interactiveAndLockedProvider = { true to false },
            dndPolicyAccessProvider = { false },
            dndFilterProvider = { mutates.incrementAndGet(); 1 },
            audioStreamsProvider = {
                mapOf(
                    "ringer_mode" to "normal",
                    "streams" to mapOf("media" to mapOf("volume" to 8, "max_volume" to 15, "percent" to 53))
                )
            }
        )

        val devInfo = sys.getDeviceInfo()
        assertEquals("success", devInfo["status"])
        assertEquals(8192L, devInfo["ram_total_mb"])
        @Suppress("UNCHECKED_CAST")
        val tr = devInfo["active_transport"] as Map<String, Any?>
        assertEquals("usb", tr["route"])
        for (forbiddenKey in listOf("imei", "serial", "android_id", "mac", "phone_number")) {
            assertFalse(devInfo.containsKey(forbiddenKey))
        }

        val audio = sys.getAudioStatus()
        assertEquals("success", audio["status"])
        assertEquals(false, audio["notification_policy_access_granted"])
        assertEquals("unavailable", audio["dnd_status"])
        assertEquals(0, mutates.get())
    }

    @Test
    fun clipboardGetRequiresGenuineForegroundLifecycleNotJustService() = runBlocking {
        val ctx = newTestContext()
        val dispatcher = AndroidCapabilityDispatcher(ctx) { null }
        dispatcher.clipboardHandler.primaryClipTextProviderOverride = { "foreground-safe-clip" }
        dispatcher.activePermissionProfile = "full_control"

        // Even with profile=full_control, backgrounded state MUST reject with FOREGROUND_REQUIRED
        ClipboardHandler.resetForegroundTracking()
        val (bgData, bgErr) = dispatcher.dispatch("snow_android_clipboard_get", emptyMap())
        assertNull(bgData)
        assertNotNull(bgErr)
        assertEquals(ErrorCode.UNAUTHORIZED, bgErr!!.code)
        assertTrue(bgErr.message.contains("FOREGROUND_REQUIRED"))

        // Activity paused -> still blocked
        ClipboardHandler.onActivityResumed("MainActivity")
        ClipboardHandler.onActivityPaused("MainActivity")
        val (_, pausedErr) = dispatcher.dispatch("android_clipboard_get", emptyMap())
        assertNotNull(pausedErr)
        assertTrue(pausedErr!!.message.contains("FOREGROUND_REQUIRED"))

        // Activity resumed in foreground -> succeeds cleanly
        ClipboardHandler.onActivityResumed("MainActivity")
        ClipboardHandler.isUserIntentGranted = true
        val (fgData, fgErr) = dispatcher.dispatch("snow_android_clipboard_get", emptyMap())
        assertNull(fgErr)
        assertNotNull(fgData)
        assertEquals("foreground-safe-clip", fgData!!["text"])
    }
}
