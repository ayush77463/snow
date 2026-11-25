package org.snow.ui

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.network.AndroidPeerHostManager
import org.snow.network.DeviceNode
import org.snow.network.PeerHostState
import java.io.File

/**
 * Automated JVM behavioral & source-contract regression tests for SNOW V5.0.0 fixes.
 */
class Stage5V5ReleaseRegressionTest {

    private class InMemorySharedPreferences : SharedPreferences {
        private val data = mutableMapOf<String, Any?>()
        override fun getAll(): MutableMap<String, *> = data.toMutableMap()
        override fun getString(key: String?, defValue: String?): String? = (data[key] as? String) ?: defValue
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            (data[key] as? Set<String>)?.toMutableSet() ?: defValues
        override fun getInt(key: String?, defValue: Int): Int = (data[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (data[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (data[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = (data[key] as? Boolean) ?: defValue
        override fun contains(key: String?): Boolean = data.containsKey(key)
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val pending = mutableMapOf<String, Any?>()
            private var clearAll = false
            override fun putString(key: String?, value: String?) = apply { if (key != null) pending[key] = value }
            override fun putStringSet(key: String?, values: MutableSet<String>?) = apply { if (key != null) pending[key] = values?.toSet() }
            override fun putInt(key: String?, value: Int) = apply { if (key != null) pending[key] = value }
            override fun putLong(key: String?, value: Long) = apply { if (key != null) pending[key] = value }
            override fun putFloat(key: String?, value: Float) = apply { if (key != null) pending[key] = value }
            override fun putBoolean(key: String?, value: Boolean) = apply { if (key != null) pending[key] = value }
            override fun remove(key: String?) = apply { if (key != null) pending[key] = null }
            override fun clear() = apply { clearAll = true }
            override fun commit(): Boolean { apply(); return true }
            override fun apply() {
                if (clearAll) data.clear()
                pending.forEach { (k, v) -> if (v == null) data.remove(k) else data[k] = v }
            }
        }
    }

    private class FakeAppContext(private val tempRoot: File) : ContextWrapper(null) {
        private val prefs = mutableMapOf<String, SharedPreferences>()
        override fun getApplicationContext(): Context = this
        override fun getCacheDir(): File = File(tempRoot, "cache").apply { mkdirs() }
        override fun getFilesDir(): File = File(tempRoot, "files").apply { mkdirs() }
        override fun getPackageName(): String = "org.snow"
        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences =
            prefs.getOrPut(name ?: "default") { InMemorySharedPreferences() }
    }

    private fun resolveModuleFile(relPath: String): File {
        val candidates = listOf(File(relPath), File("app", relPath), File("android/app", relPath))
        return candidates.firstOrNull { it.exists() }
            ?: error("Could not locate file: $relPath (cwd=${File(".").absolutePath})")
    }

    @Test
    fun testPhase1ManifestIncludesAllImplementedCapabilitiesAndDispatcherProfileRules() {
        val manifest = DeviceNode.buildAndroidManifest(null)
        val expectedNewCaps = listOf(
            "android.notifications.list",
            "android.notifications.reply",
            "android.notifications.dismiss",
            "android.media.control",
            "android.link.share",
            "android.screen.capture",
            "android.screen.stream",
            "android.camera.capture"
        )
        expectedNewCaps.forEach { cap ->
            assertTrue("Manifest missing implemented capability: $cap", manifest.supportsCapability(cap))
            assertTrue("Classification missing for: $cap", manifest.classifications.containsKey(cap))
        }

        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_v5_manifest_${System.nanoTime()}").apply { mkdirs() }
        try {
            val safeContextManifest = DeviceNode.buildAndroidManifest(FakeAppContext(tempDir))
            assertTrue(safeContextManifest.supportedCapabilities.size >= 17)

            val dispatcher = AndroidCapabilityDispatcher(FakeAppContext(tempDir)) { null }
            dispatcher.activePermissionProfile = "clipboard_only"
            for (blocked in listOf("media_control", "share_link", "notifications_list", "android_screenshot", "screen_stream_stop", "android_screen_stream_stop", "android_camera_capture")) {
                assertFalse("clipboard_only must block $blocked", dispatcher.isActionAllowedByProfile(blocked))
            }

            dispatcher.activePermissionProfile = "files_and_clipboard"
            for (blocked in listOf("media_control", "share_link", "notifications_list", "android_screenshot", "screen_stream_stop", "android_camera_capture")) {
                assertFalse("files_and_clipboard must block $blocked", dispatcher.isActionAllowedByProfile(blocked))
            }

            dispatcher.activePermissionProfile = "full_control"
            assertTrue(dispatcher.isActionAllowedByProfile("android_screen_stream_stop"))
            assertTrue(dispatcher.isActionAllowedByProfile("media_control"))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testPhase2And3BackgroundReliabilityAndSeparatedLaunchers() {
        val manifestText = resolveModuleFile("src/main/AndroidManifest.xml").readText()
        assertTrue(manifestText.contains("android.permission.SYSTEM_ALERT_WINDOW"))

        val fgServiceText = resolveModuleFile("src/main/java/org/snow/service/SnowForegroundService.kt").readText()
        assertTrue(fgServiceText.contains("START_STICKY"))
        assertTrue(fgServiceText.contains("if (userDisconnected && !peerHostManager.isHostModeActive())"))

        val mainActivityText = resolveModuleFile("src/main/java/org/snow/ui/MainActivity.kt").readText()
        assertTrue(mainActivityText.contains("oneTimeScreenCaptureLauncher"))
        assertTrue(mainActivityText.contains("liveScreenShareLauncher"))
        assertTrue(mainActivityText.contains("Manifest.permission.POST_NOTIFICATIONS"))
    }

    @Test
    fun testPhase4RealPeerHostPairingQrGenerationAndAutoPinRefresh() {
        val mgr = AndroidPeerHostManager()
        // Without an active cert fingerprint, refuses to emit broken QR
        assertNull(mgr.generatePairingQrJson("android-dev-01", "SNW-1234-5678"))

        mgr.setHostStateForTesting(
            PeerHostState(
                isActive = true,
                ipAddress = "192.168.1.77",
                port = 8767,
                certFingerprint = "AA:BB:CC:DD:EE:FF:00:11",
                pairingPin = null
            )
        )

        val qrStr = mgr.generatePairingQrJson("android-dev-01", "SNW-1234-5678")
        assertNotNull("Expected valid Protocol v1 JSON pairing QR", qrStr)
        val obj = JSONObject(qrStr!!)
        assertEquals(1, obj.getInt("v"))
        assertEquals("android-dev-01", obj.getString("id"))
        assertEquals("SNW-1234-5678", obj.getString("snow_id"))
        assertEquals("192.168.1.77", obj.getJSONArray("ips").getString(0))
        assertEquals(8767, obj.getInt("port"))
        assertEquals("AABBCCDDEEFF0011", obj.getString("fp"))
        val pin1 = obj.getString("pin")
        assertEquals(6, pin1.length)
        assertTrue(pin1.all { it.isDigit() })

        // Consuming single-use PIN causes next generatePairingQrJson() to mint a fresh PIN
        assertTrue(mgr.verifyAndConsumePairingPin(pin1))
        val qr2Str = mgr.generatePairingQrJson("android-dev-01", "SNW-1234-5678")
        assertNotNull(qr2Str)
        val pin2 = JSONObject(qr2Str!!).getString("pin")
        assertEquals(6, pin2.length)
        assertTrue(pin2.all { it.isDigit() })
    }

    @Test
    fun testPhase5StitchParityAndRegressionFixesInUiSources() {
        val homeSrc = resolveModuleFile("src/main/java/org/snow/ui/home/HomeScreen.kt").readText()
        assertTrue(homeSrc.contains("UnifiedClipboardItemRow"))
        assertTrue(homeSrc.contains("LocalPhoneTelemetryStrip"))
        assertTrue(homeSrc.contains("SnowPullToRefreshBox"))
        assertTrue(homeSrc.contains("height(96.dp)"))
        assertFalse(homeSrc.contains("ClipboardItemCard"))

        val islandSrc = resolveModuleFile("src/main/java/org/snow/ui/shell/SnowDeviceSelectorIsland.kt").readText()
        assertTrue(islandSrc.contains("text = \"Join Another Network\""))
        assertFalse(islandSrc.contains("+ Join Another Network"))
        assertTrue(islandSrc.contains("localPhoneTelemetry"))

        val approvalsSrc = resolveModuleFile("src/main/java/org/snow/ui/shell/SnowApprovalsSheet.kt").readText()
        assertFalse(approvalsSrc.contains("Live Activity"))

        val connectSrc = resolveModuleFile("src/main/java/org/snow/ui/connect/SnowConnectSheet.kt").readText()
        assertFalse(connectSrc.contains("Instant smart discovery enabled"))
        assertTrue(connectSrc.contains("pairingQrJson"))

        val settingsSrc = resolveModuleFile("src/main/java/org/snow/ui/settings/SettingsScreen.kt").readText()
        assertTrue(settingsSrc.contains("Background App Launch"))
        assertTrue(settingsSrc.contains("ACTION_MANAGE_OVERLAY_PERMISSION"))
    }
}
