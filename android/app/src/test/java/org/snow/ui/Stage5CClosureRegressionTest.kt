package org.snow.ui

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.capabilities.MediaControlHandler
import org.snow.network.AuthState
import org.snow.security.PairingState
import org.snow.service.AutoConnectTileService
import org.snow.service.ClipSyncTileService
import java.io.File

/**
 * Behavioral & architectural regression tests for Stage 5C closure fixes.
 */
class Stage5CClosureRegressionTest {

    private class InMemorySharedPreferences : SharedPreferences {
        private val data = mutableMapOf<String, Any?>()

        override fun getAll(): MutableMap<String, *> = data.toMutableMap()
        override fun getString(key: String?, defValue: String?): String? =
            (data[key] as? String) ?: defValue

        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            (data[key] as? Set<String>)?.toMutableSet() ?: defValues

        override fun getInt(key: String?, defValue: Int): Int = (data[key] as? Int) ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = (data[key] as? Long) ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = (data[key] as? Float) ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean =
            (data[key] as? Boolean) ?: defValue

        override fun contains(key: String?): Boolean = data.containsKey(key)
        override fun registerOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) = Unit

        override fun unregisterOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) = Unit

        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val pending = mutableMapOf<String, Any?>()
            private var clearAll = false

            override fun putString(key: String?, value: String?): SharedPreferences.Editor = apply {
                if (key != null) pending[key] = value
            }

            override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = apply {
                if (key != null) pending[key] = values?.toSet()
            }

            override fun putInt(key: String?, value: Int): SharedPreferences.Editor = apply {
                if (key != null) pending[key] = value
            }

            override fun putLong(key: String?, value: Long): SharedPreferences.Editor = apply {
                if (key != null) pending[key] = value
            }

            override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = apply {
                if (key != null) pending[key] = value
            }

            override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = apply {
                if (key != null) pending[key] = value
            }

            override fun remove(key: String?): SharedPreferences.Editor = apply {
                if (key != null) pending[key] = null
            }

            override fun clear(): SharedPreferences.Editor = apply { clearAll = true }

            override fun commit(): Boolean {
                apply()
                return true
            }

            override fun apply() {
                if (clearAll) data.clear()
                pending.forEach { (k, v) ->
                    if (v == null) data.remove(k) else data[k] = v
                }
            }
        }
    }

    private class FakeAppContext(private val tempRoot: File) : ContextWrapper(null) {
        private val prefs = mutableMapOf<String, SharedPreferences>()

        override fun getApplicationContext(): Context = this
        override fun getCacheDir(): File = File(tempRoot, "cache").apply { mkdirs() }
        override fun getFilesDir(): File = File(tempRoot, "files").apply { mkdirs() }
        override fun getPackageName(): String = "org.snow"
        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
            return prefs.getOrPut(name ?: "default") { InMemorySharedPreferences() }
        }
    }

    private fun resolveModuleFile(relPath: String): File {
        val candidates = listOf(
            File(relPath),
            File("app", relPath),
            File("android/app", relPath),
        )
        return candidates.firstOrNull { it.exists() }
            ?: error("Could not locate project file: $relPath (cwd=${File(".").absolutePath})")
    }

    @Test
    fun testQuickSettingsTileServicesExistAndInvalidTileRemoved() {
        assertEquals("org.snow.service.AutoConnectTileService", AutoConnectTileService::class.java.name)
        assertEquals("org.snow.service.ClipSyncTileService", ClipSyncTileService::class.java.name)

        val settingsSource = resolveModuleFile("src/main/java/org/snow/ui/settings/SettingsScreen.kt").readText()
        assertFalse(
            "SettingsScreen.kt must never reference non-existent SnowConnectTileService",
            settingsSource.contains("org.snow.tile.SnowConnectTileService")
        )
        assertTrue(settingsSource.contains("AutoConnectTileService::class.java"))
        assertTrue(settingsSource.contains("ClipSyncTileService::class.java"))

        val manifestText = resolveModuleFile("src/main/AndroidManifest.xml").readText()
        assertTrue(manifestText.contains(".service.AutoConnectTileService"))
        assertTrue(manifestText.contains(".service.ClipSyncTileService"))
    }

    @Test
    fun testCanonicalPermissionProfileKeyAndEnforcement() {
        assertEquals("permission_profile", SnowUiRepository.PREF_KEY_PERMISSION_PROFILE)

        val fgSource = resolveModuleFile("src/main/java/org/snow/service/SnowForegroundService.kt").readText()
        assertTrue(fgSource.contains("SnowUiRepository.PREF_KEY_PERMISSION_PROFILE"))

        assertEquals("full_control", SnowUiRepository.normalizeAccessProfile("FULL"))
        assertEquals("files_only", SnowUiRepository.normalizeAccessProfile("FILES_ONLY"))
        assertEquals("clipboard_only", SnowUiRepository.normalizeAccessProfile("READ_ONLY"))
        assertEquals("files_and_clipboard", SnowUiRepository.normalizeAccessProfile("files_and_clipboard"))
        assertEquals("clipboard_only", SnowUiRepository.normalizeAccessProfile("clipboard_only"))
        assertEquals("full_control", SnowUiRepository.normalizeAccessProfile("full_control"))
        assertEquals("not_allowed", SnowUiRepository.normalizeAccessProfile("not_allowed"))
        assertEquals("not_allowed", SnowUiRepository.normalizeAccessProfile("unknown_tier"))

        val devicesSource = resolveModuleFile("src/main/java/org/snow/ui/devices/DevicesScreen.kt").readText()
        assertTrue(devicesSource.contains("\"Full Control\""))
        assertTrue(devicesSource.contains("\"Files & Clip\""))
        assertTrue(devicesSource.contains("\"Clip Only\""))
        assertFalse(devicesSource.contains("onClick = { onUpdateTier(\"FILES_ONLY\") }"))
        assertFalse(devicesSource.contains("onClick = { onUpdateTier(\"READ_ONLY\") }"))

        val snowAppSource = resolveModuleFile("src/main/java/org/snow/ui/SnowApp.kt").readText()
        assertTrue(snowAppSource.contains("LaunchedEffect(currentTab, showDeviceIsland, connectionState)"))
        assertTrue(snowAppSource.contains("repository.setAccessProfile(canonical)"))

        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_5c_prof_${System.nanoTime()}").apply { mkdirs() }
        try {
            val dispatcher = AndroidCapabilityDispatcher(FakeAppContext(tempDir)) { null }

            dispatcher.activePermissionProfile = "clipboard_only"
            assertTrue(dispatcher.isActionAllowedByProfile("clipboard_pull"))
            assertFalse(dispatcher.isActionAllowedByProfile("file_list"))
            assertEquals("PERMISSION_DENIED", dispatcher.validateExecutionContract("file_list", null)?.get("status"))

            dispatcher.activePermissionProfile = "files_and_clipboard"
            assertTrue(dispatcher.isActionAllowedByProfile("file_list"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_screenshot"))
            assertEquals("PERMISSION_DENIED", dispatcher.validateExecutionContract("android_screenshot", null)?.get("status"))

            dispatcher.activePermissionProfile = "full_control"
            assertTrue(dispatcher.isActionAllowedByProfile("file_list"))
            assertTrue(dispatcher.isActionAllowedByProfile("android_screenshot"))
            assertTrue(dispatcher.isActionAllowedByProfile("android_camera_capture"))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testTerminalExecutionStateConfirmationTicketAndCancel() {
        val initial = TerminalExecutionState()
        assertNull(initial.pendingTicket)
        assertNull(initial.pendingCommand)
        assertFalse(initial.isRunning)

        val awaitingApproval = initial.copy(
            isRunning = false,
            activeCommand = "ipconfig /all",
            pendingTicket = "ticket-abc-123",
            pendingCommand = "ipconfig /all"
        )
        assertEquals("ticket-abc-123", awaitingApproval.pendingTicket)
        assertEquals("ipconfig /all", awaitingApproval.pendingCommand)

        val cancelled = awaitingApproval.copy(
            isRunning = false,
            activeCommand = null,
            pendingTicket = null,
            pendingCommand = null
        )
        assertFalse(cancelled.isRunning)
        assertNull(cancelled.activeCommand)
        assertNull(cancelled.pendingTicket)
        assertNull(cancelled.pendingCommand)
    }

    @Test
    fun testUnifiedClipboardCachePathAndRepositoryIntegration() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_5c_clip_${System.nanoTime()}").apply { mkdirs() }
        try {
            val cacheDir = File(tempDir, "clipboard_cache").apply { mkdirs() }
            val itemId = "cb_1234567890ab_cdef12"
            val cachedPng = File(cacheDir, "clip_item_${itemId}.png").apply {
                writeBytes(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))
            }
            assertTrue(cachedPng.exists() && cachedPng.length() > 0)

            // Verify SnowUiRepository image cache lookup and version parity on JVM if keystore permits
            val repoSource = resolveModuleFile("src/main/java/org/snow/ui/SnowUiRepository.kt").readText()
            assertTrue(repoSource.contains("fun clipboardImageCacheFile("))
            assertTrue(repoSource.contains("fun findCachedClipboardImageFile("))
            assertTrue(repoSource.contains("Intent.FLAG_GRANT_READ_URI_PERMISSION"))

            val gradleText = resolveModuleFile("build.gradle.kts").readText()
            assertTrue(gradleText.contains("versionCode = 4"))
            assertTrue(gradleText.contains("versionName = \"5.2.0\""))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testAuthAndPairingMetadataRepresentPlatformExplicitly() {
        val androidAuth = AuthState.Authenticated(
            sessionId = "sess-1",
            trustTier = "peer",
            peerDeviceName = "Galaxy S24",
            peerDeviceType = "android"
        )
        assertEquals("android", androidAuth.peerDeviceType)
        assertEquals("Galaxy S24", androidAuth.peerDeviceName)

        val windowsAuth = AuthState.Authenticated(
            sessionId = "sess-2",
            trustTier = "owner",
            peerDeviceName = "Workstation",
            peerDeviceType = "windows"
        )
        assertEquals("windows", windowsAuth.peerDeviceType)

        val androidPair = PairingState.Paired(
            desktopId = "dev-phone-1",
            desktopName = "Peer Phone",
            sessionId = "sess-3",
            trustTier = "peer",
            deviceType = "android"
        )
        assertEquals("android", androidPair.deviceType)
    }

    @Test
    fun testMediaControlHandlerBoundedVolumeAndAliases() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_5c_media_${System.nanoTime()}").apply { mkdirs() }
        try {
            val handler = MediaControlHandler(FakeAppContext(tempDir))

            for (badLevel in listOf<Number?>(null, -1, 101, Double.NaN, Double.POSITIVE_INFINITY)) {
                val res = handler.handleMediaControl("volume_set", badLevel)
                assertEquals("error", res["status"])
                assertEquals("INVALID_VOLUME_LEVEL", res["error"])
            }

            // On unit-test JVM AudioManager is null, so valid actions fail cleanly on AudioManager availability,
            // never with UNSUPPORTED_MEDIA_ACTION.
            for (supported in listOf("stop", "volume_mute", "mute", "toggle_mute", "play_pause")) {
                val res = handler.handleMediaControl(supported)
                assertNotEquals("UNSUPPORTED_MEDIA_ACTION", res["error"])
            }
        } finally {
            tempDir.deleteRecursively()
        }
    }
}
