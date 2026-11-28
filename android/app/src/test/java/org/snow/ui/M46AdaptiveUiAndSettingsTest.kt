package org.snow.ui

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.ui.settings.SettingsPermissionInspector
import org.snow.ui.tools.ToolSubTab
import java.io.File

/**
 * M4.6 Android UI, Manifest Permissions, 2-Step SNOW ID -> PIN, Adaptive Tools & Multi-Transfer Tests.
 */
class M46AdaptiveUiAndSettingsTest {

    private fun resolveModuleFile(relPath: String): File {
        val candidates = listOf(File(relPath), File("app", relPath), File("android/app", relPath))
        return candidates.firstOrNull { it.exists() }
            ?: error("Could not locate file: $relPath (cwd=${File(".").absolutePath})")
    }

    private fun buildStubContext(tempDir: File): Context {
        val prefsMap = mutableMapOf<String, Any?>()
        val fakePrefs = object : SharedPreferences {
            override fun getAll(): MutableMap<String, *> = prefsMap
            override fun getString(k: String?, d: String?): String? = prefsMap[k] as? String ?: d
            override fun getStringSet(k: String?, d: MutableSet<String>?): MutableSet<String>? = d
            override fun getInt(k: String?, d: Int): Int = (prefsMap[k] as? Int) ?: d
            override fun getLong(k: String?, d: Long): Long = (prefsMap[k] as? Long) ?: d
            override fun getFloat(k: String?, d: Float): Float = (prefsMap[k] as? Float) ?: d
            override fun getBoolean(k: String?, d: Boolean): Boolean = (prefsMap[k] as? Boolean) ?: d
            override fun contains(k: String?): Boolean = prefsMap.containsKey(k)
            override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
                override fun putString(k: String?, v: String?) = apply { if (k != null) prefsMap[k] = v }
                override fun putStringSet(k: String?, v: MutableSet<String>?) = apply { if (k != null) prefsMap[k] = v }
                override fun putInt(k: String?, v: Int) = apply { if (k != null) prefsMap[k] = v }
                override fun putLong(k: String?, v: Long) = apply { if (k != null) prefsMap[k] = v }
                override fun putFloat(k: String?, v: Float) = apply { if (k != null) prefsMap[k] = v }
                override fun putBoolean(k: String?, v: Boolean) = apply { if (k != null) prefsMap[k] = v }
                override fun remove(k: String?) = apply { prefsMap.remove(k) }
                override fun clear() = apply { prefsMap.clear() }
                override fun commit(): Boolean = true
                override fun apply() {}
            }
            override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
            override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        }
        return object : ContextWrapper(null) {
            override fun getApplicationContext(): Context = this
            override fun getPackageName(): String = "org.snow"
            override fun getFilesDir(): File = tempDir
            override fun getCacheDir(): File = tempDir
            override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = fakePrefs
        }
    }

    @Test
    fun `manifest declares MANAGE_EXTERNAL_STORAGE and SYSTEM_ALERT_WINDOW without high risk install or battery opt permissions`() {
        val manifest = resolveModuleFile("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("android.permission.MANAGE_EXTERNAL_STORAGE"))
        assertTrue(manifest.contains("android.permission.SYSTEM_ALERT_WINDOW"))
        assertFalse(manifest.contains("android.permission.REQUEST_INSTALL_PACKAGES"))
        assertFalse(manifest.contains("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"))
    }

    @Test
    fun `settings screen puts Remote AI Link toggle in header without raw error display and keeps exact 4-row Permissions card`() {
        val settingsSrc = resolveModuleFile("src/main/java/org/snow/ui/settings/SettingsScreen.kt").readText()

        // Remote AI Link header toggle without "Enable Remote AI Link" or raw HTTP error text
        val remoteAiCard = settingsSrc
            .substringAfter("// Top-Level Remote AI Link Card")
            .substringBefore("Divider(color = colors.borderSubtle)")
        assertTrue(remoteAiCard.contains("text = \"Remote AI Link\""))
        assertTrue(remoteAiCard.contains("SnowStatusBadge("))
        assertTrue(remoteAiCard.contains("Switch("))
        assertTrue(remoteAiCard.contains("onCheckedChange = onToggleAndroidRemoteMcp"))
        assertFalse(settingsSrc.contains("Enable Remote AI Link"))
        assertFalse(settingsSrc.contains("text = androidMcpError"))

        // Exact 4-row Permissions card: Notification Sync, File Access, Transfer Folder, Background Run
        val permissionsSection = settingsSrc
            .substringAfter("SnowSectionHeader(title = \"Permissions & System Setup\")")
            .substringBefore("SnowSectionHeader(title = \"Application Updates\")")
        assertTrue(permissionsSection.contains("title = \"Notification Sync\""))
        assertTrue(permissionsSection.contains("title = \"File Access\""))
        assertTrue(permissionsSection.contains("title = \"Transfer Folder\""))
        assertTrue(permissionsSection.contains("title = \"Background Run\""))
        assertFalse(permissionsSection.contains("Post Notifications"))
        assertFalse(permissionsSection.contains("Background Activity & Service"))
        assertFalse(permissionsSection.contains("Notification Sync & Listener"))
        assertFalse(permissionsSection.contains("All Files Access"))
        val rowCount = Regex("PermissionRowItem\\(").findAll(permissionsSection).count()
        assertEquals("Permissions card must contain exactly 4 rows", 4, rowCount)

        // Verify permission snapshot badge helpers for all 4 rows
        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_m46_perm_${System.nanoTime()}").apply { mkdirs() }
        try {
            val ctx = buildStubContext(tempDir)
            val missing = SettingsPermissionInspector.inspect(
                context = ctx,
                listenerGranted = false,
                allFilesAccessOverride = false,
                safConfiguredOverride = false,
                overlayPermissionOverride = false
            )
            assertEquals("SETUP", missing.notificationSyncBadgeText())
            assertEquals("SETUP", missing.fileAccessBadgeText())
            assertEquals("DEFAULT", missing.transferFolderBadgeText())
            assertEquals("SETUP", missing.backgroundRunBadgeText())

            val granted = SettingsPermissionInspector.inspect(
                context = ctx,
                listenerGranted = true,
                allFilesAccessOverride = true,
                safConfiguredOverride = true,
                safFolderNameOverride = "SNOW_Shared",
                overlayPermissionOverride = true
            )
            assertEquals("GRANTED", granted.notificationSyncBadgeText())
            assertEquals("GRANTED", granted.fileAccessBadgeText())
            assertEquals("CONFIGURED", granted.transferFolderBadgeText())
            assertEquals("GRANTED", granted.backgroundRunBadgeText())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `connect sheet implements 2-step SNOW ID to PIN flow without upfront manualVerifyPin`() {
        val connectSrc = resolveModuleFile("src/main/java/org/snow/ui/connect/SnowConnectSheet.kt").readText()

        // Preserved M4.5 invariants
        assertTrue(connectSrc.contains("MY SNOW ID"))
        assertTrue(connectSrc.contains("MY NETWORK ID"))
        assertTrue(connectSrc.contains("Generate 6-Digit PIN"))
        assertTrue(connectSrc.contains("SNOW ID or Network Code"))
        assertTrue(connectSrc.contains("Live Zero-PIN Pairing QR"))

        // Step 1: Single SNOW ID input without upfront manualVerifyPin
        assertFalse(connectSrc.contains("manualVerifyPin"))
        assertTrue(connectSrc.contains("Enter Peer SNOW ID"))
        assertTrue(connectSrc.contains("onConnectSnowIdStep1"))
        assertTrue(connectSrc.contains("SnowIdStep1Result.AlreadyConnected"))
        assertTrue(connectSrc.contains("SnowIdStep1Result.NeedsPin"))

        // Step 2: 6-digit PIN entry with Verify & Pair, Change ID, and inline retry prompt keeping snowId
        assertTrue(connectSrc.contains("Enter the 6-digit PIN shown on \$step2SnowId"))
        assertTrue(connectSrc.contains("Verify & Pair"))
        assertTrue(connectSrc.contains("Change ID"))
        assertTrue(connectSrc.contains("onConnectSnowIdStep2"))
        assertTrue(connectSrc.contains("Incorrect PIN — \$remainingAttempts attempts remaining. Please re-enter."))
    }

    @Test
    fun `tools screen adapts to ANDROID_PEER hiding Terminal and Windows chips while rendering concurrent activeTransfers`() {
        // Enum preserves 5 entries for Stage5B/Stage6C while ToolsScreen filters visible tabs for ANDROID_PEER
        assertEquals(5, ToolSubTab.values().size)
        assertEquals(TargetDeviceType.ANDROID_PEER, TargetDeviceType.valueOf("ANDROID_PEER"))
        assertEquals(TargetDeviceType.WINDOWS_PC, TargetDeviceType.valueOf("WINDOWS_PC"))

        val toolsSrc = resolveModuleFile("src/main/java/org/snow/ui/tools/ToolsScreen.kt").readText()
        assertTrue(toolsSrc.contains("targetDeviceType: TargetDeviceType = TargetDeviceType.WINDOWS_PC"))
        assertTrue(toolsSrc.contains("val isAndroidPeer = targetDeviceType == TargetDeviceType.ANDROID_PEER"))
        assertTrue(toolsSrc.contains("listOf(ToolSubTab.FILES, ToolSubTab.APPS, ToolSubTab.MEDIA, ToolSubTab.SCREEN)"))
        assertTrue(toolsSrc.contains("if (isAndroidPeer && currentSubTab == ToolSubTab.TERMINAL)"))

        // FilesToolView hides Windows C:/D:/Desktop/Documents when isAndroidPeer and renders activeTransfers
        val filesSection = toolsSrc.substringAfter("private fun FilesToolView(").substringBefore("private fun FileRowItem(")
        assertTrue(filesSection.contains("if (!isAndroidPeer)"))
        assertTrue(filesSection.contains("SnowFilterChip(text = \"Desktop\""))
        assertTrue(filesSection.contains("SnowFilterChip(text = \"Documents\""))
        assertTrue(filesSection.contains("SnowFilterChip(text = \"C:\""))
        assertTrue(filesSection.contains("SnowFilterChip(text = \"D:\""))
        assertTrue(filesSection.contains("activeTransfers: List<ActiveTransferInfo>"))
        assertTrue(filesSection.contains("items(visibleTransfers, key = { it.transferId })"))
        assertTrue(filesSection.contains("ToolsActiveTransferCard("))
        assertTrue(filesSection.contains("onCancelTransferById(transfer.transferId)"))
        assertTrue(filesSection.contains("onDismissTransferById(transfer.transferId)"))

        // AppsToolView supports peer phone apps & hides custom PC .exe card when isAndroidPeer
        val appsSection = toolsSrc.substringAfter("private fun AppsToolView(").substringBefore("private fun MediaToolView(")
        assertTrue(appsSection.contains("if (isAndroidPeer)"))
        assertTrue(appsSection.contains("onLaunchPeerApp("))
        assertTrue(appsSection.contains("onRefreshPeerApps"))
        assertTrue(appsSection.contains("Launch Custom PC Target"))

        // MediaToolView adapts header and offers Ring Phone for Android peer while keeping REMOTE PC MEDIA CONTROLS
        val mediaSection = toolsSrc.substringAfter("private fun MediaToolView(").substringBefore("private fun ScreenToolView(")
        assertTrue(mediaSection.contains("REMOTE PC MEDIA CONTROLS"))
        assertTrue(mediaSection.contains("PEER PHONE MEDIA CONTROLS"))
        assertTrue(mediaSection.contains("onSendPeerMediaCommand("))
        assertTrue(mediaSection.contains("onRingPeerPhone"))
        assertTrue(mediaSection.contains("Ring Phone"))

        // Preserved invariants
        assertTrue(toolsSrc.contains("HorizontalPager("))
        assertTrue(toolsSrc.contains("beyondBoundsPageCount"))
        assertFalse(toolsSrc.contains("No SAF folder"))
    }

    @Test
    fun `home screen and snow app wire activeTransfers multi-transfer cards, 2-step connect, and peer tools`() {
        val homeSrc = resolveModuleFile("src/main/java/org/snow/ui/home/HomeScreen.kt").readText()
        assertTrue(homeSrc.contains("activeTransfers: List<ActiveTransferInfo> = listOfNotNull(activeTransfer)"))
        assertTrue(homeSrc.contains("onCancelTransferById: (String) -> Unit"))
        assertTrue(homeSrc.contains("onDismissTransferById: (String) -> Unit"))
        assertTrue(homeSrc.contains("items(visibleTransfers, key = { it.transferId })"))
        assertTrue(homeSrc.contains("HomeActiveTransferCard("))
        assertTrue(homeSrc.contains("formatTransferBytes("))
        assertTrue(homeSrc.contains("transfer.transportLabel"))

        val appSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowApp.kt").readText()
        assertTrue(appSrc.contains("repository.connectedPeerSessions.collectAsState()"))
        assertTrue(appSrc.contains("repository.activeTransfers.collectAsState()"))
        assertTrue(appSrc.contains("repository.resolveTargetDeviceType("))
        assertTrue(appSrc.contains("repository.listPeerDirectory("))
        assertTrue(appSrc.contains("repository.listPeerApps("))
        assertTrue(appSrc.contains("repository.launchPeerApp("))
        assertTrue(appSrc.contains("repository.sendPeerMediaCommand("))
        assertTrue(appSrc.contains("repository.connectSnowIdStep1("))
        assertTrue(appSrc.contains("repository.connectSnowIdStep2WithPin("))
        assertTrue(appSrc.contains("repository.cancelTransfer("))
        assertTrue(appSrc.contains("repository.dismissTransfer("))
        assertTrue(appSrc.contains("7.0.0"))
    }
}
