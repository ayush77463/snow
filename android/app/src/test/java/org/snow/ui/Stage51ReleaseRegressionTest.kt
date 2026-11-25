package org.snow.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * JVM regression suite covering all SNOW V5.1.0 Android workstreams:
 * WS1 (Instant Sync default true + IME URI permissions),
 * WS2 (Reactive pending approvals),
 * WS6/WS7 (SAF/MediaStore downloads + notification-assisted camera fallback),
 * WS8 (Transfer cancellation, route badge, readable byte formatting, Diagnostics removal),
 * WS11 (Devices ConnectionControlCard, auto-reconnect, Disconnect All),
 * WS12 (versionCode = 3, versionName = "5.1.0").
 */
class Stage51ReleaseRegressionTest {

    private fun resolveModuleFile(relPath: String): File {
        val candidates = listOf(File(relPath), File("app", relPath), File("android/app", relPath))
        return candidates.firstOrNull { it.exists() }
            ?: error("Could not locate file: $relPath (cwd=${File(".").absolutePath})")
    }

    @Test
    fun testWorkstream1InstantSyncDefaultTrueAndImeGrant() {
        val repoSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowUiRepository.kt").readText()
        assertFalse(repoSrc.contains("getBoolean(PREF_KEY_INSTANT_SYNC, false)"))
        assertTrue(repoSrc.contains("grantImeUriPermission"))

        val dispSrc = resolveModuleFile("src/main/java/org/snow/capabilities/AndroidCapabilityDispatcher.kt").readText()
        assertFalse(dispSrc.contains("getBoolean(SnowUiRepository.PREF_KEY_INSTANT_SYNC, false)"))
    }

    @Test
    fun testWorkstream2ReactivePendingApprovalsContract() {
        val repoSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowUiRepository.kt").readText()
        assertTrue(repoSrc.contains("val pendingApprovals: StateFlow<List<PendingApprovalItem>>"))
        assertTrue(repoSrc.contains("fun refreshPendingApprovals("))
        assertTrue(repoSrc.contains("fun onApprovalEventReceived("))
        assertTrue(repoSrc.contains("approvalsEpoch"))

        val appSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowApp.kt").readText()
        assertTrue(appSrc.contains("repository.pendingApprovals.collectAsState()"))
    }

    @Test
    fun testWorkstream6And7DownloadsAndCameraFallback() {
        val fileHandlerSrc = resolveModuleFile("src/main/java/org/snow/capabilities/AndroidFileHandler.kt").readText()
        assertTrue(fileHandlerSrc.contains("MediaStore.Downloads"))
        assertTrue(fileHandlerSrc.contains("commitVerifiedDownload"))
        assertTrue(fileHandlerSrc.contains("saved_path"))

        val mainSrc = resolveModuleFile("src/main/java/org/snow/ui/MainActivity.kt").readText()
        assertTrue(mainSrc.contains("request_camera_capture"))
    }

    @Test
    fun testWorkstream8FormattingTransportBadgesAndCancellation() {
        assertEquals("0 B", formatTransferBytes(0L))
        assertEquals("512 B", formatTransferBytes(512L))
        assertEquals("1.5 KB", formatTransferBytes(1536L))
        assertEquals("2.5 MB", formatTransferBytes((2.5 * 1024 * 1024).toLong()))

        assertEquals("USB • Zero Data", resolveTransportBadge("127.0.0.1:8765"))
        assertEquals("USB • Zero Data", resolveTransportBadge("localhost:8765"))
        assertEquals("Remote • Uses Data", resolveTransportBadge("https://snow-relay.onrender.com:8770"))
        assertEquals("Wi-Fi • Zero Data", resolveTransportBadge("192.168.1.42:8765"))

        val transferClientSrc = resolveModuleFile("src/main/java/org/snow/transfer/FileTransferClient.kt").readText()
        assertTrue(transferClientSrc.contains("fun cancelActiveTransfer()"))
        assertTrue(transferClientSrc.contains("activeCall.getAndSet(null)?.cancel()"))

        val toolsSrc = resolveModuleFile("src/main/java/org/snow/ui/tools/ToolsScreen.kt").readText()
        assertTrue(toolsSrc.contains("ToolsActiveTransferCard"))
        assertTrue(toolsSrc.contains("formatTransferBytes"))

        val settingsSrc = resolveModuleFile("src/main/java/org/snow/ui/settings/SettingsScreen.kt").readText()
        assertFalse(settingsSrc.contains("Diagnostic Logs"))
    }

    @Test
    fun testWorkstream11DevicesSimplifiedAndDisconnectAll() {
        val devicesSrc = resolveModuleFile("src/main/java/org/snow/ui/devices/DevicesScreen.kt").readText()
        assertFalse(devicesSrc.contains("Phone-to-Phone Host Mode"))
        assertFalse(devicesSrc.contains("PeerHostModeCard"))
        assertTrue(devicesSrc.contains("ConnectionControlCard"))
        assertTrue(devicesSrc.contains("Auto-Reconnect"))
        assertTrue(devicesSrc.contains("Disconnect All"))

        val repoSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowUiRepository.kt").readText()
        assertTrue(repoSrc.contains("fun disconnectAll()"))
        assertTrue(repoSrc.contains("fun setAutoReconnectEnabled("))

        val fgSrc = resolveModuleFile("src/main/java/org/snow/service/SnowForegroundService.kt").readText()
        assertTrue(fgSrc.contains("fun setDisconnectedByUser("))
    }

    @Test
    fun testWorkstream12VersionCode3And510() {
        val gradleSrc = resolveModuleFile("build.gradle.kts").readText()
        assertTrue(gradleSrc.contains("versionCode = 3"))
        assertTrue(gradleSrc.contains("versionName = \"5.1.0\""))

        val settingsXml = resolveModuleFile("src/main/res/layout/fragment_settings.xml").readText()
        assertTrue(settingsXml.contains("5.1.0"))
    }
}
