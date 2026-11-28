package org.snow.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.capabilities.AndroidFileHandler
import org.snow.network.RelayClient
import org.snow.service.SnowForegroundService
import java.io.File

/**
 * Behavioral & contract regression tests for Milestone 3B Section 5:
 * - 5.1 Seamless USB auto-promotion & Wi-Fi fallback
 * - 5.2 Zero-config Render Hub Remote Access
 * - 5.3 ToolsScreen pager clipping & directory chip horizontal scroll
 * - 5.4 / 5.5 Play Protect Option 1 permission & dead QS tile cleanup
 */
class Milestone3BSection5TransportUiPlayProtectTest {

    private fun resolveModuleFile(relPath: String): File {
        val candidates = listOf(
            File(relPath),
            File("app", relPath),
            File("android/app", relPath)
        )
        return candidates.firstOrNull { it.exists() }
            ?: error("Could not locate project file: $relPath (cwd=${File(".").absolutePath})")
    }

    @Test
    fun `usb promotion allows authenticated wifi session after cooldown and blocks remote_only`() {
        val allowed = SnowForegroundService.shouldProbeUsbPromotion(
            connectionMode = "auto",
            userDisconnected = false,
            isConnected = true,
            isAuthenticated = true,
            currentHost = "192.168.1.25",
            nowMs = 20_000L,
            lastAttemptMs = 10_000L
        )
        assertTrue(allowed)

        // Cooldown suppression (< 5s)
        assertFalse(
            SnowForegroundService.shouldProbeUsbPromotion(
                connectionMode = "auto",
                userDisconnected = false,
                isConnected = true,
                isAuthenticated = true,
                currentHost = "192.168.1.25",
                nowMs = 12_000L,
                lastAttemptMs = 10_000L
            )
        )

        // Already on USB loopback
        assertFalse(
            SnowForegroundService.shouldProbeUsbPromotion(
                connectionMode = "auto",
                userDisconnected = false,
                isConnected = true,
                isAuthenticated = true,
                currentHost = "127.0.0.1",
                nowMs = 20_000L,
                lastAttemptMs = 0L
            )
        )

        // remote_only policy must never promote to local USB
        assertFalse(
            SnowForegroundService.shouldProbeUsbPromotion(
                connectionMode = "remote_only",
                userDisconnected = false,
                isConnected = true,
                isAuthenticated = true,
                currentHost = "192.168.1.25",
                nowMs = 20_000L,
                lastAttemptMs = 0L
            )
        )

        // User disconnected guard
        assertFalse(
            SnowForegroundService.shouldProbeUsbPromotion(
                connectionMode = "auto",
                userDisconnected = true,
                isConnected = true,
                isAuthenticated = true,
                currentHost = "192.168.1.25",
                nowMs = 20_000L,
                lastAttemptMs = 0L
            )
        )
    }

    @Test
    fun `usb unplug fallback resolves last non-loopback wifi target safely`() {
        val fallback = SnowForegroundService.resolveUsbFallbackTarget(
            lastWifiHost = "192.168.1.44",
            lastWifiPort = 8765,
            savedHost = "127.0.0.1",
            savedPort = 8765
        )
        assertEquals("192.168.1.44" to 8765, fallback)

        // When savedHost is also loopback, return null so AutoConnect cascade runs
        val noWifi = SnowForegroundService.resolveUsbFallbackTarget(
            lastWifiHost = "127.0.0.1",
            lastWifiPort = 8765,
            savedHost = "localhost",
            savedPort = 8765
        )
        assertNull(noWifi)
    }

    @Test
    fun `zero config render hub endpoint and multi-mode relay hello payloads work without static ticket`() {
        assertEquals(
            "wss://snow-relay.onrender.com/v1/tunnel",
            SnowForegroundService.resolveEffectiveRelayEndpoint("")
        )
        assertEquals(
            "wss://custom.example.com/v1/tunnel",
            SnowForegroundService.resolveEffectiveRelayEndpoint("https://custom.example.com")
        )

        val hubAuth = SnowForegroundService.resolveEffectiveRelayAuth(
            ticket = "",
            bootstrapToken = "rbs1_boot",
            hubToken = "hub_tok_123"
        )
        assertNotNull(hubAuth)
        assertEquals("hub_tok_123", hubAuth!!.hubToken)

        val bootAuth = SnowForegroundService.resolveEffectiveRelayAuth(
            ticket = "",
            bootstrapToken = "rbs1_boot",
            hubToken = ""
        )
        assertEquals("rbs1_boot", bootAuth?.bootstrapToken)

        val hubHello = RelayClient.buildHelloPayload(
            deviceId = "android-1",
            groupId = "SNW-NET-1234",
            hubToken = "hub_tok_123",
            networkId = "SNW-NET-1234"
        )
        assertEquals("hello", hubHello.getString("type"))
        assertEquals("hub_tok_123", hubHello.getString("hub_token"))
        assertEquals("SNW-NET-1234", hubHello.getString("network_id"))
        assertEquals("android-1", hubHello.getString("device_id"))
        assertFalse(hubHello.has("ticket"))

        val bootHello = RelayClient.buildHelloPayload(
            deviceId = "android-1",
            groupId = "default_group",
            bootstrapToken = "rbs1_boot",
            networkId = "SNW-NET-ABCD"
        )
        assertEquals("rbs1_boot", bootHello.getString("bootstrap_token"))
        assertEquals("SNW-NET-ABCD", bootHello.getString("network_id"))
        assertFalse(bootHello.has("ticket"))

        val snowAppSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowApp.kt").readText()
        assertFalse(snowAppSrc.contains("Configure Remote Relay endpoint in Advanced Diagnostics first"))
        assertTrue(snowAppSrc.contains("getEffectiveRelayEndpointForHub()"))

        val repoSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowUiRepository.kt").readText()
        assertTrue(repoSrc.contains("launchApkInstaller"))
        assertTrue(repoSrc.contains("SecurityException"))
    }

    @Test
    fun `tools screen applies clipToBounds on pager and horizontal scroll for directory chips`() {
        val toolsSrc = resolveModuleFile("src/main/java/org/snow/ui/tools/ToolsScreen.kt").readText()
        assertTrue(toolsSrc.contains(".clipToBounds()"))
        assertTrue(toolsSrc.contains("horizontalScroll(rememberScrollState())"))
    }

    @Test
    fun `m46 manifest permits scoped file access and overlay permissions while removing dead quick settings services`() {
        val manifest = resolveModuleFile("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("android.permission.MANAGE_EXTERNAL_STORAGE"))
        assertTrue(manifest.contains("android.permission.SYSTEM_ALERT_WINDOW"))
        assertFalse(manifest.contains("android.permission.REQUEST_INSTALL_PACKAGES"))
        assertFalse(manifest.contains("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"))
        assertFalse(manifest.contains("AutoConnectTileService"))
        assertFalse(manifest.contains("ClipSyncTileService"))
        assertFalse(manifest.contains("AutoConnectTrampolineActivity"))
        assertTrue(manifest.contains(".ui.ClipSyncActivity"))
        assertTrue(manifest.contains(".service.SnowForegroundService"))

        val deadFiles = listOf(
            "src/main/java/org/snow/service/AutoConnectTileService.kt",
            "src/main/java/org/snow/service/ClipSyncTileService.kt",
            "src/main/java/org/snow/ui/AutoConnectTrampolineActivity.kt",
            "src/main/res/drawable/ic_qs_snow.xml",
            "src/main/res/drawable/ic_qs_clip.xml"
        )
        deadFiles.forEach { rel ->
            val candidates = listOf(File(rel), File("app", rel), File("android/app", rel))
            assertTrue("Dead file $rel must be deleted", candidates.none { it.exists() })
        }

        val settingsSrc = resolveModuleFile("src/main/java/org/snow/ui/settings/SettingsScreen.kt").readText()
        assertFalse(settingsSrc.contains("All Files Access"))
        assertFalse(settingsSrc.contains("Battery Optimization Exemption"))
        assertFalse(settingsSrc.contains("Background App Launch"))
        assertFalse(settingsSrc.contains("Quick Settings: SNOW Connect"))
        assertFalse(settingsSrc.contains("Quick Settings: SNOW Clip"))
        assertFalse(settingsSrc.contains("Notification Sync & Listener"))
        assertTrue(settingsSrc.contains("Notification Sync"))
        assertTrue(settingsSrc.contains("File Access"))
        assertTrue(settingsSrc.contains("Transfer Folder"))
        assertTrue(settingsSrc.contains("Background Run"))
        assertTrue(settingsSrc.contains("Application Updates"))

        val appLauncherSrc = resolveModuleFile("src/main/java/org/snow/capabilities/AppLauncherHandler.kt").readText()
        assertFalse(appLauncherSrc.contains("canDrawOverlays"))
        assertTrue(appLauncherSrc.contains("NOTIFICATION_TAP_REQUIRED"))

        val dispatcherSrc = resolveModuleFile("src/main/java/org/snow/capabilities/AndroidCapabilityDispatcher.kt").readText()
        assertFalse(dispatcherSrc.contains("canDrawOverlays"))

        // M4.6: AndroidFileHandler checks Environment.isExternalStorageManager() for OWNER_MANUAL full storage only;
        // AI_MCP stays sandboxed to Transfer Folder (SAF), and stubCtx without Android 11 runtime defaults false.
        val fileHandlerSrc = resolveModuleFile("src/main/java/org/snow/capabilities/AndroidFileHandler.kt").readText()
        assertTrue(fileHandlerSrc.contains("isExternalStorageManager"))
        assertTrue(fileHandlerSrc.contains("principal == \"OWNER_MANUAL\""))
        val stubCtx = object : android.content.ContextWrapper(null) {}
        val handlerDefault = AndroidFileHandler(context = stubCtx, transferClientProvider = { null })
        assertFalse(handlerDefault.isAllFilesAccessGranted())
        val handlerWithOverride = AndroidFileHandler(
            context = stubCtx,
            transferClientProvider = { null },
            allFilesAccessProvider = { true }
        )
        assertTrue(handlerWithOverride.isAllFilesAccessGranted())
    }
}
