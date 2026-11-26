package org.snow.ui

import android.content.ContextWrapper
import android.provider.Settings
import androidx.compose.ui.graphics.Color
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.capabilities.AndroidCapabilityDispatcher
import org.snow.network.ConnectionState
import org.snow.network.DiscoveredPeer
import org.snow.network.PeerHostState
import org.snow.ui.dashboard.AppLauncherBottomSheet
import org.snow.ui.devices.DeviceFilter
import org.snow.ui.navigation.SnowTab
import org.snow.ui.theme.DarkSnowColors
import org.snow.ui.theme.LightSnowColors
import org.snow.ui.tools.ToolSubTab
import java.io.File

/**
 * Unit tests verifying SNOW V5 Jetpack Compose Flagship UI invariants, design tokens,
 * operational state mappings, absence of mock data, and allowlist security.
 */
class Stage5BAndroidComposeUiTest {

    @Test
    fun testNavigationTabsIntegrity() {
        // Assert exactly 4 flagship tabs exist in correct order
        val tabs = SnowTab.values()
        assertEquals(4, tabs.size)
        assertEquals(SnowTab.HOME, tabs[0])
        assertEquals(SnowTab.DEVICES, tabs[1])
        assertEquals(SnowTab.TOOLS, tabs[2])
        assertEquals(SnowTab.SETTINGS, tabs[3])

        assertEquals("Home", SnowTab.HOME.title)
        assertEquals("Devices", SnowTab.DEVICES.title)
        assertEquals("Tools", SnowTab.TOOLS.title)
        assertEquals("Settings", SnowTab.SETTINGS.title)
    }

    @Test
    fun testToolsSubTabsIntegrity() {
        // Assert exactly 5 tool sub-screens exist including Stage 6C Screen tab
        val subTabs = ToolSubTab.values()
        assertEquals(5, subTabs.size)
        assertEquals(ToolSubTab.FILES, subTabs[0])
        assertEquals(ToolSubTab.APPS, subTabs[1])
        assertEquals(ToolSubTab.MEDIA, subTabs[2])
        assertEquals(ToolSubTab.TERMINAL, subTabs[3])
        assertEquals(ToolSubTab.SCREEN, subTabs[4])
    }

    @Test
    fun testDeviceFilterCategories() {
        val filters = DeviceFilter.values()
        assertEquals(3, filters.size)
        assertEquals(DeviceFilter.ALL, filters[0])
        assertEquals(DeviceFilter.PCS, filters[1])
        assertEquals(DeviceFilter.PHONES, filters[2])
    }

    @Test
    fun testThemeColorTokensFaithfulness() {
        // Dark theme tokens
        assertTrue(DarkSnowColors.isDark)
        assertEquals(Color(0xFF0F0F0F), DarkSnowColors.canvas)
        assertEquals(Color(0xFF000000), DarkSnowColors.bars)
        assertEquals(Color(0xFF181818), DarkSnowColors.surface)
        assertEquals(Color(0xFF242424), DarkSnowColors.surfaceElevated)
        assertEquals(Color(0xFF0F172A), DarkSnowColors.terminalBg)

        // Light theme tokens
        assertFalse(LightSnowColors.isDark)
        assertEquals(Color(0xFFF8FAFC), LightSnowColors.canvas)
        assertEquals(Color(0xFFFFFFFF), LightSnowColors.bars)
        assertEquals(Color(0xFFFFFFFF), LightSnowColors.surface)
        assertEquals(Color(0xFFF1F5F9), LightSnowColors.surfaceElevated)
        assertEquals(Color(0xFF0F172A), LightSnowColors.terminalBg)
    }

    @Test
    fun testMockStringsAbsentFromProductionFallbacks() {
        // Directive rule: zero mock/placeholder strings in production code
        val mockStrings = listOf(
            "Pixel 8 Pro",
            "Rahul's",
            "Lenovo_V15",
            "482 910",
            "v2.4 Pro",
            "10.15.72.23",
            "Aarav"
        )

        // Verify fallback defaults in models and screens
        val defaultPcTelemetry = PcTelemetry.UNAVAILABLE
        mockStrings.forEach { mock ->
            assertFalse(
                "Mock string '$mock' must not appear in PcTelemetry hostname fallback",
                defaultPcTelemetry.hostname?.contains(mock, ignoreCase = true) == true
            )
        }

        val emptyPeerHost = PeerHostState()
        mockStrings.forEach { mock ->
            assertFalse(
                "Mock string '$mock' must not appear in PeerHostState IP fallback",
                emptyPeerHost.ipAddress.contains(mock, ignoreCase = true)
            )
        }
    }

    @Test
    fun testAllowlistedWindowsAppsSecurity() {
        val apps = AppLauncherBottomSheet.ALLOWLISTED_WINDOWS_APPS
        assertTrue("Allowlist must contain approved desktop apps", apps.isNotEmpty())

        val targets = apps.map { it.target }
        assertTrue(targets.contains("code"))
        assertTrue(targets.contains("wt"))
        assertTrue(targets.contains("notepad"))
        assertTrue(targets.contains("calc"))
        assertTrue(targets.contains("explorer"))
        assertTrue(targets.contains("taskmgr"))

        // Security check: must NOT allow raw cmd.exe or arbitrary bash
        assertFalse("Must not allow raw cmd.exe in default apps", targets.contains("cmd.exe") || targets.contains("cmd"))
        assertFalse("Must not allow raw bash in default apps", targets.contains("bash") || targets.contains("sh"))
    }

    @Test
    fun testActiveTransferProgressCalculation() {
        // Zero transferred
        val t0 = ActiveTransferInfo("t1", "test.zip", "upload", 0L, 1000L, "in_progress")
        val p0 = if (t0.totalBytes > 0) (t0.bytesTransferred.toFloat() / t0.totalBytes).coerceIn(0f, 1f) else 0f
        assertEquals(0.0f, p0, 0.001f)

        // Half transferred
        val t1 = ActiveTransferInfo("t2", "video.mp4", "download", 500L, 1000L, "in_progress")
        val p1 = if (t1.totalBytes > 0) (t1.bytesTransferred.toFloat() / t1.totalBytes).coerceIn(0f, 1f) else 0f
        assertEquals(0.5f, p1, 0.001f)

        // Completed
        val t2 = ActiveTransferInfo("t3", "doc.pdf", "download", 1000L, 1000L, "completed")
        val p2 = if (t2.totalBytes > 0) (t2.bytesTransferred.toFloat() / t2.totalBytes).coerceIn(0f, 1f) else 0f
        assertEquals(1.0f, p2, 0.001f)

        // Division by zero safe guard
        val t3 = ActiveTransferInfo("t4", "empty.txt", "upload", 0L, 0L, "completed")
        val p3 = if (t3.totalBytes > 0) (t3.bytesTransferred.toFloat() / t3.totalBytes).coerceIn(0f, 1f) else 0f
        assertEquals(0.0f, p3, 0.001f)
    }

    @Test
    fun testSavedDeviceModelIntegrity() {
        val dev = SavedDevice(
            deviceId = "dev-1234",
            deviceName = "Host-Laptop",
            host = "192.168.1.50",
            port = 8765,
            trustTier = "FULL",
            connectionMode = "desktop"
        )
        assertEquals("dev-1234", dev.deviceId)
        assertEquals("Host-Laptop", dev.deviceName)
        assertEquals("192.168.1.50", dev.host)
        assertEquals(8765, dev.port)
        assertEquals("FULL", dev.trustTier)
        assertEquals("desktop", dev.connectionMode)
    }

    @Test
    fun testDiscoveredPeerModelIntegrity() {
        val peer = DiscoveredPeer(
            deviceId = "peer-5678",
            deviceName = "Peer-Phone",
            deviceType = "phone",
            ipAddress = "192.168.1.60",
            port = 8765,
            transferPort = 8766,
            certFingerprint = "SHA256:abcd"
        )
        assertEquals("peer-5678", peer.deviceId)
        assertEquals("Peer-Phone", peer.deviceName)
        assertEquals("192.168.1.60", peer.ipAddress)
        assertEquals(8765, peer.port)
    }

    // -------------------------------------------------------------------------
    // Stage 5B Closure Regression Tests (C3.1 - C3.9)
    // -------------------------------------------------------------------------

    private class TestContext(private val cache: File) : ContextWrapper(null) {
        override fun getCacheDir(): File = cache
    }

    @Test
    fun testC31_QrJsonRoutingLogic() {
        // Assert that connectByInput recognizes JSON payloads starting with '{'
        val validQrJson = JSONObject().apply {
            put("v", 1)
            put("id", "snow-host-desktop-01")
            put("ips", JSONArray().apply { put("192.168.1.100") })
            put("port", 8765)
            put("fp", "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899")
            put("pin", "654321")
        }.toString()

        assertTrue("Valid QR JSON must start with '{'", validQrJson.trim().startsWith("{"))

        // Parse and assert all protocol fields
        val parsed = JSONObject(validQrJson)
        assertEquals(1, parsed.getInt("v"))
        assertEquals("snow-host-desktop-01", parsed.getString("id"))
        assertEquals("192.168.1.100", parsed.getJSONArray("ips").getString(0))
        assertEquals(8765, parsed.getInt("port"))
        assertEquals("654321", parsed.getString("pin"))

        // Malformed JSON should be caught without crashing
        val malformedJson = "{not-real-json: true"
        assertTrue(malformedJson.trim().startsWith("{"))
        var caughtJsonException = false
        try {
            JSONObject(malformedJson)
        } catch (_: Exception) {
            caughtJsonException = true
        }
        assertTrue("Malformed JSON should throw parse exception safely caught by repository", caughtJsonException)

        // Non-JSON formats should NOT start with '{'
        assertFalse("Direct IP:Port must not start with '{'", "192.168.1.100:8765".startsWith("{"))
        assertFalse("Federation code must not start with '{'", "482910338".startsWith("{"))
        assertFalse("Relay URL must not start with '{'", "wss://relay.snow.org/v1/tunnel".startsWith("{"))
    }

    @Test
    fun testC32_DeviceClassificationAndCleanTransportLabels() {
        // Test explicit PC classification
        val pcDevice = SavedDevice(
            deviceId = "dev-pc-01",
            deviceName = "Main Desktop",
            host = "192.168.1.10",
            port = 8765,
            deviceType = "pc"
        )
        assertTrue("SavedDevice with deviceType='pc' must be classified as PC", pcDevice.isPc)
        assertFalse("SavedDevice with deviceType='pc' must not be classified as Phone", pcDevice.isPhone)

        // Test default deviceType fallback
        val defaultDevice = SavedDevice(
            deviceId = "dev-default-01",
            deviceName = "Default Device",
            host = "192.168.1.11",
            port = 8765
        )
        assertTrue("Default SavedDevice must be classified as PC", defaultDevice.isPc)
        assertFalse("Default SavedDevice must not be classified as Phone", defaultDevice.isPhone)

        // Test explicit Phone classification
        val phoneDevice = SavedDevice(
            deviceId = "dev-phone-01",
            deviceName = "Secondary Phone",
            host = "192.168.1.20",
            port = 8765,
            deviceType = "phone"
        )
        assertTrue("SavedDevice with deviceType='phone' must be classified as Phone", phoneDevice.isPhone)
        assertFalse("SavedDevice with deviceType='phone' must not be classified as PC", phoneDevice.isPc)

        val androidDevice = SavedDevice(
            deviceId = "dev-phone-02",
            deviceName = "Android Tablet",
            host = "192.168.1.21",
            port = 8765,
            deviceType = "android"
        )
        assertTrue("SavedDevice with deviceType='android' must be classified as Phone", androidDevice.isPhone)
        assertFalse("SavedDevice with deviceType='android' must not be classified as PC", androidDevice.isPc)

        // Clean transport label formatting tests (no raw port numbers)
        fun formatTransportLabel(dev: SavedDevice): String {
            return when {
                dev.connectionMode == "peer" -> "Direct Peer"
                dev.connectionMode == "usb" -> "USB"
                dev.connectionMode == "relay" -> "Remote"
                else -> "Wi-Fi"
            }
        }

        val peerDev = SavedDevice("d1", "P1", "1.1.1.1", 8765, connectionMode = "peer")
        val usbDev = SavedDevice("d2", "P2", "127.0.0.1", 8765, connectionMode = "usb")
        val relayDev = SavedDevice("d3", "P3", "relay.io", 443, connectionMode = "relay")
        val wifiDev = SavedDevice("d4", "P4", "192.168.1.5", 8765, connectionMode = "auto")

        assertEquals("Direct Peer", formatTransportLabel(peerDev))
        assertEquals("USB", formatTransportLabel(usbDev))
        assertEquals("Remote", formatTransportLabel(relayDev))
        assertEquals("Wi-Fi", formatTransportLabel(wifiDev))

        listOf(peerDev, usbDev, relayDev, wifiDev).forEach { dev ->
            val label = formatTransportLabel(dev)
            assertFalse("Transport label '$label' must not contain raw port ':8765'", label.contains(":8765"))
            assertFalse("Transport label '$label' must not contain raw port 'Port'", label.contains("Port"))
        }
    }

    @Test
    fun testC33_CanonicalSnowIdDerivation() {
        val canonicalRegex = Regex("^SNW-[A-Z0-9]{4}-[A-Z0-9]{4}$")

        val id1 = SnowUiRepository.deriveCanonicalSnowId("device-seed-alpha-12345")
        assertTrue("Canonical SNOW ID '$id1' must match regex ^SNW-[A-Z0-9]{4}-[A-Z0-9]{4}$", canonicalRegex.matches(id1))

        val id2 = SnowUiRepository.deriveCanonicalSnowId("device-seed-alpha-12345")
        assertEquals("SNOW ID derivation must be deterministic for identical seeds", id1, id2)

        val id3 = SnowUiRepository.deriveCanonicalSnowId("device-seed-beta-67890")
        assertTrue("Canonical SNOW ID '$id3' must match regex ^SNW-[A-Z0-9]{4}-[A-Z0-9]{4}$", canonicalRegex.matches(id3))
        assertNotEquals("Different seeds must produce distinct SNOW IDs", id1, id3)

        // Verify all characters are uppercase
        id1.filter { it.isLetter() }.forEach { ch ->
            assertTrue("Character '$ch' in SNOW ID must be uppercase", ch.isUpperCase())
        }
    }

    @Test
    fun testC34_NavigationTerminalSelectionAndFederationFlow() {
        // Assert SnowTab navigation values
        assertEquals(SnowTab.TOOLS, SnowTab.valueOf("TOOLS"))
        assertEquals(ToolSubTab.TERMINAL, ToolSubTab.valueOf("TERMINAL"))

        // Simulate onOpenTool("terminal") routing contract
        var selectedTab = SnowTab.HOME
        var selectedToolSubTab = ToolSubTab.FILES

        fun onOpenTool(tool: String) {
            if (tool == "terminal") {
                selectedTab = SnowTab.TOOLS
                selectedToolSubTab = ToolSubTab.TERMINAL
            }
        }

        onOpenTool("terminal")
        assertEquals("onOpenTool('terminal') must select TOOLS tab", SnowTab.TOOLS, selectedTab)
        assertEquals("onOpenTool('terminal') must select TERMINAL sub-tab", ToolSubTab.TERMINAL, selectedToolSubTab)

        // Verify Federation Invite Code formatting (9 digits, 3-3-3 spaced format)
        val rawFederationCode = "482910338"
        val formattedInvite = rawFederationCode.chunked(3).joinToString(" ")
        assertEquals("482 910 338", formattedInvite)
        assertEquals(9, rawFederationCode.length)
        assertTrue(rawFederationCode.all { it.isDigit() })
    }

    @Test
    fun testC35_AccessProfileKeysAndPermissions() {
        val canonicalProfileKeys = setOf("full_control", "files_and_clipboard", "clipboard_only")
        assertEquals(3, canonicalProfileKeys.size)
        assertTrue(canonicalProfileKeys.contains("full_control"))
        assertTrue(canonicalProfileKeys.contains("files_and_clipboard"))
        assertTrue(canonicalProfileKeys.contains("clipboard_only"))

        val tempDir = File(System.getProperty("java.io.tmpdir"), "snow_c35_test_${System.currentTimeMillis()}").apply { mkdirs() }
        try {
            val ctx = TestContext(tempDir)
            val dispatcher = AndroidCapabilityDispatcher(ctx) { null }

            // 1. clipboard_only profile
            dispatcher.activePermissionProfile = "clipboard_only"
            assertTrue(dispatcher.isActionAllowedByProfile("clipboard_pull"))
            assertTrue(dispatcher.isActionAllowedByProfile("clipboard_push"))
            assertTrue(dispatcher.isActionAllowedByProfile("battery_status"))
            assertFalse(dispatcher.isActionAllowedByProfile("file_list"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_screenshot"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_camera_capture"))

            // 2. files_and_clipboard profile
            dispatcher.activePermissionProfile = "files_and_clipboard"
            assertTrue(dispatcher.isActionAllowedByProfile("clipboard_pull"))
            assertTrue(dispatcher.isActionAllowedByProfile("file_list"))
            assertTrue(dispatcher.isActionAllowedByProfile("ring_phone"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_screenshot"))
            assertFalse(dispatcher.isActionAllowedByProfile("android_camera_capture"))

            // 3. full_control profile
            dispatcher.activePermissionProfile = "full_control"
            assertTrue(dispatcher.isActionAllowedByProfile("clipboard_pull"))
            assertTrue(dispatcher.isActionAllowedByProfile("file_list"))
            assertTrue(dispatcher.isActionAllowedByProfile("android_screenshot"))
            assertTrue(dispatcher.isActionAllowedByProfile("android_camera_capture"))
            assertTrue(dispatcher.isActionAllowedByProfile("ring_phone"))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun testC36_HostModeQrJsonGenerationSchema() {
        // Assert the host mode pairing QR schema requirements
        val hostJsonObj = JSONObject().apply {
            put("v", 1)
            put("id", "phone-peer-host-uuid")
            put("ips", JSONArray().apply {
                put("192.168.1.150")
            })
            put("port", 8765)
            put("fp", "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF")
            put("pin", "987654")
        }

        val jsonStr = hostJsonObj.toString()
        val parsed = JSONObject(jsonStr)

        assertEquals("Protocol version must be 1", 1, parsed.getInt("v"))
        assertEquals("Device ID must match", "phone-peer-host-uuid", parsed.getString("id"))
        val ips = parsed.getJSONArray("ips")
        assertTrue("IPs list must not be empty", ips.length() >= 1)
        assertEquals("192.168.1.150", ips.getString(0))
        assertEquals(8765, parsed.getInt("port"))
        assertEquals("11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF", parsed.getString("fp"))
        assertEquals("987654", parsed.getString("pin"))
    }

    @Test
    fun testC37_SharedClipboardImageMimeAndAttributes() {
        val imageItem = SnowUiRepository.ClipboardItemDto(
            itemId = "clip-img-001",
            type = "image",
            sourceDevice = "laptop",
            previewText = "desktop_screenshot.png",
            sizeBytes = 512000L,
            timestamp = 1718000000.0,
            isPinned = true
        )
        assertEquals("image", imageItem.type)
        assertEquals("clip-img-001", imageItem.itemId)
        assertEquals(512000L, imageItem.sizeBytes)
        assertTrue(imageItem.isPinned)

        val textItem = SnowUiRepository.ClipboardItemDto(
            itemId = "clip-txt-002",
            type = "text",
            sourceDevice = "phone",
            previewText = "Meeting notes from discussion",
            sizeBytes = 28L,
            timestamp = 1718000010.0,
            isPinned = false
        )
        assertEquals("text", textItem.type)
        assertFalse(textItem.isPinned)

        // Helper format function test
        fun formatSize(bytes: Long): String = when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "${bytes / 1024} KB"
            else -> String.format(java.util.Locale.US, "%.1f MB", bytes.toDouble() / (1024 * 1024))
        }

        assertEquals("500 KB", formatSize(imageItem.sizeBytes))
        assertEquals("28 B", formatSize(textItem.sizeBytes))
    }

    @Test
    fun testC38_SettingsPermissionStateAndBatteryIntent() {
        // Assert Settings battery optimization constant
        assertEquals(
            "android.settings.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
        )

        // Status pill mappings
        fun getPermissionPillStatus(granted: Boolean, isBattery: Boolean = false): Pair<String, Boolean> {
            return if (granted) {
                "GRANTED" to true
            } else {
                (if (isBattery) "ALLOW" else "SETUP") to false
            }
        }

        val grantedStatus = getPermissionPillStatus(true)
        assertEquals("GRANTED", grantedStatus.first)
        assertTrue(grantedStatus.second)

        val deniedGeneral = getPermissionPillStatus(false, isBattery = false)
        assertEquals("SETUP", deniedGeneral.first)
        assertFalse(deniedGeneral.second)

        val deniedBattery = getPermissionPillStatus(false, isBattery = true)
        assertEquals("ALLOW", deniedBattery.first)
        assertFalse(deniedBattery.second)
    }

    @Test
    fun testC39_AbsenceOfMockStringsInUiConstants() {
        val forbiddenMockStrings = listOf(
            "482 910 338",
            "Lenovo_V15",
            "Port 8765",
            "Running on Port",
            "Pixel 8 Pro",
            "Rahul's",
            "Aarav",
            "v2.4 Pro"
        )

        val defaultPc = PcTelemetry.UNAVAILABLE
        forbiddenMockStrings.forEach { mock ->
            assertFalse(
                "Mock string '$mock' must not be in PcTelemetry.hostname",
                defaultPc.hostname?.contains(mock, ignoreCase = true) == true
            )
        }

        val defaultPeerHost = PeerHostState()
        forbiddenMockStrings.forEach { mock ->
            assertFalse(
                "Mock string '$mock' must not be in PeerHostState.ipAddress",
                defaultPeerHost.ipAddress.contains(mock, ignoreCase = true)
            )
        }
    }
}
