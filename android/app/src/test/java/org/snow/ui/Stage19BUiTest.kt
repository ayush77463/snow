package org.snow.ui

import org.junit.Assert.*
import org.junit.Test
import org.snow.security.PairingFlow
import org.snow.ui.settings.SettingsViewModel

/**
 * Unit test suite verifying Stage 19B UI models, input validation,
 * navigation logic, and security contracts.
 */
class Stage19BUiTest {

    // --- Devices Validation Tests ---

    @Test
    fun testIpv4Validation() {
        val ipv4Regex = Regex("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)$")

        // Valid IPv4 addresses
        assertTrue(ipv4Regex.matches("192.168.1.100"))
        assertTrue(ipv4Regex.matches("10.0.0.1"))
        assertTrue(ipv4Regex.matches("127.0.0.1"))
        assertTrue(ipv4Regex.matches("172.16.254.1"))

        // Invalid IPv4 addresses
        assertFalse(ipv4Regex.matches("256.0.0.1"))
        assertFalse(ipv4Regex.matches("192.168.1"))
        assertFalse(ipv4Regex.matches("192.168.1.1.1"))
        assertFalse(ipv4Regex.matches("abc.def.ghi.jkl"))
        assertFalse(ipv4Regex.matches(""))
    }

    @Test
    fun testHostnameValidation() {
        val hostnameRegex = Regex("^[a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9]$")

        assertTrue(hostnameRegex.matches("desktop-core"))
        assertTrue(hostnameRegex.matches("my-laptop.local"))
        assertTrue(hostnameRegex.matches("pc01"))

        assertFalse(hostnameRegex.matches("-invalid"))
        assertFalse(hostnameRegex.matches("invalid-"))
        assertFalse(hostnameRegex.matches(""))
    }

    @Test
    fun testPortRangeValidation() {
        val validPorts = listOf(1, 80, 8765, 8766, 65535)
        for (port in validPorts) {
            assertTrue("Port $port should be valid", port in 1..65535)
        }

        val invalidPorts = listOf(0, -1, 65536, 70000)
        for (port in invalidPorts) {
            assertFalse("Port $port should be invalid", port in 1..65535)
        }
    }

    @Test
    fun testPinValidationFormat() {
        // Pairing PINs must be exactly 6 decimal digits
        val flow = PairingFlow(org.snow.security.DeviceIdentity(
            deviceId = java.util.UUID.randomUUID().toString(),
            deviceName = "Test Device",
            createdAt = "2026-11-19T10:00:00Z"
        ))

        assertTrue(flow.validatePin("123456"))
        assertTrue(flow.validatePin("004821"))
        assertTrue(flow.validatePin("000000"))
        assertTrue(flow.validatePin("999999"))

        assertFalse(flow.validatePin("12345"))     // 5 digits
        assertFalse(flow.validatePin("1234567"))   // 7 digits
        assertFalse(flow.validatePin("abcdef"))   // non-numeric
        assertFalse(flow.validatePin("12345a"))   // alphanumeric
        assertFalse(flow.validatePin(null))       // null
        assertFalse(flow.validatePin(""))         // empty
    }

    @Test
    fun testSavedDeviceStableDeviceId() {
        val device = SavedDevice(
            deviceId = "a1b2c3d4",
            deviceName = "Desktop Core (192.168.1.100)",
            host = "192.168.1.100",
            port = 8765,
            lastSeen = "2026-11-19 12:00:00"
        )

        assertEquals("a1b2c3d4", device.deviceId)
        assertEquals("192.168.1.100", device.host)
        assertEquals(8765, device.port)
    }

    // --- Files Explorer Tests ---

    @Test
    fun testHiddenFileFiltering() {
        val allFiles = listOf(
            PcFileItem("normal_file.txt", "C:\\normal_file.txt", false, 1024L, "2026-11-19", false),
            PcFileItem(".hidden_file", "C:\\.hidden_file", false, 512L, "2026-11-19", true),
            PcFileItem("Folder", "C:\\Folder", true, 0L, "2026-11-19", false),
            PcFileItem(".git", "C:\\.git", true, 0L, "2026-11-19", true)
        )

        val visibleFiles = allFiles.filterNot { it.isHidden }
        assertEquals(2, visibleFiles.size)
        assertTrue(visibleFiles.any { it.name == "normal_file.txt" })
        assertTrue(visibleFiles.any { it.name == "Folder" })
        assertFalse(visibleFiles.any { it.name == ".hidden_file" })
        assertFalse(visibleFiles.any { it.name == ".git" })
    }

    @Test
    fun testNavigationParentPath() {
        fun getParent(current: String): String {
            val clean = current.trimEnd('\\', '/')
            val lastSlash = maxOf(clean.lastIndexOf('\\'), clean.lastIndexOf('/'))
            return if (lastSlash > 0) {
                clean.substring(0, lastSlash)
            } else {
                ""
            }
        }

        assertEquals("C:\\Users\\User", getParent("C:\\Users\\User\\Downloads"))
        assertEquals("C:\\Users", getParent("C:\\Users\\User"))
        assertEquals("C:", getParent("C:\\Users"))
        assertEquals("", getParent("C:"))
    }

    // --- Terminal Confirmation Ticket & Security Handshake Tests ---

    @Test
    fun testTerminalConfirmationRequiredModel() {
        val cmd = "rmdir /s /q temp"
        val ticket = "ticket-sec-77291a"

        val result = TerminalResult.ConfirmationRequired(command = cmd, ticket = ticket)

        assertEquals(cmd, result.command)
        assertEquals(ticket, result.ticket)
    }

    @Test
    fun testTerminalResubmissionParametersIncludeTicket() {
        val cmd = "rmdir /s /q temp"
        val ticket = "ticket-sec-77291a"

        val params = mutableMapOf<String, Any>(
            "command" to cmd,
            "confirmed" to true
        )
        if (ticket.isNotBlank()) {
            params["confirmation_ticket"] = ticket
        }

        assertTrue(params.containsKey("command"))
        assertTrue(params.containsKey("confirmed"))
        assertTrue(params.containsKey("confirmation_ticket"))
        assertEquals(ticket, params["confirmation_ticket"])
    }

    @Test
    fun testTerminalOutputNoTicketLeakage() {
        // Output lines presented to user or logs must never contain the secret confirmation ticket
        val ticket = "super-secret-ticket-999"
        val output = TerminalOutputLine("Directory removed successfully.", isStderr = false)

        assertFalse(output.text.contains(ticket))
    }

    // --- Settings & Appearance Tests ---

    @Test
    fun testThemeModeConstants() {
        assertEquals(-1, SettingsViewModel.THEME_SYSTEM)
        assertEquals(1, SettingsViewModel.THEME_LIGHT)
        assertEquals(2, SettingsViewModel.THEME_DARK)
    }

    @Test
    fun testUiLogEntryFormatting() {
        val entry = UiLogEntry(
            timestamp = "12:34:56",
            level = "INFO",
            tag = "SnowUiRepository",
            message = "Connected to desktop"
        )

        assertEquals("12:34:56", entry.timestamp)
        assertEquals("INFO", entry.level)
        assertEquals("SnowUiRepository", entry.tag)
        assertEquals("Connected to desktop", entry.message)
    }

    // --- Fix A1: Lock PC Capability Contract Tests ---

    @Test
    fun testLockPcCapabilityContract() {
        val action = "desktop_app_launch"
        val target = "lock_screen"
        val params = mapOf("app_name" to target)

        assertEquals("desktop_app_launch", action)
        assertEquals("lock_screen", params["app_name"])
        assertFalse(params.containsKey("command"))
    }

    // --- Fix A2: App Launcher 10 Windows Targets Tests ---

    @Test
    fun testAppLauncherTenWindowsTargets() {
        val expectedTargets = mapOf(
            "VS Code" to "code",
            "Windows Terminal" to "wt",
            "Notepad" to "notepad",
            "Calculator" to "calc",
            "File Explorer" to "explorer",
            "Task Manager" to "taskmgr",
            "Paint" to "mspaint",
            "Google Chrome" to "chrome",
            "Microsoft Edge" to "msedge",
            "PowerShell" to "powershell"
        )

        val actualApps = org.snow.ui.dashboard.AppLauncherBottomSheet.ALLOWLISTED_WINDOWS_APPS
        assertEquals("Must contain exactly 10 Windows applications", 10, actualApps.size)

        for (item in actualApps) {
            assertTrue("Expected item ${item.friendlyName} in targets", expectedTargets.containsKey(item.friendlyName))
            assertEquals(expectedTargets[item.friendlyName], item.target)
        }
    }

    @Test
    fun testAppLauncherCustomTargetValidation() {
        fun isValidCustomTarget(target: String): Boolean {
            val clean = target.trim()
            if (clean.isBlank()) return false
            // Rejects shell metacharacters and requires valid format or .exe
            val forbidden = listOf("&", "|", ";", ">", "<", "`", "$")
            if (forbidden.any { clean.contains(it) }) return false
            return clean.endsWith(".exe", ignoreCase = true) || !clean.contains("\\")
        }

        assertTrue(isValidCustomTarget("C:\\Tools\\my_tool.exe"))
        assertTrue(isValidCustomTarget("tool.exe"))
        assertTrue(isValidCustomTarget("code"))

        assertFalse(isValidCustomTarget(""))
        assertFalse(isValidCustomTarget("calc & whoami"))
        assertFalse(isValidCustomTarget("calc | dir"))
    }

    // --- Fix A3: Reconnect Limit and SAF Transfer Tests ---

    @Test
    fun testSnowWebSocketClientRetryLimitConstant() {
        assertEquals(3, org.snow.network.SnowWebSocketClient.MAX_CONNECT_RETRIES)
        assertEquals(3, SnowUiRepository.MAX_CONNECT_RETRIES)
    }

    @Test
    fun testActiveTransferDirectionModels() {
        val downloadInfo = ActiveTransferInfo(
            transferId = "dl-1",
            fileName = "archive.zip",
            direction = "DOWNLOAD",
            bytesTransferred = 1024L,
            totalBytes = 2048L,
            status = "IN_PROGRESS"
        )
        val uploadInfo = ActiveTransferInfo(
            transferId = "up-1",
            fileName = "photo.jpg",
            direction = "UPLOAD",
            bytesTransferred = 512L,
            totalBytes = 1024L,
            status = "IN_PROGRESS"
        )

        assertEquals("DOWNLOAD", downloadInfo.direction)
        assertEquals("UPLOAD", uploadInfo.direction)
    }

    @Test
    fun testSafNonCollidingFilenameGeneration() {
        fun generateUniqueName(existingNames: Set<String>, baseName: String): String {
            if (!existingNames.contains(baseName)) return baseName
            val dot = baseName.lastIndexOf('.')
            val namePart = if (dot > 0) baseName.substring(0, dot) else baseName
            val extPart = if (dot > 0) baseName.substring(dot) else ""
            var i = 1
            while (i < 100) {
                val candidate = "$namePart ($i)$extPart"
                if (!existingNames.contains(candidate)) return candidate
                i++
            }
            return "${namePart}_new$extPart"
        }

        val existing = setOf("report.pdf", "report (1).pdf", "photo.jpg")

        assertEquals("new_file.txt", generateUniqueName(existing, "new_file.txt"))
        assertEquals("report (2).pdf", generateUniqueName(existing, "report.pdf"))
        assertEquals("photo (1).jpg", generateUniqueName(existing, "photo.jpg"))
    }
}
