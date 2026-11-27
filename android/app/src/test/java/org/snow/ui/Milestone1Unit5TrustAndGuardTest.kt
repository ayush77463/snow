package org.snow.ui

import android.provider.Settings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snow.network.AuthState
import org.snow.network.ConnectionState
import java.io.File

/**
 * Milestone 1 — Unit 1.5 regression tests:
 * - Trust tier (`owner`/`peer`) vs permission profile separation
 * - Canonical saved-device deduplication & idempotent legacy migration
 * - Share Code authentication / authority / capability guard
 * - Notification listener check decoupled from SettingsFragment
 * - Battery optimization intent routing & manifest hygiene
 * - Fail-closed Android release signing configuration
 */
class Milestone1Unit5TrustAndGuardTest {

    private fun resolveModuleFile(relativePath: String): File {
        val candidates = listOf(
            File(relativePath),
            File("app/$relativePath"),
            File("android/app/$relativePath")
        )
        return candidates.firstOrNull { it.exists() }
            ?: error("Unable to locate module file: $relativePath from ${File(".").absolutePath}")
    }

    @Test
    fun testTrustTierAndPermissionProfileAreStrictlySeparated() {
        val defaultDevice = SavedDevice(
            deviceId = "dev-default",
            deviceName = "Workstation",
            host = "192.168.1.25",
            port = 8765
        )
        assertEquals("not_allowed", defaultDevice.permissionProfile)
        assertEquals("PEER", defaultDevice.trustTier)

        // Trust tiers must NEVER unlock full_control permission profile
        assertEquals("not_allowed", SnowUiRepository.normalizeAccessProfile("OWNER"))
        assertEquals("not_allowed", SnowUiRepository.normalizeAccessProfile("owner_manual"))
        assertEquals("not_allowed", SnowUiRepository.normalizeAccessProfile("PEER"))
        assertEquals("not_allowed", SnowUiRepository.normalizeAccessProfile("peer"))

        // Trust tier normalization keeps owner vs peer distinct from permission profiles
        assertEquals("owner", SnowUiRepository.normalizeTrustTier("OWNER"))
        assertEquals("owner", SnowUiRepository.normalizeTrustTier("owner_manual"))
        assertEquals("peer", SnowUiRepository.normalizeTrustTier("full_control"))
        assertEquals("peer", SnowUiRepository.normalizeTrustTier("unknown"))

        // Legacy migration never converts OWNER/PEER or blank permission data into full_control
        assertEquals("owner" to "not_allowed", SnowUiRepository.resolveSeparatedTrustAndProfile("OWNER", null))
        assertEquals("peer" to "not_allowed", SnowUiRepository.resolveSeparatedTrustAndProfile("PEER", null))
        assertEquals("peer" to "not_allowed", SnowUiRepository.resolveSeparatedTrustAndProfile("", ""))

        // Legacy records where access profile previously overwrote trustTier migrate cleanly without escalating trustTier
        assertEquals(
            "peer" to "files_and_clipboard",
            SnowUiRepository.resolveSeparatedTrustAndProfile("files_and_clipboard", null)
        )
        assertEquals(
            "peer" to "full_control",
            SnowUiRepository.resolveSeparatedTrustAndProfile("Full Control", "")
        )

        // Explicit separated fields remain independent
        assertEquals(
            "owner" to "clipboard_only",
            SnowUiRepository.resolveSeparatedTrustAndProfile("owner", "clipboard_only")
        )
        assertEquals(
            "owner" to "files_only",
            SnowUiRepository.resolveSeparatedTrustAndProfile("OWNER", "FILES_ONLY")
        )
    }

    @Test
    fun testCanonicalDeviceDeduplicationOrderAndIdempotency() {
        val fpA = "AA:BB:CC:DD:EE:FF:00:11"
        val fpANoColons = "aabbccddeeff0011"
        val fpB = "99:88:77:66:55:44:33:22"

        val canonicalRecord = SavedDevice(
            deviceId = "uuid-host-1111",
            deviceName = "Lenovo V15",
            host = "192.168.1.50",
            port = 8765,
            trustTier = "OWNER",
            certFingerprint = fpA,
            recentEndpoints = listOf(DeviceEndpoint("192.168.1.50", 8765, 200L)),
            snowId = "SNW-1111-2222",
            permissionProfile = "files_and_clipboard"
        )
        val duplicateBySnowId = SavedDevice(
            deviceId = "paired-desktop-legacy",
            deviceName = "Desktop Core",
            host = "10.0.0.5",
            port = 8765,
            trustTier = "PEER",
            certFingerprint = fpA,
            recentEndpoints = listOf(DeviceEndpoint("10.0.0.5", 8765, 100L)),
            snowId = "snw-1111-2222",
            permissionProfile = "not_allowed"
        )
        val duplicateByFingerprintStub = SavedDevice(
            deviceId = "peer-192.168.1.77:8765",
            deviceName = "Old Alias",
            host = "192.168.1.77",
            port = 8765,
            trustTier = "PEER",
            certFingerprint = fpANoColons,
            recentEndpoints = listOf(DeviceEndpoint("192.168.1.77", 8765, 300L)),
            snowId = null
        )
        // Distinct device sharing the exact same display name ("Lenovo V15") MUST NOT merge
        val distinctSameNameDevice = SavedDevice(
            deviceId = "uuid-host-2222",
            deviceName = "Lenovo V15",
            host = "192.168.1.50",
            port = 8765,
            trustTier = "OWNER",
            certFingerprint = fpB,
            snowId = "SNW-3333-4444",
            permissionProfile = "clipboard_only"
        )
        // Weak host:port duplicates without stronger identifiers collapse cleanly
        val weakHostDup1 = SavedDevice(
            deviceId = "peer-192.168.2.99:8765",
            deviceName = "Workshop PC",
            host = "192.168.2.99",
            port = 8765
        )
        val weakHostDup2 = SavedDevice(
            deviceId = "paired-desktop-legacy",
            deviceName = "Workshop PC",
            host = "192.168.2.99",
            port = 8765
        )

        val firstPass = SnowUiRepository.deduplicateSavedDevices(
            listOf(
                canonicalRecord,
                duplicateBySnowId,
                duplicateByFingerprintStub,
                distinctSameNameDevice,
                weakHostDup1,
                weakHostDup2
            )
        )
        assertEquals(3, firstPass.size)

        val mergedPrimary = firstPass[0]
        assertEquals("uuid-host-1111", mergedPrimary.deviceId)
        assertEquals("SNW-1111-2222", mergedPrimary.snowId)
        assertEquals("owner", mergedPrimary.trustTier)
        assertEquals("files_and_clipboard", mergedPrimary.permissionProfile)
        assertEquals(3, mergedPrimary.recentEndpoints.size)

        val secondDistinct = firstPass[1]
        assertEquals("SNW-3333-4444", secondDistinct.snowId)
        assertEquals("clipboard_only", secondDistinct.permissionProfile)

        val mergedWeak = firstPass[2]
        assertEquals("192.168.2.99", mergedWeak.host)

        // Repeatability / idempotency
        val secondPass = SnowUiRepository.deduplicateSavedDevices(firstPass)
        assertEquals(firstPass, secondPass)
    }

    @Test
    fun testShareCodeGuardBlocksUnauthenticatedOrUnauthorizedStates() {
        val disconnected = SnowUiRepository.evaluateShareCodeEligibility(
            ConnectionState.DISCONNECTED,
            AuthState.Disconnected
        )
        assertFalse(disconnected.allowed)
        assertFalse(disconnected.reason.isNullOrBlank())

        val unauthConnected = SnowUiRepository.evaluateShareCodeEligibility(
            ConnectionState.CONNECTED,
            AuthState.ConnectedUnauthenticated
        )
        assertFalse(unauthConnected.allowed)
        assertFalse(unauthConnected.reason.isNullOrBlank())

        val failedAuth = SnowUiRepository.evaluateShareCodeEligibility(
            ConnectionState.CONNECTED,
            AuthState.AuthFailed("Invalid token")
        )
        assertFalse(failedAuth.allowed)

        val nonOwnerPeer = SnowUiRepository.evaluateShareCodeEligibility(
            ConnectionState.CONNECTED,
            AuthState.Authenticated(sessionId = "sess-peer", trustTier = "peer")
        )
        assertFalse(nonOwnerPeer.allowed)

        val missingCap = SnowUiRepository.evaluateShareCodeEligibility(
            ConnectionState.CONNECTED,
            AuthState.Authenticated(sessionId = "sess-owner", trustTier = "owner"),
            supportedCapabilities = setOf("clipboard_push", "file_list")
        )
        assertFalse(missingCap.allowed)

        val ownerReady = SnowUiRepository.evaluateShareCodeEligibility(
            ConnectionState.CONNECTED,
            AuthState.Authenticated(sessionId = "sess-owner", trustTier = "owner"),
            supportedCapabilities = setOf("federation", "clipboard_push")
        )
        assertTrue(ownerReady.allowed)

        val repoSrc = resolveModuleFile("src/main/java/org/snow/ui/SnowUiRepository.kt").readText()
        assertTrue(repoSrc.contains("val availability = evaluateShareCodeEligibility(_connectionState.value, _authState.value)"))

        // M4.5 removed CrossNetworkSharingCard / federation UI from DevicesScreen while keeping the repository guard intact
        val devicesSrc = resolveModuleFile("src/main/java/org/snow/ui/devices/DevicesScreen.kt").readText()
        assertFalse(devicesSrc.contains("CrossNetworkSharingCard("))
        assertFalse(devicesSrc.contains("enabled = canShareCode"))
    }

    @Test
    fun testDispatcherDecoupledFromSettingsFragmentAndBatterySettingsSafe() {
        val dispatcherSrc = resolveModuleFile("src/main/java/org/snow/capabilities/AndroidCapabilityDispatcher.kt").readText()
        assertFalse(
            "AndroidCapabilityDispatcher must not depend on SettingsFragment",
            dispatcherSrc.contains("SettingsFragment")
        )
        assertTrue(dispatcherSrc.contains("SnowNotificationListenerService.isNotificationServiceEnabled"))

        val intentSpecs = SnowUiRepository.createBatteryOptimizationIntentSpecs("org.snow")
        assertEquals(2, intentSpecs.size)
        assertEquals(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS, intentSpecs[0].action)
        assertEquals(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, intentSpecs[1].action)
        assertEquals("package:org.snow", intentSpecs[1].dataUri)
        assertTrue(intentSpecs.none { it.action == Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS })

        val settingsScreenSrc = resolveModuleFile("src/main/java/org/snow/ui/settings/SettingsScreen.kt").readText()
        val manifestSrc = resolveModuleFile("src/main/AndroidManifest.xml").readText()

        assertFalse(settingsScreenSrc.contains("ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"))
        assertFalse(manifestSrc.contains("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"))
    }

    @Test
    fun testFailClosedReleaseSigningContractInGradle() {
        val gradleSrc = resolveModuleFile("build.gradle.kts").readText()
        assertTrue(gradleSrc.contains("releaseSigningValidationError"))
        assertTrue(gradleSrc.contains("assembleRelease"))
        assertTrue(gradleSrc.contains("bundleRelease"))
        assertTrue(gradleSrc.contains("packageRelease"))
        assertTrue(gradleSrc.contains("packageReleaseBundle"))
        assertTrue(gradleSrc.contains("validateSigningRelease"))
        assertTrue(gradleSrc.contains("signReleaseBundle"))
    }
}
