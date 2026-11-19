package org.snow.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceNodeTest {

    @Test
    fun testBuildAndroidManifestDefaults() {
        val manifest = DeviceNode.buildAndroidManifest(null)

        assertEquals("2.0", manifest.manifestVersion)
        assertTrue("Must support android.telemetry.get", manifest.supportsCapability("android.telemetry.get"))
        assertTrue("Must support android.clipboard.get", manifest.supportsCapability("android.clipboard.get"))
        assertTrue("Must support android.clipboard.set", manifest.supportsCapability("android.clipboard.set"))
        assertTrue("Must support android.apps.list", manifest.supportsCapability("android.apps.list"))
        assertTrue("Must support android.apps.launch", manifest.supportsCapability("android.apps.launch"))
        assertTrue("Must support android.notifications.push", manifest.supportsCapability("android.notifications.push"))
        assertTrue("Must support android.files.transfer", manifest.supportsCapability("android.files.transfer"))
        assertTrue("Must support android.ringer.ring", manifest.supportsCapability("android.ringer.ring"))

        // Security check: must NEVER support restricted desktop capabilities or forbidden SMS
        assertFalse("Must NOT support desktop.exec", manifest.supportsCapability("desktop.exec"))
        assertFalse("Must NOT support android.sms.send", manifest.supportsCapability("android.sms.send"))
    }

    @Test
    fun testCapabilityExecutionClassification() {
        val manifest = DeviceNode.buildAndroidManifest(null)

        assertEquals(
            CapabilityClassification.BACKGROUND_SAFE,
            manifest.classifications["android.telemetry.get"]
        )
        assertEquals(
            CapabilityClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
            manifest.classifications["android.clipboard.get"]
        )
        assertEquals(
            CapabilityClassification.RUNTIME_PERMISSION_REQUIRED,
            manifest.classifications["android.notifications.push"]
        )
        assertEquals(
            CapabilityClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
            manifest.classifications["android.apps.launch"]
        )
        assertEquals(
            CapabilityClassification.BACKGROUND_SAFE,
            manifest.classifications["android.ringer.ring"]
        )
        assertTrue(manifest.isBackgroundSafe("android.telemetry.get"))
        assertTrue(manifest.isBackgroundSafe("android.ringer.ring"))
        assertFalse(manifest.isBackgroundSafe("android.notifications.push"))
        assertFalse(manifest.isBackgroundSafe("android.apps.launch"))
        assertFalse(manifest.isBackgroundSafe("android.clipboard.get"))
    }

    @Test
    fun testCapabilityManifestMapRoundtrip() {
        val original = CapabilityManifest(
            manifestVersion = "2.0",
            supportedCapabilities = listOf("android.telemetry.get", "android.apps.launch", "android.notifications.push"),
            permissionStates = mapOf("POST_NOTIFICATIONS" to "granted"),
            classifications = mapOf(
                "android.telemetry.get" to CapabilityClassification.BACKGROUND_SAFE,
                "android.apps.launch" to CapabilityClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
                "android.notifications.push" to CapabilityClassification.RUNTIME_PERMISSION_REQUIRED
            )
        )

        val map = original.toMap()
        assertEquals("2.0", map["manifest_version"])

        val parsed = CapabilityManifest.fromMap(map)
        assertNotNull(parsed)
        assertEquals(original.manifestVersion, parsed.manifestVersion)
        assertEquals(original.supportedCapabilities, parsed.supportedCapabilities)
        assertEquals(original.permissionStates, parsed.permissionStates)
        assertEquals(original.classifications, parsed.classifications)
    }

    @Test
    fun testCapabilityManifestFromMapNullOrEmpty() {
        val nullParsed = CapabilityManifest.fromMap(null)
        assertNotNull(nullParsed)
        assertEquals("2.0", nullParsed.manifestVersion)
        assertTrue(nullParsed.supportedCapabilities.isEmpty())

        val emptyParsed = CapabilityManifest.fromMap(emptyMap())
        assertNotNull(emptyParsed)
        assertEquals("2.0", emptyParsed.manifestVersion)
        assertTrue(emptyParsed.supportedCapabilities.isEmpty())
    }

    @Test
    fun testDeviceNodePropertiesAndSupportsCapability() {
        val manifest = DeviceNode.buildAndroidManifest(null)
        val node = DeviceNode(
            deviceId = "test-node-1234",
            deviceName = "Ayush Phone",
            platform = "android",
            protocolVersion = 1,
            reachabilityProfile = ReachabilityProfile.ACTIVE_SESSION_PEER,
            reachabilityState = ReachabilityState.CONNECTED_SESSION,
            host = "192.168.1.105",
            wssPort = 8765,
            transferPort = 8766,
            supportedCapabilities = manifest.supportedCapabilities,
            permissionStates = manifest.permissionStates,
            lastSeenTimestamp = 1700000000.0,
            trustTier = "owner",
            capabilities = manifest,
            isAuthenticated = true,
            isConnected = true,
            isPaired = true
        )

        assertEquals("test-node-1234", node.deviceId)
        assertEquals("Ayush Phone", node.deviceName)
        assertTrue(node.isConnected)
        assertTrue(node.isPaired)
        assertTrue(node.isAuthenticated)
        assertTrue(node.supportsCapability("android.telemetry.get"))
        assertTrue(node.supportsCapability("android.ringer.ring"))
        assertFalse(node.supportsCapability("desktop.exec"))

        val map = node.toMap()
        assertEquals("test-node-1234", map["device_id"])
        assertEquals("Ayush Phone", map["device_name"])
        assertEquals("ACTIVE_SESSION_PEER", map["reachability_profile"])
        assertEquals("CONNECTED_SESSION", map["reachability_state"])
        assertEquals(true, map["is_authenticated"])
        assertEquals(true, map["is_connected"])
        assertEquals(true, map["is_paired"])
        assertEquals(1700000000.0, map["last_seen_timestamp"])
        assertNotNull(map["capabilities"])

        // Roundtrip via fromMap
        val parsed = DeviceNode.fromMap(map)
        assertNotNull(parsed)
        assertEquals(node.deviceId, parsed!!.deviceId)
        assertEquals(node.deviceName, parsed.deviceName)
        assertEquals(node.reachabilityProfile, parsed.reachabilityProfile)
        assertEquals(node.reachabilityState, parsed.reachabilityState)
        assertEquals(node.lastSeenTimestamp, parsed.lastSeenTimestamp, 0.001)
        assertEquals(node.isAuthenticated, parsed.isAuthenticated)
        assertEquals(node.isPaired, parsed.isPaired)

        // Test ONLINE_ROUTED reachability state
        val routedNode = node.copy(reachabilityState = ReachabilityState.ONLINE_ROUTED)
        assertEquals(ReachabilityState.ONLINE_ROUTED, routedNode.reachabilityState)
        val routedMap = routedNode.toMap()
        assertEquals("ONLINE_ROUTED", routedMap["reachability_state"])
        val routedParsed = DeviceNode.fromMap(routedMap)
        assertEquals(ReachabilityState.ONLINE_ROUTED, routedParsed?.reachabilityState)

        // Test epoch millis migration in fromMap
        val legacyMillisMap = map.toMutableMap()
        legacyMillisMap["last_seen_timestamp"] = 1700000000000L
        val migrated = DeviceNode.fromMap(legacyMillisMap)
        assertNotNull(migrated)
        assertEquals(1700000000.0, migrated!!.lastSeenTimestamp, 0.001)
    }

    @Test
    fun testFallbackNodeWithoutManifestUsesSupportedCapabilitiesList() {
        val node = DeviceNode(
            deviceId = "legacy-device-id",
            deviceName = "Legacy Phone",
            platform = "android",
            supportedCapabilities = listOf("android.telemetry.get", "android.clipboard.get"),
            capabilities = null
        )

        assertTrue(node.supportsCapability("android.telemetry.get"))
        assertTrue(node.supportsCapability("android.clipboard.get"))
        assertFalse(node.supportsCapability("android.apps.launch"))
    }
}
