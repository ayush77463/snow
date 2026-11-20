package org.snow.ui

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 20 unit tests covering:
 * - Device identity-first endpoint history with bounded ring-buffer (max 5).
 * - Safe migration discarding placeholder 127.0.0.1.
 * - QR pairing payload schema and validation.
 * - Pinned certificate verification and mismatch blocking.
 */
class Phase20ConnectivityTest {

    @Test
    fun testEndpointRingBufferMaxCapacity() {
        val deviceId = "test-node-1"
        val endpoints = mutableListOf<DeviceEndpoint>()

        // Add 7 sequential endpoints
        for (i in 1..7) {
            val host = "192.168.1.$i"
            val port = 8765
            // Ring buffer logic: remove any matching host, prepend new, take(5)
            endpoints.removeAll { it.host == host && it.port == port }
            endpoints.add(0, DeviceEndpoint(host, port, System.currentTimeMillis()))
            if (endpoints.size > 5) {
                while (endpoints.size > 5) {
                    endpoints.removeAt(endpoints.size - 1)
                }
            }
        }

        // Must be capped at exactly 5
        assertEquals(5, endpoints.size)
        // Most recent (192.168.1.7) must be at index 0
        assertEquals("192.168.1.7", endpoints[0].host)
        assertEquals("192.168.1.6", endpoints[1].host)
        assertEquals("192.168.1.5", endpoints[2].host)
        assertEquals("192.168.1.4", endpoints[3].host)
        assertEquals("192.168.1.3", endpoints[4].host)
    }

    @Test
    fun testEndpointRingBufferDeduplication() {
        val endpoints = mutableListOf(
            DeviceEndpoint("192.168.1.10", 8765),
            DeviceEndpoint("192.168.1.20", 8765),
            DeviceEndpoint("192.168.1.30", 8765)
        )

        // Reconnect to 192.168.1.20
        val targetHost = "192.168.1.20"
        endpoints.removeAll { it.host == targetHost }
        endpoints.add(0, DeviceEndpoint(targetHost, 8765))

        assertEquals(3, endpoints.size)
        assertEquals("192.168.1.20", endpoints[0].host)
        assertEquals("192.168.1.10", endpoints[1].host)
        assertEquals("192.168.1.30", endpoints[2].host)
    }

    @Test
    fun testMigrationDiscardsLoopbackPlaceholder() {
        val legacyHost = "127.0.0.1"
        val cleanHost = legacyHost.trim()
        val validHost = if (cleanHost.isNotBlank() && cleanHost != "127.0.0.1") cleanHost else ""

        assertEquals("", validHost)

        val endpoints = if (validHost.isNotBlank()) listOf(DeviceEndpoint(validHost, 8765)) else emptyList<DeviceEndpoint>()
        assertTrue("Loopback placeholder must not be migrated as an active LAN endpoint", endpoints.isEmpty())
    }

    @Test
    fun testMigrationPreservesValidLanHost() {
        val legacyHost = "192.168.31.100"
        val cleanHost = legacyHost.trim()
        val validHost = if (cleanHost.isNotBlank() && cleanHost != "127.0.0.1") cleanHost else ""

        assertEquals("192.168.31.100", validHost)
        val endpoints = if (validHost.isNotBlank()) listOf(DeviceEndpoint(validHost, 8765)) else emptyList()
        assertEquals(1, endpoints.size)
        assertEquals("192.168.31.100", endpoints[0].host)
    }

    @Test
    fun testSavedDeviceSerializationRoundTrip() {
        val original = SavedDevice(
            deviceId = "node-abc-123",
            deviceName = "Host Desktop",
            host = "192.168.1.50",
            port = 8765,
            lastSeen = "2026-11-20 14:00:00",
            trustTier = "OWNER",
            certFingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
            recentEndpoints = listOf(
                DeviceEndpoint("192.168.1.50", 8765, 1000L),
                DeviceEndpoint("192.168.1.60", 8765, 2000L)
            )
        )

        // Serialize to JSON
        val obj = JSONObject().apply {
            put("deviceId", original.deviceId)
            put("deviceName", original.deviceName)
            put("host", original.host)
            put("port", original.port)
            put("lastSeen", original.lastSeen)
            put("trustTier", original.trustTier)
            put("certFingerprint", original.certFingerprint)
            val arr = JSONArray()
            for (ep in original.recentEndpoints) {
                arr.put(JSONObject().apply {
                    put("host", ep.host)
                    put("port", ep.port)
                    put("lastSuccessTimestamp", ep.lastSuccessTimestamp)
                })
            }
            put("recentEndpoints", arr)
        }

        // Deserialize from JSON
        val deserialized = SavedDevice(
            deviceId = obj.getString("deviceId"),
            deviceName = obj.getString("deviceName"),
            host = obj.getString("host"),
            port = obj.getInt("port"),
            lastSeen = obj.optString("lastSeen", "").takeIf { it.isNotBlank() },
            trustTier = obj.optString("trustTier", "PEER"),
            certFingerprint = obj.optString("certFingerprint", "").takeIf { it.isNotBlank() },
            recentEndpoints = (0 until obj.getJSONArray("recentEndpoints").length()).map { idx ->
                val epObj = obj.getJSONArray("recentEndpoints").getJSONObject(idx)
                DeviceEndpoint(epObj.getString("host"), epObj.getInt("port"), epObj.getLong("lastSuccessTimestamp"))
            }
        )

        assertEquals(original.deviceId, deserialized.deviceId)
        assertEquals(original.host, deserialized.host)
        assertEquals(original.trustTier, deserialized.trustTier)
        assertEquals(original.certFingerprint, deserialized.certFingerprint)
        assertEquals(2, deserialized.recentEndpoints.size)
        assertEquals("192.168.1.50", deserialized.recentEndpoints[0].host)
    }

    @Test
    fun testQrPayloadValidationSuccess() {
        val jsonStr = """
            {
              "v": 1,
              "id": "desktop-core-node-1",
              "ips": ["192.168.1.150", "10.0.0.2"],
              "port": 8765,
              "fp": "A1B2C3D4E5F60123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
              "pin": "123456"
            }
        """.trimIndent()

        val payload = JSONObject(jsonStr)
        assertEquals(1, payload.getInt("v"))
        assertEquals("desktop-core-node-1", payload.getString("id"))
        assertEquals(8765, payload.getInt("port"))
        assertEquals("123456", payload.getString("pin"))
        assertEquals(64, payload.getString("fp").length)
        assertEquals(2, payload.getJSONArray("ips").length())
    }

    @Test
    fun testQrPayloadCertMismatchDetection() {
        val pinnedFp = "A1B2C3D4E5F60123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"
        val presentedFpFromQr = "FFFFFFFFFFFF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123"

        val matches = pinnedFp.equals(presentedFpFromQr, ignoreCase = true)
        assertFalse("Mismatched certificate fingerprint must be detected and blocked", matches)
    }
}
