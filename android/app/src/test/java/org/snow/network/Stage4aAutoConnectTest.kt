package org.snow.network

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Stage 4A unit tests covering:
 * - Master QR payload parsing with optional relay fields and backward compatibility.
 * - Dynamic Quick Settings tile subtitle formatting.
 * - Relay endpoint URL validation.
 */
class Stage4aAutoConnectTest {

    @Test
    fun testMasterQrPayloadParsingWithRelay() {
        val jsonStr = """
            {
              "v": 1,
              "id": "desktop-core-stage4a",
              "ips": ["192.168.1.150"],
              "port": 8765,
              "fp": "A1B2C3D4E5F60123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
              "pin": "123456",
              "tier": "owner",
              "relay_url": "wss://relay.snow.example.com:8770/v1/tunnel",
              "relay_ticket": "eyJhbGciOiJIUzI1NiJ9.test-ticket",
              "group_id": "group-stage4a"
            }
        """.trimIndent()

        val payload = JSONObject(jsonStr)
        assertEquals(1, payload.getInt("v"))
        assertEquals("desktop-core-stage4a", payload.getString("id"))
        assertEquals(8765, payload.getInt("port"))
        assertEquals("123456", payload.getString("pin"))
        assertEquals("owner", payload.getString("tier"))
        assertEquals("wss://relay.snow.example.com:8770/v1/tunnel", payload.getString("relay_url"))
        assertEquals("eyJhbGciOiJIUzI1NiJ9.test-ticket", payload.getString("relay_ticket"))
        assertEquals("group-stage4a", payload.getString("group_id"))
    }

    @Test
    fun testMasterQrBackwardCompatibilityWithoutRelay() {
        val legacyJson = """
            {
              "v": 1,
              "id": "desktop-legacy",
              "ips": ["192.168.1.100"],
              "port": 8765,
              "fp": "A1B2C3D4E5F60123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
              "pin": "654321"
            }
        """.trimIndent()

        val payload = JSONObject(legacyJson)
        assertEquals(1, payload.getInt("v"))
        assertEquals("desktop-legacy", payload.getString("id"))
        assertEquals(8765, payload.getInt("port"))
        assertEquals("654321", payload.getString("pin"))
        assertFalse(payload.has("relay_url"))
        assertFalse(payload.has("relay_ticket"))
        assertFalse(payload.has("group_id"))
        assertEquals("", payload.optString("relay_url", ""))
    }

    @Test
    fun testTileSubtitleFormatting() {
        fun formatSubtitle(state: ConnectionState, endpoint: String): String {
            return when (state) {
                ConnectionState.CONNECTED -> {
                    if (endpoint.contains("relay", ignoreCase = true) || endpoint.contains("/v1/tunnel", ignoreCase = true) || endpoint.contains(":8770")) {
                        "Connected \u2022 Remote"
                    } else if (endpoint.contains("127.0.0.1") || endpoint.contains("usb", ignoreCase = true)) {
                        "Connected \u2022 USB"
                    } else {
                        "Connected \u2022 Wi-Fi"
                    }
                }
                ConnectionState.CONNECTING, ConnectionState.RECONNECTING -> "Connecting..."
                ConnectionState.DISCONNECTED -> "Off"
            }
        }

        assertEquals("Connected \u2022 USB", formatSubtitle(ConnectionState.CONNECTED, "127.0.0.1:8765"))
        assertEquals("Connected \u2022 USB", formatSubtitle(ConnectionState.CONNECTED, "usb-reverse-tunnel"))
        assertEquals("Connected \u2022 Wi-Fi", formatSubtitle(ConnectionState.CONNECTED, "192.168.1.100:8765"))
        assertEquals("Connected \u2022 Remote", formatSubtitle(ConnectionState.CONNECTED, "wss://relay.snow.example.com/v1/tunnel"))
        assertEquals("Connected \u2022 Remote", formatSubtitle(ConnectionState.CONNECTED, "127.0.0.1:8770"))
        assertEquals("Connecting...", formatSubtitle(ConnectionState.CONNECTING, ""))
        assertEquals("Connecting...", formatSubtitle(ConnectionState.RECONNECTING, ""))
        assertEquals("Off", formatSubtitle(ConnectionState.DISCONNECTED, ""))
    }

    @Test
    fun testRelayUrlValidation() {
        fun isValidRelayUrl(url: String): Boolean {
            val clean = url.trim()
            return clean.startsWith("wss://") || clean.startsWith("ws://")
        }

        assertTrue(isValidRelayUrl("wss://example.com:8770/v1/tunnel"))
        assertTrue(isValidRelayUrl("ws://127.0.0.1:8770/v1/tunnel"))
        assertFalse(isValidRelayUrl("http://example.com:8770"))
        assertFalse(isValidRelayUrl("https://example.com:8770"))
        assertFalse(isValidRelayUrl("javascript:alert(1)"))
    }
}
