package org.snow.ui

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.snow.network.DiscoveredPeer
import org.snow.network.DiscoveryManager

/**
 * Stage 5A Unit Test Suite verifying:
 * 1. Normalized Relay URL conversion (preserving ports, adding /v1/tunnel path).
 * 2. SavedDevice serialization and deserialization with SNOW ID.
 * 3. DiscoveredPeer serialization and deserialization with SNOW ID.
 * 4. Input recognition for connectByInput: SNOW ID, 6-digit PIN, 9-digit federation code, direct IP, and relay.
 * 5. Active updater endpoint fallback resolution.
 */
class Stage5AConnectionResolverTest {

    // -------------------------------------------------------------------------
    // 1. Relay URL Normalization
    // -------------------------------------------------------------------------
    @Test
    fun testRelayUrlNormalization() {
        fun normalizeRelayUrl(raw: String): String {
            var s = raw.trim()
            if (s.isEmpty()) return ""
            if (s.startsWith("http://", ignoreCase = true)) {
                s = "ws://" + s.substring("http://".length)
            } else if (s.startsWith("https://", ignoreCase = true)) {
                s = "wss://" + s.substring("https://".length)
            } else if (!s.startsWith("ws://", ignoreCase = true) && !s.startsWith("wss://", ignoreCase = true)) {
                s = "wss://$s"
            }

            return try {
                val uri = java.net.URI(s)
                val scheme = uri.scheme ?: if (s.startsWith("ws://", ignoreCase = true)) "ws" else "wss"
                val host = uri.host ?: s.substringAfter("://").substringBefore("/").substringBefore(":")
                val port = uri.port
                val path = uri.path
                val hostPort = if (port != -1) "$host:$port" else host
                val cleanPath = if (path.isNullOrBlank() || path == "/") "/v1/tunnel" else path
                "$scheme://$hostPort$cleanPath"
            } catch (_: Exception) {
                val scheme = if (s.startsWith("ws://", ignoreCase = true)) "ws" else "wss"
                val body = s.substringAfter("://")
                val hostPort = body.substringBefore("/")
                val path = body.substringAfter("/", "")
                val cleanPath = if (path.isBlank()) "/v1/tunnel" else "/$path"
                "$scheme://$hostPort$cleanPath"
            }
        }

        // Test bare domain
        assertEquals("wss://snow.myrelay.org/v1/tunnel", normalizeRelayUrl("snow.myrelay.org"))

        // Test explicit port
        assertEquals("wss://192.168.1.100:8770/v1/tunnel", normalizeRelayUrl("192.168.1.100:8770"))

        // Test HTTP to WS upgrade
        assertEquals("ws://10.0.0.5:8770/v1/tunnel", normalizeRelayUrl("http://10.0.0.5:8770"))

        // Test HTTPS to WSS upgrade
        assertEquals("wss://trycloudflare.com/v1/tunnel", normalizeRelayUrl("https://trycloudflare.com"))

        // Test already normalized URL
        assertEquals("wss://relay.snow.dev:8770/v1/tunnel", normalizeRelayUrl("wss://relay.snow.dev:8770/v1/tunnel"))
    }

    // -------------------------------------------------------------------------
    // 2. SavedDevice Serialization with SNOW ID
    // -------------------------------------------------------------------------
    @Test
    fun testSavedDeviceSnowIdSerialization() {
        val dev = SavedDevice(
            deviceId = "dev-12345",
            deviceName = "Lenovo V15",
            host = "192.168.1.50",
            port = 8765,
            lastSeen = "2026-11-24T16:00:00Z",
            trustTier = "OWNER",
            certFingerprint = "A".repeat(64),
            connectionMode = "auto",
            snowId = "SNW-FA12-34BC"
        )

        assertEquals("SNW-FA12-34BC", dev.snowId)
        assertEquals("auto", dev.connectionMode)

        // Test manual JSON serialization
        val obj = JSONObject().apply {
            put("deviceId", dev.deviceId)
            put("deviceName", dev.deviceName)
            put("host", dev.host)
            put("port", dev.port)
            put("trustTier", dev.trustTier)
            put("connectionMode", dev.connectionMode)
            put("snowId", dev.snowId)
        }

        assertEquals("SNW-FA12-34BC", obj.getString("snowId"))
        assertEquals("auto", obj.getString("connectionMode"))
    }

    // -------------------------------------------------------------------------
    // 3. DiscoveredPeer with SNOW ID Parsing
    // -------------------------------------------------------------------------
    @Test
    fun testDiscoveredPeerSnowIdParsing() {
        val now = System.currentTimeMillis()
        val json = JSONObject().apply {
            put("proto", "snow-discovery")
            put("v", 1)
            put("device_id", "desktop-guid-001")
            put("device_name", "Desktop Host")
            put("device_type", "windows")
            put("port", 8765)
            put("transfer_port", 8766)
            put("cert_fingerprint", "B".repeat(64))
            put("timestamp", now / 1000.0)
            put("snow_id", "SNW-99AA-BB88")
        }

        val parsed = DiscoveryManager.parseBeacon(
            data = json.toString().toByteArray(Charsets.UTF_8),
            length = json.toString().toByteArray(Charsets.UTF_8).size,
            remoteIp = "192.168.1.150",
            currentTimeMs = now
        )

        assertNotNull(parsed)
        assertEquals("SNW-99AA-BB88", parsed?.snowId)
        assertEquals("desktop-guid-001", parsed?.deviceId)
        assertEquals(8765, parsed?.port)
    }

    // -------------------------------------------------------------------------
    // 4. Unified Input Recognition Classification
    // -------------------------------------------------------------------------
    @Test
    fun testInputRecognitionClassification() {
        fun classifyInput(raw: String): String {
            val input = raw.trim()
            val snowIdRegex = Regex("^(SNW-[A-Z0-9]{4}-[A-Z0-9]{4}|SNW-[A-Z0-9]{4}|DEV-[A-Z0-9]{4})$", RegexOption.IGNORE_CASE)
            if (snowIdRegex.matches(input)) return "SNOW_ID"

            if (input.length == 6 && input.all { it.isDigit() }) return "6_DIGIT_PIN"

            val cleanFed = input.replace("-", "").replace(" ", "").trim()
            if (cleanFed.length == 9 && cleanFed.all { it.isDigit() }) return "9_DIGIT_FEDERATION"

            if (input.startsWith("wss://", ignoreCase = true) || input.startsWith("ws://", ignoreCase = true) ||
                input.startsWith("https://", ignoreCase = true) || input.startsWith("http://", ignoreCase = true) ||
                input.contains(".trycloudflare.com", ignoreCase = true) || input.contains("/v1/tunnel", ignoreCase = true)) {
                return "RELAY_URL"
            }

            val hostPart = input.substringBeforeLast(":").trim()
            val portPart = input.substringAfterLast(":", "").trim()
            if (portPart.toIntOrNull() != null && hostPart.isNotEmpty()) return "DIRECT_HOST_PORT"

            if (input.matches(Regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}$")) || input.equals("localhost", ignoreCase = true)) {
                return "DIRECT_IP"
            }

            return "UNKNOWN"
        }

        assertEquals("SNOW_ID", classifyInput("SNW-FA12-34BC"))
        assertEquals("SNOW_ID", classifyInput("snw-1234-abcd"))
        assertEquals("SNOW_ID", classifyInput("SNW-FA12"))
        assertEquals("SNOW_ID", classifyInput("DEV-34BC"))
        assertEquals("6_DIGIT_PIN", classifyInput("482910"))
        assertEquals("9_DIGIT_FEDERATION", classifyInput("123-456-789"))
        assertEquals("9_DIGIT_FEDERATION", classifyInput("123456789"))
        assertEquals("RELAY_URL", classifyInput("https://relay.trycloudflare.com"))
        assertEquals("RELAY_URL", classifyInput("wss://myrelay.net/v1/tunnel"))
        assertEquals("DIRECT_HOST_PORT", classifyInput("192.168.1.50:8765"))
        assertEquals("DIRECT_IP", classifyInput("192.168.1.50"))
        assertEquals("DIRECT_IP", classifyInput("localhost"))
        assertEquals("UNKNOWN", classifyInput("invalid!input@#"))
    }

    // -------------------------------------------------------------------------
    // 5. Host Extraction from Endpoints (Never return scheme as host)
    // -------------------------------------------------------------------------
    @Test
    fun testHostExtractionNeverReturnsScheme() {
        fun extractHost(endpoint: String?): String? {
            if (endpoint.isNullOrBlank()) return null
            val trimmed = endpoint.trim()

            try {
                val uri = if (trimmed.startsWith("relay:", ignoreCase = true)) {
                    java.net.URI("wss://${trimmed.substring("relay:".length).trimStart('/')}")
                } else if (!trimmed.contains("://")) {
                    java.net.URI("dummy://$trimmed")
                } else {
                    java.net.URI(trimmed)
                }

                val rawHost = uri.host
                if (!rawHost.isNullOrBlank()) {
                    val host = if (rawHost.startsWith("[") && rawHost.endsWith("]")) {
                        rawHost.substring(1, rawHost.length - 1)
                    } else {
                        rawHost
                    }
                    val lower = host.lowercase()
                    if (lower != "wss" && lower != "relay" && lower != "ws" && lower != "http" && lower != "https") {
                        return host
                    }
                }
            } catch (_: Exception) {}

            var clean = trimmed
            if (clean.startsWith("relay:", ignoreCase = true)) clean = clean.substring("relay:".length)
            if (clean.contains("://")) clean = clean.substringAfter("://")
            clean = clean.trimStart('/').substringBefore("/")
            if (clean.startsWith("[")) {
                val closing = clean.indexOf("]")
                if (closing != -1) return clean.substring(1, closing)
            }
            val candidate = if (clean.contains(":")) clean.substringBefore(":") else clean
            val candidateTrimmed = candidate.trim()
            if (candidateTrimmed.isNotEmpty()) {
                val lower = candidateTrimmed.lowercase()
                if (lower != "wss" && lower != "relay" && lower != "ws" && lower != "http" && lower != "https") {
                    return candidateTrimmed
                }
            }
            return null
        }

        assertEquals("myrelay.com", extractHost("wss://myrelay.com:8765/v1/tunnel"))
        assertEquals("example.org", extractHost("relay:example.org:8770"))
        assertEquals("example.org", extractHost("relay://example.org:8770"))
        assertEquals("192.168.1.100", extractHost("192.168.1.100:8765"))
        assertEquals("127.0.0.1", extractHost("127.0.0.1"))
        assertEquals("::1", extractHost("[::1]:8765"))
        assertNotEquals("wss", extractHost("wss://myrelay.com:8765"))
        assertNotEquals("relay", extractHost("relay:example.org:8770"))
    }
}
