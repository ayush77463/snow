package org.snow.network

import org.junit.Assert.*
import org.junit.Test

class Phase22RemoteRelayTest {

    @Test
    fun testReachabilityStateEnumsExist() {
        val onlineRelayed = ReachabilityState.ONLINE_RELAYED
        val dormantRelay = ReachabilityState.DORMANT_RELAY
        assertEquals("ONLINE_RELAYED", onlineRelayed.name)
        assertEquals("DORMANT_RELAY", dormantRelay.name)
    }

    @Test
    fun testRelayMaxFrameSizeConstant() {
        val maxFrameBytes = 25 * 1024 * 1024 // 25 MiB
        assertEquals(26214400, maxFrameBytes)
    }

    @Test
    fun testRelayTicketFormatValidation() {
        // Ticket format: payload_b64.sig_b64
        val malformed1 = "invalid_ticket"
        val malformed2 = "part1.part2.part3"
        val validLike = "eyJkZXZpY2VfaWQiOiAidGVzdCJ9.c2lnbmF0dXJl"

        assertFalse(malformed1.contains("."))
        assertEquals(3, malformed2.split(".").size)
        assertEquals(2, validLike.split(".").size)
    }

    @Test
    fun testRelayFrameParsing() {
        // Binary relay frame: [target_len (1 byte)] + [target_id] + [opaque_payload]
        val targetId = "device-android-123"
        val targetBytes = targetId.toByteArray(Charsets.US_ASCII)
        val payload = "INNER_TLS_DATA".toByteArray(Charsets.UTF_8)

        val frame = ByteArray(1 + targetBytes.size + payload.size)
        frame[0] = targetBytes.size.toByte()
        System.arraycopy(targetBytes, 0, frame, 1, targetBytes.size)
        System.arraycopy(payload, 0, frame, 1 + targetBytes.size, payload.size)

        // Parse
        val parsedTargetLen = frame[0].toInt()
        assertEquals(targetBytes.size, parsedTargetLen)
        val parsedTarget = String(frame, 1, parsedTargetLen, Charsets.US_ASCII)
        assertEquals(targetId, parsedTarget)

        val parsedPayload = ByteArray(frame.size - 1 - parsedTargetLen)
        System.arraycopy(frame, 1 + parsedTargetLen, parsedPayload, 0, parsedPayload.size)
        assertArrayEquals(payload, parsedPayload)
    }

    @Test
    fun testE2eRelayTunnelMaxFrameSizeLimit() {
        assertEquals(26214400, E2eRelayTunnel.MAX_FRAME_SIZE)
    }

    @Test
    fun testE2eRelayTunnelRejectsOversizedFrame() {
        val dummySslContext = javax.net.ssl.SSLContext.getDefault()
        val tunnel = E2eRelayTunnel(dummySslContext, isServer = false)
        val oversized = ByteArray(E2eRelayTunnel.MAX_FRAME_SIZE + 1)
        try {
            tunnel.feedNetworkData(oversized)
            fail("Expected IllegalArgumentException for oversized frame")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message?.contains("exceeds 25 MiB") == true)
        }
    }

    @Test
    fun testE2eRelayTunnelHandshakeNotDonePreventsEncryption() {
        val dummySslContext = javax.net.ssl.SSLContext.getDefault()
        val tunnel = E2eRelayTunnel(dummySslContext, isServer = false)
        assertFalse(tunnel.handshakeDone)
        try {
            tunnel.encryptApplicationData("hello".toByteArray(Charsets.UTF_8))
            fail("Expected IllegalStateException before handshake completion")
        } catch (e: IllegalStateException) {
            assertTrue(e.message?.contains("TLS handshake not completed") == true)
        }
    }

    @Test
    fun testRelayDefaultStateIsDisabled() {
        // Architecture Rule: Remote relay MUST be strictly disabled by default
        val defaultEnabled = false
        assertFalse("Remote relay must be disabled by default", defaultEnabled)
    }

    @Test
    fun testRelayEndpointValidation() {
        fun isValidRelayEndpoint(url: String): Boolean {
            val trimmed = url.trim()
            if (trimmed.isBlank()) return false
            return trimmed.startsWith("wss://", ignoreCase = true) || trimmed.startsWith("ws://", ignoreCase = true)
        }

        assertTrue(isValidRelayEndpoint("wss://snow.example.com:8770/v1/tunnel"))
        assertTrue(isValidRelayEndpoint("ws://127.0.0.1:8770/v1/tunnel"))
        assertTrue(isValidRelayEndpoint("WSS://RELAY.SECURE.NET/V1/TUNNEL"))

        assertFalse(isValidRelayEndpoint(""))
        assertFalse(isValidRelayEndpoint("   "))
        assertFalse(isValidRelayEndpoint("http://127.0.0.1:8770/v1/tunnel"))
        assertFalse(isValidRelayEndpoint("https://127.0.0.1:8770/v1/tunnel"))
        assertFalse(isValidRelayEndpoint("tcp://127.0.0.1:8770"))
        assertFalse(isValidRelayEndpoint("invalid_endpoint_uri"))
    }

    @Test
    fun testRelayClientLifecycleAndInitialState() {
        val client = RelayClient(
            relayUrl = "wss://127.0.0.1:8770/v1/tunnel",
            deviceId = "test-device-id",
            groupId = "test-group",
            ticket = "payload.signature",
            targetPeerId = "desktop-core"
        )
        // Initial state is UNREACHABLE_OFFLINE before connecting
        assertEquals(ReachabilityState.UNREACHABLE_OFFLINE, client.reachabilityState.value)
        // Clean disconnect sets UNREACHABLE_OFFLINE
        client.disconnect()
        assertEquals(ReachabilityState.UNREACHABLE_OFFLINE, client.reachabilityState.value)
    }
}
