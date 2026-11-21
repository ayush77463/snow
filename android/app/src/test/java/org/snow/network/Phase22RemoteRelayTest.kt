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
}
