package org.snow.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.fail
import org.junit.Test
import java.util.UUID

class ProtocolValidatorTest {

    @Test
    fun testValidRequestPasses() {
        val request = SnowMessage.createRequest("ping")
        val json = JsonSerialization.toJson(request)
        val validated = ProtocolValidator.validateRawMessage(json)
        assertEquals("ping", validated.payload?.get("action"))
    }

    @Test
    fun testValidHeartbeatAckPasses() {
        val corrId = UUID.randomUUID().toString()
        val ack = SnowMessage.createHeartbeatAck(corrId)
        val json = JsonSerialization.toJson(ack)
        val validated = ProtocolValidator.validateRawMessage(json)
        assertEquals(corrId, validated.correlationId)
    }

    @Test
    fun testRejectMalformedJson() {
        try {
            ProtocolValidator.validateRawMessage("{not-json}")
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.INVALID_JSON, e.code)
        }
    }

    @Test
    fun testRejectOversizedMessage() {
        val largeString = "{\"data\":\"" + "A".repeat(70000) + "\"}"
        try {
            ProtocolValidator.validateRawMessage(largeString)
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.OVERSIZED_MESSAGE, e.code)
        }
    }

    @Test
    fun testRejectUnsupportedVersion() {
        val raw = """{"version": 99, "type": "heartbeat", "id": "${UUID.randomUUID()}", "timestamp": "2026-11-15T12:00:00Z"}"""
        try {
            ProtocolValidator.validateRawMessage(raw)
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.UNSUPPORTED_VERSION, e.code)
        }
    }

    @Test
    fun testRejectInvalidMessageType() {
        val raw = """{"version": 1, "type": "invalid_type", "id": "${UUID.randomUUID()}", "timestamp": "2026-11-15T12:00:00Z"}"""
        try {
            ProtocolValidator.validateRawMessage(raw)
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.INVALID_MESSAGE_TYPE, e.code)
        }
    }

    @Test
    fun testRejectNonUuidV4Id() {
        val raw = """{"version": 1, "type": "heartbeat", "id": "not-a-uuid", "timestamp": "2026-11-15T12:00:00Z"}"""
        try {
            ProtocolValidator.validateRawMessage(raw)
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.INVALID_MESSAGE_ID, e.code)
        }
    }

    @Test
    fun testRejectNonZeroOffsetTimestamp() {
        val raw = """{"version": 1, "type": "heartbeat", "id": "${UUID.randomUUID()}", "timestamp": "2026-11-15T12:00:00+05:30"}"""
        try {
            ProtocolValidator.validateRawMessage(raw)
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.INVALID_TIMESTAMP, e.code)
        }
    }

    @Test
    fun testRejectNaiveTimestampWithoutTimezone() {
        val raw = """{"version": 1, "type": "heartbeat", "id": "${UUID.randomUUID()}", "timestamp": "2026-11-15T12:00:00"}"""
        try {
            ProtocolValidator.validateRawMessage(raw)
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.INVALID_TIMESTAMP, e.code)
        }
    }

    @Test
    fun testRejectRequestWithoutAction() {
        val raw = """{"version": 1, "type": "request", "id": "${UUID.randomUUID()}", "timestamp": "2026-11-15T12:00:00Z", "payload": {}}"""
        try {
            ProtocolValidator.validateRawMessage(raw)
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.INVALID_PAYLOAD, e.code)
        }
    }

    @Test
    fun testRejectResponseWithoutCorrelationId() {
        val raw = """{"version": 1, "type": "response", "id": "${UUID.randomUUID()}", "timestamp": "2026-11-15T12:00:00Z", "payload": {"status": "ok"}}"""
        try {
            ProtocolValidator.validateRawMessage(raw)
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.INVALID_CORRELATION_ID, e.code)
        }
    }

    @Test
    fun testRejectHeartbeatAckWithoutCorrelationId() {
        val raw = """{"version": 1, "type": "heartbeat_ack", "id": "${UUID.randomUUID()}", "timestamp": "2026-11-15T12:00:00Z"}"""
        try {
            ProtocolValidator.validateRawMessage(raw)
            fail("Expected ProtocolValidationError")
        } catch (e: ProtocolValidationError) {
            assertEquals(ErrorCode.INVALID_CORRELATION_ID, e.code)
        }
    }
}
