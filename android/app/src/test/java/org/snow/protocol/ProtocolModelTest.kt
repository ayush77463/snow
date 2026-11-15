package org.snow.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class ProtocolModelTest {

    @Test
    fun testCreateRequest() {
        val request = SnowMessage.createRequest("ping", mapOf("key" to "value"))
        assertEquals(Constants.PROTOCOL_VERSION, request.version)
        assertEquals(MessageType.REQUEST, request.type)
        assertNotNull(UUID.fromString(request.id))
        assertTrue(request.timestamp.endsWith("Z"))
        assertNull(request.correlationId)
        assertNull(request.error)
        assertNotNull(request.payload)
        assertEquals("ping", request.payload?.get("action"))
    }

    @Test
    fun testCreateResponse() {
        val corrId = UUID.randomUUID().toString()
        val response = SnowMessage.createResponse(corrId, mapOf("status" to "ok"))
        assertEquals(Constants.PROTOCOL_VERSION, response.version)
        assertEquals(MessageType.RESPONSE, response.type)
        assertEquals(corrId, response.correlationId)
        assertNotNull(response.payload)
        assertEquals("ok", response.payload?.get("status"))
        assertNull(requestOrNull = response.error)
    }

    @Test
    fun testCreateError() {
        val corrId = UUID.randomUUID().toString()
        val errorMsg = SnowMessage.createError(
            code = ErrorCode.INVALID_PAYLOAD,
            message = "Missing parameter",
            correlationId = corrId
        )
        assertEquals(Constants.PROTOCOL_VERSION, errorMsg.version)
        assertEquals(MessageType.ERROR, errorMsg.type)
        assertEquals(corrId, errorMsg.correlationId)
        assertNotNull(errorMsg.error)
        assertEquals(ErrorCode.INVALID_PAYLOAD, errorMsg.error?.code)
        assertEquals("Missing parameter", errorMsg.error?.message)
        assertNull(errorMsg.payload)
    }

    @Test
    fun testCreateHeartbeat() {
        val heartbeat = SnowMessage.createHeartbeat()
        assertEquals(Constants.PROTOCOL_VERSION, heartbeat.version)
        assertEquals(MessageType.HEARTBEAT, heartbeat.type)
        assertNull(heartbeat.correlationId)
        assertNull(heartbeat.payload)
        assertNull(heartbeat.error)
    }

    @Test
    fun testCreateHeartbeatAck() {
        val corrId = UUID.randomUUID().toString()
        val ack = SnowMessage.createHeartbeatAck(corrId)
        assertEquals(Constants.PROTOCOL_VERSION, ack.version)
        assertEquals(MessageType.HEARTBEAT_ACK, ack.type)
        assertEquals(corrId, ack.correlationId)
        assertNull(ack.payload)
        assertNull(ack.error)
    }

    @Test
    fun testStandardizedPingResponse() {
        val requestId = UUID.randomUUID().toString()
        val pingResponse = SnowMessage.createResponse(
            correlationId = requestId,
            payload = mapOf("status" to "success", "action" to "pong")
        )
        assertEquals(Constants.PROTOCOL_VERSION, pingResponse.version)
        assertEquals(MessageType.RESPONSE, pingResponse.type)
        assertEquals(requestId, pingResponse.correlationId)
        assertNotNull(UUID.fromString(pingResponse.id))
        assertTrue(pingResponse.timestamp.endsWith("Z"))
        assertEquals("success", pingResponse.payload?.get("status"))
        assertEquals("pong", pingResponse.payload?.get("action"))
        assertNull(pingResponse.error)
    }

    private fun assertNull(requestOrNull: Any?) {
        org.junit.Assert.assertNull(requestOrNull)
    }
}
