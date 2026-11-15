package org.snow.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class JsonSerializationTest {

    @Test
    fun testCleanSerializationOmissionOfNulls() {
        val heartbeat = SnowMessage.createHeartbeat()
        val json = JsonSerialization.toJson(heartbeat)

        // Strict clean serialization invariant: null fields must NOT appear in JSON string
        assertFalse(json.contains("\"correlation_id\""))
        assertFalse(json.contains("\"payload\""))
        assertFalse(json.contains("\"error\""))
        assertTrue(json.contains("\"version\":1"))
        assertTrue(json.contains("\"type\":\"heartbeat\""))
        assertTrue(json.contains("\"id\":\"${heartbeat.id}\""))
    }

    @Test
    fun testRequestSerializationOmissionOfNulls() {
        val request = SnowMessage.createRequest("ping")
        val json = JsonSerialization.toJson(request)

        assertFalse(json.contains("\"correlation_id\""))
        assertFalse(json.contains("\"error\""))
        assertTrue(json.contains("\"payload\":{"))
        assertTrue(json.contains("\"action\":\"ping\""))
    }

    @Test
    fun testResponseRoundTrip() {
        val corrId = UUID.randomUUID().toString()
        val original = SnowMessage.createResponse(corrId, mapOf("status" to "ok", "count" to 42))
        val json = JsonSerialization.toJson(original)

        assertFalse(json.contains("\"error\""))
        assertTrue(json.contains("\"correlation_id\":\"$corrId\""))

        val parsed = JsonSerialization.fromJson(json)
        assertEquals(original.version, parsed.version)
        assertEquals(original.type, parsed.type)
        assertEquals(original.id, parsed.id)
        assertEquals(original.correlationId, parsed.correlationId)
        assertEquals("ok", parsed.payload?.get("status"))
        assertEquals(42, parsed.payload?.get("count"))
        assertNull(parsed.error)
    }

    @Test
    fun testErrorRoundTrip() {
        val corrId = UUID.randomUUID().toString()
        val original = SnowMessage.createError(ErrorCode.INVALID_PAYLOAD, "Missing field", corrId)
        val json = JsonSerialization.toJson(original)

        assertFalse(json.contains("\"payload\""))
        val parsed = JsonSerialization.fromJson(json)
        assertEquals(original.id, parsed.id)
        assertEquals(original.correlationId, parsed.correlationId)
        assertEquals(ErrorCode.INVALID_PAYLOAD, parsed.error?.code)
        assertEquals("Missing field", parsed.error?.message)
        assertNull(parsed.payload)
    }
}
