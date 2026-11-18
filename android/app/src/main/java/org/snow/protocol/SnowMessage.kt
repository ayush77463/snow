package org.snow.protocol

import java.time.Instant
import java.util.UUID

/**
 * Immutable envelope model for SNOW Device Protocol v1 messages.
 */
data class SnowMessage(
    val version: Int,
    val type: String,
    val id: String,
    val timestamp: String,
    val correlationId: String? = null,
    val payload: Map<String, Any?>? = null,
    val error: SnowError? = null
) {
    val isSuccess: Boolean
        get() = type == MessageType.RESPONSE && error == null

    companion object {
        fun currentIsoTimestamp(): String {
            return Instant.now().toString()
        }

        fun createRequest(
            action: String,
            data: Map<String, Any?>? = null,
            version: Int = Constants.PROTOCOL_VERSION
        ): SnowMessage {
            val payloadMap = mutableMapOf<String, Any?>("action" to action)
            if (data != null) {
                payloadMap["data"] = data
            }
            return SnowMessage(
                version = version,
                type = MessageType.REQUEST,
                id = UUID.randomUUID().toString(),
                timestamp = currentIsoTimestamp(),
                payload = payloadMap
            )
        }

        fun createResponse(
            correlationId: String,
            payload: Map<String, Any?>,
            version: Int = Constants.PROTOCOL_VERSION
        ): SnowMessage {
            return SnowMessage(
                version = version,
                type = MessageType.RESPONSE,
                id = UUID.randomUUID().toString(),
                timestamp = currentIsoTimestamp(),
                correlationId = correlationId,
                payload = payload
            )
        }

        fun createError(
            code: String,
            message: String,
            correlationId: String? = null,
            version: Int = Constants.PROTOCOL_VERSION
        ): SnowMessage {
            return SnowMessage(
                version = version,
                type = MessageType.ERROR,
                id = UUID.randomUUID().toString(),
                timestamp = currentIsoTimestamp(),
                correlationId = correlationId,
                error = SnowError(code = code, message = message)
            )
        }

        fun createHeartbeat(version: Int = Constants.PROTOCOL_VERSION): SnowMessage {
            return SnowMessage(
                version = version,
                type = MessageType.HEARTBEAT,
                id = UUID.randomUUID().toString(),
                timestamp = currentIsoTimestamp()
            )
        }

        fun createHeartbeatAck(
            correlationId: String,
            version: Int = Constants.PROTOCOL_VERSION
        ): SnowMessage {
            return SnowMessage(
                version = version,
                type = MessageType.HEARTBEAT_ACK,
                id = UUID.randomUUID().toString(),
                timestamp = currentIsoTimestamp(),
                correlationId = correlationId
            )
        }
    }
}
