package org.snow.protocol

object Constants {
    const val PROTOCOL_VERSION: Int = 1
    const val DEFAULT_MAX_MESSAGE_SIZE: Int = 65536
    const val DEFAULT_PORT: Int = 8765
    const val HEARTBEAT_INTERVAL_MS: Long = 15000L
    const val HEARTBEAT_TIMEOUT_MS: Long = 45000L
}

object MessageType {
    const val REQUEST = "request"
    const val RESPONSE = "response"
    const val ERROR = "error"
    const val HEARTBEAT = "heartbeat"
    const val HEARTBEAT_ACK = "heartbeat_ack"

    val VALID_TYPES: Set<String> = setOf(REQUEST, RESPONSE, ERROR, HEARTBEAT, HEARTBEAT_ACK)
}

object ErrorCode {
    const val INVALID_JSON = "INVALID_JSON"
    const val OVERSIZED_MESSAGE = "OVERSIZED_MESSAGE"
    const val UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    const val INVALID_MESSAGE_TYPE = "INVALID_MESSAGE_TYPE"
    const val INVALID_MESSAGE_ID = "INVALID_MESSAGE_ID"
    const val INVALID_CORRELATION_ID = "INVALID_CORRELATION_ID"
    const val INVALID_PAYLOAD = "INVALID_PAYLOAD"
    const val INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    const val UNSUPPORTED_ACTION = "UNSUPPORTED_ACTION"
    const val HEARTBEAT_TIMEOUT = "HEARTBEAT_TIMEOUT"
    const val INTERNAL_ERROR = "INTERNAL_ERROR"
}
