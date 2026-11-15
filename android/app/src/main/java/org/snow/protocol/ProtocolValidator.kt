package org.snow.protocol

import java.nio.charset.StandardCharsets
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException
import java.util.UUID
import java.util.regex.Pattern
import org.json.JSONException
import org.json.JSONObject

/**
 * Validates wire messages against the SNOW Device Protocol v1 specification.
 */
object ProtocolValidator {

    private val UUID_V4_PATTERN = Pattern.compile(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )

    /**
     * Validate that a value is a valid RFC 4122 UUIDv4 string.
     */
    @Throws(ProtocolValidationError::class)
    fun validateUuidV4(
        value: Any?,
        fieldName: String,
        errorCode: String,
        correlationId: String? = null
    ): String {
        if (value !is String || value.trim().isEmpty()) {
            throw ProtocolValidationError(
                code = errorCode,
                message = "'$fieldName' must be a non-empty string, got $value.",
                correlationId = correlationId
            )
        }

        if (!UUID_V4_PATTERN.matcher(value).matches()) {
            throw ProtocolValidationError(
                code = errorCode,
                message = "'$fieldName' must be a valid RFC 4122 UUID version 4 string, got '$value'.",
                correlationId = correlationId
            )
        }

        try {
            val parsed = UUID.fromString(value)
            if (parsed.version() != 4) {
                throw ProtocolValidationError(
                    code = errorCode,
                    message = "'$fieldName' must be UUID version 4, got version ${parsed.version()}.",
                    correlationId = correlationId
                )
            }
            return parsed.toString()
        } catch (e: IllegalArgumentException) {
            throw ProtocolValidationError(
                code = errorCode,
                message = "'$fieldName' must be a valid UUID string, got '$value'.",
                correlationId = correlationId
            )
        }
    }

    /**
     * Parse and strictly validate an incoming raw message string against SNOW Device Protocol v1.
     */
    @Throws(ProtocolValidationError::class)
    fun validateRawMessage(
        rawInput: String,
        maxSize: Int = Constants.DEFAULT_MAX_MESSAGE_SIZE
    ): SnowMessage {
        // 1. Size verification
        val byteCount = rawInput.toByteArray(StandardCharsets.UTF_8).size
        if (byteCount > maxSize) {
            throw ProtocolValidationError(
                code = ErrorCode.OVERSIZED_MESSAGE,
                message = "Message size ($byteCount bytes) exceeds maximum allowed limit ($maxSize bytes)."
            )
        }

        // 2. JSON decoding
        val parsedValue = try {
            org.json.JSONTokener(rawInput).nextValue()
        } catch (e: JSONException) {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_JSON,
                message = "Malformed JSON payload: ${e.message}"
            )
        }

        if (parsedValue !is JSONObject) {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_PAYLOAD,
                message = "Root message must be a JSON object, got ${parsedValue.javaClass.simpleName}."
            )
        }
        val root = parsedValue

        // 3. Early correlation_id validation if present
        var correlationId: String? = null
        if (root.has("correlation_id") && !root.isNull("correlation_id")) {
            val rawCorr = root.get("correlation_id")
            correlationId = validateUuidV4(
                value = rawCorr,
                fieldName = "correlation_id",
                errorCode = ErrorCode.INVALID_CORRELATION_ID,
                correlationId = null
            )
        }

        // 4. Version verification
        if (!root.has("version") || root.isNull("version")) {
            throw ProtocolValidationError(
                code = ErrorCode.UNSUPPORTED_VERSION,
                message = "Missing required field: 'version'.",
                correlationId = correlationId
            )
        }
        val rawVersion = root.get("version")
        if (rawVersion !is Int) {
            throw ProtocolValidationError(
                code = ErrorCode.UNSUPPORTED_VERSION,
                message = "'version' must be an integer, got ${rawVersion.javaClass.simpleName}.",
                correlationId = correlationId
            )
        }
        if (rawVersion != Constants.PROTOCOL_VERSION) {
            throw ProtocolValidationError(
                code = ErrorCode.UNSUPPORTED_VERSION,
                message = "Unsupported protocol version $rawVersion. Supported version is ${Constants.PROTOCOL_VERSION}.",
                correlationId = correlationId
            )
        }

        // 5. Type verification
        if (!root.has("type") || root.isNull("type")) {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_MESSAGE_TYPE,
                message = "Missing required field: 'type'.",
                correlationId = correlationId
            )
        }
        val rawType = root.get("type")
        if (rawType !is String || !MessageType.VALID_TYPES.contains(rawType)) {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_MESSAGE_TYPE,
                message = "Invalid message type '$rawType'. Must be one of ${MessageType.VALID_TYPES.sorted()}.",
                correlationId = correlationId
            )
        }

        // 6. ID verification (strictly UUIDv4)
        if (!root.has("id") || root.isNull("id")) {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_MESSAGE_ID,
                message = "Missing required field: 'id'.",
                correlationId = correlationId
            )
        }
        val rawId = root.get("id")
        val validId = validateUuidV4(
            value = rawId,
            fieldName = "id",
            errorCode = ErrorCode.INVALID_MESSAGE_ID,
            correlationId = correlationId
        )

        // 7. Timestamp verification (strictly UTC ISO-8601 with zero offset)
        if (!root.has("timestamp") || root.isNull("timestamp")) {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_TIMESTAMP,
                message = "Missing required field: 'timestamp'.",
                correlationId = correlationId
            )
        }
        val rawTs = root.get("timestamp")
        if (rawTs !is String || rawTs.trim().isEmpty()) {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_TIMESTAMP,
                message = "'timestamp' must be a non-empty ISO-8601 string, got '$rawTs'.",
                correlationId = correlationId
            )
        }
        try {
            val parsedOffsetDateTime = OffsetDateTime.parse(rawTs)
            if (parsedOffsetDateTime.offset.totalSeconds != 0) {
                throw ProtocolValidationError(
                    code = ErrorCode.INVALID_TIMESTAMP,
                    message = "Timestamp must have a zero UTC offset, got offset ${parsedOffsetDateTime.offset}.",
                    correlationId = correlationId
                )
            }
        } catch (e: DateTimeParseException) {
            throw ProtocolValidationError(
                code = ErrorCode.INVALID_TIMESTAMP,
                message = "Invalid ISO-8601 timestamp format '$rawTs': ${e.message}",
                correlationId = correlationId
            )
        }

        val hasPayload = root.has("payload") && !root.isNull("payload")
        val rawPayload = if (hasPayload) root.get("payload") else null

        val hasError = root.has("error") && !root.isNull("error")
        val rawError = if (hasError) root.get("error") else null

        // 8. Type-specific verification rules
        when (rawType) {
            MessageType.REQUEST -> {
                if (rawPayload !is JSONObject) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_PAYLOAD,
                        message = "Request message must contain a 'payload' JSON object.",
                        correlationId = validId
                    )
                }
                if (!rawPayload.has("action") || rawPayload.isNull("action")) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_PAYLOAD,
                        message = "Request payload must contain a non-empty string 'action'.",
                        correlationId = validId
                    )
                }
                val rawAction = rawPayload.get("action")
                if (rawAction !is String || rawAction.trim().isEmpty()) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_PAYLOAD,
                        message = "Request payload must contain a non-empty string 'action'.",
                        correlationId = validId
                    )
                }
                if (rawPayload.has("data") && !rawPayload.isNull("data")) {
                    val rawData = rawPayload.get("data")
                    if (rawData !is JSONObject) {
                        throw ProtocolValidationError(
                            code = ErrorCode.INVALID_PAYLOAD,
                            message = "Request payload 'data' must be a JSON object, got ${rawData.javaClass.simpleName}.",
                            correlationId = validId
                        )
                    }
                }
            }
            MessageType.RESPONSE -> {
                if (correlationId == null) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_CORRELATION_ID,
                        message = "Response message must specify a non-empty 'correlation_id'."
                    )
                }
                if (rawPayload !is JSONObject) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_PAYLOAD,
                        message = "Response message must contain a 'payload' JSON object.",
                        correlationId = correlationId
                    )
                }
            }
            MessageType.ERROR -> {
                if (rawError !is JSONObject) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_PAYLOAD,
                        message = "Error message must contain an 'error' JSON object.",
                        correlationId = correlationId
                    )
                }
                if (!rawError.has("code") || rawError.isNull("code")) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_PAYLOAD,
                        message = "Error object must contain a non-empty string 'code'.",
                        correlationId = correlationId
                    )
                }
                val errCode = rawError.get("code")
                if (errCode !is String || errCode.trim().isEmpty()) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_PAYLOAD,
                        message = "Error object must contain a non-empty string 'code'.",
                        correlationId = correlationId
                    )
                }
                if (!rawError.has("message") || rawError.isNull("message")) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_PAYLOAD,
                        message = "Error object must contain a string 'message'.",
                        correlationId = correlationId
                    )
                }
                val errMsg = rawError.get("message")
                if (errMsg !is String) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_PAYLOAD,
                        message = "Error object must contain a string 'message'.",
                        correlationId = correlationId
                    )
                }
            }
            MessageType.HEARTBEAT_ACK -> {
                if (correlationId == null) {
                    throw ProtocolValidationError(
                        code = ErrorCode.INVALID_CORRELATION_ID,
                        message = "Heartbeat acknowledgement must specify a non-empty 'correlation_id'."
                    )
                }
            }
        }

        val parsedPayload = if (rawPayload is JSONObject) JsonSerialization.jsonToMap(rawPayload) else null
        val parsedError = if (rawError is JSONObject) {
            SnowError(
                code = rawError.getString("code"),
                message = rawError.getString("message")
            )
        } else null

        return SnowMessage(
            version = rawVersion,
            type = rawType,
            id = validId,
            timestamp = rawTs,
            correlationId = correlationId,
            payload = parsedPayload,
            error = parsedError
        )
    }
}
