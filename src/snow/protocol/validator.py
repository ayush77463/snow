"""Message validation and deserialization for SNOW Device Protocol v1."""

from datetime import datetime, timedelta
import json
from typing import Any, Dict, Optional, Union
import uuid

from snow.protocol.constants import (
    DEFAULT_MAX_MESSAGE_SIZE,
    ErrorCode,
    MessageType,
    PROTOCOL_VERSION,
    VALID_MESSAGE_TYPES,
)
from snow.protocol.models import SnowMessage


class ProtocolValidationError(Exception):
    """Exception raised when an incoming message violates protocol specifications."""

    def __init__(
        self,
        code: str,
        message: str,
        correlation_id: Optional[str] = None,
    ) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.correlation_id = correlation_id


def _validate_uuidv4(
    val: Any,
    field_name: str,
    error_code: str,
    correlation_id: Optional[str] = None,
) -> str:
    """Validate that a field contains a valid UUIDv4 string.

    Args:
        val: Value to validate.
        field_name: Name of the field for error messages.
        error_code: ErrorCode to raise on validation failure.
        correlation_id: Optional correlation_id to associate with the error.

    Returns:
        Canonical string representation of the parsed UUIDv4.

    Raises:
        ProtocolValidationError: If val is not a valid UUIDv4 string.
    """
    if not isinstance(val, str) or not val.strip():
        raise ProtocolValidationError(
            code=error_code,
            message=f"'{field_name}' must be a non-empty string, got {val!r}.",
            correlation_id=correlation_id,
        )

    try:
        parsed_uuid = uuid.UUID(val)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ProtocolValidationError(
            code=error_code,
            message=f"'{field_name}' must be a valid UUID string, got {val!r}.",
            correlation_id=correlation_id,
        ) from exc

    if parsed_uuid.version != 4:
        raise ProtocolValidationError(
            code=error_code,
            message=f"'{field_name}' must be UUID version 4, got version {parsed_uuid.version}.",
            correlation_id=correlation_id,
        )

    return str(parsed_uuid)


def validate_raw_message(
    raw_input: Union[str, bytes],
    max_size: int = DEFAULT_MAX_MESSAGE_SIZE,
) -> SnowMessage:
    """Parse and validate an incoming raw message against SNOW Device Protocol v1.

    Args:
        raw_input: String or bytes received over the WebSocket channel.
        max_size: Maximum allowed message size in bytes (defaults to 64 KB).

    Returns:
        A validated, immutable `SnowMessage` instance.

    Raises:
        ProtocolValidationError: If any protocol rule or structural invariant is violated.
    """
    # 1. Size verification
    byte_count = len(raw_input) if isinstance(raw_input, bytes) else len(raw_input.encode("utf-8"))
    if byte_count > max_size:
        raise ProtocolValidationError(
            code=ErrorCode.OVERSIZED_MESSAGE,
            message=f"Message size ({byte_count} bytes) exceeds maximum allowed limit ({max_size} bytes).",
        )

    # 2. JSON decoding
    try:
        data: Any = json.loads(raw_input)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_JSON,
            message=f"Malformed JSON payload: {exc}",
        ) from exc

    # 3. Root structure verification
    if not isinstance(data, dict):
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_PAYLOAD,
            message=f"Root message must be a JSON object, got {type(data).__name__}.",
        )

    # Extract and strictly validate correlation_id early if present
    raw_corr_id = data.get("correlation_id")
    corr_id: Optional[str] = None
    if raw_corr_id is not None:
        corr_id = _validate_uuidv4(
            raw_corr_id,
            field_name="correlation_id",
            error_code=ErrorCode.INVALID_CORRELATION_ID,
            correlation_id=None,
        )

    # 4. Version verification
    version = data.get("version")
    if version is None:
        raise ProtocolValidationError(
            code=ErrorCode.UNSUPPORTED_VERSION,
            message="Missing required field: 'version'.",
            correlation_id=corr_id,
        )
    if not isinstance(version, int) or isinstance(version, bool):
        raise ProtocolValidationError(
            code=ErrorCode.UNSUPPORTED_VERSION,
            message=f"'version' must be an integer, got {type(version).__name__}.",
            correlation_id=corr_id,
        )
    if version != PROTOCOL_VERSION:
        raise ProtocolValidationError(
            code=ErrorCode.UNSUPPORTED_VERSION,
            message=f"Unsupported protocol version {version}. Server supports version {PROTOCOL_VERSION}.",
            correlation_id=corr_id,
        )

    # 5. Type verification
    msg_type = data.get("type")
    if msg_type is None:
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_MESSAGE_TYPE,
            message="Missing required field: 'type'.",
            correlation_id=corr_id,
        )
    if not isinstance(msg_type, str) or msg_type not in VALID_MESSAGE_TYPES:
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_MESSAGE_TYPE,
            message=f"Invalid message type '{msg_type}'. Must be one of {sorted(VALID_MESSAGE_TYPES)}.",
            correlation_id=corr_id,
        )

    # 6. ID verification (strictly UUIDv4)
    msg_id = data.get("id")
    if msg_id is None:
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_MESSAGE_ID,
            message="Missing required field: 'id'.",
            correlation_id=corr_id,
        )
    valid_id = _validate_uuidv4(
        msg_id,
        field_name="id",
        error_code=ErrorCode.INVALID_MESSAGE_ID,
        correlation_id=corr_id,
    )

    # 7. Timestamp verification (strictly UTC ISO-8601 with zero offset)
    timestamp = data.get("timestamp")
    if timestamp is None:
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_TIMESTAMP,
            message="Missing required field: 'timestamp'.",
            correlation_id=corr_id,
        )
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_TIMESTAMP,
            message=f"'timestamp' must be a non-empty ISO-8601 string, got {timestamp!r}.",
            correlation_id=corr_id,
        )
    try:
        parsed_dt = datetime.fromisoformat(timestamp)
    except (ValueError, TypeError) as exc:
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_TIMESTAMP,
            message=f"Invalid ISO-8601 timestamp format '{timestamp}': {exc}",
            correlation_id=corr_id,
        ) from exc

    if parsed_dt.tzinfo is None or parsed_dt.utcoffset() is None:
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_TIMESTAMP,
            message=f"Timestamp must include a timezone offset (e.g. 'Z' or '+00:00'), got naive timestamp '{timestamp}'.",
            correlation_id=corr_id,
        )

    if parsed_dt.utcoffset() != timedelta(0):
        raise ProtocolValidationError(
            code=ErrorCode.INVALID_TIMESTAMP,
            message=f"Timestamp must have a zero UTC offset, got offset {parsed_dt.utcoffset()}.",
            correlation_id=corr_id,
        )

    payload = data.get("payload")
    error_data = data.get("error")

    # 8. Type-specific validation rules
    if msg_type == MessageType.REQUEST:
        if payload is None or not isinstance(payload, dict):
            raise ProtocolValidationError(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Request message must contain a 'payload' JSON object.",
                correlation_id=valid_id,
            )
        action = payload.get("action")
        if action is None or not isinstance(action, str) or not action.strip():
            raise ProtocolValidationError(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Request payload must contain a non-empty string 'action'.",
                correlation_id=valid_id,
            )
        if "data" in payload and not isinstance(payload["data"], dict):
            raise ProtocolValidationError(
                code=ErrorCode.INVALID_PAYLOAD,
                message=f"Request payload 'data' must be a JSON object, got {type(payload['data']).__name__}.",
                correlation_id=valid_id,
            )

    elif msg_type == MessageType.RESPONSE:
        if corr_id is None:
            raise ProtocolValidationError(
                code=ErrorCode.INVALID_CORRELATION_ID,
                message="Response message must specify a non-empty 'correlation_id'.",
            )
        if payload is None or not isinstance(payload, dict):
            raise ProtocolValidationError(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Response message must contain a 'payload' JSON object.",
                correlation_id=corr_id,
            )

    elif msg_type == MessageType.ERROR:
        if error_data is None or not isinstance(error_data, dict):
            raise ProtocolValidationError(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Error message must contain an 'error' JSON object.",
                correlation_id=corr_id,
            )
        err_code = error_data.get("code")
        err_msg = error_data.get("message")
        if not isinstance(err_code, str) or not err_code.strip():
            raise ProtocolValidationError(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Error object must contain a non-empty string 'code'.",
                correlation_id=corr_id,
            )
        if not isinstance(err_msg, str):
            raise ProtocolValidationError(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Error object must contain a string 'message'.",
                correlation_id=corr_id,
            )

    elif msg_type == MessageType.HEARTBEAT_ACK:
        if corr_id is None:
            raise ProtocolValidationError(
                code=ErrorCode.INVALID_CORRELATION_ID,
                message="Heartbeat acknowledgement must specify a non-empty 'correlation_id'.",
            )

    return SnowMessage(
        version=version,
        type=msg_type,
        id=valid_id,
        timestamp=timestamp,
        correlation_id=corr_id,
        payload=payload if isinstance(payload, dict) else None,
        error=error_data if isinstance(error_data, dict) else None,
    )
