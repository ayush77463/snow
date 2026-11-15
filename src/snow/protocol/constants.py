"""Constants and error codes for SNOW Device Protocol v1."""

from enum import StrEnum
from typing import FrozenSet

# Current frozen protocol version
PROTOCOL_VERSION: int = 1

# Maximum allowed message size in bytes (64 KB)
DEFAULT_MAX_MESSAGE_SIZE: int = 65536


class MessageType(StrEnum):
    """Supported message types in SNOW Device Protocol v1."""

    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"


VALID_MESSAGE_TYPES: FrozenSet[str] = frozenset(
    {
        MessageType.REQUEST,
        MessageType.RESPONSE,
        MessageType.ERROR,
        MessageType.HEARTBEAT,
        MessageType.HEARTBEAT_ACK,
    }
)


class ErrorCode(StrEnum):
    """Standardized error codes returned in protocol error responses."""

    INVALID_JSON = "INVALID_JSON"
    OVERSIZED_MESSAGE = "OVERSIZED_MESSAGE"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    INVALID_MESSAGE_TYPE = "INVALID_MESSAGE_TYPE"
    INVALID_MESSAGE_ID = "INVALID_MESSAGE_ID"
    INVALID_CORRELATION_ID = "INVALID_CORRELATION_ID"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    UNSUPPORTED_ACTION = "UNSUPPORTED_ACTION"
    HEARTBEAT_TIMEOUT = "HEARTBEAT_TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"
