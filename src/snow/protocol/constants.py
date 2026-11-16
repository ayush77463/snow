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

    # Phase 2.1 Pairing Error Codes
    INVALID_PIN = "INVALID_PIN"
    PIN_EXPIRED = "PIN_EXPIRED"
    PAIRING_LOCKED = "PAIRING_LOCKED"
    ALREADY_PAIRED = "ALREADY_PAIRED"

    # Phase 2.2 Security / Session Error Codes
    UNAUTHORIZED = "UNAUTHORIZED"
    INVALID_TOKEN = "INVALID_TOKEN"
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"

    # Phase 3 File Transfer Error Codes
    TRANSFER_NOT_FOUND = "TRANSFER_NOT_FOUND"
    INTEGRITY_MISMATCH = "INTEGRITY_MISMATCH"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    INVALID_RANGE = "INVALID_RANGE"
