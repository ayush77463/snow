"""Message envelope models and factories for SNOW Device Protocol v1."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional
import uuid

from snow.protocol.constants import PROTOCOL_VERSION, MessageType


def current_iso_timestamp() -> str:
    """Generate a UTC ISO-8601 formatted timestamp string."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SnowMessage:
    """Immutable envelope model for SNOW Device Protocol v1 messages.

    Attributes:
        version: Integer protocol version (currently 1).
        type: Message classification (request, response, error, heartbeat, heartbeat_ack).
        id: Unique message identifier (UUID v4 string).
        timestamp: ISO-8601 UTC timestamp string.
        correlation_id: Unique identifier linking a response or ack to its request.
        payload: Structured payload dictionary for requests and responses.
        error: Structured error dictionary for error messages (code and message).
    """

    version: int
    type: str
    id: str
    timestamp: str
    correlation_id: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None

    @property
    def action(self) -> Optional[str]:
        """Extract request action string if present in payload."""
        if self.payload and isinstance(self.payload, dict):
            return self.payload.get("action")
        return None

    @property
    def data(self) -> Dict[str, Any]:
        """Extract data dictionary from payload if present."""
        if self.payload and isinstance(self.payload, dict):
            val = self.payload.get("data")
            if isinstance(val, dict):
                return val
            return self.payload
        return {}

    @classmethod
    def from_json(cls, raw: str) -> "SnowMessage":
        """Parse and validate JSON string into SnowMessage."""
        from snow.protocol.validator import validate_raw_message
        return validate_raw_message(raw)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the message into a dictionary, omitting None values for clean JSON."""
        data: Dict[str, Any] = {
            "version": self.version,
            "type": self.type,
            "id": self.id,
            "timestamp": self.timestamp,
        }
        if self.correlation_id is not None:
            data["correlation_id"] = self.correlation_id
        if self.payload is not None:
            data["payload"] = self.payload
        if self.error is not None:
            data["error"] = self.error
        return data

    def to_json(self) -> str:
        """Serialize the message into a JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def create_request(
        cls, action: str, data: Optional[Dict[str, Any]] = None, version: int = PROTOCOL_VERSION
    ) -> "SnowMessage":
        """Factory for generating a valid request message."""
        payload: Dict[str, Any] = {"action": action}
        if data is not None:
            payload["data"] = data
        return cls(
            version=version,
            type=MessageType.REQUEST,
            id=str(uuid.uuid4()),
            timestamp=current_iso_timestamp(),
            payload=payload,
        )

    @classmethod
    def create_response(
        cls,
        correlation_id: str,
        payload: Dict[str, Any],
        version: int = PROTOCOL_VERSION,
    ) -> "SnowMessage":
        """Factory for generating a valid response message linked to a request ID."""
        return cls(
            version=version,
            type=MessageType.RESPONSE,
            id=str(uuid.uuid4()),
            correlation_id=correlation_id,
            timestamp=current_iso_timestamp(),
            payload=payload,
        )

    @classmethod
    def create_error(
        cls,
        code: str,
        message: str,
        correlation_id: Optional[str] = None,
        version: int = PROTOCOL_VERSION,
    ) -> "SnowMessage":
        """Factory for generating a structured protocol error response."""
        return cls(
            version=version,
            type=MessageType.ERROR,
            id=str(uuid.uuid4()),
            correlation_id=correlation_id,
            timestamp=current_iso_timestamp(),
            error={"code": code, "message": message},
        )

    @classmethod
    def create_heartbeat(cls, version: int = PROTOCOL_VERSION) -> "SnowMessage":
        """Factory for generating a heartbeat keepalive message."""
        return cls(
            version=version,
            type=MessageType.HEARTBEAT,
            id=str(uuid.uuid4()),
            timestamp=current_iso_timestamp(),
        )

    @classmethod
    def create_heartbeat_ack(
        cls, correlation_id: str, version: int = PROTOCOL_VERSION
    ) -> "SnowMessage":
        """Factory for generating a heartbeat acknowledgement message."""
        return cls(
            version=version,
            type=MessageType.HEARTBEAT_ACK,
            id=str(uuid.uuid4()),
            correlation_id=correlation_id,
            timestamp=current_iso_timestamp(),
        )
