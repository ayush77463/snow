"""In-memory PIN pairing manager and verification logic for SNOW Desktop Core."""

from dataclasses import dataclass
from enum import StrEnum
import hmac
import logging
import secrets
import sys
import threading
import time
from typing import Callable, Optional, Tuple
import uuid

from snow.protocol.constants import ErrorCode

logger = logging.getLogger(__name__)

# Constants frozen for Sub-Milestone 2.1
DEFAULT_PIN_LIFETIME_SECONDS: float = 60.0
MAX_FAILED_PAIRING_ATTEMPTS: int = 3


class PairingOutcome(StrEnum):
    """Distinguishable outcomes for PIN pairing attempts."""

    SUCCESS = "SUCCESS"
    INVALID_PIN = "INVALID_PIN"
    EXPIRED = "EXPIRED"
    LOCKED = "LOCKED"
    ALREADY_PAIRED = "ALREADY_PAIRED"
    NO_ACTIVE_PIN = "NO_ACTIVE_PIN"


@dataclass(frozen=True)
class VerificationResult:
    """Structured result of a PIN verification attempt."""

    outcome: PairingOutcome
    message: str
    remaining_attempts: int
    session_id: Optional[str] = None
    paired_device_id: Optional[str] = None
    assigned_trust_tier: str = "peer"

    @property
    def is_success(self) -> bool:
        """Return True if pairing succeeded."""
        return self.outcome == PairingOutcome.SUCCESS

    @property
    def error_code(self) -> Optional[str]:
        """Map the outcome to a protocol ErrorCode if not successful."""
        if self.outcome == PairingOutcome.INVALID_PIN:
            return ErrorCode.INVALID_PIN
        elif self.outcome == PairingOutcome.EXPIRED:
            return ErrorCode.PIN_EXPIRED
        elif self.outcome == PairingOutcome.LOCKED:
            return ErrorCode.PAIRING_LOCKED
        elif self.outcome == PairingOutcome.ALREADY_PAIRED:
            return ErrorCode.ALREADY_PAIRED
        elif self.outcome == PairingOutcome.NO_ACTIVE_PIN:
            return ErrorCode.PIN_EXPIRED
        return None


class PairingManager:
    """Thread-safe, in-memory pairing manager for temporary 6-digit PIN verification.

    Enforces 60-second lifetime, 3-attempt lockout, timing-attack resistant verification
    via hmac.compare_digest, and prevention of replay or concurrent PIN consumption.
    """

    def __init__(
        self,
        pin_lifetime: float = DEFAULT_PIN_LIFETIME_SECONDS,
        max_attempts: int = MAX_FAILED_PAIRING_ATTEMPTS,
        time_provider: Callable[[], float] = time.monotonic,
    ) -> None:
        self.pin_lifetime = pin_lifetime
        self.max_attempts = max_attempts
        self.time_provider = time_provider

        self._lock = threading.Lock()
        self._active_pin: Optional[str] = None
        self._owner_pin: Optional[str] = None
        self._peer_pin: Optional[str] = None
        self._pin_generated_at: float = 0.0
        self._failed_attempts: int = 0
        self._is_locked: bool = False
        self._is_paired: bool = False
        self._paired_device_id: Optional[str] = None
        self._session_id: Optional[str] = None

    @property
    def is_locked(self) -> bool:
        """Return True if pairing is locked out due to excessive failed attempts."""
        with self._lock:
            return self._is_locked

    @property
    def is_paired(self) -> bool:
        """Return True if this session has successfully completed pairing."""
        with self._lock:
            return self._is_paired

    @property
    def has_active_pin(self) -> bool:
        """Return True if there is currently an unexpired, active PIN."""
        with self._lock:
            if (self._active_pin is None and self._owner_pin is None and self._peer_pin is None) or self._is_locked or self._is_paired:
                return False
            elapsed = self.time_provider() - self._pin_generated_at
            return elapsed < self.pin_lifetime

    def generate_pin(self, display_to_stderr: bool = True) -> str:
        """Generate cryptographically secure 6-digit decimal PINs for Owner and Peer pairing.

        Resets failed attempts and starts a fresh 60-second pairing window.
        Outputs the generated PINs strictly to sys.stderr (never stdout).

        Returns:
            The primary owner PIN string for compatibility.
        """
        with self._lock:
            raw_owner = secrets.randbelow(1_000_000)
            raw_peer = secrets.randbelow(1_000_000)
            while raw_peer == raw_owner:
                raw_peer = secrets.randbelow(1_000_000)

            owner_pin = f"{raw_owner:06d}"
            peer_pin = f"{raw_peer:06d}"

            self._active_pin = owner_pin
            self._owner_pin = owner_pin
            self._peer_pin = peer_pin
            self._pin_generated_at = self.time_provider()
            self._failed_attempts = 0
            self._is_locked = False
            self._is_paired = False
            self._paired_device_id = None
            self._session_id = None

            if display_to_stderr:
                self._display_pin_stderr(owner_pin, peer_pin)

            return owner_pin

    def _display_pin_stderr(self, owner_pin: str, peer_pin: str) -> None:
        """Display the active pairing PINs to sys.stderr."""
        lifetime_sec = int(self.pin_lifetime)
        banner = (
            f"\n======================================================\n"
            f" [SNOW PAIRING] Temporary Pairing PINs (Expires in {lifetime_sec}s):\n"
            f"   - Owner Provisioning PIN: [ {owner_pin} ] -> Grants OWNER_MANUAL\n"
            f"   - Peer Pairing PIN:       [ {peer_pin} ] -> Grants PEER\n"
            f" Enter the appropriate PIN on your Android device.\n"
            f"======================================================\n"
        )
        sys.stderr.write(banner)
        sys.stderr.flush()
        logger.info("Generated active pairing PINs (owner and peer, expires in %ds)", lifetime_sec)

    def verify_pin(self, submitted_pin: str, client_device_id: Optional[str] = None) -> VerificationResult:
        """Verify a submitted 6-digit PIN.

        Thread-safe: Concurrent requests cannot race to consume the same valid PIN.
        Uses hmac.compare_digest for constant-time comparison.

        Args:
            submitted_pin: 6-digit decimal PIN submitted by the client.
            client_device_id: Optional UUID of the client device requesting pairing.

        Returns:
            VerificationResult detailing the outcome, message, remaining attempts,
            and session ID on success.
        """
        with self._lock:
            # 1. Check if already paired (prevent replay after successful pairing)
            if self._is_paired:
                logger.warning("Rejected pairing attempt: Session is already paired.")
                return VerificationResult(
                    outcome=PairingOutcome.ALREADY_PAIRED,
                    message="Device is already paired in this session.",
                    remaining_attempts=0,
                    session_id=self._session_id,
                    paired_device_id=self._paired_device_id,
                )

            # 2. Check if locked out
            if self._is_locked:
                logger.warning("Rejected pairing attempt: Pairing is locked.")
                return VerificationResult(
                    outcome=PairingOutcome.LOCKED,
                    message=f"Pairing is locked due to {self.max_attempts} failed attempts. Please generate a new PIN.",
                    remaining_attempts=0,
                )

            # 3. Check if an active PIN exists
            if self._active_pin is None and self._owner_pin is None and self._peer_pin is None:
                logger.warning("Rejected pairing attempt: No active pairing PIN exists.")
                return VerificationResult(
                    outcome=PairingOutcome.NO_ACTIVE_PIN,
                    message="No active pairing PIN. Please request or generate a new PIN on the desktop.",
                    remaining_attempts=0,
                )

            # 4. Check for PIN expiry
            elapsed = self.time_provider() - self._pin_generated_at
            if elapsed >= self.pin_lifetime:
                logger.warning("Rejected pairing attempt: PIN expired (elapsed: %.1fs >= %.1fs)",
                               elapsed, self.pin_lifetime)
                self._active_pin = None
                self._owner_pin = None
                self._peer_pin = None
                remaining = max(0, self.max_attempts - self._failed_attempts)
                return VerificationResult(
                    outcome=PairingOutcome.EXPIRED,
                    message="Pairing PIN has expired. Please request a new PIN.",
                    remaining_attempts=remaining,
                )

            # 5. Normalize and validate input format
            cleaned_pin = str(submitted_pin).strip()
            if len(cleaned_pin) != 6 or not cleaned_pin.isdigit():
                self._failed_attempts += 1
                remaining = max(0, self.max_attempts - self._failed_attempts)
                if self._failed_attempts >= self.max_attempts:
                    self._is_locked = True
                    self._active_pin = None
                    self._owner_pin = None
                    self._peer_pin = None
                    logger.warning("Pairing locked after %d failed attempts.", self.max_attempts)
                    return VerificationResult(
                        outcome=PairingOutcome.LOCKED,
                        message=f"Pairing locked: Exceeded maximum allowed attempts ({self.max_attempts}).",
                        remaining_attempts=0,
                    )
                return VerificationResult(
                    outcome=PairingOutcome.INVALID_PIN,
                    message=f"PIN must be exactly 6 decimal digits. {remaining} attempt(s) remaining.",
                    remaining_attempts=remaining,
                )

            # 6. Timing-safe comparison using hmac.compare_digest
            is_owner_match = bool(self._owner_pin and hmac.compare_digest(cleaned_pin, self._owner_pin))
            is_peer_match = bool(self._peer_pin and hmac.compare_digest(cleaned_pin, self._peer_pin))
            # Fallback to _active_pin if owner_pin was not set
            if not is_owner_match and not is_peer_match and self._active_pin:
                is_owner_match = bool(hmac.compare_digest(cleaned_pin, self._active_pin))

            if is_owner_match or is_peer_match:
                # SUCCESS: Immediately consume PINs to prevent reuse
                assigned_tier = "owner" if is_owner_match else "peer"
                self._is_paired = True
                self._active_pin = None
                self._owner_pin = None
                self._peer_pin = None
                session_id = str(uuid.uuid4())
                self._session_id = session_id
                self._paired_device_id = client_device_id
                remaining = self.max_attempts - self._failed_attempts

                logger.info("Pairing successful for client device [%s] (tier=%s, session_id=%s)",
                            client_device_id, assigned_tier, session_id)
                return VerificationResult(
                    outcome=PairingOutcome.SUCCESS,
                    message="Pairing successful.",
                    remaining_attempts=remaining,
                    session_id=session_id,
                    paired_device_id=client_device_id,
                    assigned_trust_tier=assigned_tier,
                )
            else:
                # MISMATCH: Increment failure count
                self._failed_attempts += 1
                remaining = max(0, self.max_attempts - self._failed_attempts)

                if self._failed_attempts >= self.max_attempts:
                    self._is_locked = True
                    self._active_pin = None
                    self._owner_pin = None
                    self._peer_pin = None
                    logger.warning("Pairing locked after %d failed attempts.", self.max_attempts)
                    return VerificationResult(
                        outcome=PairingOutcome.LOCKED,
                        message=f"Pairing locked: Exceeded maximum allowed attempts ({self.max_attempts}).",
                        remaining_attempts=0,
                    )

                logger.warning("Incorrect pairing PIN submitted (%d attempts remaining).", remaining)
                return VerificationResult(
                    outcome=PairingOutcome.INVALID_PIN,
                    message=f"Invalid pairing PIN. {remaining} attempt(s) remaining.",
                    remaining_attempts=remaining,
                )
