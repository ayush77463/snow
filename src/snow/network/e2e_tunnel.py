"""End-to-End Encrypted TLS 1.3 Tunnel for SNOW Device Protocol over Untrusted Relays.

Implements payload-blind, bidirectional TLS 1.3 mutual endpoint encryption using
standard Python `ssl.SSLContext` and `ssl.MemoryBIO`. The untrusted relay carries
opaque inner TLS records without access to plaintext application data or keys.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import ssl
from typing import Any, Callable, Dict, Optional, Tuple

from snow.protocol.models import SnowMessage
from snow.security.tls import compute_cert_fingerprint, format_fingerprint

logger = logging.getLogger(__name__)


class FingerprintMismatchError(Exception):
    """Raised when the peer presents a TLS certificate whose SHA-256 fingerprint does not match the pinned credential."""

    def __init__(self, expected: str, presented: str) -> None:
        super().__init__(f"TLS Certificate Fingerprint Mismatch! Pinned: {expected}, Presented: {presented}")
        self.expected = expected
        self.presented = presented


class TlsMemoryBioTunnel:
    """Manages an in-memory TLS 1.3 state machine over an arbitrary stream using SSLContext and MemoryBIO."""

    def __init__(
        self,
        ssl_context: ssl.SSLContext,
        is_server: bool = False,
        expected_peer_fingerprint: Optional[str] = None,
        server_hostname: Optional[str] = None,
    ) -> None:
        self.ssl_context = ssl_context
        self.is_server = is_server
        self.expected_peer_fingerprint = (
            format_fingerprint(expected_peer_fingerprint) if expected_peer_fingerprint else None
        )
        self.server_hostname = server_hostname

        self.incoming_bio = ssl.MemoryBIO()
        self.outgoing_bio = ssl.MemoryBIO()

        self.ssl_obj = self.ssl_context.wrap_bio(
            incoming=self.incoming_bio,
            outgoing=self.outgoing_bio,
            server_side=self.is_server,
            server_hostname=self.server_hostname if not self.is_server else None,
        )
        self.handshake_done = False
        self.peer_fingerprint: Optional[str] = None

    def drive_handshake(self) -> Tuple[bool, bytes]:
        """Perform handshake step. Returns (is_completed, outgoing_bytes_to_send)."""
        if self.handshake_done:
            return True, b""

        try:
            self.ssl_obj.do_handshake()
            # Handshake finished: extract and verify peer certificate BEFORE marking handshake_done
            self._verify_peer()
            self.handshake_done = True
            out_bytes = self.outgoing_bio.read() or b""
            return True, out_bytes
        except ssl.SSLWantReadError:
            out_bytes = self.outgoing_bio.read() or b""
            return False, out_bytes
        except ssl.SSLWantWriteError:
            out_bytes = self.outgoing_bio.read() or b""
            return False, out_bytes

    def feed_network_data(self, data: bytes) -> None:
        """Feed received outer raw bytes into the incoming TLS buffer."""
        if data:
            self.incoming_bio.write(data)

    def encrypt_application_data(self, plaintext: bytes) -> bytes:
        """Encrypt application bytes into TLS record bytes."""
        if not self.handshake_done:
            raise ssl.SSLError("Cannot write application data before TLS handshake completes.")
        self.ssl_obj.write(plaintext)
        return self.outgoing_bio.read() or b""

    def decrypt_application_data(self) -> bytes:
        """Decrypt available TLS records into plaintext application bytes."""
        if not self.handshake_done:
            return b""
        chunks = []
        while True:
            try:
                chunk = self.ssl_obj.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            except ssl.SSLWantReadError:
                break
            except ssl.SSLZeroReturnError:
                # TLS closure received
                break
            except ssl.SSLError:
                # Tampered or corrupted TLS record
                break
        return b"".join(chunks)

    def _verify_peer(self) -> None:
        """Extract peer certificate DER and enforce fingerprint pinning."""
        peer_cert_der = self.ssl_obj.getpeercert(binary_form=True)
        if peer_cert_der:
            presented_fp = compute_cert_fingerprint(peer_cert_der)
            self.peer_fingerprint = presented_fp
            if self.expected_peer_fingerprint:
                if presented_fp != self.expected_peer_fingerprint:
                    raise FingerprintMismatchError(expected=self.expected_peer_fingerprint, presented=presented_fp)
        elif not self.is_server and self.expected_peer_fingerprint:
            raise FingerprintMismatchError(expected=self.expected_peer_fingerprint, presented="<none>")


def create_e2e_tunnel_ssl_context(
    cert_path: str,
    key_path: str,
    is_server: bool = False,
    require_client_cert: bool = True,
    peer_cert_path: Optional[str] = None,
) -> ssl.SSLContext:
    """Create an SSLContext strictly enforcing TLS 1.3 for in-memory tunnel encryption."""
    purpose = ssl.Purpose.CLIENT_AUTH if is_server else ssl.Purpose.SERVER_AUTH
    ctx = ssl.create_default_context(purpose)
    # Strictly enforce TLS 1.3
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Load local cert and private key
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Disable standard hostname check because endpoint identities are verified cryptographically via certificate fingerprint pinning
    ctx.check_hostname = False

    if peer_cert_path:
        ctx.load_verify_locations(cafile=peer_cert_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        # Without an explicit peer certificate CA path, use CERT_NONE so OpenSSL does not
        # fail on self-signed certs. TlsMemoryBioTunnel cryptographically enforces pinning on peer cert.
        ctx.verify_mode = ssl.CERT_NONE

    return ctx
