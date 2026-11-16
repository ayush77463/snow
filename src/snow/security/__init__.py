"""Security, identity, pairing, TLS, and persistence facilities for SNOW."""

from snow.security.db import (
    AuditEventRecord,
    DatabaseManager,
    PairedDeviceRecord,
    hash_token,
)
from snow.security.identity import DeviceIdentity, load_or_create_device_identity
from snow.security.pairing import PairingManager, PairingOutcome, VerificationResult
from snow.security.session import SessionManager, SessionRecord
from snow.security.tls import (
    CertificateInfo,
    compute_cert_fingerprint,
    create_server_ssl_context,
    ensure_tls_certificate,
    format_fingerprint,
    generate_self_signed_cert,
    load_certificate_info,
    print_tls_fingerprint_banner,
)

__all__ = [
    "AuditEventRecord",
    "CertificateInfo",
    "DatabaseManager",
    "DeviceIdentity",
    "PairedDeviceRecord",
    "PairingManager",
    "PairingOutcome",
    "SessionManager",
    "SessionRecord",
    "VerificationResult",
    "compute_cert_fingerprint",
    "create_server_ssl_context",
    "ensure_tls_certificate",
    "format_fingerprint",
    "generate_self_signed_cert",
    "hash_token",
    "load_certificate_info",
    "load_or_create_device_identity",
    "print_tls_fingerprint_banner",
]
