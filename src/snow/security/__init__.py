"""Security, identity, pairing, TLS, and persistence facilities for SNOW."""

from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import (
    AuditEventRecord,
    DatabaseManager,
    PairedDeviceRecord,
    hash_token,
)
from snow.security.identity import DeviceIdentity, load_or_create_device_identity
from snow.security.pairing import (
    PairingManager,
    PairingOutcome,
    VerificationResult,
    create_qr_pairing_payload,
    validate_qr_pairing_payload,
)
from snow.security.policy import (
    ACTION_TO_CAPABILITY,
    CAPABILITY_DESKTOP_APP_LAUNCH,
    CAPABILITY_DESKTOP_CLIPBOARD_READ,
    CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    CAPABILITY_DESKTOP_EXEC,
    CAPABILITY_DESKTOP_FILES_DOWNLOAD,
    CAPABILITY_DESKTOP_FILES_LIST,
    CAPABILITY_DESKTOP_STATUS,
    CAPABILITY_FILE_TRANSFER,
    DEFAULT_PAIRED_CAPABILITIES,
    PeerCapabilityPolicy,
)
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
    "ExecutionContext",
    "ExecutionPrincipal",
    "PairedDeviceRecord",
    "PairingManager",
    "PairingOutcome",
    "PeerCapabilityPolicy",
    "SessionManager",
    "SessionRecord",
    "VerificationResult",
    "create_qr_pairing_payload",
    "validate_qr_pairing_payload",
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
