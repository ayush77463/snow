"""Security, identity, pairing, TLS, and persistence facilities for SNOW (lazy-loaded)."""

from __future__ import annotations

import importlib
from typing import Any

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "ApprovalPolicyEngine": ("snow.security.approval", "ApprovalPolicyEngine"),
    "ApprovalRequest": ("snow.security.approval", "ApprovalRequest"),
    "ApprovalStatus": ("snow.security.approval", "ApprovalStatus"),
    "compute_args_hash": ("snow.security.approval", "compute_args_hash"),
    "ExecutionContext": ("snow.security.context", "ExecutionContext"),
    "ExecutionPrincipal": ("snow.security.context", "ExecutionPrincipal"),
    "AuditEventRecord": ("snow.security.db", "AuditEventRecord"),
    "DatabaseManager": ("snow.security.db", "DatabaseManager"),
    "PairedDeviceRecord": ("snow.security.db", "PairedDeviceRecord"),
    "hash_token": ("snow.security.db", "hash_token"),
    "redact_sensitive_data": ("snow.security.db", "redact_sensitive_data"),
    "DeviceIdentity": ("snow.security.identity", "DeviceIdentity"),
    "load_or_create_device_identity": ("snow.security.identity", "load_or_create_device_identity"),
    "PairingManager": ("snow.security.pairing", "PairingManager"),
    "PairingOutcome": ("snow.security.pairing", "PairingOutcome"),
    "VerificationResult": ("snow.security.pairing", "VerificationResult"),
    "create_qr_pairing_payload": ("snow.security.pairing", "create_qr_pairing_payload"),
    "validate_qr_pairing_payload": ("snow.security.pairing", "validate_qr_pairing_payload"),
    "ACTION_TO_CAPABILITY": ("snow.security.policy", "ACTION_TO_CAPABILITY"),
    "CAPABILITY_DESKTOP_APP_LAUNCH": ("snow.security.policy", "CAPABILITY_DESKTOP_APP_LAUNCH"),
    "CAPABILITY_DESKTOP_CLIPBOARD_READ": ("snow.security.policy", "CAPABILITY_DESKTOP_CLIPBOARD_READ"),
    "CAPABILITY_DESKTOP_CLIPBOARD_WRITE": ("snow.security.policy", "CAPABILITY_DESKTOP_CLIPBOARD_WRITE"),
    "CAPABILITY_DESKTOP_EXEC": ("snow.security.policy", "CAPABILITY_DESKTOP_EXEC"),
    "CAPABILITY_DESKTOP_FILES_DOWNLOAD": ("snow.security.policy", "CAPABILITY_DESKTOP_FILES_DOWNLOAD"),
    "CAPABILITY_DESKTOP_FILES_LIST": ("snow.security.policy", "CAPABILITY_DESKTOP_FILES_LIST"),
    "CAPABILITY_DESKTOP_STATUS": ("snow.security.policy", "CAPABILITY_DESKTOP_STATUS"),
    "CAPABILITY_FILE_TRANSFER": ("snow.security.policy", "CAPABILITY_FILE_TRANSFER"),
    "DEFAULT_PAIRED_CAPABILITIES": ("snow.security.policy", "DEFAULT_PAIRED_CAPABILITIES"),
    "PeerCapabilityPolicy": ("snow.security.policy", "PeerCapabilityPolicy"),
    "SessionManager": ("snow.security.session", "SessionManager"),
    "SessionRecord": ("snow.security.session", "SessionRecord"),
    "CertificateInfo": ("snow.security.tls", "CertificateInfo"),
    "compute_cert_fingerprint": ("snow.security.tls", "compute_cert_fingerprint"),
    "create_server_ssl_context": ("snow.security.tls", "create_server_ssl_context"),
    "ensure_tls_certificate": ("snow.security.tls", "ensure_tls_certificate"),
    "format_fingerprint": ("snow.security.tls", "format_fingerprint"),
    "generate_self_signed_cert": ("snow.security.tls", "generate_self_signed_cert"),
    "load_certificate_info": ("snow.security.tls", "load_certificate_info"),
    "print_tls_fingerprint_banner": ("snow.security.tls", "print_tls_fingerprint_banner"),
}

__all__ = [
    "ApprovalPolicyEngine",
    "ApprovalRequest",
    "ApprovalStatus",
    "compute_args_hash",
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
    "redact_sensitive_data",
]


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_name, attr_name = target
    mod = importlib.import_module(mod_name)
    val = getattr(mod, attr_name)
    globals()[name] = val
    return val


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
