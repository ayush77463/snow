"""TLS certificate management and SSLContext creation for SNOW.

Provides self-signed X.509 certificate generation, persistence, SHA-256
fingerprint calculation, and server SSLContext configuration enforcing TLS 1.2+.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import logging
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
from typing import List, Optional, Set, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

DEFAULT_TLS_DIR = Path.home() / ".snow" / "tls"
DEFAULT_CERT_FILE = "server.crt"
DEFAULT_KEY_FILE = "server.key"
CERT_VALIDITY_DAYS = 365


@dataclass(frozen=True)
class CertificateInfo:
    """Metadata for a loaded or generated TLS certificate."""

    cert_path: Path
    key_path: Path
    fingerprint_sha256: str
    subject_common_name: str
    san_entries: Tuple[str, ...]
    not_valid_before: datetime
    not_valid_after: datetime


def format_fingerprint(raw_hex_or_bytes: str | bytes) -> str:
    """Format a 32-byte SHA-256 digest into uppercase colon-separated hex string.

    Example: 'E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55'
    """
    if isinstance(raw_hex_or_bytes, bytes):
        raw_hex = raw_hex_or_bytes.hex().upper()
    else:
        # Strip existing colons, spaces, and normalize to uppercase
        raw_hex = raw_hex_or_bytes.replace(":", "").replace(" ", "").strip().upper()

    if len(raw_hex) != 64:
        raise ValueError(f"Invalid SHA-256 digest length: expected 64 hex characters, got {len(raw_hex)}")

    return ":".join(raw_hex[i : i + 2] for i in range(0, 64, 2))


def compute_cert_fingerprint(cert_der: bytes) -> str:
    """Compute standard colon-separated uppercase SHA-256 fingerprint over DER bytes."""
    digest = hashlib.sha256(cert_der).digest()
    return format_fingerprint(digest)


def set_private_key_permissions(key_path: Path) -> None:
    """Apply restrictive file permissions to the private key file.

    On POSIX, sets mode 0o600 (owner read/write only).
    On Windows, uses icacls to grant full control strictly to the current user
    and remove inherited access, falling back safely if icacls is unavailable.
    """
    try:
        os.chmod(key_path, 0o600)
    except Exception as exc:
        logger.debug("os.chmod failed on %s: %s", key_path, exc)

    if sys.platform == "win32":
        username = os.getenv("USERNAME")
        if username:
            try:
                # Remove inherited access and grant full control only to current user
                cmd = ["icacls", str(key_path), "/inheritance:r", "/grant:r", f"{username}:(F)"]
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception as exc:
                logger.debug("icacls restriction failed on %s: %s", key_path, exc)


def generate_self_signed_cert(
    cert_path: Path,
    key_path: Path,
    active_ips: Optional[List[str]] = None,
    common_name: str = "SNOW-Desktop-Core",
    validity_days: int = CERT_VALIDITY_DAYS,
) -> CertificateInfo:
    """Generate a 2048-bit RSA private key and self-signed X.509 certificate.

    Includes Subject Alternative Name (SAN) entries for:
    - 127.0.0.1
    - 0.0.0.0
    - localhost
    - local machine hostname
    - all provided active local IPv4 addresses

    Saves certificate and private key to disk with strict permissions.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Generate 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Build SAN list
    san_list: List[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
    ]
    seen_ips: Set[str] = {"127.0.0.1", "0.0.0.0"}

    # Include local hostname if available
    try:
        hostname = socket.gethostname().strip()
        if hostname and hostname != "localhost":
            san_list.append(x509.DNSName(hostname))
    except Exception:
        pass

    # Include detected local IPv4 addresses
    if active_ips:
        for ip_str in active_ips:
            ip_clean = ip_str.strip()
            if ip_clean and ip_clean not in seen_ips:
                try:
                    ip_addr = ipaddress.ip_address(ip_clean)
                    san_list.append(x509.IPAddress(ip_addr))
                    seen_ips.add(ip_clean)
                except ValueError:
                    logger.warning("Skipping invalid IP for certificate SAN: %s", ip_str)

    # 3. Create X.509 self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SNOW Capability Bridge"),
    ])

    now = datetime.now(timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )

    certificate = cert_builder.sign(
        private_key,
        hashes.SHA256(),
    )

    # 4. Write private key to disk (PEM format, PKCS#8, no encryption)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_path, "wb") as f:
        f.write(key_pem)
    set_private_key_permissions(key_path)

    # 5. Write certificate to disk (PEM format)
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    with open(cert_path, "wb") as f:
        f.write(cert_pem)

    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = compute_cert_fingerprint(cert_der)

    san_strings = tuple(str(x.value) for x in san_list)
    logger.info("Generated new self-signed TLS certificate at %s", cert_path)
    logger.info("Server certificate SHA-256 fingerprint: %s", fingerprint)

    return CertificateInfo(
        cert_path=cert_path,
        key_path=key_path,
        fingerprint_sha256=fingerprint,
        subject_common_name=common_name,
        san_entries=san_strings,
        not_valid_before=certificate.not_valid_before_utc,
        not_valid_after=certificate.not_valid_after_utc,
    )


def load_certificate_info(cert_path: Path, key_path: Path) -> CertificateInfo:
    """Load and validate existing certificate and private key from disk.

    Validates that:
    1. Both files exist and are readable.
    2. Private key and certificate are syntactically valid PEM.
    3. The public key in the certificate matches the private key.

    Raises:
        FileNotFoundError: If either file is missing.
        ValueError: If PEM is malformed or key pair does not match.
    """
    if not cert_path.exists():
        raise FileNotFoundError(f"TLS certificate file not found: {cert_path}")
    if not key_path.exists():
        raise FileNotFoundError(f"TLS private key file not found: {key_path}")

    with open(cert_path, "rb") as f:
        cert_data = f.read()
    with open(key_path, "rb") as f:
        key_data = f.read()

    try:
        certificate = x509.load_pem_x509_certificate(cert_data)
    except Exception as exc:
        raise ValueError(f"Corrupt or invalid TLS certificate file '{cert_path}': {exc}") from exc

    try:
        private_key = serialization.load_pem_private_key(key_data, password=None)
    except Exception as exc:
        raise ValueError(f"Corrupt or invalid TLS private key file '{key_path}': {exc}") from exc

    # Validate that the certificate public key matches the private key
    cert_pub_bytes = certificate.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if cert_pub_bytes != key_pub_bytes:
        raise ValueError(
            f"Mismatched TLS identity: certificate '{cert_path}' public key "
            f"does not match private key '{key_path}'."
        )

    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = compute_cert_fingerprint(cert_der)

    san_strings: List[str] = []
    try:
        san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            san_strings.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    common_name = "SNOW-Desktop-Core"
    try:
        cn_attrs = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            common_name = str(cn_attrs[0].value)
    except Exception:
        pass

    return CertificateInfo(
        cert_path=cert_path,
        key_path=key_path,
        fingerprint_sha256=fingerprint,
        subject_common_name=common_name,
        san_entries=tuple(san_strings),
        not_valid_before=certificate.not_valid_before_utc,
        not_valid_after=certificate.not_valid_after_utc,
    )


def ensure_tls_certificate(
    cert_path: Path,
    key_path: Path,
    active_ips: Optional[List[str]] = None,
    regenerate_if_ip_missing: bool = True,
) -> CertificateInfo:
    """Ensure a valid TLS certificate and matching private key exist.

    If either file does not exist, generates a fresh certificate and key.
    If both exist, loads and validates them.
    If regenerate_if_ip_missing is True and any active IP is missing from SAN,
    rotates the certificate. Otherwise, logs an explicit warning.
    """
    if cert_path.exists() and key_path.exists():
        try:
            info = load_certificate_info(cert_path, key_path)
            # Check if active IPs are covered in SAN
            if active_ips:
                missing_ips = [ip for ip in active_ips if ip not in info.san_entries]
                if missing_ips:
                    if regenerate_if_ip_missing:
                        logger.warning(
                            "Certificate SAN missing active IP(s) %s. Regenerating certificate...",
                            missing_ips,
                        )
                        return generate_self_signed_cert(cert_path, key_path, active_ips=active_ips)
                    else:
                        logger.warning(
                            "Active IP(s) %s not present in existing certificate SAN entries (%s). "
                            "Clients connecting to these IPs may encounter hostname verification errors.",
                            missing_ips,
                            info.san_entries,
                        )
            return info
        except Exception as exc:
            logger.error("Failed to load existing TLS certificate: %s. Re-generating...", exc)
            return generate_self_signed_cert(cert_path, key_path, active_ips=active_ips)

    # First-time generation
    return generate_self_signed_cert(cert_path, key_path, active_ips=active_ips)


def create_server_ssl_context(
    cert_path: Path,
    key_path: Path,
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
) -> ssl.SSLContext:
    """Create a strictly configured Python ssl.SSLContext for server WSS.

    Enforces:
    - Minimum TLS version (TLS 1.2 by default, supporting TLS 1.3).
    - Modern secure cipher suites (disabling legacy/broken ciphers).
    - Certificate and private key loading.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = min_version
    # Modern cipher string (PFS, AEAD ciphers)
    context.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
    )
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def print_tls_fingerprint_banner(fingerprint: str) -> None:
    """Display the TLS server certificate fingerprint prominently to sys.stderr."""
    banner = (
        f"\n======================================================\n"
        f" [SNOW TLS] Server Certificate SHA-256 Fingerprint:\n"
        f" [ {fingerprint} ]\n"
        f" Compare this fingerprint on your Android device before confirming trust.\n"
        f"======================================================\n"
    )
    sys.stderr.write(banner)
    sys.stderr.flush()
