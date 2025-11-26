"""
Shared utilities for monitoring certificate verification.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

import structlog
from cryptography import x509

from app.core.config import settings
from app.models.certificate import Certificate

logger = structlog.get_logger(__name__)

VerificationResult = dict[str, Optional[object]]


def _default_result() -> VerificationResult:
    return {
        "certificate_match": None,
        "observed_serial_number": None,
        "last_verified_at": None,
        "verification_error": None,
    }


def extract_target(target_url: str, override_port: Optional[int]) -> Optional[Tuple[str, int]]:
    """Normalize a monitoring target into host/port tuple."""
    normalized = target_url if "://" in target_url else f"https://{target_url}"
    parsed = urlparse(normalized)
    host = parsed.hostname or parsed.path
    if not host:
        return None
    port = override_port or parsed.port
    if not port:
        port = 80 if (parsed.scheme or "http").lower() == "http" else 443
    return host, port


def verify_remote_certificate(cert: Certificate) -> VerificationResult:
    """Fetch the remote certificate for the monitored target and compare serial numbers."""
    result = _default_result()

    if not settings.MONITORING_ENABLED:
        return result

    if not cert.monitoring_enabled or not cert.monitoring_target_url:
        return result

    target = extract_target(cert.monitoring_target_url, cert.monitoring_target_port)
    if not target:
        result["verification_error"] = "Invalid monitoring target"
        return result

    host, port = target
    now = datetime.now(timezone.utc)

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=settings.MONITORING_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)

        remote_cert = x509.load_der_x509_certificate(der_cert)
        observed_serial = str(remote_cert.serial_number)
        matches = observed_serial == cert.serial_number

        return {
            "certificate_match": matches,
            "observed_serial_number": observed_serial,
            "last_verified_at": now,
            "verification_error": None if matches else "Remote certificate serial does not match assigned certificate.",
        }
    except Exception as exc:  # pragma: no cover - network errors are expected
        error_message = str(exc)
        logger.warning(
            "Remote certificate verification failed",
            error=error_message,
            target_host=host,
            target_url=cert.monitoring_target_url,
        )
        return {
            "certificate_match": False,
            "observed_serial_number": None,
            "last_verified_at": now,
            "verification_error": error_message,
        }
