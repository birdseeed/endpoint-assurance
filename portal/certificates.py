"""Bounded public certificate validation and metadata-only display models."""

import base64
import binascii
import re
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding

MAX_FILE_BYTES = 64 * 1024
MAX_BODY_BYTES = 96 * 1024
_PEM = re.compile(
    rb"[ \t\r\n]*-----BEGIN CERTIFICATE-----[ \t\r\n]+"
    rb"([A-Za-z0-9+/= \t\r\n]+)-----END CERTIFICATE-----[ \t\r\n]*"
)
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)


def valid_id(value) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def valid_label(value) -> bool:
    # Match the platform's Unicode character limit and Unicode control class.
    return (isinstance(value, str) and 1 <= len(value.strip()) <= 200
            and not re.search(r"[\x00-\x1f\x7f-\x9f]", value))


def validate_public_certificate(raw: bytes) -> None:
    """Accept exactly one PEM/DER X.509 object, never a key or container.

    Decode the whole PEM ourselves before the standard X.509 parser because
    parsers may accept a valid first block and ignore appended secret material.
    Canonical DER round-trip equality also rejects trailing DER objects/bytes.
    No parse error includes the submitted contents.
    """
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise ValueError("A public certificate up to 64 KiB is required.")
    try:
        match = _PEM.fullmatch(raw)
        der = (base64.b64decode(re.sub(rb"[ \t\r\n]", b"", match[1]), validate=True)
               if match else raw)
        cert = x509.load_der_x509_certificate(der)
        if cert.public_bytes(Encoding.DER) != der:
            raise ValueError
        if cert.not_valid_after_utc < cert.not_valid_before_utc:
            raise ValueError
    except (ValueError, TypeError, binascii.Error, UnsupportedAlgorithm) as exc:
        raise ValueError("Choose one public X.509 certificate in PEM or DER format.") from exc


def _date(value) -> datetime | None:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def row_view(row: dict, now: datetime) -> dict:
    """Never substitute collection-time health or invent uploaded provenance."""
    expiry = _date(row.get("not_after"))
    start = _date(row.get("not_before"))
    days = int((expiry - now).total_seconds() // 86400) if expiry else None
    if start and expiry and start > expiry:
        days = None
    status = ("unknown" if days is None else "expired" if days < 0
              else "critical" if days <= 7 else "warning" if days <= 30 else "healthy")
    source = row.get("source")
    uploaded = source == "uploaded"
    agent = source == "agent"
    record_id = row.get("id")
    device_id = row.get("device_id") if agent else None
    return {
        "id": record_id if uploaded and valid_id(record_id) else None,
        "source": "Uploaded" if uploaded else "Agent" if agent else "Unknown",
        "label": row.get("label") if uploaded else None,
        "subject": row.get("subject_cn") or "Not reported",
        "issuer": row.get("issuer_cn") or "Not reported",
        "fingerprint": row.get("fingerprint_sha256") or row.get("sha1") or "Not reported",
        "fingerprint_kind": "SHA-256" if row.get("fingerprint_sha256") else "SHA-1",
        "not_before": start.strftime("%d %b %Y, %H:%M UTC") if start else "Unknown",
        "not_after": expiry.strftime("%d %b %Y, %H:%M UTC") if expiry else "Unknown",
        "days": days, "status": status,
        "pill": {"unknown": "pill-muted", "expired": "pill-bad",
                 "critical": "pill-bad", "warning": "pill-warn", "healthy": "pill-ok"}[status],
        "device_url": f"/devices/{device_id}" if valid_id(device_id) else None,
    }
