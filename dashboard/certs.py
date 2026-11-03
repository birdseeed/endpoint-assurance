"""
PAT-218 cert helpers — pure functions, no I/O.

classify_cert_type  — deterministic classification from cert dict fields
compute_days_until_expiry — live expiry in whole days (negative = expired)
"""

import re
from datetime import datetime, timezone

_MDM_RE = re.compile(r"MDM|Mobile Device Management|APNS|Apple Push Services", re.IGNORECASE)

_CERT_TYPE_CODE_SIGNING  = "code_signing"
_CERT_TYPE_MDM_ISSUED    = "mdm_issued"
_CERT_TYPE_APPLE_PKI     = "apple_pki"
_CERT_TYPE_CA_ROOT       = "ca_root"
_CERT_TYPE_INTERMEDIATE  = "intermediate"
_CERT_TYPE_LEAF          = "leaf"
_CERT_TYPE_OTHER         = "other"

ALL_CERT_TYPES = [
    _CERT_TYPE_CODE_SIGNING,
    _CERT_TYPE_MDM_ISSUED,
    _CERT_TYPE_APPLE_PKI,
    _CERT_TYPE_CA_ROOT,
    _CERT_TYPE_INTERMEDIATE,
    _CERT_TYPE_LEAF,
    _CERT_TYPE_OTHER,
]


def classify_cert_type(cert: dict) -> str:
    """Return the cert type string; precedence order is fixed — first match wins."""
    eku     = cert.get("ext_key_usage") or []
    issuer  = cert.get("issuer_cn") or ""
    is_ca   = bool(cert.get("basic_constraints_ca", False))
    is_self = bool(cert.get("is_self_signed", False))

    if "1.3.6.1.5.5.7.3.3" in eku:
        return _CERT_TYPE_CODE_SIGNING
    if _MDM_RE.search(issuer):
        return _CERT_TYPE_MDM_ISSUED
    if "apple" in issuer.lower():
        return _CERT_TYPE_APPLE_PKI
    if is_ca and is_self:
        return _CERT_TYPE_CA_ROOT
    if is_ca and not is_self:
        return _CERT_TYPE_INTERMEDIATE
    if not is_ca:
        return _CERT_TYPE_LEAF
    return _CERT_TYPE_OTHER


def compute_days_until_expiry(cert: dict) -> int | None:
    """Whole UTC days remaining; absent, malformed or naive evidence is unknown."""
    not_after = cert.get("not_after")
    if not isinstance(not_after, str) or not not_after:
        return None
    try:
        dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        if dt.tzinfo is None or dt.utcoffset() is None:
            return None
        delta = dt - datetime.now(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None
    return int(delta.total_seconds() // 86400)
