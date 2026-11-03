"""Shared fixtures: signing keys, fake JWKS, token factory, stub platform."""

import csv
import io
import json
import re
import socket
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import auth  # noqa: E402

TEAM_DOMAIN = "testteam.cloudflareaccess.com"
AUD = "aud0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
GOOD_KID = "portal-test-key-1"
ROGUE_KID = "rogue-key-1"


@pytest.fixture(scope="session")
def keypairs():
    good = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {"good": good, "rogue": rogue}


@pytest.fixture(scope="session")
def jwks(keypairs):
    entry = json.loads(
        pyjwt.algorithms.RSAAlgorithm.to_jwk(keypairs["good"].public_key())
    )
    entry.update({"kid": GOOD_KID, "alg": "RS256", "use": "sig"})
    return {"keys": [entry]}


@pytest.fixture(autouse=True)
def access_env(monkeypatch, jwks):
    monkeypatch.setenv("PORTAL_ACCESS_TEAM_DOMAIN", TEAM_DOMAIN)
    monkeypatch.setenv("PORTAL_ACCESS_AUD", AUD)
    monkeypatch.setattr(auth, "_fetch_jwks", lambda: jwks)
    auth.reset_jwks_cache()
    yield
    auth.reset_jwks_cache()


@pytest.fixture
def make_token(keypairs):
    """Factory for CF-Access-shaped JWTs. Defaults produce a valid token."""

    def _make(
        email="alice@tenant-a.example",
        aud=AUD,
        iss=f"https://{TEAM_DOMAIN}",
        exp_delta=600,
        key="good",
        kid=GOOD_KID,
        drop_email=False,
    ):
        now = int(time.time())
        claims = {
            "aud": [aud],
            "iss": iss,
            "iat": now - 30,
            "nbf": now - 30,
            "exp": now + exp_delta,
            "sub": "test-sub",
            "email": email,
            "identity_nonce": "abc123",
            "country": "IM",
        }
        if drop_email:
            del claims["email"]
        return pyjwt.encode(
            claims, keypairs[key], algorithm="RS256", headers={"kid": kid}
        )

    return _make


# ── Stub platform API ─────────────────────────────────────────────────────
STUB_STATE = {"mode": "ok", "expected_jwt": None, "generate_calls": 0,
              "schedule": None, "schedule_puts": [],
              "catalogue": None, "schedules": None, "typed_schedule_puts": [],
              "generate_posts": [], "catalogue_request_jwts": [],
              "enrolment_calls": 0, "enrolment_posts": [],
              "findings_data": None, "overview_data": None, "devices_data": None,
              "control_coverage_data": None,
              "overview_cards_data": None, "overview_cards_requests": [],
              "devices_page_responses": {}, "devices_page_statuses": {},
              "device_request_jwts": [], "device_request_offsets": [],
              "device_detail_data": None,
              "exceptions_data": None, "protected_data": None,
              "software_inventory_data": None, "software_inventory_requests": [],
              "lifecycle_current_overrides": {}, "lifecycle_history_overrides": {},
              "lifecycle_status_override": None, "lifecycle_requests": [],
              "cve_assessment_data": None,
              "ai_tooling_summary_data": None, "ai_tagged_products_data": None,
              "ai_tagged_product_requests": [],
              "ai_tagged_products_reorder_after_first": False,
              "ai_tooling_devices_data": None, "ai_tooling_device_items_data": None,
              "ai_tooling_item_requests": [],
              "software_notifications_data": None, "software_notification_puts": [],
              "software_notifications_error": None,
              "alerts_data": None, "alert_overrides": {}, "alert_history_overrides": {},
              "alert_list_requests": [], "alert_list_status_override": None,
              "alert_detail_status_override": None,
              "alert_acknowledge_posts": [], "alert_acknowledge_status_override": None,
              "sam_unsupported_data": None, "sam_unsupported_status": None,
              "sam_unsupported_requests": [],
              "sam_devices_data": None, "sam_devices_status": None,
              "sam_devices_requests": [], "sam_csv_data": None,
              "remote_access_data": None, "remote_access_status": None,
              "remote_access_requests": [],
              "remote_access_devices_data": None, "remote_access_devices_status": None,
              "remote_access_devices_requests": [], "remote_access_csv_data": None,
              "remote_access_devices_csv_data": None,
              "version_sprawl_data": None, "version_sprawl_status": None,
              "version_sprawl_requests": [], "version_sprawl_csv_data": None,
              "duplicate_tools_data": None, "duplicate_tools_status": None,
              "duplicate_tools_requests": [], "duplicate_tools_csv_data": None,
              "publishers_data": None, "publishers_status": None,
              "publishers_requests": [],
              "publishers_devices_data": None, "publishers_devices_status": None,
              "publishers_devices_requests": [], "publishers_csv_data": None,
              "publishers_devices_csv_data": None,
              # PAT-2010 (PAT-2009 platform reads): GET /v1/portal/
              # software/new|drift|approved and their ?format=csv forms.
              "new_software_data": None, "new_software_status": None,
              "new_software_requests": [], "new_software_csv_data": None,
              "software_drift_data": None, "software_drift_status": None,
              "software_drift_requests": [], "software_drift_csv_data": None,
              "software_approved_data": None, "software_approved_status": None,
              "software_approved_requests": [], "software_approved_csv_data": None,
              # PAT-2145: Jamf Pro coverage. jamf_mode: "not_configured" (never
              # connected - the default), "ok", "amber" or "revoked".
              "jamf_mode": "not_configured", "jamf_token_state": "active",
              "jamf_token_rotated_at": None, "jamf_token_revoked_at": None,
              "jamf_check_in_enabled": False, "jamf_instance_reset": False,
              "jamf_coverage_requests": [], "jamf_coverage_status_override": None,
              "jamf_setup_status_override": None, "jamf_token_posts": [],
              "jamf_token_post_status": None, "jamf_token_delete_calls": 0,
              "jamf_token_delete_status": None, "jamf_setup_puts": [],
              "jamf_setup_put_status": None, "jamf_devices_purge_calls": 0,
              "jamf_devices_delete_status": None,
              # PAT-1927: GET /v1/portal/ce-readiness and its ?format=csv form.
              "ce_readiness_data": None, "ce_readiness_status": None,
              "ce_readiness_requests": [], "ce_readiness_csv_data": None,
              # PAT-2258: GET /v1/portal/insurance-evidence (json/csv/pdf).
              "insurance_evidence_data": None, "insurance_evidence_status": None,
              "insurance_evidence_requests": [],
              # PAT-2251: estate enrolment keys. enrolment_keys_data is the
              # list GET /v1/portal/enrolment-keys returns (view rows, no
              # plaintext) - a fresh list per test, defaulting to [].
              "enrolment_keys_data": None, "enrolment_keys_list_status_override": None,
              "enrolment_keys_list_requests": 0,
              "enrolment_key_creates": 0, "enrolment_key_create_posts": [],
              "enrolment_key_create_status_override": None,
              "enrolment_key_revokes": 0, "enrolment_key_revoke_posts": [],
              "enrolment_key_revoke_status_override": None,
              # PAT-2263: GET /v1/portal/driver-findings.
              "driver_findings_data": None, "driver_findings_status": None,
              "driver_findings_requests": [],
              # PAT-2405: POST /v1/portal/exports/table-pdf (list exports as PDF).
              "table_pdf_posts": [], "table_pdf_status": None,
              "table_pdf_content_type": None}

OVERVIEW = {
    "tenant_name": "Acme Trust Ltd",
    "generated_at": "2026-07-02T10:15:00Z",
    "devices_total": 12,
    "devices_reporting_24h": 11,
    "cis_score_current": 84,
    "cis_trend": [
        {"date": "2026-12-25", "score": 78},
        {"date": "2026-12-28", "score": 81},
        {"date": "2026-07-01", "score": 84},
    ],
    "findings_open": {"critical": 1, "high": 3, "medium": 5, "low": 2},
    "patch_status": {"up_to_date": 9, "pending": 2, "failed": 1},
    "oldest_successful_ingest": "2026-12-15T09:00:00Z",
    "devices_degraded": 1,
    # PAT-2135: devices_retired deliberately left unset (reads as 0) in this
    # shared default fixture - many existing overview tests assert exact
    # "N devices"/"missing" figures derived from devices_total/
    # devices_reporting_24h above, and coverage_geometry already carves
    # devices_retired out of "missing" (see main.coverage_geometry and its
    # own unit tests, plus tests/test_pat2135_device_selfservice.py's
    # dedicated overview_data override for the retired-devices case).
}

# PAT-1859: deliberately non-reconciled aggregate values prove that the
# portal renders this dedicated platform read model as supplied. It must not
# sum benchmark rows, infer identifier mappings, or derive a new score.
CONTROL_COVERAGE = {
    "generated_at": "2026-09-20T10:15:00Z",
    "platforms": ["macos", "windows"],
    "controls": {
        "total": 83, "evaluated": 47, "out_of_scope": 9,
        "undetermined_evaluations": 13,
    },
    "measurements": {
        "pass": 31, "fail": 7, "undetermined": 13, "not_applicable": 5,
    },
    "identifiers": {"cis_mapped": 29, "cis_unmapped": 23, "non_cis": 17},
    "benchmarks": [
        {
            "benchmark": "CIS Apple macOS Benchmark", "benchmark_version": "3.1.0",
            "controls": {
                "total": 40, "evaluated": 25, "out_of_scope": 4,
                "undetermined_evaluations": 8,
            },
            "measurements": {
                "pass": 17, "fail": 4, "undetermined": 8, "not_applicable": 2,
            },
            "identifiers": {"cis_mapped": 17, "cis_unmapped": 12, "non_cis": 11},
        },
        {
            "benchmark": "CIS Microsoft Windows 11 Benchmark", "benchmark_version": "4.0.0",
            "controls": {
                "total": 39, "evaluated": 20, "out_of_scope": 3,
                "undetermined_evaluations": 5,
            },
            "measurements": {
                "pass": 10, "fail": 2, "undetermined": 5, "not_applicable": 3,
            },
            "identifiers": {"cis_mapped": 10, "cis_unmapped": 9, "non_cis": 8},
        },
    ],
    "total_zero": False,
}

# PAT-2190/PAT-2207: GET /v1/portal/overview/cards, the ten-card Overview
# summary read model (contracts/portal-api.md "overview/cards", mirrored by
# go-service/internal/report/portal_overview_cards.go). Every card carries
# state/source/scope/window/freshness/completeness/values/
# unavailable_signals, exactly as the contract's own worked example does -
# these fixtures follow that shape field-for-field rather than a portal-side
# shorthand, so a test asserting against them is really asserting against
# the wire contract.
#
# Three shapes:
#   OVERVIEW_CARDS        a routine day - a mix of value/zero/partial states.
#   OVERVIEW_CARDS_ZERO   a clean, checked-empty estate - every card that can
#                         read zero does; os_updates/agent_health, which the
#                         contract says can never be value or zero, read
#                         their nearest honest state instead (unavailable/
#                         unknown) rather than being forced into a false
#                         zero.
#   OVERVIEW_CARDS_MIXED  a spread of unknown/unavailable/partial so every
#                         non-value state has at least one card exercising
#                         it, alongside one plain value card as a control.
#
# recent_activity is always unavailable (not_yet_supported) in every shape -
# the contract states this is unconditional until PAT-2197.
_CARDS_GENERATED_AT = "2026-09-28T10:00:00Z"


def _card(state, source, scope="current_snapshot", window=None, observed_at=None,
          reason=None, values=None, unavailable_signals=None):
    return {
        "state": state,
        "source": source,
        "scope": scope,
        "window": window,
        "freshness": {"generated_at": _CARDS_GENERATED_AT, "observed_at": observed_at},
        "completeness": {"complete": state in ("value", "zero"), "reason": reason},
        "values": values,
        "unavailable_signals": unavailable_signals or [],
    }


OVERVIEW_CARDS = {
    "generated_at": _CARDS_GENERATED_AT,
    "thresholds": {
        "active_within_hours": 24, "silent_after_days": 14,
        "exception_review_due_within_days": 30,
    },
    "cards": {
        "devices": _card(
            "value", "devices.last_seen", observed_at="2026-09-28T09:58:12Z",
            values={"total": 6, "active": 2, "stale": 1, "silent": 1, "unknown": 1, "retired": 1},
        ),
        "os_updates": _card(
            "partial", "devices.pending_updates", observed_at="2026-09-28T09:58:12Z",
            reason="version_evidence_pending",
            values={"up_to_date": 4, "pending": 2, "unknown": 0},
        ),
        "vulnerabilities": _card(
            "value", "device_cve_findings", observed_at="2026-09-27T22:00:00Z",
            values={"critical": 2, "high": 5},
        ),
        "cis_posture": _card(
            "value", "compliance_evaluations", observed_at="2026-09-27T09:00:00Z",
            values={"score": 84.2, "evaluations": 120},
            unavailable_signals=[{"signal": "material_regression", "reason": "not_yet_supported"}],
        ),
        "browser_extensions": _card(
            "zero", "device_browser_extensions",
            values={"elevated": 0, "total": 18},
        ),
        "high_risk_software": _card(
            "value", "software_installations.first_seen_at", scope="bounded_window",
            window={
                "since": "2026-09-14T00:00:00Z", "until": _CARDS_GENERATED_AT,
                "days": 14, "basis": "default_window",
            },
            values={"critical": 1, "high": 2, "classified": 6},
        ),
        "software_awaiting_approval": _card(
            "value", "software_governance_estate",
            values={"products": 9, "devices": 14},
        ),
        "exceptions_review": _card(
            "zero", "tenant_software_exceptions",
            values={"review_overdue": 0, "review_due_soon": 0, "no_review_date": 2,
                    "unaccepted": 0, "total": 5},
            unavailable_signals=[{"signal": "expiry", "reason": "not_modelled"}],
        ),
        "agent_health": _card(
            "partial", "device_agent_health", observed_at="2026-09-28T09:58:12Z",
            reason="devices_not_reporting",
            values={"devices_degraded": 1, "devices_reporting": 3, "devices_not_reporting": 2,
                    "oldest_successful_ingest": "2026-12-15T09:00:00Z"},
        ),
        "recent_activity": _card(
            "unavailable", "activity_feed", scope="bounded_window", reason="not_yet_supported",
        ),
    },
}

OVERVIEW_CARDS_ZERO = {
    "generated_at": _CARDS_GENERATED_AT,
    "thresholds": OVERVIEW_CARDS["thresholds"],
    "cards": {
        "devices": _card(
            "zero", "devices.last_seen", observed_at=None,
            values={"total": 0, "active": 0, "stale": 0, "silent": 0, "unknown": 0, "retired": 0},
        ),
        # os_updates can never be value/zero (contract) - a clean estate
        # with no update evidence at all reads unavailable, not a false
        # "0 pending".
        "os_updates": _card("unavailable", "devices.pending_updates", reason="no_update_evidence"),
        "vulnerabilities": _card(
            "zero", "device_cve_findings", observed_at="2026-09-28T01:00:00Z",
            values={"critical": 0, "high": 0},
        ),
        # cis_posture with no evaluations yet is unknown, not a false clean
        # zero (the contract's own no_evaluations rule).
        "cis_posture": _card("unknown", "compliance_evaluations", reason="no_evaluations",
                              unavailable_signals=[{"signal": "material_regression",
                                                     "reason": "not_yet_supported"}]),
        "browser_extensions": _card("zero", "device_browser_extensions",
                                     values={"elevated": 0, "total": 0}),
        "high_risk_software": _card(
            "zero", "software_installations.first_seen_at", scope="bounded_window",
            window={"since": "2026-09-14T00:00:00Z", "until": _CARDS_GENERATED_AT,
                    "days": 14, "basis": "default_window"},
            values={"critical": 0, "high": 0, "classified": 0},
        ),
        "software_awaiting_approval": _card(
            "zero", "software_governance_estate", values={"products": 0, "devices": 0},
        ),
        "exceptions_review": _card(
            "zero", "tenant_software_exceptions",
            values={"review_overdue": 0, "review_due_soon": 0, "no_review_date": 0,
                    "unaccepted": 0, "total": 0},
            unavailable_signals=[{"signal": "expiry", "reason": "not_modelled"}],
        ),
        # agent_health with no non-retired devices is unknown (no_devices),
        # never a false clean zero.
        "agent_health": _card("unknown", "device_agent_health", reason="no_devices"),
        "recent_activity": _card(
            "unavailable", "activity_feed", scope="bounded_window", reason="not_yet_supported",
        ),
    },
}

OVERVIEW_CARDS_MIXED = {
    "generated_at": _CARDS_GENERATED_AT,
    "thresholds": OVERVIEW_CARDS["thresholds"],
    "cards": {
        # One plain value card as a control, so a test can tell "correctly
        # rendered as a value" apart from "accidentally rendered as
        # something else".
        "devices": _card(
            "value", "devices.last_seen", observed_at="2026-09-28T09:58:12Z",
            values={"total": 9, "active": 5, "stale": 2, "silent": 1, "unknown": 0, "retired": 1},
        ),
        "os_updates": _card("unavailable", "devices.pending_updates", reason="no_update_evidence"),
        # source not migrated yet on this tenant.
        "vulnerabilities": _card(
            "unavailable", "device_cve_findings", reason="source_not_migrated",
        ),
        "cis_posture": _card("unknown", "compliance_evaluations", reason="no_evaluations"),
        "browser_extensions": _card(
            "partial", "device_browser_extensions", reason="truncated",
            values={"elevated": 3, "total": 500},
        ),
        "high_risk_software": _card(
            "partial", "software_installations.first_seen_at", scope="bounded_window",
            window={"since": "2026-09-14T00:00:00Z", "until": _CARDS_GENERATED_AT,
                    "days": 14, "basis": "default_window"},
            reason="coverage_incomplete",
            values={"critical": 0, "high": 1, "classified": 4},
        ),
        "software_awaiting_approval": _card("unavailable", "software_governance_estate",
                                             reason="estate_too_large"),
        "exceptions_review": _card("unavailable", "tenant_software_exceptions",
                                    reason="source_not_migrated",
                                    unavailable_signals=[{"signal": "expiry",
                                                           "reason": "not_modelled"}]),
        "agent_health": _card("unavailable", "device_agent_health", reason="source_not_migrated"),
        "recent_activity": _card(
            "unavailable", "activity_feed", scope="bounded_window", reason="not_yet_supported",
        ),
    },
}


def _iso_days_ago(days: float) -> str:
    """Roster timestamps are relative to the wall clock so staleness maths
    stays stable however long these fixtures live (PAT-701)."""
    return (datetime.now(UTC) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


STALE_DEVICE_DAYS = 10

DEVICES = {
    "devices": [
        {
            "device_id": "dev-mac-001",
            "hostname": "acme-mbp-frontdesk",
            "platform": "macOS",
            "os_version": "15.5",
            # PAT-2324: a Mac is always a workstation and has no caption.
            "device_class": "workstation",
            "os_caption": None,
            "last_seen": _iso_days_ago(0.04),
            "cis_score": 91,
            # PAT-2294: matches DEVICE_DETAIL below, whose signals hold one
            # failing check, so the list and the device page read one figure.
            "findings_open": 1,
            "encryption_ok": True,
            "patch_pending": False,
            # PAT-2025: assessed, with two current CVE matches.
            "cve_assessment": {
                "state": "assessed", "last_matched_at": "2026-07-02T09:00:00Z",
                "finding_count": 2, "assessed_products": 2,
                "pending_products": 1, "not_assessed_products": 1,
            },
        },
        {
            "device_id": "dev-win-002",
            "hostname": "acme-win-accounts",
            "platform": "Windows",
            # PAT-2256: a real Windows build number (what the agent sends), and
            # the update state the platform actually returns for every Windows
            # device today: null, because patch_pending is derived only from
            # the macOS-only pending_updates list. The walker was green on the
            # live page's overlap and mid-number wrap because this row used to
            # read "11 24H2" and an answered update state.
            "os_version": "10.0.26200.8457",
            # PAT-2324: a Windows workstation the platform has classified.
            "device_class": "workstation",
            "os_caption": "Microsoft Windows 11 Enterprise",
            "last_seen": _iso_days_ago(1.2),
            "cis_score": 30.76923076923077,
            "findings_open": 6,
            "encryption_ok": False,
            "patch_pending": None,
            # PAT-2025: at least one mapped product queued, none matched yet.
            "cve_assessment": {
                "state": "pending", "last_matched_at": None, "finding_count": None,
                "assessed_products": 1, "pending_products": 2,
                "not_assessed_products": 0,
            },
        },
        {
            "device_id": "dev-mac-003",
            "hostname": "acme-mbp-storeroom",
            "platform": "macOS",
            "os_version": "14.7",
            "last_seen": _iso_days_ago(STALE_DEVICE_DAYS),
            "cis_score": 74,
            "findings_open": 1,
            "encryption_ok": True,
            "patch_pending": False,
            # PAT-2025: a device where every installed product is not yet
            # assessed - no CPE mapping covers anything on it.
            "cve_assessment": {
                "state": "not_assessed", "last_matched_at": None, "finding_count": None,
                "assessed_products": 0, "pending_products": 0,
                "not_assessed_products": 3,
            },
        },
        # PAT-2135: a plain retired device - long silent, but excluded from
        # the silent/quiet/normal grouping and from "not reporting" counts
        # because it is the customer's own decision, not a coverage gap.
        {
            "device_id": "dev-mac-004",
            "hostname": "acme-mbp-retired",
            "platform": "macOS",
            "os_version": "14.5",
            "last_seen": _iso_days_ago(40),
            "cis_score": 55,
            "findings_open": 0,
            "encryption_ok": True,
            "patch_pending": False,
            "cve_assessment": {
                "state": "not_assessed", "last_matched_at": None, "finding_count": None,
                "assessed_products": 0, "pending_products": 0,
                "not_assessed_products": 1,
            },
            "retirement": {
                "retired_at": "2026-08-01T09:00:00Z", "retired_by": "admin@tenant-a.example",
                "reason": "Written off after theft", "reported_after_retirement": False,
            },
        },
        # PAT-2135: retired, but it has reported again since - the
        # "Reported after retirement" warning pill this needs.
        {
            "device_id": "dev-mac-005",
            "hostname": "acme-mbp-zombie",
            "platform": "macOS",
            "os_version": "15.1",
            "last_seen": _iso_days_ago(0.5),
            "cis_score": 88,
            "findings_open": 0,
            "encryption_ok": True,
            "patch_pending": False,
            "cve_assessment": {
                "state": "not_assessed", "last_matched_at": None, "finding_count": None,
                "assessed_products": 0, "pending_products": 0,
                "not_assessed_products": 1,
            },
            "retirement": {
                "retired_at": "2026-08-15T09:00:00Z", "retired_by": "admin@tenant-a.example",
                "reason": None, "reported_after_retirement": True,
            },
        },
        # PAT-2324: a Windows Server the platform has classified as a server.
        # Reporting normally (so the default Normal tab shows it), with a real
        # Windows Server build number and caption, and a CIS score (measured
        # against the workstation benchmark, as there is no server one yet).
        {
            "device_id": "dev-win-101",
            "hostname": "acme-win-dc1",
            "platform": "Windows",
            "os_version": "10.0.20348.5499",
            "device_class": "server",
            "os_caption": "Microsoft Windows Server 2022 Standard",
            "last_seen": _iso_days_ago(0.3),
            "cis_score": 62.5,
            "findings_open": 4,
            # PAT-2496: the agent could not read this server's encryption
            # state, so the roster reads "Not assessed" and the BitLocker rule
            # in DEVICE_DETAIL_DEV_WIN_101 below is undetermined.
            "encryption_ok": None,
            "patch_pending": None,
            "cve_assessment": {
                "state": "not_assessed", "last_matched_at": None, "finding_count": None,
                "assessed_products": 0, "pending_products": 0,
                "not_assessed_products": 2,
            },
        },
    ]
}

# PAT-2141: additive identity/hardware blocks (contracts/portal-api.md
# "GET /v1/portal/devices/{deviceID}" - "identity and hardware (PAT-2141)").
# dev-mac-001 is the fully-collected device: every field and every hardware
# sub-block present and complete, so the unit/e2e suites have one device
# proving real values render (serial, model identifier, CPU, memory, a
# SMART-verified internal SSD, a volume past the 90% warning threshold, and
# a Normal-condition battery).
DEVICE_DETAIL_IDENTITY = {
    "status": "complete",
    "serial": "C02XL0GTJGH5",
    "hardware_model": "Mac16,1",
    "computer_name": "Alice's MacBook Pro",
    "architecture": "arm64",
    "os_name": "macOS",
    "os_version": "15.5",
    "os_build": "24F74",
    "agent_version": "0.19.23",
    "first_seen": "2026-11-01T09:12:44Z",
    "last_seen": "2026-07-02T09:58:00Z",
    "evidence": {
        "observed_at": "2026-07-02T09:40:42Z",
        "received_at": "2026-07-02T09:58:00Z",
        "freshness": "fresh",
    },
}
DEVICE_DETAIL_HARDWARE = {
    "status": "complete",
    "evidence": {
        "observed_at": "2026-07-02T09:40:42Z",
        "received_at": "2026-07-02T09:58:00Z",
        "freshness": "fresh",
    },
    "cpu": {"status": "complete", "model": "Apple M2", "cores": 8},
    "memory": {"status": "complete", "total_gb": 16},
    "disks": {
        "status": "complete",
        "items": [
            {"device": "disk0", "smart_status": "Verified", "internal": True, "solid_state": True},
        ],
    },
    "volumes": {
        "status": "complete",
        "items": [
            # Deliberately past the 90%-used warning threshold (PAT-2141
            # Done-when: a volume >=90% used gets the warning treatment).
            {"mount": "/", "total_bytes": 494384795648, "free_bytes": 32135159808, "used_pct": 93},
            # A real Mac's APFS system sub-volumes (Andy's MacBook, 25 Sept
            # 2026): they share the "/" container and collapse into a
            # disclosure rather than burying the volumes that matter.
            {"mount": "/System/Volumes/Data",
             "total_bytes": 494384795648, "free_bytes": 14100000000, "used_pct": 97},
            {"mount": "/System/Volumes/Hardware",
             "total_bytes": 524288000, "free_bytes": 503316480, "used_pct": 4},
            {"mount": "/System/Volumes/Preboot",
             "total_bytes": 494384795648, "free_bytes": 14100000000, "used_pct": 97},
            {"mount": "/System/Volumes/VM",
             "total_bytes": 494384795648, "free_bytes": 14100000000, "used_pct": 97},
            {"mount": "/Volumes/DEV_BACKUP",
             "total_bytes": 15500000000, "free_bytes": 12000000000, "used_pct": 22},
        ],
    },
    "battery": {
        "status": "complete", "present": True, "cycle_count": 30,
        "condition": "Normal", "max_capacity_pct": 100,
    },
}

DEVICE_DETAIL = {
    "device_id": "dev-mac-001",
    "hostname": "acme-mbp-frontdesk",
    "platform": "macOS",
    "os_version": "15.5",
    # PAT-2324: the platform's additive classification (a Mac is always a
    # workstation with no caption); every stub derived from this fixture
    # inherits it unless it passes its own.
    "device_class": "workstation",
    "os_caption": None,
    "last_seen": "2026-07-02T09:58:00Z",
    "cis_score": 64.70588235294117,
    # PAT-2294: the three summary figures the platform now returns on this
    # route, the same values as this device's DEVICES roster row.
    # findings_open agrees with the compliance_signals below (one failing
    # check), so the existing tile expectations hold; the stubs derived from
    # this fixture take the figures of their own roster row instead, and
    # several of those differ from their signals on purpose.
    "findings_open": 1,
    "encryption_ok": True,
    "patch_pending": False,
    "identity": DEVICE_DETAIL_IDENTITY,
    "hardware": DEVICE_DETAIL_HARDWARE,
    "compliance_signals": [
        {
            "rule_id": "cis-1.1",
            "title": "Automatic software updates enabled",
            "severity": "high",
            "status": "pass",
            "advisory": "",
        },
        {
            "rule_id": "cis-2.6",
            "title": "Firewall enabled",
            "severity": "critical",
            "status": "fail",
            "advisory": "Enable the application firewall in System Settings.",
        },
    ],
    "apps_with_findings": [
        {
            "app": "ExampleBrowser",
            "version": "124.0.1",
            "cve_ids": ["CVE-2026-1234", "CVE-2026-5678"],
            "max_severity": "high",
            "match_confidence": "version_confirmed",
            "fixed_version": "125.0.0",
        }
    ],
    # PAT-2025 (contracts/portal-api.md "CVE assessment state (PAT-2024)"):
    # one product per state - ExampleBrowser is assessed with two matches
    # (mirrors apps_with_findings above, so the severity join has something
    # to find), CleanApp is assessed with zero (a genuine "No known CVEs",
    # never confused with QueuedApp/In-House Tool below), QueuedApp is
    # mapped but not matched yet, and In-House Tool has no mapping at all.
    "cve_assessment": {
        "state": "assessed", "last_matched_at": "2026-07-02T09:00:00Z",
        "finding_count": 2, "assessed_products": 2, "pending_products": 1,
        "not_assessed_products": 1,
        "products": [
            {"app": "ExampleBrowser", "versions": ["124.0.1"], "state": "assessed",
             "last_matched_at": "2026-07-02T09:00:00Z", "finding_count": 2},
            {"app": "CleanApp", "versions": ["1.0"], "state": "assessed",
             "last_matched_at": "2026-07-02T09:00:00Z", "finding_count": 0},
            {"app": "QueuedApp", "versions": ["2.0"], "state": "pending",
             "last_matched_at": None, "finding_count": None},
            {"app": "In-House Tool", "versions": ["3.1"], "state": "not_assessed",
             "last_matched_at": None, "finding_count": None},
        ],
    },
}

# PAT-2141: the not_collected counterpart to DEVICE_DETAIL_IDENTITY/
# DEVICE_DETAIL_HARDWARE above - a device row that exists but has never
# delivered a payload the identity/hardware extraction could read. Battery
# fields stay omitted together with status, never a false "present": false
# standing in for "no battery data" (contracts/portal-api.md's own rule).
DEVICE_DETAIL_IDENTITY_NOT_COLLECTED = {"status": "not_collected"}
DEVICE_DETAIL_HARDWARE_NOT_COLLECTED = {
    "status": "not_collected",
    "cpu": {"status": "not_collected"},
    "memory": {"status": "not_collected"},
    "disks": {"status": "not_collected"},
    "volumes": {"status": "not_collected"},
    "battery": {"status": "not_collected"},
}

# PAT-2025: a device detail response where every product is not_assessed -
# no CPE mapping covers anything installed on it. Used to prove the whole
# page renders honestly (never "No known CVEs") when nothing can be stated.
# PAT-2141 reuses it as the not_collected identity/hardware device too - a
# device this thin on CVE assessment is a plausible one to have never sent
# an inventory payload either, and it means every fixture derived from it
# below (dev-mac-002, dev-mac-003, dev-win-002) exercises the not_collected
# render path rather than silently inheriting dev-mac-001's complete data.
DEVICE_DETAIL_ALL_NOT_ASSESSED = {
    **{k: v for k, v in DEVICE_DETAIL.items()
       if k not in ("apps_with_findings", "cve_assessment", "identity", "hardware")},
    "identity": DEVICE_DETAIL_IDENTITY_NOT_COLLECTED,
    "hardware": DEVICE_DETAIL_HARDWARE_NOT_COLLECTED,
    "apps_with_findings": [],
    "cve_assessment": {
        "state": "not_assessed", "last_matched_at": None, "finding_count": None,
        "assessed_products": 0, "pending_products": 0, "not_assessed_products": 2,
        "products": [
            {"app": "In-House Tool", "versions": ["3.1"], "state": "not_assessed",
             "last_matched_at": None, "finding_count": None},
            {"app": "Legacy Utility", "versions": ["0.9"], "state": "not_assessed",
             "last_matched_at": None, "finding_count": None},
        ],
    },
}


# PAT-2294: the keys the platform nests under `device` on GET
# /v1/portal/devices/{id} (contracts/portal-api.md). Everything else on that
# response (compliance_signals, apps_with_findings, cve_assessment, identity,
# hardware, ...) is a top-level sibling of `device`. The fixtures in this file
# are flat, which the portal also reads, so tests that want the real shape
# wrap one with platform_shaped_detail().
DEVICE_LEVEL_KEYS = (
    "device_id", "hostname", "serial", "platform", "os_version", "os_caption", "device_class",
    "os_build",
    "first_seen", "last_seen", "cis_score", "findings_open", "encryption_ok",
    "patch_pending", "retirement", "evidence",
)


def platform_shaped_detail(flat: dict, **device_fields) -> dict:
    """The flat detail fixture `flat` in the shape the real platform sends:
    device-level fields (including findings_open, encryption_ok and
    patch_pending) under `device`, the rest beside it. `device_fields`
    overrides or adds device-level values; pass None to send a JSON null. A
    field to leave out entirely is removed with `del result["device"][key]`."""
    device = {k: v for k, v in flat.items() if k in DEVICE_LEVEL_KEYS}
    device.update(device_fields)
    rest = {k: v for k, v in flat.items() if k not in DEVICE_LEVEL_KEYS}
    return {"generated_at": "2026-09-29T12:00:00Z", "device": device, **rest}


def _roster_figures(device_id: str) -> dict:
    """The findings_open / encryption_ok / patch_pending of this device's
    DEVICES roster row, or {} when it has none. The platform computes the
    three with the same code for the list and the device page (PAT-2294), so
    a stub detail response for a roster device must carry its row's values,
    not whatever DEVICE_DETAIL happens to hold."""
    for row in DEVICES["devices"]:
        if row["device_id"] == device_id:
            return {k: row[k] for k in ("findings_open", "encryption_ok", "patch_pending")}
    return {}


def _device_detail_stub(device_id: str, hostname: str, platform: str, os_version: str,
                        retirement=None, **device_fields) -> dict:
    """Minimal-but-valid GET /v1/portal/devices/{id} response for a device
    the list fixtures (DEVICES, EXTENSIONS, ALERTS, ...) link to but that
    doesn't need its own bespoke detail fixture - PAT-2128 follow-up. Every
    device id those list fixtures reference must resolve here (or in
    DEVICE_DETAIL/DEVICE_DETAIL_ALL_NOT_ASSESSED above) so a walked detail
    link is never a false 404 the walker has to report as noise. PAT-2135:
    an optional retirement block, carried straight through as the roster
    row's own (so a device page opened for a retired roster device sees
    the same retirement state the list did). PAT-2294: a roster device also
    carries its row's findings_open / encryption_ok / patch_pending, which
    for dev-win-002 (six failing, signals imply one) proves the platform's
    figure, not the signal count, is what the device page shows."""
    return {
        **{k: v for k, v in DEVICE_DETAIL_ALL_NOT_ASSESSED.items()
           if k not in ("device_id", "hostname", "platform", "os_version")},
        "device_id": device_id, "hostname": hostname,
        "platform": platform, "os_version": os_version,
        "retirement": retirement,
        **_roster_figures(device_id),
        **device_fields,
    }


# PAT-2496: a Windows disk-encryption rule result without the platform's
# `undetermined` flag; each fixture device below adds the flag itself.
# dev-mac-001's DEVICE_DETAIL rows carry no `undetermined` at all, which is
# what a platform that predates the field sends.
BITLOCKER_RULE = {
    "rule_id": "cis_win_bitlocker_system_drive",
    "title": "BitLocker protects the system drive",
    "severity": "high",
    "status": "fail",
    "advisory": "Turn on BitLocker for the operating system drive.",
}

# One device-detail fixture for every id DEVICES/EXTENSIONS/ALERTS link to
# that isn't dev-mac-001 (which keeps its bespoke DEVICE_DETAIL above) -
# PAT-2128 follow-up. dev-win-002/dev-mac-003 are DEVICES rows; dev-mac-002
# only ever appears as a linked device on EXTENSIONS/ALERTS rows (hostname
# "LT-0043" there), never in DEVICES itself.
# PAT-2294: served in the platform's real shape (device fields under
# `device`), so the browser suites exercise that path once; every other
# stub stays flat.
DEVICE_DETAIL_DEV_WIN_002 = platform_shaped_detail(_device_detail_stub(
    "dev-win-002", "acme-win-accounts", "Windows", "11 24H2",
    device_class="workstation", os_caption="Microsoft Windows 11 Enterprise",
    # PAT-2496: an observed failure (`undetermined` false) on the device whose
    # roster row says encryption_ok false.
    compliance_signals=[
        *DEVICE_DETAIL["compliance_signals"],
        {**BITLOCKER_RULE, "undetermined": False},
    ]))
DEVICE_DETAIL_DEV_MAC_002 = _device_detail_stub(
    "dev-mac-002", "LT-0043", "macOS", "14.6")
DEVICE_DETAIL_DEV_MAC_003 = _device_detail_stub(
    "dev-mac-003", "acme-mbp-storeroom", "macOS", "14.7")
# PAT-2135: detail fixtures for the two retired roster devices above -
# same retirement block as their DEVICES row, so opening either device
# page directly shows the same retired/reported-after-retirement state.
DEVICE_DETAIL_DEV_MAC_004 = _device_detail_stub(
    "dev-mac-004", "acme-mbp-retired", "macOS", "14.5",
    retirement={"retired_at": "2026-08-01T09:00:00Z", "retired_by": "admin@tenant-a.example",
                "reason": "Written off after theft", "reported_after_retirement": False})
DEVICE_DETAIL_DEV_MAC_005 = _device_detail_stub(
    "dev-mac-005", "acme-mbp-zombie", "macOS", "15.1",
    retirement={"retired_at": "2026-08-15T09:00:00Z", "retired_by": "admin@tenant-a.example",
                "reason": None, "reported_after_retirement": True})
# PAT-2145: three more non-retired Mac ids, needed only so the Jamf
# coverage buckets below can each reference a distinct device with its own
# detail stub (a broken /devices/{id} link is walker noise otherwise - see
# the PAT-2128 follow-up comment above _device_detail_stub).
DEVICE_DETAIL_DEV_MAC_006 = _device_detail_stub("dev-mac-006", "acme-mbp-pending", "macOS", "15.4")
DEVICE_DETAIL_DEV_MAC_007 = _device_detail_stub(
    "dev-mac-007", "acme-mbp-unidentified", "macOS", "15.4")
DEVICE_DETAIL_DEV_MAC_008 = _device_detail_stub(
    "dev-mac-008", "acme-mbp-unknownstate", "macOS", "15.4")
DEVICE_DETAIL_DEV_MAC_009 = _device_detail_stub(
    "dev-mac-009", "acme-mbp-uuidmatch", "macOS", "15.2")
# PAT-2215: the two Windows devices LOCAL_ADMINS_DATA links its By-device
# rows and its By-account device lists to (dev-mac-001 above already has a
# bespoke detail fixture, so it needs no entry here) - same PAT-2128
# follow-up rule: a device id a page links to must resolve here or the
# link check has to report it as a broken link, not walker noise.
# PAT-2324: also a DEVICES roster row now, the stub's one Windows Server, so
# this detail response carries the same class and caption as that row.
DEVICE_DETAIL_DEV_WIN_101 = _device_detail_stub(
    "dev-win-101", "acme-win-dc1", "Windows", "10.0.20348.5499",
    device_class="server", os_caption="Microsoft Windows Server 2022 Standard",
    # PAT-2496: the rule failed only because the value was unreadable (the
    # roster row's encryption_ok is null), so the platform marks it
    # `undetermined` and the Compliance tab reads "Not assessed".
    compliance_signals=[
        *DEVICE_DETAIL["compliance_signals"],
        {**BITLOCKER_RULE, "undetermined": True},
    ])
DEVICE_DETAIL_DEV_WIN_102 = _device_detail_stub(
    "dev-win-102", "acme-win-unreadable", "Windows", "11 24H2")

# PAT-2145: Jamf Pro coverage (GET/PUT /v1/portal/mdm/jamf/setup, POST/
# DELETE /v1/portal/mdm/jamf/token, DELETE /v1/portal/mdm/jamf/devices,
# GET /v1/portal/mdm/jamf/coverage). STUB_STATE["jamf_mode"] drives the
# connector's shape: "not_configured" (never connected), "ok", "amber"
# (no event in 24h) or "revoked". Rows are fixed fixtures covering every
# bucket and every not_reported_by_jamf mdm_state; only the connector/
# basis/counts vary with jamf_mode, matching how the real reconciliation
# only ever removes rows entirely (no backfill) rather than reshaping them.
JAMF_WEBHOOK_ID = "q3XbTestWebhookId000001"
JAMF_WEBHOOK_URL = f"https://api.patched.im/v1/webhooks/jamf/{JAMF_WEBHOOK_ID}"

JAMF_EVENTS_BASE = [
    {"event": "ComputerAdded", "required": True, "purpose": "a Mac enrolled in Jamf Pro"},
    {"event": "ComputerInventoryCompleted", "required": True,
     "purpose": "a Mac sent Jamf its inventory"},
    {"event": "DeviceAddedToDEP", "required": True,
     "purpose": "a Mac was assigned to Jamf in Apple Business Manager"},
    {"event": "ComputerCheckIn", "required": False,
     "purpose": "optional: a Mac checked in (collapsed to one update per Mac per hour)"},
]

JAMF_AUTHENTICATION = {
    "type": "Header Authentication", "content_type": "JSON",
    "header_json": ('{"Authorization":"Bearer <your webhook token>",'
                    '"X-Patched-Jamf-Instance":"https://<your instance>.jamfcloud.com"}'),
    "alternative": "Basic Authentication with any username and the webhook token as the password",
    "instance_header_note": (
        "The X-Patched-Jamf-Instance header is optional. Jamf Pro webhooks do not name the "
        "Jamf Pro server, so this is how Patched records which instance the events come from "
        "and flags a change."),
}

# gap: Jamf reports it, Patched has never seen it - no device_id, no link.
JAMF_GAP_ROWS = [
    {"jamf_id": 61, "serial": "C02SILENT01", "udid": None, "device_name": "acme-mbp-silent",
     "model": "MacBookPro18,3", "os_version": "15.6", "jamf_state": "enrolled",
     "first_jamf_event_at": "2026-08-01T09:00:00Z", "last_jamf_event_at": "2026-08-10T09:00:00Z",
     "last_jamf_event_type": "ComputerAdded", "days_since_jamf_event": 47,
     "note": "not heard from Jamf in 47 days"},
    {"jamf_id": 62, "serial": None, "udid": "ABCDEF12-3456-7890-ABCD-EF1234567890",
     "device_name": "acme-mbp-newhire", "model": "MacBookAir15,2", "os_version": "15.6",
     "jamf_state": "dep_assigned_only", "first_jamf_event_at": "2026-09-20T09:00:00Z",
     "last_jamf_event_at": "2026-09-20T09:00:00Z", "last_jamf_event_type": "DeviceAddedToDEP",
     "days_since_jamf_event": 6,
     "note": "assigned to Jamf in Apple Business Manager, no enrolment event from Jamf since"},
]

# not_reported_by_jamf: one row per mdm_state, each device_id a distinct
# non-retired Mac with its own detail stub above.
JAMF_NOT_REPORTED_ROWS = [
    {"device_id": "dev-mac-002", "hostname": "LT-0043", "serial": None, "os_version": "14.6",
     "last_seen": "2026-09-26T08:00:00Z", "mdm_state": "other_mdm",
     "mdm_vendor": "Microsoft Intune", "mdm_server_host": "i.manage.microsoft.com",
     "note": "enrolled with Microsoft Intune (i.manage.microsoft.com)"},
    {"device_id": "dev-mac-006", "hostname": "acme-mbp-pending", "serial": "C02PENDING01",
     "os_version": "15.4", "last_seen": "2026-09-25T09:00:00Z", "mdm_state": "jamf_no_event_yet",
     "mdm_vendor": "Jamf", "mdm_server_host": "acme.jamfcloud.com",
     "note": ("the Mac reports enrolment with Jamf (acme.jamfcloud.com), but Jamf has sent no "
              "event for it since setup")},
    {"device_id": "dev-mac-007", "hostname": "acme-mbp-unidentified", "serial": "C02UNIDENT01",
     "os_version": "15.4", "last_seen": "2026-09-24T09:00:00Z",
     "mdm_state": "enrolled_mdm_unidentified", "mdm_vendor": None, "mdm_server_host": None,
     "note": "the Mac reports MDM enrolment, but not which server"},
    # PAT-2145 rule: "unmanaged" only ever means the agent itself reported
    # no MDM enrolment - never inferred from Jamf's silence.
    {"device_id": "dev-mac-003", "hostname": "acme-mbp-storeroom", "serial": None,
     "os_version": "14.7", "last_seen": "2026-09-20T09:00:00Z", "mdm_state": "unmanaged",
     "mdm_vendor": None, "mdm_server_host": None, "note": "the Mac reports no MDM enrolment"},
    {"device_id": "dev-mac-008", "hostname": "acme-mbp-unknownstate", "serial": "C02UNKNOWN01",
     "os_version": "15.4", "last_seen": "2026-09-23T09:00:00Z", "mdm_state": "unknown",
     "mdm_vendor": None, "mdm_server_host": None,
     "note": "no MDM enrolment evidence from the agent yet"},
]

# covered: both. One serial match, one UDID match.
JAMF_COVERED_ROWS = [
    {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk", "serial": "C02XL0GTJGH5",
     "last_seen": "2026-09-26T09:58:00Z", "jamf_id": 63, "jamf_device_name": "acme-mbp-frontdesk",
     "last_jamf_event_at": "2026-09-26T08:00:00Z", "days_since_jamf_event": 0,
     "match_basis": "serial", "note": ""},
    {"device_id": "dev-mac-009", "hostname": "acme-mbp-uuidmatch", "serial": None,
     "last_seen": "2026-09-10T09:00:00Z", "jamf_id": 64, "jamf_device_name": "acme-mbp-uuidmatch",
     "last_jamf_event_at": "2026-08-01T09:00:00Z", "days_since_jamf_event": 56,
     "match_basis": "udid", "note": "not heard from Jamf in 56 days"},
]

JAMF_INSTANCE_PINNED = {"url": "https://acme.jamfcloud.com",
                        "last_claimed": "https://acme.jamfcloud.com",
                        "mismatch": False, "mismatch_seen_at": None}
JAMF_INSTANCE_NONE = {
    "url": None, "last_claimed": None, "mismatch": False, "mismatch_seen_at": None}


def _jamf_connector(mode: str) -> dict:
    if mode == "amber":
        return {"status": "amber", "amber": True,
                "message": "No Jamf event in the last 24 hours. Check the webhooks in Jamf Pro.",
                "token_active": True, "first_event_at": "2026-08-01T09:00:00Z",
                "last_event_at": "2026-09-24T09:00:00Z", "hours_since_last_event": 48,
                "events_rejected": 0, "last_rejected_at": None, "last_rejected_reason": None,
                "check_in_enabled": STUB_STATE.get("jamf_check_in_enabled", False),
                "amber_after_hours": 24, "jamf_instance": JAMF_INSTANCE_PINNED}
    if mode == "revoked":
        return {"status": "revoked", "amber": True,
                "message": ("The webhook token is revoked, so Jamf events are refused. An admin "
                            "can create a new token."),
                "token_active": False, "first_event_at": "2026-08-01T09:00:00Z",
                "last_event_at": "2026-09-20T09:00:00Z", "hours_since_last_event": 140,
                "events_rejected": 3, "last_rejected_at": "2026-09-21T09:00:00Z",
                "last_rejected_reason": "token_revoked",
                "check_in_enabled": STUB_STATE.get("jamf_check_in_enabled", False),
                "amber_after_hours": 24, "jamf_instance": JAMF_INSTANCE_PINNED}
    if mode == "not_configured":
        return {"status": "not_configured", "amber": False,
                "message": ("Jamf is not connected. An admin can create a webhook token on the "
                            "setup page."),
                "token_active": False, "first_event_at": None, "last_event_at": None,
                "hours_since_last_event": None, "events_rejected": 0, "last_rejected_at": None,
                "last_rejected_reason": None, "check_in_enabled": False, "amber_after_hours": 24,
                "jamf_instance": JAMF_INSTANCE_NONE}
    return {"status": "ok", "amber": False, "message": "Receiving Jamf events.",
            "token_active": True, "first_event_at": "2026-09-01T09:12:00Z",
            "last_event_at": "2026-09-26T08:00:00Z", "hours_since_last_event": 3,
            "events_rejected": 0, "last_rejected_at": None, "last_rejected_reason": None,
            "check_in_enabled": STUB_STATE.get("jamf_check_in_enabled", False),
            "amber_after_hours": 24,
            "jamf_instance": (JAMF_INSTANCE_NONE if STUB_STATE.get("jamf_instance_reset")
                              else JAMF_INSTANCE_PINNED)}


def _jamf_basis(mode: str) -> dict:
    base = {
        "no_backfill": (
            "Patched only knows Macs Jamf has sent a webhook for since setup. A Mac Jamf has "
            "not reported since then is not in these lists yet, so a Mac missing from 'managed "
            "by Jamf' is not evidence Jamf does not manage it."),
        "no_delete_event": (
            "Jamf Pro sends no event when a Mac is removed. A Mac that goes quiet is shown as "
            "'not heard from Jamf in N days', never as removed or unmanaged."),
        "silent_after_days": 30, "match_basis": "serial_then_udid",
        "scope": ("macOS devices only. Devices you have retired are left out, as on every "
                 "other page."),
        "seed": ("To cover Macs Jamf had before setup, upload a Jamf Pro computer export as "
                "your device list on the Devices page."),
    }
    if mode == "not_configured":
        return {**base, "since": None, "statement": "No Jamf webhook has been received yet."}
    return {**base, "since": "2026-09-01T09:12:00Z",
           "statement": "From Jamf webhooks since 1 September 2026."}


def _jamf_counts(mode: str) -> dict:
    if mode == "not_configured":
        return {"gap": 0, "gap_dep_assigned_only": 0, "gap_silent": 0,
                "not_reported_by_jamf": 0,
                "not_reported_by_jamf_by_mdm_state": {
                    "other_mdm": 0, "jamf_no_event_yet": 0, "enrolled_mdm_unidentified": 0,
                    "unmanaged": 0, "unknown": 0},
                "agent_reports_no_mdm": 0, "covered": 0, "covered_jamf_silent": 0,
                "jamf_devices_total": 0, "retired_excluded": 0, "non_mac_devices_excluded": 0}
    rows = _jamf_bucket_rows(mode)
    return {"gap": len(rows["gap"]),
            "gap_dep_assigned_only": sum(r.get("jamf_state") == "dep_assigned_only"
                                         for r in rows["gap"]),
            "gap_silent": sum(r.get("days_since_jamf_event", 0) >= 30 for r in rows["gap"]),
            "not_reported_by_jamf": len(JAMF_NOT_REPORTED_ROWS),
            "not_reported_by_jamf_by_mdm_state": {
                "other_mdm": 1, "jamf_no_event_yet": 1, "enrolled_mdm_unidentified": 1,
                "unmanaged": 1, "unknown": 1},
            "agent_reports_no_mdm": 1, "covered": len(rows["covered"]),
            "covered_jamf_silent": sum(r.get("days_since_jamf_event", 0) >= 30
                                        for r in rows["covered"]),
            "jamf_devices_total": len(rows["gap"]) + len(rows["covered"]),
            "retired_excluded": 1, "non_mac_devices_excluded": 1}


def _jamf_bucket_rows(mode: str) -> dict:
    if mode == "not_configured":
        return {"gap": [], "not_reported_by_jamf": [], "covered": []}
    deleted = STUB_STATE.get("jamf_deleted_ids", set())
    return {"gap": [r for r in JAMF_GAP_ROWS if r["jamf_id"] not in deleted],
            "not_reported_by_jamf": JAMF_NOT_REPORTED_ROWS,
            "covered": [r for r in JAMF_COVERED_ROWS if r["jamf_id"] not in deleted]}


def _jamf_coverage_response(bucket: str, limit: int, offset: int) -> dict:
    mode = STUB_STATE.get("jamf_mode", "not_configured")
    out = {"generated_at": "2026-09-26T12:00:00Z", "connector": _jamf_connector(mode),
          "basis": _jamf_basis(mode), "counts": _jamf_counts(mode),
          "bucket": bucket or None, "limit": limit, "offset": offset}
    all_rows = _jamf_bucket_rows(mode)
    for key, rows in all_rows.items():
        if bucket and bucket != key:
            continue
        out[key] = {"total": len(rows), "rows": rows[offset:offset + limit]}
    return out


def _jamf_setup_response() -> dict:
    mode = STUB_STATE.get("jamf_mode", "not_configured")
    configured = mode != "not_configured"
    token_active = configured and STUB_STATE.get("jamf_token_state", "active") == "active"
    check_in_enabled = STUB_STATE.get("jamf_check_in_enabled", False)
    events = [{"event": e["event"], "required": e["required"],
               "subscribed": e["required"] or check_in_enabled, "purpose": e["purpose"]}
             for e in JAMF_EVENTS_BASE]
    token = {"exists": token_active,
            "created_at": "2026-09-01T09:00:00Z" if configured else None,
            "issued_at": "2026-09-01T09:00:00Z" if token_active else None,
            "last_rotated_at": STUB_STATE.get("jamf_token_rotated_at") if token_active else None,
            "revoked_at": STUB_STATE.get("jamf_token_revoked_at"),
            "plaintext_shown": "once, when created or rotated"}
    return {
        "configured": configured,
        "webhook_url": JAMF_WEBHOOK_URL if configured else None,
        "token": token, "check_in_enabled": check_in_enabled, "events": events,
        "authentication": JAMF_AUTHENTICATION,
        "jamf_instance": (
            JAMF_INSTANCE_NONE if not configured or STUB_STATE.get("jamf_instance_reset")
            else JAMF_INSTANCE_PINNED),
        "patched_holds": "no Jamf credential; Jamf Pro pushes webhooks to Patched",
    }


JAMF_COVERAGE_CSV_HEADER = [
    "bucket", "device_id", "hostname", "serial", "udid", "jamf_id", "jamf_device_name", "model",
    "os_version", "patched_last_seen", "first_jamf_event_at", "last_jamf_event_at",
    "days_since_jamf_event", "jamf_state", "mdm_state", "mdm_vendor", "mdm_server_host",
    "match_basis", "note", "basis", "generated_at",
]


def _jamf_coverage_csv_rows(bucket: str) -> list:
    mode = STUB_STATE.get("jamf_mode", "not_configured")
    basis_stmt = _jamf_basis(mode)["statement"]
    gen = "2026-09-26T12:00:00Z"
    all_rows = _jamf_bucket_rows(mode)
    rows = [JAMF_COVERAGE_CSV_HEADER]
    if bucket in ("", "gap"):
        for r in all_rows["gap"]:
            rows.append(["gap", "", "", r.get("serial") or "", r.get("udid") or "",
                        str(r.get("jamf_id") or ""), r.get("device_name") or "",
                        r.get("model") or "", r.get("os_version") or "", "",
                        r.get("first_jamf_event_at") or "", r.get("last_jamf_event_at") or "",
                        str(r.get("days_since_jamf_event") or ""), r.get("jamf_state") or "",
                        "", "", "", "", r.get("note") or "", basis_stmt, gen])
    if bucket in ("", "not_reported_by_jamf"):
        for r in all_rows["not_reported_by_jamf"]:
            rows.append(["not_reported_by_jamf", r["device_id"], r.get("hostname") or "",
                        r.get("serial") or "", "", "", "", "", r.get("os_version") or "",
                        r.get("last_seen") or "", "", "", "", "", r.get("mdm_state") or "",
                        r.get("mdm_vendor") or "", r.get("mdm_server_host") or "", "",
                        r.get("note") or "", basis_stmt, gen])
    if bucket in ("", "covered"):
        for r in all_rows["covered"]:
            rows.append(["covered", r["device_id"], r.get("hostname") or "",
                        r.get("serial") or "", "", str(r.get("jamf_id") or ""),
                        r.get("jamf_device_name") or "", "", "", r.get("last_seen") or "", "",
                        r.get("last_jamf_event_at") or "",
                        str(r.get("days_since_jamf_event") or ""), "", "", "", "",
                        r.get("match_basis") or "", r.get("note") or "", basis_stmt, gen])
    return rows


# PAT-2025 tenant-level cve_assessment (GET /v1/portal/findings additive
# object). Deliberately non-round numbers so a test cannot pass by coincidence
# against a suspiciously tidy total.
CVE_ASSESSMENT_TENANT = {
    "last_feed_sync_at": "2026-09-22T01:04:12Z",
    "last_full_match_at": "2026-09-22T01:09:40Z",
    "queued_observations": 0,
    "assessed_products": 180,
    "pending_products": 3,
    "not_assessed_products": 412,
}

# PAT-1879: PAT-1969's finding-lifecycle contract. cis-1.1 walks a finding
# all the way to an authoritative verified_fixed closure; cis-2.6 fails,
# is verified fixed, then recurs - proving still_failing/recurred retain the
# earlier history rather than starting a fresh timeline. Every rule_id here
# matches a DEVICE_DETAIL compliance_signals row so the portal's per-row
# lookup by finding_key has something to find.
LIFECYCLE_CIS_CURRENT = [
    {
        "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
        "finding_key": "cis-1.1", "status": "verified_fixed",
        "first_observed_at": "2026-12-01T08:00:00Z",
        "currently_observed_at": "2026-12-01T08:00:00Z",
        "acknowledged_at": None, "risk_accepted_at": None,
        "guidance_issued_at": "2026-12-02T09:00:00Z",
        "customer_applied_at": "2026-12-03T10:00:00Z",
        "pending_verification_at": "2026-12-03T10:05:00Z",
        "verified_fixed_at": "2026-12-04T09:00:00Z", "still_failing_at": None,
        "verification_unknown_at": None, "recurred_at": None,
        "recurrence_count": 0, "event_count": 5,
        "status_recorded_at": "2026-12-04T09:00:05Z",
        "status_observed_at": "2026-12-04T09:00:00Z",
        "status_authoritative": True,
    },
    {
        "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
        "finding_key": "cis-2.6", "status": "recurred",
        "first_observed_at": "2026-11-01T08:00:00Z",
        "currently_observed_at": "2026-07-01T08:00:00Z",
        "acknowledged_at": None, "risk_accepted_at": None,
        "guidance_issued_at": "2026-11-02T09:00:00Z", "customer_applied_at": None,
        "pending_verification_at": None,
        "verified_fixed_at": "2026-12-01T09:00:00Z",
        "still_failing_at": "2026-07-01T08:00:00Z",
        "verification_unknown_at": None, "recurred_at": "2026-07-01T08:00:00Z",
        "recurrence_count": 1, "event_count": 5,
        "status_recorded_at": "2026-07-01T08:00:06Z",
        "status_observed_at": "2026-07-01T08:00:00Z",
        "status_authoritative": True,
    },
]

LIFECYCLE_CIS_HISTORY = [
    {"id": 1, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-1.1", "event_type": "first_observed",
     "source_type": "endpoint_observation", "actor": "", "reason": "",
     "observed_at": "2026-12-01T08:00:00Z", "authoritative": True, "evidence": {},
     "recorded_at": "2026-12-01T08:00:05Z"},
    {"id": 2, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-1.1", "event_type": "guidance_issued",
     "source_type": "operator_action", "actor": "alex@patched.im",
     "reason": "Enable automatic software updates in System Settings.",
     "observed_at": None, "authoritative": False, "evidence": {},
     "recorded_at": "2026-12-02T09:00:00Z"},
    {"id": 3, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-1.1", "event_type": "customer_applied",
     "source_type": "operator_action", "actor": "jane@tenant-a.example",
     "reason": "Enabled via System Settings.",
     "observed_at": None, "authoritative": False, "evidence": {},
     "recorded_at": "2026-12-03T10:00:00Z"},
    {"id": 4, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-1.1", "event_type": "pending_verification",
     "source_type": "operator_action", "actor": "jane@tenant-a.example", "reason": "",
     "observed_at": None, "authoritative": False, "evidence": {},
     "recorded_at": "2026-12-03T10:05:00Z"},
    {"id": 5, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-1.1", "event_type": "verified_fixed",
     "source_type": "endpoint_observation", "actor": "", "reason": "",
     "observed_at": "2026-12-04T09:00:00Z", "authoritative": True,
     "evidence": {"rule_id": "cis-1.1", "observed_value": "true"},
     "recorded_at": "2026-12-04T09:00:05Z"},
    {"id": 6, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-2.6", "event_type": "first_observed",
     "source_type": "endpoint_observation", "actor": "", "reason": "",
     "observed_at": "2026-11-01T08:00:00Z", "authoritative": True, "evidence": {},
     "recorded_at": "2026-11-01T08:00:05Z"},
    {"id": 7, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-2.6", "event_type": "guidance_issued",
     "source_type": "operator_action", "actor": "alex@patched.im",
     "reason": "Enable the application firewall.",
     "observed_at": None, "authoritative": False, "evidence": {},
     "recorded_at": "2026-11-02T09:00:00Z"},
    {"id": 8, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-2.6", "event_type": "verified_fixed",
     "source_type": "endpoint_observation", "actor": "", "reason": "",
     "observed_at": "2026-12-01T09:00:00Z", "authoritative": True, "evidence": {},
     "recorded_at": "2026-12-01T09:00:05Z"},
    {"id": 9, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-2.6", "event_type": "still_failing",
     "source_type": "endpoint_observation", "actor": "", "reason": "",
     "observed_at": "2026-07-01T08:00:00Z", "authoritative": True, "evidence": {},
     "recorded_at": "2026-07-01T08:00:05Z"},
    {"id": 10, "tenant_id": "t1", "finding_kind": "cis", "device_id": "dev-mac-001",
     "finding_key": "cis-2.6", "event_type": "recurred",
     "source_type": "endpoint_observation", "actor": "", "reason": "",
     "observed_at": "2026-07-01T08:00:00Z", "authoritative": True, "evidence": {},
     "recorded_at": "2026-07-01T08:00:06Z"},
]

# CVE-2026-1234 stays mid-flow (pending_verification, must never read the
# same as a fixed finding). CVE-2026-0001 is a deliberately non-authoritative
# verified_fixed row: the real platform's finding_lifecycle_events schema
# (migration 0156) can only emit an authoritative verified_fixed event today,
# but the wire contract still carries status_authoritative as a real field,
# and the portal must render off that value rather than an assumption about
# which combinations the current schema can produce - see main.py's
# _lifecycle_pill_class.
LIFECYCLE_CVE_CURRENT = [
    {
        "tenant_id": "t1", "finding_kind": "cve", "device_id": None,
        "finding_key": "CVE-2026-1234", "status": "pending_verification",
        "first_observed_at": "2026-12-20T08:00:00Z",
        "currently_observed_at": "2026-12-20T08:00:00Z",
        "acknowledged_at": None, "risk_accepted_at": None,
        "guidance_issued_at": None, "customer_applied_at": None,
        "pending_verification_at": "2026-12-25T09:00:00Z",
        "verified_fixed_at": None, "still_failing_at": None,
        "verification_unknown_at": None, "recurred_at": None,
        "recurrence_count": 0, "event_count": 2,
        "status_recorded_at": "2026-12-25T09:00:00Z", "status_observed_at": None,
        "status_authoritative": False,
    },
    {
        "tenant_id": "t1", "finding_kind": "cve", "device_id": None,
        "finding_key": "CVE-2026-0001", "status": "verified_fixed",
        "first_observed_at": "2026-12-28T08:00:00Z",
        "currently_observed_at": "2026-12-28T08:00:00Z",
        "acknowledged_at": None, "risk_accepted_at": None,
        "guidance_issued_at": None, "customer_applied_at": None,
        "pending_verification_at": None,
        "verified_fixed_at": "2026-07-01T09:00:00Z", "still_failing_at": None,
        "verification_unknown_at": None, "recurred_at": None,
        "recurrence_count": 0, "event_count": 2,
        "status_recorded_at": "2026-07-01T09:00:05Z",
        "status_observed_at": "2026-07-01T09:00:00Z",
        "status_authoritative": False,
    },
]

LIFECYCLE_CVE_HISTORY = [
    {"id": 101, "tenant_id": "t1", "finding_kind": "cve", "device_id": None,
     "finding_key": "CVE-2026-1234", "event_type": "first_observed",
     "source_type": "endpoint_observation", "actor": "", "reason": "",
     "observed_at": "2026-12-20T08:00:00Z", "authoritative": True, "evidence": {},
     "recorded_at": "2026-12-20T08:00:05Z"},
    {"id": 102, "tenant_id": "t1", "finding_kind": "cve", "device_id": None,
     "finding_key": "CVE-2026-1234", "event_type": "pending_verification",
     "source_type": "operator_action", "actor": "alex@patched.im",
     "reason": "Vendor patch reported applied, awaiting a fresh scan.",
     "observed_at": None, "authoritative": False, "evidence": {},
     "recorded_at": "2026-12-25T09:00:00Z"},
    {"id": 103, "tenant_id": "t1", "finding_kind": "cve", "device_id": None,
     "finding_key": "CVE-2026-0001", "event_type": "first_observed",
     "source_type": "endpoint_observation", "actor": "", "reason": "",
     "observed_at": "2026-12-28T08:00:00Z", "authoritative": True, "evidence": {},
     "recorded_at": "2026-12-28T08:00:05Z"},
    {"id": 104, "tenant_id": "t1", "finding_kind": "cve", "device_id": None,
     "finding_key": "CVE-2026-0001", "event_type": "verified_fixed",
     "source_type": "endpoint_observation", "actor": "", "reason": "",
     "observed_at": "2026-07-01T09:00:00Z", "authoritative": False,
     "evidence": {"note": "partial scan, low sample confidence"},
     "recorded_at": "2026-07-01T09:00:05Z"},
]

FINDINGS = [
    {
        "cve_id": "CVE-2026-1234",
        "severity": "high",
        "cvss": 8.1,
        "app": "ExampleBrowser",
        "version": "124.0.1",
        "devices_affected": 3,
        "first_seen": "2026-12-20T08:00:00Z",
        "summary": "Use-after-free in the rendering engine.",
        "match_confidence": "version_confirmed",
        "fixed_version": "124.0.5",
        "devices": [{"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk"}],
        "devices_truncated": False,
    },
    {
        "cve_id": "CVE-2026-0001",
        "severity": "critical",
        "cvss": 9.8,
        "app": "ArchiveTool",
        "version": "3.2",
        "devices_affected": 1,
        "first_seen": "2026-12-28T08:00:00Z",
        "summary": "Remote code execution when opening crafted archives.",
        "match_confidence": "version_unverified",
        "fixed_version": "",
    },
]

# PAT-2263: GET /v1/portal/driver-findings lists' provenance
# (contracts/portal-api.md "kernel_drivers (PAT-2263)") - one fresh,
# succeeded source and one stale, failed source, so tests exercise both a
# healthy list and a stale one without extra fixture wiring.
DRIVER_LISTS = [
    {"source": "microsoft_driver_blocklist",
     "source_url": "https://aka.ms/VulnerableDriverBlockList",
     "status": "succeeded", "fetched_at": "2026-09-29T01:00:00Z",
     "attempted_at": "2026-09-29T01:00:00Z",
     "list_version": "10.0.29545.0", "entry_count": 1124, "stale": False},
    {"source": "loldrivers", "source_url": "https://www.loldrivers.io/api/drivers.json",
     "status": "failed", "fetched_at": "2026-09-26T01:00:00Z",
     "attempted_at": "2026-09-29T01:00:00Z",
     "list_version": "sha256:4be1...", "entry_count": 4630, "stale": True},
]

# GET /v1/portal/driver-findings default fixture - one loaded, blocklist-
# not-enforced match (the critical case, PAT-2263's own ticket ruling) on
# dev-mac-001's Windows sibling roster entry.
DRIVER_FINDINGS = [
    {
        "device_id": "dev-win-002", "hostname": "acme-win-accounts",
        "path": "C:\\Windows\\Temp\\helper.sys", "service_name": "helper", "start_type": "demand",
        "loaded": True, "version": "1.0.0.1", "sha256": "a" * 64,
        "reported_at": "2026-09-29T09:00:00Z", "first_seen_at": "2026-09-27T09:00:00Z",
        "category": "vulnerable", "blocklist_enforced": "no",
        "matches": [
            {"source": "microsoft_driver_blocklist",
             "source_url": "https://aka.ms/VulnerableDriverBlockList", "category": "vulnerable",
             "entry_id": "e-1", "entry_name": "helper.sys", "hash_kind": "sha256",
             "hash": "a" * 64, "list_version": "10.0.29545.0",
             "list_fetched_at": "2026-09-29T01:00:00Z", "list_stale": False},
        ],
    },
]

UNAPPROVED_APPS = {
    "apps": [
        {"app_name": "TorrentBox", "enforcement_tier": "app_management", "devices_affected": 4},
        {"app_name": "SketchyVPN", "enforcement_tier": "managed", "devices_affected": 1},
    ]
}

# PAT-1727: the tenant's applications with a policy state - every configured
# tenant_app_policies row (mandatory/approved/unapproved/unmanaged) plus every
# installed application matching none of them ("undecided"). Deliberately
# includes a name_match_only undecided row (GuessWho) and two unapproved rows
# with zero matching devices (evidence_basis "unknown") to exercise the same
# gaps PAT-1742 was opened for.
APPLICATIONS = {
    "total": 8,
    "truncated": False,
    "estate_too_large": False,
    "applications": [
        {
            "type": "application", "name": "TorrentBox", "identifier": "",
            "platform": "any", "policy_state": "unapproved",
            "enforcement_tier": "app_management", "device_count": 4,
            "evidence_basis": "identifier_match", "identifier_matched_devices": 4,
            "name_matched_devices": 0, "removal_state": "not_available",
            # PAT-1839: the permanent application-policy-row shape -
            # decided_at + justification populated, decided_by always null
            # (tenant_app_policies has no actor column).
            "decided_by": None, "decided_at": "2026-12-01T10:00:00Z",
            "justification": "Peer-to-peer client, not permitted on the estate.",
            # PAT-1832: signed AND notarized, >1 version.
            "version_count": 2, "team_id": "TORR12345X",
            "signed_by": "Torrent Software LLC", "notarized": True,
        },
        {
            "type": "application", "name": "GhostApp", "identifier": "",
            "platform": "any", "policy_state": "unapproved",
            "enforcement_tier": "app_management", "device_count": 0,
            "evidence_basis": "unknown", "identifier_matched_devices": 0,
            "name_matched_devices": 0, "removal_state": "not_available",
            # PAT-1832: 0 devices -> version_count 0 (never null), and
            # fully unknown signing state (macOS row, no evidence at all).
            "version_count": 0, "team_id": None, "signed_by": None, "notarized": None,
        },
        {
            "type": "application", "name": "PhantomTool", "identifier": "",
            "platform": "any", "policy_state": "unapproved",
            "enforcement_tier": "managed", "device_count": 0,
            "evidence_basis": "unknown", "identifier_matched_devices": 0,
            "name_matched_devices": 0, "removal_state": "not_available",
            # PAT-1832: 0 devices -> version_count 0; signed but notarized
            # genuinely unknown (null, not false) - reads its own distinct
            # "signed, notarization unknown" badge, never the same label
            # an explicit false gets (that would claim knowledge the
            # platform doesn't have).
            "version_count": 0, "team_id": "PHNT98765",
            "signed_by": "Phantom Co", "notarized": None,
        },
        {
            "type": "application", "name": "MysteryApp",
            "identifier": "com.example.mysteryapp", "platform": "macos",
            "policy_state": "undecided", "enforcement_tier": "", "device_count": 5,
            "evidence_basis": "identifier_match", "identifier_matched_devices": 0,
            "name_matched_devices": 0, "removal_state": "not_available",
            # PAT-1839: genuinely no decision record - a legitimate state,
            # not a bug. All three null.
            "decided_by": None, "decided_at": None, "justification": None,
            # PAT-1832: exactly 1 version -> no "on 1 version" suffix.
            # Fully unknown signing (macOS row with no collected evidence).
            "version_count": 1, "team_id": None, "signed_by": None, "notarized": None,
        },
        {
            "type": "application", "name": "GuessWho", "identifier": "",
            "platform": "windows", "policy_state": "undecided",
            "enforcement_tier": "", "device_count": 2,
            "evidence_basis": "name_match_only", "identifier_matched_devices": 0,
            "name_matched_devices": 2, "removal_state": "not_available",
            # PAT-1839: an undecided-application-row lookup against the
            # triage table - unlike a policy row, decided_by here IS a real
            # person, not a permanent null. All three populated.
            "decided_by": "priya@example.com", "decided_at": "2026-08-20T14:30:00Z",
            "justification": "Name-only match, held pending identifier confirmation.",
            # PAT-1832: Windows platform - team_id/signed_by/notarized are
            # permanently null here (PAT-1828, the current Windows
            # collector never reports them), which must render "Unknown",
            # never a guessed "Unsigned".
            "version_count": 1, "team_id": None, "signed_by": None, "notarized": None,
        },
        {
            "type": "application", "name": "Slack", "identifier": "",
            "platform": "any", "policy_state": "approved",
            "enforcement_tier": "report", "device_count": 40,
            "evidence_basis": "identifier_match", "identifier_matched_devices": 40,
            "name_matched_devices": 0, "removal_state": "not_available",
            "decided_by": None, "decided_at": "2026-11-14T09:00:00Z",
            "justification": "Standard estate collaboration tool.",
            # PAT-1832: signed AND notarized, >1 version.
            "version_count": 3, "team_id": "SLCK54321",
            "signed_by": "Slack Technologies, Inc.", "notarized": True,
        },
        {
            "type": "application", "name": "CorpVPN", "identifier": "",
            "platform": "any", "policy_state": "mandatory",
            "enforcement_tier": "report", "device_count": 12,
            "evidence_basis": "identifier_match", "identifier_matched_devices": 12,
            "name_matched_devices": 0, "removal_state": "not_available",
            # PAT-1839: decided_at present, no justification recorded.
            "decided_by": None, "decided_at": "2026-10-02T08:00:00Z",
            "justification": None,
            # PAT-1832: signed, notarized explicitly False (not null) -
            # real negative evidence, a distinct badge from PhantomTool's
            # genuinely-unknown null.
            "version_count": 1, "team_id": "ACME11111",
            "signed_by": "Acme Networks", "notarized": False,
        },
        {
            # PAT-2008: was "unmanaged", which PAT-2007 now defines as the
            # stored form of a customer Ignore (it groups with Ignored). A
            # value the portal genuinely does not know keeps this row
            # exercising the unrecognised group.
            "type": "application", "name": "OddPolicy", "identifier": "",
            "platform": "any", "policy_state": "legacy_quarantine",
            "enforcement_tier": "", "device_count": 1,
            "evidence_basis": "identifier_match", "identifier_matched_devices": 1,
            "name_matched_devices": 0, "removal_state": "not_available",
            "decided_by": None, "decided_at": "2026-09-11T11:00:00Z",
            "justification": "Legacy policy row, category not yet reclassified.",
            # PAT-1832: fully unknown signing, in the unrecognised group -
            # the badge (or its absence-safe rendering) must still hold
            # outside the three main groups.
            "version_count": 1, "team_id": None, "signed_by": None, "notarized": None,
        },
    ],
}

# PAT-933: browser extension estate with four-valued approval_state
# (approved / unapproved / ignored are explicit policy rows; unreviewed
# means no policy entry exists for that extension at all). PAT-1725/PAT-1726
# add evidence_basis and removal_state to every row.
EXTENSIONS = {
    "total": 4,
    "truncated": False,
    "estate_too_large": False,
    "extensions": [
        {
            "extension_id": "shadycoupons-ext-id",
            "name": "ShadyCoupons",
            "browser": "chrome",
            "risk_level": "elevated",
            "versions": ["1.2.0", "1.3.1"],
            "device_count": 2,
            "devices": [
                {"device_id": "dev-mac-001", "hostname": "LT-0042"},
                {"device_id": "dev-mac-002", "hostname": "LT-0043"},
            ],
            "devices_truncated": False,
            "approval_state": "unapproved",
            "evidence_basis": "identifier_match",
            "removal_state": "requested",
            "removal_targets_total": 2,
            "removal_targets_completed": 0,
            # PAT-1839: extension provenance sources from
            # tenant_extension_policies, so decided_by CAN be a real value -
            # all three populated here.
            "decided_by": "admin@example.com", "decided_at": "2026-07-15T13:00:00Z",
            "justification": "Elevated risk, blocked pending review.",
            # PAT-1832: extensions get version_count only - never a signing
            # field, not even null (they carry none at all).
            "version_count": 2,
        },
        {
            "extension_id": "teamchat-ext-id",
            "name": "TeamChat",
            "browser": "chrome",
            "risk_level": "normal",
            "versions": ["4.0.2"],
            "device_count": 5,
            "devices": [{"device_id": "dev-mac-001", "hostname": "LT-0042"}],
            "devices_truncated": False,
            "approval_state": "approved",
            "evidence_basis": "identifier_match",
            "removal_state": "not_requested",
            "removal_targets_total": 0,
            "removal_targets_completed": 0,
            # PAT-1839: decided_by + decided_at present, no justification.
            "decided_by": "admin@example.com", "decided_at": "2026-08-10T10:00:00Z",
            "justification": None,
            # PAT-1832: exactly 1 version -> no "on 1 version" suffix.
            "version_count": 1,
        },
        {
            "extension_id": "mysteryhelper-ext-id",
            "name": "MysteryHelper",
            "browser": "firefox",
            "risk_level": "normal",
            "versions": [],
            "device_count": 1,
            "devices": [{"device_id": "dev-mac-002", "hostname": "LT-0043"}],
            "devices_truncated": False,
            "approval_state": "unreviewed",
            "evidence_basis": "identifier_match",
            "removal_state": "not_requested",
            "removal_targets_total": 0,
            "removal_targets_completed": 0,
            # PAT-1839: no decision record - unreviewed extension.
            "decided_by": None, "decided_at": None, "justification": None,
            "version_count": 1,
        },
        {
            "extension_id": "oldtheme-ext-id",
            "name": "OldTheme",
            "browser": "edge",
            "risk_level": "normal",
            "versions": ["0.9"],
            "device_count": 1,
            "devices": [{"device_id": "dev-mac-001", "hostname": "LT-0042"}],
            "devices_truncated": False,
            "approval_state": "ignored",
            "evidence_basis": "identifier_match",
            "removal_state": "not_requested",
            "removal_targets_total": 0,
            "removal_targets_completed": 0,
            "version_count": 1,
        },
    ]
}

# PAT-1821: GET /v1/portal/protected-software - the tenant's customer- or
# platform-managed protection layer (EDR/MDM/backup/security/Patched Agent/
# customer-defined), vendor + product_name only, no shared id with
# /v1/portal/applications' device_apps-derived `name`. CorpVPN mirrors an
# application row's name exactly (rule 1 of the portal's matching index);
# GuardianEDR only appears vendor-prefixed on a device
# ("Aegis GuardianEDR"), exercising rule 2.
PROTECTED_SOFTWARE = {
    "products": [
        {
            "vendor": "Acme Networks", "product_name": "CorpVPN",
            "category": "security", "protected": True,
        },
        {
            "vendor": "Aegis", "product_name": "GuardianEDR",
            "category": "edr", "protected": True,
        },
    ]
}

# PAT-2215: GET /v1/portal/local-admins default fixture. One compliant
# macOS device (a single named user), one Windows device over the
# lte-2 threshold carrying every principal-labelling case at once (a
# disabled built-in Administrator excluded from the assessed count, a
# directory group, an unresolved SID and a second named user), and one
# Windows device whose roster could not be read at all - reported_admin_
# count/assessed_admin_count/pass are all None there, so it renders as
# unknown, never a false zero (root AGENTS.md: absence requires
# authority).
LOCAL_ADMINS_DATA = {
    "generated_at": "2026-09-29T10:00:00Z",
    "threshold": 2,
    "over_limit_devices": 1,
    "distinct_accounts": 5,
    "unreadable_devices": 1,
    "devices": [
        {
            "device_id": "dev-mac-001",
            "hostname": "acme-mbp-frontdesk",
            "platform": "macos",
            "reported_admin_count": 1,
            "assessed_admin_count": 1,
            "pass": True,
            "membership_readable": True,
            "collection_status": "complete",
            "builtin_admin_state": "not-applicable",
            "builtin_admin_note": (
                "No built-in account check on macOS: the agent leaves root out of "
                "the admin roster, so this verdict is based on the roster and "
                "count as reported."
            ),
            "principals": [
                {"name": "alice", "principal_type": "user", "builtin": False,
                 "account_state": None},
            ],
        },
        {
            "device_id": "dev-win-101",
            "hostname": "acme-win-dc1",
            "platform": "windows",
            "reported_admin_count": 4,
            "assessed_admin_count": 3,
            "pass": False,
            "membership_readable": True,
            "collection_status": "complete",
            "builtin_admin_state": "disabled",
            "builtin_admin_note": (
                "The built-in Administrator account is disabled, so it is not "
                "counted as a standing admin."
            ),
            "principals": [
                {"name": "ACME\\Administrator", "principal_type": "user",
                 "builtin": True, "account_state": "disabled"},
                {"name": "ACME\\Domain Admins", "principal_type": "group",
                 "builtin": False, "account_state": None},
                {"name": "S-1-5-21-999-999-999-9999", "principal_type": "unresolved",
                 "builtin": False, "account_state": None},
                {"name": "ACME\\bob", "principal_type": "user", "builtin": False,
                 "account_state": None},
            ],
        },
        {
            "device_id": "dev-win-102",
            "hostname": "acme-win-unreadable",
            "platform": "windows",
            "reported_admin_count": None,
            "assessed_admin_count": None,
            "pass": None,
            "membership_readable": False,
            "collection_status": "unavailable",
            "builtin_admin_state": "not-applicable",
            "builtin_admin_note": "",
            "principals": [],
        },
    ],
}

HOMEBREW_SUMMARY = {
    "generated_at": "2026-09-23T12:00:00Z",
    "macos_device_count": 2, "devices_with_homebrew": 1,
    "device_status": {
        "complete": 1, "partial": 0, "not_present": 0, "failed": 0, "not_reported": 1,
    },
    "formula_count": 2, "formula_on_request_count": 1, "formula_installation_count": 2,
    "cask_count": 1, "cask_installation_count": 1, "linked_cask_installation_count": 1,
    "tap_count": 1, "third_party_tap_count": 1, "estate_software_installation_count": 4,
    # PAT-2058: distinct current formulae+casks resolved to those two states
    # - openssl@3 and firefox are unreviewed below, readline is unapproved.
    "unreviewed_count": 2, "unapproved_count": 1,
}

HOMEBREW_FORMULAE = {
    "generated_at": "2026-09-23T12:00:00Z", "total": 2, "limit": 500, "offset": 0,
    "include_dependencies": True,
    "formulae": [
        {"identity": {"kind": "homebrew_formula", "name": "openssl@3", "tap": "homebrew/core"},
         "name": "openssl@3", "tap": "homebrew/core", "third_party_tap": False,
         "versions": ["3.5.2"], "device_count": 1, "installation_count": 1,
         "on_request_device_count": 1, "dependency_device_count": 0,
         "first_seen_at": "2026-09-01T10:00:00Z", "evidence_at": "2026-09-23T11:00:00Z",
         # PAT-2058: never null on the real platform - always a confirmed
         # identity (contracts/portal-api.md "GET /v1/portal/homebrew/
         # formulae").
         "approval_state": "unreviewed", "product_key": "homebrew:formula:openssl@3"},
        {"identity": {"kind": "homebrew_formula", "name": "readline", "tap": "homebrew/core"},
         "name": "readline", "tap": "homebrew/core", "third_party_tap": False,
         "versions": ["8.2"], "device_count": 1, "installation_count": 1,
         "on_request_device_count": 0, "dependency_device_count": 1,
         "first_seen_at": "2026-09-01T10:00:00Z", "evidence_at": "2026-09-23T11:00:00Z",
         "approval_state": "unapproved", "product_key": "homebrew:formula:readline"},
    ],
}

HOMEBREW_CASKS = {
    "generated_at": "2026-09-23T12:00:00Z", "total": 1, "limit": 500, "offset": 0,
    "casks": [
        {"identity": {"kind": "homebrew_cask", "name": "firefox", "tap": "homebrew/cask"},
         "token": "firefox", "tap": "homebrew/cask", "third_party_tap": False,
         "versions": ["143.0"], "unknown_version_installation_count": 0,
         "device_count": 1, "installation_count": 1, "linked_app_device_count": 1,
         "app_names": ["Firefox.app"],
         "first_seen_at": "2026-09-10T08:00:00Z", "evidence_at": "2026-09-23T11:00:00Z",
         "approval_state": "unreviewed", "product_key": "homebrew:cask:firefox"},
    ],
}

HOMEBREW_TAPS = {
    "generated_at": "2026-09-23T12:00:00Z", "total": 1, "limit": 500, "offset": 0,
    "include_core": False,
    "taps": [
        {"identity": {"kind": "homebrew_tap", "name": "acme/tools", "tap": ""},
         "name": "acme/tools", "third_party": True,
         "remote_urls": ["https://github.com/acme/homebrew-tools"],
         "device_count": 1, "first_seen_at": "2026-09-01T10:00:00Z",
         "evidence_at": "2026-09-23T11:00:00Z"},
    ],
}

HOMEBREW_DEVICES = {
    "generated_at": "2026-09-23T12:00:00Z", "total": 2, "limit": 500, "offset": 0,
    "devices": [
        {"device_id": "hb-mac-01", "hostname": "mac-01",
         "collection_status": "complete", "truncated": False, "truncation_reason": None,
         "reported_at": "2026-09-23T11:00:00Z", "authority_at": "2026-09-23T11:00:00Z",
         "prefixes": [{"path": "/opt/homebrew", "owner": "alice", "owner_uid": 501,
                       "collection_status": "complete", "formulae": 2, "casks": 1, "taps": 1}],
         "issues": [], "formula_count": 2, "cask_count": 1, "tap_count": 1},
        {"device_id": "hb-mac-02", "hostname": "mac-02",
         "collection_status": "not_reported", "truncated": False, "truncation_reason": None,
         "reported_at": None, "authority_at": None, "prefixes": [], "issues": [],
         "formula_count": 0, "cask_count": 0, "tap_count": 0},
    ],
}

HOMEBREW_DEVICE_DETAIL = {
    "generated_at": "2026-09-23T12:00:00Z",
    "state": HOMEBREW_DEVICES["devices"][0],
    "total": 1, "kind": "cask", "limit": 500, "offset": 0,
    "entries": [
        {"kind": "cask",
         "identity": {"kind": "homebrew_cask", "name": "firefox", "tap": "homebrew/cask"},
         "prefix": "/opt/homebrew", "name": "firefox", "version": "143.0",
         "tap": "homebrew/cask", "third_party_tap": False,
         "installed_on_request": True, "installed_as_dependency": None,
         "installed_at": "2026-09-10T08:00:00Z", "runtime_dependencies": None,
         "homepage": None, "source_url": None, "opt_linked": None,
         "receipt_status": "read", "formula_file_status": None,
         "versions_on_disk": ["143.0"],
         "apps": [{"name": "Firefox.app", "path": None, "exists": None}],
         "linked_apps": [{"path": "/Applications/Firefox.app", "link_basis": "default_appdir",
                           "app_name": "Firefox"}],
         "directory": None, "remote_url": None, "config_status": None,
         "first_seen_at": "2026-09-10T08:00:00Z", "evidence_at": "2026-09-23T11:00:00Z"},
    ],
}

# hb-mac-02 (HOMEBREW_DEVICES' second row: collection_status "not_reported",
# nothing collected yet) - PAT-2128 follow-up. /homebrew links to it same as
# hb-mac-01; without a detail fixture of its own the stub 404s it and a
# genuine broken link and walker noise become indistinguishable.
HOMEBREW_DEVICE_DETAIL_HB_MAC_02 = {
    "generated_at": "2026-09-23T12:00:00Z",
    "state": HOMEBREW_DEVICES["devices"][1],
    "total": 0, "kind": None, "limit": 500, "offset": 0,
    "entries": [],
}

# PAT-2022: the three platform reads behind the AI Tooling tab. The tagged
# product response is deliberately mixed across inventory kinds and CVE
# assessment states so the portal cannot accidentally collapse "pending" or
# "not assessed" into a clean zero.
AI_TOOLING_SUMMARY = {
    "generated_at": "2026-09-27T12:00:00Z",
    "device_count": 3,
    "devices_with_tooling": 3,
    "collection_status": {
        "ide_extensions": {"complete": 2, "partial": 0, "not_present": 0,
                           "failed": 0, "not_reported": 1},
        "package_managers": {"complete": 2, "partial": 0, "not_present": 0,
                             "failed": 0, "not_reported": 1},
        "local_models": {"complete": 2, "partial": 0, "not_present": 0,
                         "failed": 0, "not_reported": 1},
        "mcp_servers": {"complete": 2, "partial": 0, "not_present": 0,
                        "failed": 0, "not_reported": 1},
    },
    "ide_extensions": {"installed": 2, "distinct": 1, "devices": 2},
    "packages": {
        "npm_global": {"installed": 1, "distinct": 1, "devices": 1},
        "pip_user": {"installed": 0, "distinct": 0, "devices": 0},
        "pipx": {"installed": 0, "distinct": 0, "devices": 0},
    },
    "local_models": {
        "models": {"installed": 2, "distinct": 2, "devices": 1},
        "runtime_installations": {"installed": 1, "distinct": 1, "devices": 1},
        "total_bytes": 7000000000, "lower_bound_devices": 0,
    },
    "mcp_servers": {"installed": 1, "distinct": 1, "devices": 1},
    "mcp_servers_by_client": {
        "claude_desktop": {"installed": 1, "distinct": 1, "devices": 1},
    },
    "vulnerability_products": [
        {"subject_kind": "package", "ecosystem": "npm", "identity": "ai-helper",
         "source": "npm", "version": "2.4.0", "state": "assessed", "reason": None,
         "finding_count": 1, "highest_severity": "HIGH", "device_count": 1,
         "advisory_sources": ["osv"]},
        {"subject_kind": "ide_extension", "ecosystem": None,
         "identity": "vendor.copilot", "source": "vscode_marketplace",
         "version": "1.3.0", "state": "pending", "reason": "inventory_changed",
         "finding_count": None, "highest_severity": None, "device_count": 2,
         "advisory_sources": []},
        {"subject_kind": "mcp_server", "ecosystem": None, "identity": "github",
         "source": "claude_desktop", "version": "0.6.0", "state": "not_assessed",
         "reason": "package_unresolved", "finding_count": None,
         "highest_severity": None, "device_count": 1, "advisory_sources": []},
    ],
}

AI_TAGGED_PRODUCTS = {
    "generated_at": "2026-09-27T12:00:00Z", "category": "ai_tooling",
    "subtype": None, "total": 4, "limit": 1000, "offset": 0,
    "estate_too_large": False, "distinct_device_total": 3,
    "products": [
        {"category": "ai_tooling", "subtype": "desktop_app",
         "observation_kind": "app", "product_key": "product:chatgpt",
         "name": "ChatGPT", "canonical_name": "ChatGPT", "vendor": "OpenAI",
         "observed_publisher": "OpenAI, L.L.C.", "identifier": "ChatGPT.ChatGPT",
         "browser": None, "platforms": ["windows"], "versions": ["1.2.3"],
         "version_count": 1, "device_count": 2,
         "devices": ["dev-win-002", "dev-win-003"], "devices_truncated": False,
         "user_count": None,
         "first_seen": "2026-09-01T09:00:00Z", "last_seen": "2026-09-27T11:00:00Z",
         "approval_state": "unreviewed",
         "approval_target": {"type": "application", "platform": "windows",
                             "identifier": "ChatGPT.ChatGPT", "team_id": None,
                             "browser": None, "extension_id": None, "name": None,
                             "tap": None, "identity_kind": None, "source": None},
         "match_basis": ["windows_authenticode"],
         "last_used_at": "2026-09-26T08:30:00Z",
         "metered_installation_count": 2, "unmetered_installation_count": 0,
         "stale_metering_installation_count": 0,
         "unknown_metering_installation_count": 0, "metering_state": "metered"},
        {"category": "ai_tooling", "subtype": "browser_extension",
         "observation_kind": "browser_extension", "product_key": "ext:chrome:abcd",
         "name": "AI Search Helper", "canonical_name": None, "vendor": None,
         "observed_publisher": None, "identifier": "abcd", "browser": "chrome",
         "platforms": ["macos", "windows"], "versions": ["3.0"],
         "version_count": 1, "device_count": 2,
         "devices": ["dev-mac-001", "dev-win-002"], "devices_truncated": False,
         "user_count": 3,
         "first_seen": "2026-09-03T09:00:00Z", "last_seen": "2026-09-27T10:00:00Z",
         "approval_state": "unapproved",
         "approval_target": {"type": "browser_extension", "platform": None,
                             "identifier": None, "team_id": None, "browser": "chrome",
                             "extension_id": "abcd", "name": None, "tap": None,
                             "identity_kind": None, "source": None},
         "match_basis": ["browser_extension"], "last_used_at": None,
         "metered_installation_count": 0, "unmetered_installation_count": 0,
         "stale_metering_installation_count": 0,
         "unknown_metering_installation_count": 0, "metering_state": "not_applicable"},
        {"category": "ai_tooling", "subtype": "ide_extension",
         "observation_kind": "ide_extension", "product_key": "ide_extension:macos:copilot",
         "name": "Copilot", "canonical_name": None, "vendor": "GitHub",
         "observed_publisher": None, "identifier": "vendor.copilot", "browser": None,
         "platforms": ["macos", "windows"], "versions": ["1.3.0"],
         "version_count": 1, "device_count": 2,
         "devices": ["dev-mac-001", "dev-win-002"], "devices_truncated": False,
         "user_count": 2,
         "first_seen": "2026-09-04T09:00:00Z", "last_seen": "2026-09-27T09:00:00Z",
         "approval_state": "approved",
         "approval_target": {"type": "observation", "platform": None,
                             "identifier": None, "team_id": None, "browser": None,
                             "extension_id": None, "name": "vendor.copilot", "tap": None,
                             "identity_kind": "ide_extension",
                             "source": "vscode_marketplace"},
         "match_basis": ["ide_extension"], "last_used_at": None,
         "metered_installation_count": 0, "unmetered_installation_count": 0,
         "stale_metering_installation_count": 0,
         "unknown_metering_installation_count": 0, "metering_state": "not_applicable"},
        {"category": "ai_tooling", "subtype": "cli", "observation_kind": "package",
         "product_key": "package:macos:ai-helper", "name": "ai-helper",
         "canonical_name": None, "vendor": None, "observed_publisher": None,
         "identifier": "ai-helper", "browser": None, "platforms": ["macos"],
         "versions": ["2.4.0"], "version_count": 1, "device_count": 1,
         "devices": ["dev-mac-001"], "devices_truncated": False,
         "user_count": 1, "first_seen": "2026-09-05T09:00:00Z",
         "last_seen": "2026-09-27T08:00:00Z", "approval_state": "unreviewed",
         "approval_target": {"type": "observation", "platform": None,
                             "identifier": None, "team_id": None, "browser": None,
                             "extension_id": None, "name": "ai-helper", "tap": None,
                             "identity_kind": "npm_package", "source": "npm"},
         "match_basis": ["package"], "last_used_at": None,
         "metered_installation_count": 0, "unmetered_installation_count": 0,
         "stale_metering_installation_count": 0,
         "unknown_metering_installation_count": 0, "metering_state": "not_applicable"},
    ],
}

AI_TOOLING_DEVICES = {
    "generated_at": "2026-09-27T12:00:00Z", "total": 3, "limit": 500, "offset": 0,
    "devices": [
        {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk", "platform": "macos",
         "ide_extensions": {"collection_status": "complete", "units": {},
                            "reported_at": "2026-09-27T11:00:00Z", "lower_bound": False,
                            "item_count": 1, "items_by_unit": {}},
         "package_managers": {"collection_status": "complete",
                              "units": {"npm_global": "complete"},
                              "reported_at": "2026-09-27T11:00:00Z", "lower_bound": False,
                              "item_count": 1, "items_by_unit": {"npm_global": 1}},
         "local_models": {"collection_status": "complete", "units": {"ollama": "complete"},
                          "reported_at": "2026-09-27T11:00:00Z", "lower_bound": False,
                          "item_count": 2, "items_by_unit": {"ollama": 2},
                          "runtime_installation_count": 1, "total_bytes": 7000000000},
         "mcp_servers": {"collection_status": "complete",
                         "units": {"claude_desktop": "complete"},
                         "reported_at": "2026-09-27T11:00:00Z", "lower_bound": False,
                         "item_count": 1, "items_by_unit": {"claude_desktop": 1}},
         "vulnerability_products": AI_TOOLING_SUMMARY["vulnerability_products"]},
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts", "platform": "windows",
         "ide_extensions": {"collection_status": "complete", "units": {},
                            "reported_at": "2026-09-27T10:00:00Z", "lower_bound": False,
                            "item_count": 1, "items_by_unit": {}},
         "package_managers": {"collection_status": "not_present", "units": {},
                              "reported_at": "2026-09-27T10:00:00Z", "lower_bound": False,
                              "item_count": 0, "items_by_unit": {}},
         "local_models": {"collection_status": "not_present", "units": {},
                          "reported_at": "2026-09-27T10:00:00Z", "lower_bound": False,
                          "item_count": 0, "items_by_unit": {},
                          "runtime_installation_count": 0, "total_bytes": 0},
         "mcp_servers": {"collection_status": "not_present", "units": {},
                         "reported_at": "2026-09-27T10:00:00Z", "lower_bound": False,
                         "item_count": 0, "items_by_unit": {}},
         "vulnerability_products": []},
        {"device_id": "dev-mac-003", "hostname": "acme-mbp-storeroom", "platform": "macos",
         **{block: {"collection_status": "not_reported", "units": {}, "reported_at": None,
                    "lower_bound": False, "item_count": None, "items_by_unit": {}}
            for block in ("ide_extensions", "package_managers", "mcp_servers")},
         "local_models": {"collection_status": "not_reported", "units": {},
                          "reported_at": None, "lower_bound": False, "item_count": None,
                          "items_by_unit": {}, "runtime_installation_count": None,
                          "total_bytes": None},
         "vulnerability_products": []},
    ],
}

AI_TOOLING_DEVICE_ITEMS = {
    "generated_at": "2026-09-27T12:00:00Z", "device_id": "dev-mac-001",
    "total": 4, "limit": 100, "offset": 0,
    "items": [
        {
            "item_id": "ati_app_1", "device_id": "dev-mac-001",
            "hostname": "acme-mbp-frontdesk", "platform": "macos",
            "block": "desktop_apps", "unit": "", "entry_kind": "application",
            "collection_status": "current", "lower_bound": False,
            "identity_kind": "app", "identity": "com.openai.chat",
            "source": "", "name": "ChatGPT", "version": "1.2.3",
            "publisher": "OpenAI, L.L.C.", "observed_at": "2026-09-27T11:00:00Z",
            "policy_state": "approved",
            "approval_target": {"type": "application", "platform": "macos",
                                "identifier": "com.openai.chat", "team_id": None,
                                "browser": None, "extension_id": None, "name": None,
                                "tap": None, "identity_kind": None, "source": None},
            "last_used_at": "2026-09-26T08:30:00Z", "metering_state": "metered",
            "assessments": [],
        },
        {
            "item_id": "ati_ext_1", "device_id": "dev-mac-001",
            "hostname": "acme-mbp-frontdesk", "platform": "macos",
            "block": "browser_extensions", "unit": "",
            "entry_kind": "browser_extension", "collection_status": "current",
            "lower_bound": False, "identity_kind": "browser_extension",
            "identity": "abcd", "source": "chrome", "name": "AI Search Helper",
            "version": "3.0", "publisher": None,
            "observed_at": "2026-09-27T11:00:00Z", "policy_state": "unapproved",
            "approval_target": {"type": "browser_extension", "platform": None,
                                "identifier": None, "team_id": None,
                                "browser": "chrome", "extension_id": "abcd",
                                "name": None, "tap": None, "identity_kind": None,
                                "source": None},
            "last_used_at": None, "metering_state": "not_applicable",
            "assessments": [],
        },
        {
            "item_id": "ati_model_1", "device_id": "dev-mac-001",
            "hostname": "acme-mbp-frontdesk", "platform": "macos",
            "block": "local_models", "unit": "ollama", "entry_kind": "model",
            "collection_status": "complete", "lower_bound": False,
            "identity_kind": "local_model", "identity": "llama3:8b",
            "source": "ollama", "name": "Llama 3 8B", "version": "8b",
            "publisher": "Meta", "observed_at": "2026-09-27T11:00:00Z",
            "policy_state": "unreviewed",
            "approval_target": {"type": "observation", "platform": None,
                                "identifier": None, "team_id": None, "browser": None,
                                "extension_id": None, "name": "llama3:8b", "tap": None,
                                "identity_kind": "local_model", "source": "ollama"},
            "runtime": "ollama", "model_tag": "llama3:8b", "model_format": "gguf",
            "size_bytes": 4800000000,
            "assessments": [],
        },
        {
            "item_id": "ati_mcp_1", "device_id": "dev-mac-001",
            "hostname": "acme-mbp-frontdesk", "platform": "macos",
            "block": "mcp_servers", "unit": "claude_desktop", "entry_kind": "server",
            "collection_status": "partial", "lower_bound": True,
            "identity_kind": "mcp_server", "identity": "github",
            "source": "claude_desktop", "name": "GitHub", "version": "0.6.0",
            "publisher": None, "observed_at": "2026-09-27T11:00:00Z",
            "policy_state": "approved",
            "approval_target": {"type": "observation", "platform": None,
                                "identifier": None, "team_id": None, "browser": None,
                                "extension_id": None, "name": "github", "tap": None,
                                "identity_kind": "mcp_server", "source": "claude_desktop"},
            "transport": "stdio", "transport_source": "config",
            "runner": "npx", "package": "@modelcontextprotocol/server-github",
            "package_status": "extracted", "host": "github.com",
            "assessments": [{
                "subject_kind": "package", "ecosystem": "npm",
                "identity": "@modelcontextprotocol/server-github", "source": "npm",
                "version": "0.6.0", "state": "assessed", "unsupported_reason": None,
                "finding_count": 1, "highest_severity": "HIGH",
                "evidence_provenance": {
                    "item_id": "ati_mcp_1", "input_observed_at": "2026-09-27T11:00:00Z",
                    "assessed_at": "2026-09-27T11:30:00Z",
                    "fresh_until": "2026-09-28T13:30:00Z", "fresh": True,
                },
                "advisories": [{
                    "source": "osv", "advisory_id": "GHSA-abcd-efgh-ijkl",
                    "canonical_cve_id": "CVE-2026-1234", "severity": "HIGH",
                    "score": 8.1, "published_at": "2026-09-20T00:00:00Z",
                    "modified_at": "2026-09-21T00:00:00Z",
                    "synced_at": "2026-09-27T10:00:00Z",
                }],
            }],
        },
    ],
}

SOFTWARE_NOTIFICATIONS = {
    "unapproved_alerts_enabled": True,
    "new_software_enabled": False,
    "ai_tooling_notifications_enabled": False,
    "is_default": True, "updated_at": None, "updated_by": None,
    "unapproved_alert": {
        "event": "software.unapproved_detected",
        "email_recipient": {"email": "it@customer.example", "configured": True},
        "webhook_endpoints": 1,
        "email_schedule": "marked: immediately; newly observed: daily digest",
        "digest_hour_utc": 7,
        "webhook_subscribe_to": "software.unapproved_detected",
    },
    "new_software": {"event": "software.first_seen", "channels": 1,
                     "digest_hour_utc": 7},
    "ai_tooling": {"event": "ai_tooling.first_seen", "channels": 1,
                   "digest_hour_utc": 7},
}

SOFTWARE_INVENTORY = {
    "generated_at": "2026-09-20T12:00:00Z",
    "coverage": {
        "installation_count": 10, "metered_installation_count": 7,
        "unmetered_installation_count": 3, "stale_installation_count": 1,
        "unused_installation_count": 2,
    },
    "products": [
        {"name": "ArchiveTool", "names": ["ArchiveTool"], "identifier": "com.acme.archive",
         "platform": "macos", "versions": ["2.0"], "unknown_version_installation_count": 0,
         "device_count": 2, "installation_count": 2, "evidence_at": "2026-09-20T11:00:00Z",
         "last_used_at": "2026-11-01T10:00:00Z", "metered_installation_count": 2,
         "unmetered_installation_count": 0, "stale_installation_count": 0,
         "unused_installation_count": 2, "usage_state": "unused", "removal_candidate": True,
         "canonical_key": "archive-tool", "canonical_name": "ArchiveTool",
         # PAT-2028: estate-wide assessed, genuinely clean (finding_count 0).
         "cve_assessment": {
             "state": "assessed", "last_matched_at": "2026-09-20T09:00:00Z",
             "finding_count": 0,
         }},
        {"name": "MeteringGap", "names": ["MeteringGap"], "identifier": "com.acme.gap",
         "platform": "windows", "versions": ["1.0"], "unknown_version_installation_count": 0,
         "device_count": 1, "installation_count": 1, "evidence_at": "2026-09-20T11:00:00Z",
         "last_used_at": None, "metered_installation_count": 0, "unmetered_installation_count": 1,
         "stale_installation_count": 0, "unused_installation_count": 0, "usage_state": "unmetered",
         "removal_candidate": False, "canonical_key": None, "canonical_name": None,
         # PAT-2028: mapped, at least one installation not yet matched at its
         # current version - last_matched_at null, finding_count from the
         # last completed match.
         "cve_assessment": {
             "state": "pending", "last_matched_at": None, "finding_count": 2,
         }},
        {"name": "PartialEvidence", "names": ["PartialEvidence"], "identifier": "com.acme.partial",
         "platform": "macos", "versions": ["4.0"], "unknown_version_installation_count": 0,
         "device_count": 2, "installation_count": 2, "evidence_at": "2026-09-20T11:00:00Z",
         "last_used_at": "2026-07-01T10:00:00Z", "metered_installation_count": 1,
         "unmetered_installation_count": 1, "stale_installation_count": 0,
         "unused_installation_count": 1, "usage_state": "mixed", "removal_candidate": False,
         "canonical_key": None, "canonical_name": None,
         # PAT-2028: assessed with a genuine non-zero count.
         "cve_assessment": {
             "state": "assessed", "last_matched_at": "2026-09-19T08:00:00Z",
             "finding_count": 4,
         }},
        {"name": "OldMetering", "names": ["OldMetering"], "identifier": "com.acme.old",
         "platform": "macos", "versions": ["3.0"], "unknown_version_installation_count": 1,
         "device_count": 1, "installation_count": 1, "evidence_at": "2026-08-01T11:00:00Z",
         "last_used_at": None, "metered_installation_count": 1, "unmetered_installation_count": 0,
         "stale_installation_count": 1, "unused_installation_count": 0, "usage_state": "stale",
         "removal_candidate": False, "canonical_key": None, "canonical_name": None,
         # PAT-2028: no CPE mapping anywhere in the tenant - never "No known
         # CVEs", finding_count and last_matched_at both null.
         "cve_assessment": {
             "state": "not_assessed", "last_matched_at": None, "finding_count": None,
         }},
        # PAT-2326: the fixture's one product the platform calls used, so the
        # stub /software shows all three verdicts the usage filter offers
        # (ArchiveTool unused, MeteringGap unmetered, this one used).
        {"name": "UsedTool", "names": ["UsedTool"], "identifier": "com.acme.used",
         "platform": "macos", "versions": ["5.1"], "unknown_version_installation_count": 0,
         "device_count": 2, "installation_count": 2, "evidence_at": "2026-09-20T11:00:00Z",
         "last_used_at": "2026-09-19T16:20:00Z", "metered_installation_count": 2,
         "unmetered_installation_count": 0, "stale_installation_count": 0,
         "unused_installation_count": 0, "usage_state": "used", "removal_candidate": False,
         "canonical_key": None, "canonical_name": None,
         "cve_assessment": {
             "state": "assessed", "last_matched_at": "2026-09-20T06:00:00Z",
             "finding_count": 0,
         }},
        {"name": "UnknownEvidence", "names": ["UnknownEvidence"], "identifier": "com.acme.unknown",
         "platform": "unknown", "versions": [], "unknown_version_installation_count": 1,
         "device_count": 1, "installation_count": 1, "evidence_at": "2026-09-20T11:00:00Z",
         "last_used_at": None, "metered_installation_count": 0, "unmetered_installation_count": 0,
         "stale_installation_count": 0, "unused_installation_count": 0, "usage_state": "unknown",
         "removal_candidate": False, "canonical_key": None, "canonical_name": None,
         "cve_assessment": {
             "state": "assessed", "last_matched_at": "2026-09-20T07:00:00Z",
             "finding_count": 1,
         }},
    ],
}

# PAT-2156: GET /v1/portal/software / GET /v1/portal/extensions with
# `device_id` set (contracts/portal-api.md "device_id (PAT-2156)") - the
# fixture backing /devices/{device_id}/software. Unlike SOFTWARE_INVENTORY
# above (predates PAT-2104), every product here carries team_id/
# product_key/policy_state, exactly as the real device-scoped endpoint
# does, plus first_seen_on_device. Only "dev-mac-001" (DEVICES' first
# fixture device) is served; see StubPlatformHandler.do_GET for the
# shape-valid-but-unknown (404) and malformed (400) device_id cases.
DEVICE_SOFTWARE = {
    "generated_at": "2026-09-25T12:00:00Z",
    "coverage": {
        "installation_count": 3, "metered_installation_count": 2,
        "unmetered_installation_count": 1, "stale_installation_count": 0,
        "unused_installation_count": 1,
    },
    "products": [
        {
            "name": "Example App", "names": ["Example App"],
            "identifier": "com.example.app", "platform": "macos",
            "versions": ["2.1"], "unknown_version_installation_count": 0,
            "device_count": 1, "installation_count": 1,
            "evidence_at": "2026-09-25T11:00:00Z", "last_used_at": "2026-09-24T10:00:00Z",
            "metered_installation_count": 1, "unmetered_installation_count": 0,
            "stale_installation_count": 0, "unused_installation_count": 0,
            "usage_state": "used", "removal_candidate": False,
            "canonical_key": None, "canonical_name": None,
            "team_id": "ABCDE12345", "product_key": "application:macos:com.example.app",
            "policy_state": "approved",
            "first_seen_on_device": "2026-08-01T09:00:00Z",
            # PAT-2028: assessed, genuinely clean (finding_count 0) - must
            # never read the same as not_assessed.
            "cve_assessment": {
                "state": "assessed", "last_matched_at": "2026-09-25T09:00:00Z",
                "finding_count": 0,
            },
        },
        {
            "name": "NotMeteredApp", "names": ["NotMeteredApp"],
            "identifier": "com.example.notmetered", "platform": "macos",
            "versions": ["1.0"], "unknown_version_installation_count": 0,
            "device_count": 1, "installation_count": 1,
            "evidence_at": "2026-09-25T11:00:00Z", "last_used_at": None,
            "metered_installation_count": 0, "unmetered_installation_count": 1,
            "stale_installation_count": 0, "unused_installation_count": 0,
            "usage_state": "unmetered", "removal_candidate": False,
            "canonical_key": None, "canonical_name": None,
            "team_id": None, "product_key": "application:macos:com.example.notmetered",
            "policy_state": "undecided",
            "first_seen_on_device": "2026-07-01T09:00:00Z",
            # No CPE mapping anywhere - never "No known CVEs".
            "cve_assessment": {
                "state": "not_assessed", "last_matched_at": None, "finding_count": None,
            },
        },
        {
            "name": "WindowsTool", "names": ["WindowsTool"],
            "identifier": "windowstool.exe", "platform": "windows",
            "versions": ["9.9"], "unknown_version_installation_count": 0,
            "device_count": 1, "installation_count": 1,
            "evidence_at": "2026-09-20T11:00:00Z", "last_used_at": None,
            "metered_installation_count": 1, "unmetered_installation_count": 0,
            "stale_installation_count": 0, "unused_installation_count": 1,
            "usage_state": "unused", "removal_candidate": True,
            "canonical_key": None, "canonical_name": None,
            "team_id": None, "product_key": "application:windows:windowstool.exe",
            "policy_state": "unapproved",
            "first_seen_on_device": "2026-12-15T09:00:00Z",
            "cve_assessment": {
                "state": "pending", "last_matched_at": None, "finding_count": 3,
            },
        },
    ],
}

DEVICE_EXTENSIONS = {
    "generated_at": "2026-09-25T12:00:00Z",
    "total": 2,
    "truncated": False,
    "estate_too_large": False,
    "extensions": [
        {
            "extension_id": "cfhdojbkjhnklbpkdaibdccddilifddb", "name": "AdBlock Plus",
            "browser": "chrome", "risk_level": "elevated",
            "versions": ["3.2.1"], "versions_truncated": False, "version_count": 1,
            "device_count": 1,
            "devices": [{"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk"}],
            "devices_truncated": False, "approval_state": "unapproved",
            "evidence_basis": "identifier_match", "removal_state": "not_requested",
            "removal_targets_total": 0, "removal_targets_completed": 0,
            "decided_by": "admin@example.com", "decided_at": "2026-12-30T09:12:00Z",
            "justification": "Flagged by security review",
        },
        {
            "extension_id": "aapocclcgogkmnckokdopfmhonfmgoek", "name": "Slack",
            "browser": "chrome", "risk_level": "normal",
            "versions": ["1.0.0"], "versions_truncated": False, "version_count": 1,
            "device_count": 1,
            "devices": [{"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk"}],
            "devices_truncated": False, "approval_state": "approved",
            "evidence_basis": "identifier_match", "removal_state": "not_requested",
            "removal_targets_total": 0, "removal_targets_completed": 0,
            "decided_by": "admin@example.com", "decided_at": "2026-11-14T11:00:00Z",
            "justification": None,
        },
    ],
}

# PAT-2156's own _approval_return_to regex (main.py) requires a real UUID
# device_id, unlike every other device fixture in this file (which use the
# readable "dev-mac-001" convention) - this is the one id that exercises
# the full approve-from-this-view-and-land-back-here round trip. It serves
# the exact same DEVICE_SOFTWARE/DEVICE_EXTENSIONS/DEVICE_DETAIL content as
# "dev-mac-001" (see StubPlatformHandler's routes dict and
# _device_software_response/_device_extensions_response below).
DEVICE_SOFTWARE_UUID_ID = "042c97f3-58cf-4a11-9c2e-0123456789ab"

# A device_id shaped like the test suite's own convention ("dev-mac-001",
# "hb-mac-01", ...) but not a fixture StubPlatformHandler actually serves is
# the platform's honest 404 (unknown, or another tenant's device - the two
# are indistinguishable by design). Anything NOT even shaped like a
# plausible id (empty, containing characters no device_id could carry) is
# the platform's 400 (malformed device_id) - see contracts/portal-api.md
# "device_id (PAT-2156, optional, UUID)". This stub does not itself require
# a real UUID (every other device fixture in this file uses the readable
# "dev-mac-001" convention, not production UUID formatting), only a
# plausible id shape, so the portal's own 400-vs-404 branching can be
# exercised without coupling every existing device fixture to a UUID.
_DEVICE_ID_SHAPE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")


_DEVICE_SOFTWARE_KNOWN_IDS = ("dev-mac-001", DEVICE_SOFTWARE_UUID_ID)


def _device_software_response(device_id: str, query: dict) -> tuple[int, dict]:
    if not _DEVICE_ID_SHAPE_RE.match(device_id):
        return 400, {"error": "malformed device_id"}
    if device_id not in _DEVICE_SOFTWARE_KNOWN_IDS:
        return 404, {"error": "device not found"}
    try:
        limit = int((query.get("limit") or ["500"])[0])
        offset = int((query.get("offset") or ["0"])[0])
    except ValueError:
        return 400, {"error": "invalid pagination"}
    search = (query.get("search") or [""])[0]
    products = DEVICE_SOFTWARE["products"]
    if search:
        needle = search.casefold()
        products = [p for p in products if needle in p.get("name", "").casefold()
                    or needle in p.get("identifier", "").casefold()]
    return 200, {**DEVICE_SOFTWARE, "total": len(products), "limit": limit,
                 "offset": offset, "products": products[offset:offset + limit]}


def _device_extensions_response(device_id: str) -> tuple[int, dict]:
    if not _DEVICE_ID_SHAPE_RE.match(device_id):
        return 400, {"error": "malformed device_id"}
    if device_id not in _DEVICE_SOFTWARE_KNOWN_IDS:
        return 404, {"error": "device not found"}
    return 200, DEVICE_EXTENSIONS


REPORTS = {
    "reports": [
        {"id": "rep-0001", "report_type": "executive-summary",
         "report_label": "Executive Estate Summary",
         "generated_at": "2026-07-01T09:00:00Z", "formats": ["pdf", "csv"]},
        # PAT-2405: generated before CSV existed, so the platform lists PDF only.
        {"id": "rep-0002", "report_type": "patch-status",
         "report_label": "Patch & Update Status",
         "generated_at": "2026-12-01T09:00:00Z", "formats": ["pdf"]},
        # An older platform build that does not send `formats` at all.
        {"id": "rep-0003", "report_type": "executive-summary",
         "report_label": "Executive Estate Summary",
         "generated_at": "2026-11-01T09:00:00Z"},
    ]
}

CSV_BYTES = b"section,item,value\r\nsummary,devices,12\r\n"
# Ids the stub knows; any other id is another tenant's or unknown: 404.
REPORT_CSV_AVAILABLE = {"rep-0001"}
REPORT_KNOWN_IDS = {"rep-0001", "rep-0002", "rep-0003"}

REPORT_CATALOGUE = {
    "reports": [
        {"type": "executive-summary", "label": "Executive Estate Summary",
         "description": "A concise estate assurance summary.",
         "default_frequency": "monthly", "subject_scope": "tenant"},
        {"type": "patch-status", "label": "Patch & Update Status",
         "description": "Current update currency and overdue patches.",
         "default_frequency": "weekly", "subject_scope": "tenant"},
        {"type": "ai-tooling-evidence", "label": "AI Tooling Evidence",
         "description": ("Current AI tooling identities, collection coverage, approval state "
                         "and exact vulnerability assessment evidence by device."),
         "default_frequency": "monthly", "subject_scope": "tenant"},
        # PAT-2009/PAT-2010: the catalogue entries backing the two new
        # Reports-tab pages' "Generate report" (PDF) buttons - the CSV form
        # of each is the matching GET /v1/portal/software/*?format=csv read,
        # not this catalogue (contracts/portal-api.md "GET /v1/portal/
        # reports/catalogue").
        {"type": "new-software", "label": "New Software",
         "description": "Products first seen on your estate since your last review.",
         "default_frequency": "weekly", "subject_scope": "tenant"},
        {"type": "software-drift", "label": "Unapproved & Unreviewed Software",
         "description": ("Installed products that are Unapproved or Unreviewed, with a "
                         "26-week trend and the devices carrying the most Unapproved software."),
         "default_frequency": "weekly", "subject_scope": "tenant"},
        {"type": "approved-software", "label": "Approved Software List",
         "description": "Every approved application, browser extension and Homebrew policy.",
         "default_frequency": "monthly", "subject_scope": "tenant"},
    ]
}

# PAT-2147: GET /v1/portal/reports/software/unsupported (contracts/
# portal-api.md). Covers all four states (one row each), a partial basis
# (a stale device, a non-empty not_counted list, complete=False) and the
# evidence-only cyber_essentials block. SAM_UNSUPPORTED_DEVICES below is
# the matching /devices drill-down, keyed the same way so a product_key
# filter on one always has a real row on the other.
SAM_UNSUPPORTED_SUMMARY = {
    "definition": {"id": "sam.unsupported-software", "version": 1,
                   "title": "Unsupported software", "ending_window_days": 90,
                   "lifecycle_cache_ttl_days": 7, "stale_after_days": 14,
                   "lifecycle_source": "endoflife.date"},
    "generated_at": "2026-09-25T12:00:00Z",
    "summary": {
        "installation_count": 4,
        "states": {
            "unsupported": {"installation_count": 1, "device_count": 1},
            "ending_within_90_days": {"installation_count": 1, "device_count": 1},
            "unknown": {"installation_count": 1, "device_count": 1},
            "supported": {"installation_count": 1, "device_count": 1},
        },
        "unknown_by_reason": {"no_published_mapping": 1},
    },
    "basis": {
        "generated_at": "2026-09-25T12:00:00Z",
        "evidence_newest_at": "2026-09-25T11:00:00Z",
        "evidence_oldest_at": "2026-09-05T11:00:00Z",
        "devices_total": 4, "devices_assessed": 4, "devices_reporting": 3,
        "devices_stale": 1, "devices_without_inventory": 0, "stale_after_days": 14,
        "lifecycle_source": "endoflife.date",
        "lifecycle_checked_oldest_at": "2026-09-17T01:02:00Z",
        "lifecycle_checked_newest_at": "2026-09-25T01:02:00Z",
        "retired_devices_excluded": True, "devices_retired": 0,
        "not_counted": [
            {"reason": "retired_devices",
             "description": "devices your organisation has retired", "count": 0},
            {"reason": "unrecognised_platform",
             "description": "devices reporting an operating system other than macOS or Windows",
             "count": 0},
            {"reason": "developer_tooling",
             "description": ("IDE extensions, language packages, local models and MCP "
                             "servers are not assessed by this report"),
             "count": 1},
            {"reason": "homebrew_taps",
             "description": "Homebrew taps are package sources, not installed software",
             "count": 0},
        ],
        "complete": False,
        "statement": ("An estimate from the software and operating system versions your "
                     "devices reported, compared with public end of support dates from "
                     "endoflife.date. It is not an audit or a compliance position. Unknown "
                     "means Patched could not determine support; it never means supported."),
        "notes": [],
    },
    "cyber_essentials": {
        "requirement": "security_update_management",
        "evidence_kind": "unsupported_software",
        "position": "evidence_only",
        "statement": ("Cyber Essentials requires in-scope software to be licensed and "
                     "supported. This is evidence only, not a pass or fail."),
        "evidence_at": "2026-09-25T12:00:00Z",
        "devices_assessed": 4,
        "devices_with_unsupported_software": 1,
        "devices_with_unknown_support": 1,
        "unsupported_installation_count": 1,
        "complete": False,
        "devices": [
            {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk",
             "device_last_seen": "2026-09-25T11:00:00Z", "device_stale": False,
             "unsupported": [
                 {"kind": "operating_system", "product_key": "os:macos", "name": "macOS",
                  "version": "13.6.1", "cycle": "13", "eol_date": "2025-09-15",
                  "source": {"name": "endoflife.date", "slug": "macos",
                            "url": "https://endoflife.date/macos"},
                  "last_checked_at": "2026-09-25T01:02:00Z", "note": None},
             ]},
        ],
    },
    "total": 4, "limit": 100, "offset": 0,
    "products": [
        {"product_key": "os:macos", "kind": "operating_system", "name": "macOS",
         "platform": "macos", "version": "13.6.1", "edition": None,
         "state": "unsupported", "cycle": "13", "eol_date": "2025-09-15", "days_to_eol": -375,
         "device_count": 1, "stale_device_count": 0, "installation_count": 1,
         "source": {"name": "endoflife.date", "slug": "macos",
                    "url": "https://endoflife.date/macos"},
         "last_checked_at": "2026-09-25T01:02:00Z",
         "unknown_reason": None, "unknown_reason_text": None, "note": None},
        {"product_key": "os:windows", "kind": "operating_system", "name": "Windows",
         "platform": "windows", "version": "10.0.19045",
         "edition": "Microsoft Windows 10 Pro",
         "state": "ending_within_90_days", "cycle": "10-22h2", "eol_date": "2026-12-01",
         "days_to_eol": 67, "device_count": 1, "stale_device_count": 1, "installation_count": 1,
         "source": {"name": "endoflife.date", "slug": "windows",
                    "url": "https://endoflife.date/windows"},
         "last_checked_at": "2026-09-25T01:02:00Z",
         "unknown_reason": None, "unknown_reason_text": None,
         "note": "paid extended security updates are available; enrolment is not evidenced"},
        {"product_key": "app:3f1c2a", "kind": "application", "name": "Proposed App",
         "platform": "windows", "version": "1.0", "edition": None,
         "state": "unknown", "cycle": None, "eol_date": None, "days_to_eol": None,
         "device_count": 1, "stale_device_count": 0, "installation_count": 1,
         "source": None, "last_checked_at": None,
         "unknown_reason": "no_published_mapping",
         "unknown_reason_text": "no published lifecycle mapping for this product", "note": None},
        {"product_key": "app:9b2e11", "kind": "application", "name": "Slack",
         "platform": "macos", "version": "4.40.0", "edition": None,
         "state": "supported", "cycle": "4", "eol_date": "2027-06-01", "days_to_eol": 613,
         "device_count": 1, "stale_device_count": 0, "installation_count": 1,
         "source": {"name": "endoflife.date", "slug": "slack",
                    "url": "https://endoflife.date/slack"},
         "last_checked_at": "2026-09-25T01:02:00Z",
         "unknown_reason": None, "unknown_reason_text": None, "note": None},
    ],
}

SAM_UNSUPPORTED_DEVICES = {
    "definition": SAM_UNSUPPORTED_SUMMARY["definition"],
    "generated_at": "2026-09-25T12:00:00Z",
    "basis": SAM_UNSUPPORTED_SUMMARY["basis"],
    "total": 4, "limit": 100, "offset": 0,
    "rows": [
        {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk",
         "device_last_seen": "2026-09-25T11:00:00Z", "device_stale": False,
         "product_key": "os:macos", "kind": "operating_system", "name": "macOS",
         "platform": "macos", "version": "13.6.1", "edition": None,
         "state": "unsupported", "cycle": "13", "eol_date": "2025-09-15", "days_to_eol": -375,
         "source": {"name": "endoflife.date", "slug": "macos",
                    "url": "https://endoflife.date/macos"},
         "last_checked_at": "2026-09-25T01:02:00Z",
         "unknown_reason": None, "unknown_reason_text": None, "note": None},
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
         "device_last_seen": "2026-09-10T08:00:00Z", "device_stale": True,
         "product_key": "os:windows", "kind": "operating_system", "name": "Windows",
         "platform": "windows", "version": "10.0.19045",
         "edition": "Microsoft Windows 10 Pro",
         "state": "ending_within_90_days", "cycle": "10-22h2", "eol_date": "2026-12-01",
         "days_to_eol": 67,
         "source": {"name": "endoflife.date", "slug": "windows",
                    "url": "https://endoflife.date/windows"},
         "last_checked_at": "2026-09-25T01:02:00Z",
         "unknown_reason": None, "unknown_reason_text": None,
         "note": "paid extended security updates are available; enrolment is not evidenced"},
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
         "device_last_seen": "2026-09-10T08:00:00Z", "device_stale": True,
         "product_key": "app:3f1c2a", "kind": "application", "name": "Proposed App",
         "platform": "windows", "version": "1.0", "edition": None,
         "state": "unknown", "cycle": None, "eol_date": None, "days_to_eol": None,
         "source": None, "last_checked_at": None,
         "unknown_reason": "no_published_mapping",
         "unknown_reason_text": "no published lifecycle mapping for this product", "note": None},
        {"device_id": "dev-mac-002", "hostname": "acme-mbp-design",
         "device_last_seen": "2026-09-25T10:00:00Z", "device_stale": False,
         "product_key": "app:9b2e11", "kind": "application", "name": "Slack",
         "platform": "macos", "version": "4.40.0", "edition": None,
         "state": "supported", "cycle": "4", "eol_date": "2027-06-01", "days_to_eol": 613,
         "source": {"name": "endoflife.date", "slug": "slack",
                    "url": "https://endoflife.date/slack"},
         "last_checked_at": "2026-09-25T01:02:00Z",
         "unknown_reason": None, "unknown_reason_text": None, "note": None},
    ],
}

SAM_UNSUPPORTED_CSV = (
    "device_id,hostname,device_last_seen,device_stale,kind,product_key,name,platform,version,"
    "edition,state,cycle,eol_date,days_to_eol,source,source_url,last_checked_at,unknown_reason,"
    "note,generated_at\r\n"
    "dev-mac-001,acme-mbp-frontdesk,2026-09-25T11:00:00Z,False,operating_system,os:macos,macOS,"
    "macos,13.6.1,,unsupported,13,2025-09-15,-375,endoflife.date,"
    "https://endoflife.date/macos,2026-09-25T01:02:00Z,,,2026-09-25T12:00:00Z\r\n"
)

# PAT-2148: GET /v1/portal/reports/software/remote-access (contracts/
# portal-api.md). One row per state so the unsanctioned-first summary and
# pill tones are all exercised: AnyDesk is unapproved (unsanctioned, with a
# per-user install), a Chrome Remote Desktop extension is unreviewed, LogMeIn
# is ignored, TeamViewer is approved (sanctioned, machine-wide), and
# NinjaOne Agent is the one rmm_agent row - kept in its own category/summary
# section so an MSP's own tooling is never presented as a finding.
# REMOTE_ACCESS_DEVICES below is the matching /devices drill-down, keyed the
# same way so a product_key filter always has a real row on both.
REMOTE_ACCESS_BASIS = {
    "generated_at": "2026-09-26T12:00:00Z",
    "evidence_newest_at": "2026-09-26T11:00:00Z", "evidence_oldest_at": "2026-09-20T11:00:00Z",
    "devices_total": 6, "devices_assessed": 5, "devices_reporting": 5,
    "devices_stale": 1, "devices_without_inventory": 0, "stale_after_days": 14,
    "retired_devices_excluded": True, "devices_retired": 1,
    "not_counted": [
        {"reason": "retired_devices",
         "description": "devices your organisation has retired", "count": 1},
        {"reason": "unrecognised_platform",
         "description": "devices reporting an operating system other than macOS or Windows",
         "count": 0},
    ],
    "complete": False,
    "statement": (
        "Every remote access tool and RMM agent Patched's category rules recognise, by "
        "device and user where a per-user install is reported, with your tenant's existing "
        "software approval state. Detection covers only the tools this catalogue "
        "recognises: a device reporting none of them is not evidence that no remote access "
        "tool is installed, only that none of the catalogued ones were found. It is not an "
        "audit or a compliance position."
    ),
    "notes": [],
}

REMOTE_ACCESS_SUMMARY = {
    "definition": {"id": "sam.remote-access", "version": 1, "title": "Remote access tools"},
    "generated_at": "2026-09-26T12:00:00Z",
    "summary": {
        "remote_access": {
            "unapproved": {"tool_count": 1, "installation_count": 1, "device_count": 1},
            "unreviewed": {"tool_count": 1, "installation_count": 1, "device_count": 1},
            "ignored": {"tool_count": 1, "installation_count": 1, "device_count": 1},
            "approved": {"tool_count": 1, "installation_count": 1, "device_count": 1},
        },
        "rmm_agents": {
            "unapproved": {"tool_count": 1, "installation_count": 1, "device_count": 1},
            "unreviewed": {"tool_count": 0, "installation_count": 0, "device_count": 0},
            "ignored": {"tool_count": 0, "installation_count": 0, "device_count": 0},
            "approved": {"tool_count": 0, "installation_count": 0, "device_count": 0},
        },
        "remote_access_tool_count": 4, "remote_access_installation_count": 4,
        "rmm_agent_tool_count": 1, "rmm_agent_installation_count": 1,
    },
    "basis": REMOTE_ACCESS_BASIS,
    "total": 5, "limit": 100, "offset": 0,
    "products": [
        {"product_key": "remote_access:app:com.philandro.anydesk", "category": "remote_access",
         "kind": "app", "name": "AnyDesk", "platform": "macos",
         "identifier": "com.philandro.anydesk", "approval_state": "unapproved",
         "device_count": 1, "stale_device_count": 0, "installation_count": 1,
         "users": ["alice"], "machine_wide_count": 0, "last_seen": "2026-09-26T11:00:00Z"},
        {"product_key": "remote_access:browser_extension:gotoremote-crd",
         "category": "remote_access",
         "kind": "browser_extension", "name": "Chrome Remote Desktop", "platform": "windows",
         "identifier": "gbchcmhmhahfdphkhkmpfmihenigjmpp", "approval_state": "unreviewed",
         "device_count": 1, "stale_device_count": 0, "installation_count": 1,
         "users": [], "machine_wide_count": 1, "last_seen": "2026-09-25T09:00:00Z"},
        {"product_key": "remote_access:app:com.logmein.logmeinclient", "category": "remote_access",
         "kind": "app", "name": "LogMeIn", "platform": "macos",
         "identifier": "com.logmein.logmeinclient", "approval_state": "ignored",
         "device_count": 1, "stale_device_count": 1, "installation_count": 1,
         "users": [], "machine_wide_count": 1, "last_seen": "2026-09-10T08:00:00Z"},
        {"product_key": "remote_access:app:com.teamviewer.teamviewer", "category": "remote_access",
         "kind": "app", "name": "TeamViewer", "platform": "windows",
         "identifier": "com.teamviewer.teamviewer", "approval_state": "approved",
         "device_count": 1, "stale_device_count": 0, "installation_count": 1,
         "users": [], "machine_wide_count": 1, "last_seen": "2026-09-26T10:00:00Z"},
        {"product_key": "rmm_agent:app:com.ninjarmm.agent", "category": "rmm_agent",
         "kind": "app", "name": "NinjaOne Agent", "platform": "windows",
         "identifier": "com.ninjarmm.agent", "approval_state": "unapproved",
         "device_count": 1, "stale_device_count": 0, "installation_count": 1,
         "users": [], "machine_wide_count": 1, "last_seen": "2026-09-26T10:00:00Z"},
    ],
}

REMOTE_ACCESS_DEVICES = {
    "definition": REMOTE_ACCESS_SUMMARY["definition"],
    "generated_at": "2026-09-26T12:00:00Z",
    "basis": REMOTE_ACCESS_BASIS,
    "total": 5, "limit": 100, "offset": 0,
    "rows": [
        # Device ids reused from the shared roster (dev-mac-001/dev-win-002/
        # dev-mac-003) rather than invented ones, so each device link the
        # devices drill-down renders resolves to a real device-detail fixture
        # (same lesson as the 2026-09-25 walk fix noted in AGENTS.md's
        # Walker section: fixed in the stub data, not by weakening the
        # walker's `link` check).
        {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk",
         "device_last_seen": "2026-09-26T11:00:00Z", "device_stale": False,
         "product_key": "remote_access:app:com.philandro.anydesk", "category": "remote_access",
         "kind": "app", "name": "AnyDesk", "platform": "macos",
         "identifier": "com.philandro.anydesk", "approval_state": "unapproved",
         "user": "alice", "machine_wide": False, "last_seen": "2026-09-26T11:00:00Z"},
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
         "device_last_seen": "2026-09-25T09:00:00Z", "device_stale": False,
         "product_key": "remote_access:browser_extension:gotoremote-crd",
         "category": "remote_access", "kind": "browser_extension",
         "name": "Chrome Remote Desktop", "platform": "windows",
         "identifier": "gbchcmhmhahfdphkhkmpfmihenigjmpp", "approval_state": "unreviewed",
         "user": None, "machine_wide": True, "last_seen": "2026-09-25T09:00:00Z"},
        {"device_id": "dev-mac-003", "hostname": "acme-mbp-storeroom",
         "device_last_seen": "2026-09-10T08:00:00Z", "device_stale": True,
         "product_key": "remote_access:app:com.logmein.logmeinclient",
         "category": "remote_access", "kind": "app", "name": "LogMeIn", "platform": "macos",
         "identifier": "com.logmein.logmeinclient", "approval_state": "ignored",
         "user": None, "machine_wide": True, "last_seen": "2026-09-10T08:00:00Z"},
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
         "device_last_seen": "2026-09-26T10:00:00Z", "device_stale": False,
         "product_key": "remote_access:app:com.teamviewer.teamviewer",
         "category": "remote_access", "kind": "app", "name": "TeamViewer", "platform": "windows",
         "identifier": "com.teamviewer.teamviewer", "approval_state": "approved",
         "user": None, "machine_wide": True, "last_seen": "2026-09-26T10:00:00Z"},
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
         "device_last_seen": "2026-09-26T10:00:00Z", "device_stale": False,
         "product_key": "rmm_agent:app:com.ninjarmm.agent", "category": "rmm_agent",
         "kind": "app", "name": "NinjaOne Agent", "platform": "windows",
         "identifier": "com.ninjarmm.agent", "approval_state": "unapproved",
         "user": None, "machine_wide": True, "last_seen": "2026-09-26T10:00:00Z"},
    ],
}

REMOTE_ACCESS_CSV = (
    "device_id,hostname,device_last_seen,device_stale,category,kind,product_key,name,platform,"
    "identifier,version,approval_state,user,last_seen,generated_at\r\n"
    "dev-mac-001,acme-mbp-frontdesk,2026-09-26T11:00:00Z,False,remote_access,app,"
    "remote_access:app:com.philandro.anydesk,AnyDesk,macos,com.philandro.anydesk,8.0.19,"
    "unapproved,alice,2026-09-26T11:00:00Z,2026-09-26T12:00:00Z\r\n"
)

# PAT-2150: GET /v1/portal/reports/software/version-sprawl (contracts/
# portal-api.md). ManyVersionApp exercises the many-version + CVE-on-oldest
# path, SingleVersionApp the one-version path, UnknownLatestApp the
# latest_released == null / "Not known" path, and NotAssessedApp the
# cve_not_assessed_on_oldest_version path (never rendered as a bare 0).
# PAT-2509: every latest_released_source carries `label` (the plain wording
# the portal shows) and `checked_at`; `name` is a machine name that is never
# rendered. SingleVersionApp is the curated_catalogue row whose label is
# "Patched reference list", NotAssessedApp has a label and no date, and
# OlderPlatformApp is a source with no `label` at all (a platform that
# predates the field), which must render the version and no source line.
VERSION_SPRAWL_BASIS = {
    "generated_at": "2026-09-26T12:00:00Z",
    "devices_total": 6, "devices_assessed": 5, "devices_stale": 1, "stale_after_days": 14,
    "retired_devices_excluded": True, "devices_retired": 1,
    "not_counted": [
        {"reason": "retired_devices",
         "description": "devices your organisation has retired", "count": 1},
        {"reason": "unrecognised_platform",
         "description": "devices reporting an operating system other than macOS or Windows",
         "count": 0},
        {"reason": "developer_tooling",
         "description": ("IDE extensions, language packages, local models and MCP "
                         "servers are not assessed by this report"),
         "count": 0},
        {"reason": "homebrew_taps",
         "description": "Homebrew taps are package sources, not installed software",
         "count": 0},
    ],
    "complete": False,
    "statement": (
        "An estimate of version spread across your estate from installed application "
        "versions, compared against each product's own newest live version and, where "
        "Patched holds a trusted source for it, the vendor's most recently released "
        "version. It is not an audit or a compliance position."
    ),
    "notes": [],
}

VERSION_SPRAWL_SUMMARY = {
    "definition": {
        "id": "sam.version-sprawl", "version": 1, "title": "Version sprawl",
        "stale_after_days": 14, "lifecycle_cache_ttl_days": 7,
        "major_version_rule": (
            "a version's major is the leading run of digits before the first separator"
        ),
        "latest_source_precedence": ["endoflife.date", "curated_catalogue", "vendor_feed"],
    },
    "generated_at": "2026-09-26T12:00:00Z",
    "basis": VERSION_SPRAWL_BASIS,
    "total": 5, "limit": 100, "offset": 0,
    "products": [
        {"product_key": "app:3f1c2a", "name": "ManyVersionApp", "platform": "macos",
         "distinct_versions": 3, "oldest_version": "8.0.0", "newest_version": "10.0.0",
         "latest_released": "10.4.0",
         "latest_released_source": {"name": "endoflife.date", "slug": "manyversionapp",
                                    "url": "https://endoflife.date/manyversionapp",
                                    "label": "endoflife.date",
                                    "checked_at": "2026-10-05T01:02:00Z"},
         "devices_more_than_one_major_behind": 2, "devices_not_comparable": 1,
         "cve_count_on_oldest_version": 3, "cve_not_assessed_on_oldest_version": False,
         "device_count": 5, "stale_device_count": 1,
         "versions": [
             {"version": "10.0.0", "device_count": 1, "stale_device_count": 0},
             {"version": "9.5.0", "device_count": 1, "stale_device_count": 0},
             {"version": "8.0.0", "device_count": 2, "stale_device_count": 1},
         ]},
        {"product_key": "app:9b2e11", "name": "SingleVersionApp", "platform": "windows",
         "distinct_versions": 1, "oldest_version": "2.1.0", "newest_version": "2.1.0",
         "latest_released": "2.1.0",
         "latest_released_source": {"name": "curated_catalogue", "slug": "", "url": "",
                                    "label": "Patched reference list",
                                    "checked_at": "2026-10-05T01:02:00Z"},
         "devices_more_than_one_major_behind": 0, "devices_not_comparable": 0,
         "cve_count_on_oldest_version": 0, "cve_not_assessed_on_oldest_version": False,
         "device_count": 2, "stale_device_count": 0,
         "versions": [
             {"version": "2.1.0", "device_count": 2, "stale_device_count": 0},
         ]},
        {"product_key": "app:71ad04", "name": "UnknownLatestApp", "platform": "macos",
         "distinct_versions": 2, "oldest_version": "1.0", "newest_version": "1.2",
         "latest_released": None, "latest_released_source": None,
         "devices_more_than_one_major_behind": 0, "devices_not_comparable": 0,
         "cve_count_on_oldest_version": 1, "cve_not_assessed_on_oldest_version": False,
         "device_count": 3, "stale_device_count": 0,
         "versions": [
             {"version": "1.2", "device_count": 2, "stale_device_count": 0},
             {"version": "1.0", "device_count": 1, "stale_device_count": 0},
         ]},
        {"product_key": "app:c40e88", "name": "NotAssessedApp", "platform": "windows",
         "distinct_versions": 1, "oldest_version": "5.0", "newest_version": "5.0",
         "latest_released": "5.0",
         "latest_released_source": {"name": "endoflife.date", "slug": "notassessedapp",
                                    "url": "https://endoflife.date/notassessedapp",
                                    "label": "endoflife.date", "checked_at": None},
         "devices_more_than_one_major_behind": 0, "devices_not_comparable": 0,
         "cve_count_on_oldest_version": None, "cve_not_assessed_on_oldest_version": True,
         "device_count": 1, "stale_device_count": 0,
         "versions": [
             {"version": "5.0", "device_count": 1, "stale_device_count": 0},
         ]},
        {"product_key": "app:e17b53", "name": "OlderPlatformApp", "platform": "macos",
         "distinct_versions": 1, "oldest_version": "3.1.0", "newest_version": "3.1.0",
         "latest_released": "3.2.1",
         "latest_released_source": {"name": "curated_catalogue", "slug": "", "url": ""},
         "devices_more_than_one_major_behind": 0, "devices_not_comparable": 0,
         "cve_count_on_oldest_version": 0, "cve_not_assessed_on_oldest_version": False,
         "device_count": 1, "stale_device_count": 0,
         "versions": [
             {"version": "3.1.0", "device_count": 1, "stale_device_count": 0},
         ]},
    ],
}

# PAT-2509: latest_released_source holds the plain label (never the machine
# name) and latest_released_checked_at is appended after generated_at.
VERSION_SPRAWL_CSV = (
    "product_key,name,platform,distinct_versions,oldest_version,newest_version,"
    "latest_released,latest_released_source,devices_more_than_one_major_behind,"
    "devices_not_comparable,cve_count_oldest_version,device_count,stale_device_count,"
    "generated_at,latest_released_checked_at\r\n"
    "app:3f1c2a,ManyVersionApp,macos,3,8.0.0,10.0.0,10.4.0,endoflife.date,2,1,3,5,1,"
    "2026-09-26T12:00:00Z,2026-10-05T01:02:00Z\r\n"
    "app:9b2e11,SingleVersionApp,windows,1,2.1.0,2.1.0,2.1.0,Patched reference list,0,0,0,2,0,"
    "2026-09-26T12:00:00Z,2026-10-05T01:02:00Z\r\n"
)

# PAT-2151: GET /v1/portal/reports/software/duplicate-tools (contracts/
# portal-api.md). password_manager is flagged (three distinct products:
# 1Password cross-platform, Bitwarden macOS, LastPass Windows, one of each
# approval state so the pill mapping is exercised); vpn_client is present
# but unflagged (two products only). DUPLICATE_TOOLS_ROWS is the per-device
# row list the CSV export (and this stub's product_key filter) reads from -
# device ids reused from the shared roster (dev-mac-001/002/003,
# dev-win-002) rather than invented ones, same lesson AGENTS.md's Walker
# section records for the other SAM reports.
DUPLICATE_TOOLS_BASIS = {
    "generated_at": "2026-09-26T12:00:00Z",
    "evidence_newest_at": "2026-09-26T11:00:00Z", "evidence_oldest_at": "2026-09-20T11:00:00Z",
    "devices_total": 6, "devices_assessed": 5, "devices_reporting": 5,
    "devices_stale": 0, "devices_without_inventory": 0, "stale_after_days": 14,
    "retired_devices_excluded": True, "devices_retired": 1,
    "not_counted": [
        {"reason": "retired_devices",
         "description": "devices your organisation has retired", "count": 1},
    ],
    "paid_products_rule_pending": True,
    "complete": False,
    "statement": (
        "Categories where Patched's curated category rules recognise three or more distinct "
        "products installed across your estate, which makes each one a consolidation "
        "candidate. This is shown without needing licence or price data. Detection covers "
        "only the products this catalogue recognises: a category showing fewer than three "
        "products is not evidence that fewer are actually installed, only that fewer of the "
        "catalogued ones were found. A second rule, two or more paid products in a category, "
        "needs licence data and is not applied yet. It is not an audit or a compliance "
        "position."
    ),
    "notes": [],
}

DUPLICATE_TOOLS_SUMMARY = {
    "definition": {
        "id": "sam.duplicate-tools", "version": 1, "title": "Duplicate tools by category",
    },
    "generated_at": "2026-09-26T12:00:00Z",
    "summary": {
        "categories_assessed": 8, "categories_with_products": 2,
        "categories_flagged": 1, "product_count": 5, "installation_count": 6,
    },
    "basis": DUPLICATE_TOOLS_BASIS,
    "total": 2, "limit": 50, "offset": 0,
    "categories": [
        {
            "category": "password_manager", "display_name": "Password managers",
            "flagged": True, "product_count": 3,
            "products": [
                {"product_key": "password_manager:onepassword", "category": "password_manager",
                 "name": "1Password", "kinds": ["app"], "platforms": ["macos", "windows"],
                 "identifiers": ["agilebits.1password", "com.1password.1password"],
                 "approval_state": "unreviewed", "device_count": 2, "stale_device_count": 0,
                 "installation_count": 2, "users": [], "machine_wide_count": 2,
                 "last_seen": "2026-09-26T11:00:00Z"},
                {"product_key": "password_manager:bitwarden", "category": "password_manager",
                 "name": "Bitwarden", "kinds": ["app"], "platforms": ["macos"],
                 "identifiers": ["com.bitwarden.desktop"],
                 "approval_state": "unapproved", "device_count": 1, "stale_device_count": 0,
                 "installation_count": 1, "users": ["alice"], "machine_wide_count": 0,
                 "last_seen": "2026-09-25T09:00:00Z"},
                {"product_key": "password_manager:lastpass", "category": "password_manager",
                 "name": "LastPass", "kinds": ["app"], "platforms": ["windows"],
                 "identifiers": ["lastpass.lastpass"],
                 "approval_state": "ignored", "device_count": 1, "stale_device_count": 0,
                 "installation_count": 1, "users": [], "machine_wide_count": 1,
                 "last_seen": "2026-09-24T09:00:00Z"},
            ],
        },
        {
            "category": "vpn_client", "display_name": "VPN clients",
            "flagged": False, "product_count": 2,
            "products": [
                {"product_key": "vpn_client:nordvpn", "category": "vpn_client",
                 "name": "NordVPN", "kinds": ["app"], "platforms": ["macos"],
                 "identifiers": ["com.nordvpn.macos"],
                 "approval_state": "approved", "device_count": 1, "stale_device_count": 0,
                 "installation_count": 1, "users": [], "machine_wide_count": 1,
                 "last_seen": "2026-09-26T10:00:00Z"},
                {"product_key": "vpn_client:expressvpn", "category": "vpn_client",
                 "name": "ExpressVPN", "kinds": ["app"], "platforms": ["windows"],
                 "identifiers": ["expressvpn.expressvpn"],
                 "approval_state": "unreviewed", "device_count": 1, "stale_device_count": 0,
                 "installation_count": 1, "users": [], "machine_wide_count": 1,
                 "last_seen": "2026-09-23T09:00:00Z"},
            ],
        },
    ],
}

DUPLICATE_TOOLS_ROWS = [
    {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk",
     "device_last_seen": "2026-09-26T11:00:00Z", "device_stale": False,
     "category": "password_manager", "product_key": "password_manager:onepassword",
     "name": "1Password", "platform": "macos", "kind": "app",
     "identifier": "com.1password.1password", "version": "8.10.0",
     "approval_state": "unreviewed", "user": None, "machine_wide": True,
     "last_seen": "2026-09-26T11:00:00Z"},
    {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
     "device_last_seen": "2026-09-26T11:00:00Z", "device_stale": False,
     "category": "password_manager", "product_key": "password_manager:onepassword",
     "name": "1Password", "platform": "windows", "kind": "app",
     "identifier": "agilebits.1password", "version": "8.10.32",
     "approval_state": "unreviewed", "user": None, "machine_wide": True,
     "last_seen": "2026-09-26T11:00:00Z"},
    {"device_id": "dev-mac-002", "hostname": "acme-mbp-sales",
     "device_last_seen": "2026-09-25T09:00:00Z", "device_stale": False,
     "category": "password_manager", "product_key": "password_manager:bitwarden",
     "name": "Bitwarden", "platform": "macos", "kind": "app",
     "identifier": "com.bitwarden.desktop", "version": "2026.8.0",
     "approval_state": "unapproved", "user": "alice", "machine_wide": False,
     "last_seen": "2026-09-25T09:00:00Z"},
    {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
     "device_last_seen": "2026-09-24T09:00:00Z", "device_stale": False,
     "category": "password_manager", "product_key": "password_manager:lastpass",
     "name": "LastPass", "platform": "windows", "kind": "app",
     "identifier": "lastpass.lastpass", "version": "4.129.0",
     "approval_state": "ignored", "user": None, "machine_wide": True,
     "last_seen": "2026-09-24T09:00:00Z"},
    {"device_id": "dev-mac-003", "hostname": "acme-mbp-storeroom",
     "device_last_seen": "2026-09-26T10:00:00Z", "device_stale": False,
     "category": "vpn_client", "product_key": "vpn_client:nordvpn",
     "name": "NordVPN", "platform": "macos", "kind": "app",
     "identifier": "com.nordvpn.macos", "version": "7.20.0",
     "approval_state": "approved", "user": None, "machine_wide": True,
     "last_seen": "2026-09-26T10:00:00Z"},
    {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
     "device_last_seen": "2026-09-23T09:00:00Z", "device_stale": False,
     "category": "vpn_client", "product_key": "vpn_client:expressvpn",
     "name": "ExpressVPN", "platform": "windows", "kind": "app",
     "identifier": "expressvpn.expressvpn", "version": "12.60.0",
     "approval_state": "unreviewed", "user": None, "machine_wide": True,
     "last_seen": "2026-09-23T09:00:00Z"},
]

DUPLICATE_TOOLS_CSV = (
    "device_id,hostname,device_last_seen,device_stale,category,product_key,name,platform,kind,"
    "identifier,version,approval_state,user,last_seen,generated_at\r\n"
    "dev-mac-001,acme-mbp-frontdesk,2026-09-26T11:00:00Z,False,password_manager,"
    "password_manager:onepassword,1Password,macos,app,com.1password.1password,8.10.0,"
    "unreviewed,machine-wide,2026-09-26T11:00:00Z,2026-09-26T12:00:00Z\r\n"
)

# PAT-2152: GET /v1/portal/reports/software/publishers (+ /devices,
# contracts/portal-api.md). All four groups on both platforms: unsigned_or_
# adhoc and invalid are call-out rows with no publisher identity at all;
# unverified is a signed-but-unpinned call-out row; verified carries one
# trusted (macOS Team ID) and one untrusted (Windows Authenticode) publisher
# so both pill states render. PUBLISHERS_DEVICES is the matching /devices
# drill-down, keyed the same way so a publisher_key/group/platform filter
# always has a real row on both - device ids reused from the shared roster
# (dev-mac-001/002/003, dev-win-002).
PUBLISHERS_BASIS = {
    "generated_at": "2026-09-26T12:00:00Z",
    "evidence_newest_at": "2026-09-26T11:00:00Z", "evidence_oldest_at": "2026-09-20T11:00:00Z",
    "devices_total": 6, "devices_assessed": 5, "devices_reporting": 5,
    "devices_stale": 0, "devices_without_inventory": 0, "stale_after_days": 14,
    "retired_devices_excluded": True, "devices_retired": 1,
    "not_counted": [
        {"reason": "retired_devices",
         "description": "devices your organisation has retired", "count": 1},
    ],
    "complete": False,
    "statement": (
        "Every currently installed application, grouped by the publisher its code signing "
        "evidence proves: the macOS Team ID, or the Windows Authenticode signer pinned to its "
        "signing root. Never the display name, registry Publisher string or any other "
        "installer-claimed metadata. Unsigned, invalid and unverifiable publishers are listed "
        "first. Trusted means this tenant has approved a product under that exact publisher "
        "identity; it is this tenant's own decision, not a judgement on the vendor, and it is "
        "not an audit or a compliance position."
    ),
    "notes": [],
}

PUBLISHERS_SUMMARY = {
    "definition": {"id": "sam.software-publishers", "version": 1, "title": "Software publishers"},
    "generated_at": "2026-09-26T12:00:00Z",
    "summary": {
        "publisher_count": 2, "trusted_publisher_count": 1, "untrusted_publisher_count": 1,
        "unsigned_installation_count": 1, "invalid_installation_count": 1,
        "unverified_installation_count": 1, "installation_count": 5,
    },
    "basis": PUBLISHERS_BASIS,
    "total": 4, "limit": 100, "offset": 0,
    "publishers": [
        {"publisher_key": "", "group": "unsigned_or_adhoc", "platform": "macos",
         "identity_basis": "none", "publisher": None, "trusted": False, "signing": "unsigned",
         "signer_class": None, "notarisation": "not_applicable",
         "product_count": 1, "device_count": 1, "stale_device_count": 0, "installation_count": 1},
        {"publisher_key": "", "group": "invalid", "platform": "windows",
         "identity_basis": "none", "publisher": None, "trusted": False, "signing": "invalid",
         "signer_class": None, "notarisation": "unknown",
         "product_count": 1, "device_count": 1, "stale_device_count": 0, "installation_count": 1},
        {"publisher_key": "", "group": "unverified", "platform": "windows",
         "identity_basis": "none", "publisher": None, "trusted": False, "signing": "signed",
         "signer_class": None, "notarisation": "unknown",
         "product_count": 1, "device_count": 1, "stale_device_count": 0, "installation_count": 1},
        {"publisher_key": "team:ABCDE12345", "group": "verified", "platform": "macos",
         "identity_basis": "team_id", "publisher": "ABCDE12345", "trusted": True,
         "signing": "signed", "signer_class": "developer_id", "notarisation": "confirmed",
         "product_count": 1, "device_count": 1, "stale_device_count": 0, "installation_count": 1},
        {"publisher_key": "authenticode:CN=Contoso Software Ltd", "group": "verified",
         "platform": "windows", "identity_basis": "authenticode_signer",
         "publisher": "CN=Contoso Software Ltd", "trusted": False, "signing": "signed",
         "signer_class": "authenticode", "notarisation": "not_applicable",
         "product_count": 1, "device_count": 1, "stale_device_count": 0, "installation_count": 1},
    ],
}

PUBLISHERS_DEVICES = {
    "definition": PUBLISHERS_SUMMARY["definition"],
    "generated_at": "2026-09-26T12:00:00Z",
    "basis": PUBLISHERS_BASIS,
    "total": 5, "limit": 100, "offset": 0,
    "rows": [
        {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk",
         "device_last_seen": "2026-09-26T11:00:00Z", "device_stale": False,
         "publisher_key": "", "group": "unsigned_or_adhoc", "platform": "macos",
         "identity_basis": "none", "publisher": None, "trusted": False, "signing": "unsigned",
         "signer_class": None, "notarisation": "not_applicable",
         "product_key": "app:mysteryapp-mac", "name": "MysteryApp",
         "identifier": "com.example.mysteryapp", "version": "1.0.0"},
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
         "device_last_seen": "2026-09-25T09:00:00Z", "device_stale": False,
         "publisher_key": "", "group": "invalid", "platform": "windows",
         "identity_basis": "none", "publisher": None, "trusted": False, "signing": "invalid",
         "signer_class": None, "notarisation": "unknown",
         "product_key": "app:brokensigner-win", "name": "BrokenSigner",
         "identifier": "brokensigner.exe", "version": "2.1.0"},
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
         "device_last_seen": "2026-09-26T10:00:00Z", "device_stale": False,
         "publisher_key": "", "group": "unverified", "platform": "windows",
         "identity_basis": "none", "publisher": None, "trusted": False, "signing": "signed",
         "signer_class": None, "notarisation": "unknown",
         "product_key": "app:unpinnedtool-win", "name": "UnpinnedTool",
         "identifier": "unpinnedtool.exe", "version": "3.4.0"},
        {"device_id": "dev-mac-003", "hostname": "acme-mbp-storeroom",
         "device_last_seen": "2026-09-26T10:00:00Z", "device_stale": False,
         "publisher_key": "team:ABCDE12345", "group": "verified", "platform": "macos",
         "identity_basis": "team_id", "publisher": "ABCDE12345", "trusted": True,
         "signing": "signed", "signer_class": "developer_id", "notarisation": "confirmed",
         "product_key": "app:trustedtool-mac", "name": "TrustedTool",
         "identifier": "com.trusted.tool", "version": "4.0.0"},
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
         "device_last_seen": "2026-09-26T10:00:00Z", "device_stale": False,
         "publisher_key": "authenticode:CN=Contoso Software Ltd", "group": "verified",
         "platform": "windows", "identity_basis": "authenticode_signer",
         "publisher": "CN=Contoso Software Ltd", "trusted": False, "signing": "signed",
         "signer_class": "authenticode", "notarisation": "not_applicable",
         "product_key": "app:contosoapp-win", "name": "ContosoApp", "identifier": "contosoapp.exe",
         "version": "5.2.0"},
    ],
}

PUBLISHERS_CSV = (
    "device_id,hostname,device_last_seen,device_stale,group,platform,publisher_key,"
    "identity_basis,publisher,trusted,signing,signer_class,notarisation,product_key,name,"
    "identifier,version,generated_at\r\n"
    "dev-mac-001,acme-mbp-frontdesk,2026-09-26T11:00:00Z,False,unsigned_or_adhoc,macos,,none,,"
    "False,unsigned,,not_applicable,app:mysteryapp-mac,MysteryApp,com.example.mysteryapp,1.0.0,"
    "2026-09-26T12:00:00Z\r\n"
)

# PAT-2010 (consuming PAT-2009): GET /v1/portal/software/new,
# GET /v1/portal/software/drift and GET /v1/portal/software/approved
# (contracts/portal-api.md "Software governance reporting (PAT-2009)"). One
# addressable application row (a real identifier/product_key, so the quick
# approve/unapprove control on the report row has something to post) and one
# name_only row (product_key null, per the contract "cannot be given an
# approval decision") in the new-software fixture, so both the addressable
# and locked row shapes are exercised. NEW_SOFTWARE_COVERAGE is reused by
# the drift fixture too - same shape, real values differ.
NEW_SOFTWARE_COVERAGE = {
    "devices_total": 6, "devices_reporting": 5, "devices_stale": 1,
    "devices_retired": 0, "devices_without_inventory": 0,
    "oldest_device_last_seen": "2026-09-01T09:00:00Z",
    "stale_after_days": 14, "complete": False,
}

NEW_SOFTWARE_REPORT = {
    "generated_at": "2026-09-24T12:00:00Z",
    "since": "2026-09-20T10:15:00Z",
    "since_basis": "last_review",
    "until": "2026-09-24T12:00:00Z",
    "last_review_at": "2026-09-20T10:15:00Z",
    "coverage": NEW_SOFTWARE_COVERAGE,
    "total": 2,
    "truncated": False,
    "products": [
        {"name": "New Tool", "platform": "windows", "identifier": "vendor.newtool",
         "identity_basis": "identifier",
         "product_key": "application:windows:vendor.newtool",
         "approval_state": "unreviewed", "first_seen_at": "2026-09-23T08:00:00Z",
         "device_count": 1,
         "first_device": {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
                          "first_seen_at": "2026-09-23T08:00:00Z", "still_installed": True}},
        {"name": "Legacy Tool", "platform": "macos", "identifier": None,
         "identity_basis": "name_only", "product_key": None,
         "approval_state": "unreviewed", "first_seen_at": "2026-09-21T08:00:00Z",
         "device_count": 1,
         "first_device": {"device_id": "dev-mac-002", "hostname": "acme-mbp-sales",
                          "first_seen_at": "2026-09-21T08:00:00Z", "still_installed": False}},
    ],
}

NEW_SOFTWARE_REPORT_EMPTY = {
    **NEW_SOFTWARE_REPORT,
    "since_basis": "no_review", "since": None, "last_review_at": None,
    "total": 0, "truncated": False, "products": [],
}

# CSV columns per contract: first_seen_at, name, platform, identifier,
# team_id, identity_basis, product_key, approval_state, device_count,
# first_device_hostname, first_device_id, first_device_still_installed,
# since, since_basis. The second row's name is already formula-injection
# escaped exactly as the platform would send it (a leading "'" ahead of
# "="), proving the portal's CSV proxy passes platform bytes through
# unmangled rather than re-encoding them.
NEW_SOFTWARE_CSV = (
    "first_seen_at,name,platform,identifier,team_id,identity_basis,product_key,approval_state,"
    "device_count,first_device_hostname,first_device_id,first_device_still_installed,since,"
    "since_basis\r\n"
    "2026-09-23T08:00:00Z,New Tool,windows,vendor.newtool,,identifier,"
    "application:windows:vendor.newtool,unreviewed,1,acme-win-accounts,dev-win-002,True,"
    "2026-09-20T10:15:00Z,last_review\r\n"
    "2026-09-24T08:00:00Z,'=cmd|' /C calc'!A1,macos,evil.tool,,identifier,"
    "application:macos:evil.tool,unreviewed,1,acme-mbp-sales,dev-mac-002,False,"
    "2026-09-20T10:15:00Z,last_review\r\n"
)


def _drift_trend(unapproved: int, unreviewed: int, installed: int, stale: int,
                 previous: tuple[int, int, int, int] | None = None) -> list:
    """26 weeks oldest-first, Monday UTC, matching the contract's own
    trend shape: every earlier week unrecorded (null counts) except the
    live current week, so a test can tell the live point from history
    without hand-typing 26 dicts. `previous` optionally records the week
    immediately before the current one too (unapproved, unreviewed,
    installed, stale) - PAT-2010's drift trend chart needs two or more
    recorded weeks before it draws a line at all, so a fixture that wants
    to exercise the drawn-polyline path passes this; one that wants the
    fewer-than-two-recorded-weeks text state leaves it unset."""
    weeks = []
    for i in range(25):
        weeks.append({
            "week_start": f"2026-{(3 + i // 4):02d}-{1 + (i % 4) * 7:02d}",
            "recorded": False, "live": False,
            "unapproved_products": None, "unreviewed_products": None,
            "unapproved_devices": None, "installed_products": None, "devices_stale": None,
        })
    if previous is not None:
        p_unapproved, p_unreviewed, p_installed, p_stale = previous
        weeks[-1] = {
            **weeks[-1], "recorded": True,
            "unapproved_products": p_unapproved, "unreviewed_products": p_unreviewed,
            "unapproved_devices": p_stale, "installed_products": p_installed,
            "devices_stale": p_stale,
        }
    weeks.append({
        "week_start": "2026-09-21", "recorded": True, "live": True,
        "unapproved_products": unapproved, "unreviewed_products": unreviewed,
        "unapproved_devices": stale, "installed_products": installed, "devices_stale": stale,
    })
    return weeks


SOFTWARE_DRIFT_REPORT = {
    "generated_at": "2026-09-24T12:00:00Z",
    "coverage": NEW_SOFTWARE_COVERAGE,
    "counts": {"installed_products": 42, "unapproved": 2, "unreviewed": 1, "approved": 20,
              "ignored": 3, "mandatory": 0, "unapproved_devices": 2},
    "products": [
        {"type": "application", "product_key": "application:macos:com.example.bad",
         "name": "Bad App", "platform": "macos", "identifier": "com.example.bad",
         "team_id": "ABCDE12345", "approval_state": "unapproved",
         "device_count": 2, "stale_device_count": 1, "observed_since": "2026-09-01T09:00:00Z"},
        {"type": "homebrew_formula", "product_key": "homebrew:formula:openssl@3",
         "name": "openssl@3", "platform": "macos", "identifier": "openssl@3", "tap": "",
         "approval_state": "unapproved",
         "device_count": 1, "stale_device_count": 0, "observed_since": "2026-09-10T08:00:00Z"},
        {"type": "application", "product_key": "application:windows:vendor.tool2",
         "name": "Waiting Tool", "platform": "windows", "identifier": "vendor.tool2",
         "approval_state": "unreviewed",
         "device_count": 1, "stale_device_count": 0, "observed_since": "2026-09-15T08:00:00Z"},
    ],
    "products_total": 3,
    "products_truncated": False,
    "trend": _drift_trend(2, 1, 42, 1, previous=(1, 2, 40, 0)),
    "top_devices": [
        {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk", "platform": "macos",
         "unapproved_product_count": 2, "unapproved_products": ["Bad App", "openssl@3"],
         "last_seen": "2026-09-26T11:00:00Z", "stale": False},
    ],
    "unapproved_present": [
        {"type": "application", "product_key": "application:macos:com.example.bad",
         "name": "Bad App", "platform": "macos", "identifier": "com.example.bad",
         "team_id": "ABCDE12345", "policy_kind": "application", "policy_id": 42,
         "device_count": 2, "stale_device_count": 1,
         "devices": [{"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk",
                     "platform": "macos", "observed_since": "2026-09-01T09:00:00Z",
                     "last_seen": "2026-09-26T11:00:00Z", "stale": False}],
         "marked_by": "alice@tenant-a.example", "marked_via": "portal",
         "marked_at": "2026-09-20T10:15:00Z", "marked_at_basis": "decision",
         "present_since": "2026-09-01T09:00:00Z", "since": "2026-09-20T10:15:00Z"},
    ],
}

SOFTWARE_DRIFT_REPORT_EMPTY = {
    "generated_at": "2026-09-24T12:00:00Z",
    "coverage": NEW_SOFTWARE_COVERAGE,
    "counts": {"installed_products": 0, "unapproved": 0, "unreviewed": 0, "approved": 0,
              "ignored": 0, "mandatory": 0, "unapproved_devices": 0},
    "products": [], "products_total": 0, "products_truncated": False,
    "trend": _drift_trend(0, 0, 0, 0),
    "top_devices": [], "unapproved_present": [],
}

# CSV columns per contract: approval_state, name, type, platform, identifier,
# team_id, browser, extension_id, product_key, device_count,
# stale_device_count, observed_since, unapproved_since, marked_by,
# marked_via (last three only on Unapproved rows). Second row again carries
# a pre-escaped formula-injection name.
SOFTWARE_DRIFT_CSV = (
    "approval_state,name,type,platform,identifier,team_id,browser,extension_id,product_key,"
    "device_count,stale_device_count,observed_since,unapproved_since,marked_by,marked_via\r\n"
    "unapproved,Bad App,application,macos,com.example.bad,ABCDE12345,,,"
    "application:macos:com.example.bad,2,1,2026-09-01T09:00:00Z,2026-09-20T10:15:00Z,"
    "alice@tenant-a.example,portal\r\n"
    "unapproved,'=cmd|' /C calc'!A1,application,windows,evil.tool,,,,"
    "application:windows:evil.tool,1,0,2026-09-15T08:00:00Z,2026-09-20T10:15:00Z,"
    "alice@tenant-a.example,portal\r\n"
)

SOFTWARE_APPROVED_REPORT = {
    "generated_at": "2026-09-24T12:00:00Z",
    "total": 2,
    "products": [
        {"type": "application", "policy_id": 26,
         "product_key": "application:macos:com.example.good:ABCDE12345",
         "name": "Good App", "platform": "macos", "identifier": "com.example.good",
         "team_id": "ABCDE12345", "approved_by": "alice@tenant-a.example",
         "approved_via": "portal", "approved_at": "2026-09-20T10:15:00Z",
         "approved_at_basis": "decision", "justification": None},
        {"type": "homebrew_cask", "policy_id": 5, "product_key": "homebrew:cask:firefox",
         "name": "firefox", "platform": "macos", "identifier": "firefox",
         "approved_by": "alice@tenant-a.example", "approved_via": "portal",
         "approved_at": "2026-09-23T09:00:00Z", "approved_at_basis": "decision",
         "justification": None},
    ],
}

SOFTWARE_APPROVED_REPORT_EMPTY = {
    "generated_at": "2026-09-24T12:00:00Z", "total": 0, "products": [],
}

# CSV columns per contract: name, type, platform, identifier, team_id,
# winget_id, match_name, browser, extension_id, product_key, approved_by,
# approved_via, approved_at, approved_at_basis, justification, policy_id.
SOFTWARE_APPROVED_CSV = (
    "name,type,platform,identifier,team_id,winget_id,match_name,browser,extension_id,"
    "product_key,approved_by,approved_via,approved_at,approved_at_basis,justification,"
    "policy_id\r\n"
    "Good App,application,macos,com.example.good,ABCDE12345,,,,,"
    "application:macos:com.example.good:ABCDE12345,alice@tenant-a.example,portal,"
    "2026-09-20T10:15:00Z,decision,,26\r\n"
    "'=cmd|' /C calc'!A1,application,windows,evil.tool,,,,,,"
    "application:windows:evil.tool,,operator,2026-08-01T09:00:00Z,policy_last_updated,,28\r\n"
)

# PAT-1927: GET /v1/portal/ce-readiness (contracts/portal-api.md, platform
# go-service/internal/report/portal_ce_readiness.go). Field names copied
# verbatim from that contract - never invented. Three devices exercise all
# three device states: dev-mac-001 is not_passing (one overdue critical CVE
# item plus a failing firewall control), dev-win-002 is unknown (CVE
# matching still pending), dev-mac-003 is no_outstanding_items_evidenced.
# retired_excluded is a bare count (PAT-2135 retired devices are excluded
# from the devices array entirely, never listed).
CE_READINESS_REPORT = {
    "generated_at": "2026-09-28T10:00:00Z",
    "thresholds": {"update_due_after_days": 14, "active_within_hours": 24,
                   "silent_after_days": 14},
    "cve_matching": {"state": "evidenced", "reason": None,
                     "source": "cve_match_runs.full_match",
                     "observed_at": "2026-09-28T01:10:00Z"},
    "estate": {
        "devices_total": 3, "not_passing": 1, "with_outstanding_items": 1,
        "with_controls_not_passing": 1, "unknown": 1,
        "no_outstanding_items_evidenced": 1, "retired_excluded": 1,
        "source": "devices",
        "freshness": {"generated_at": "2026-09-28T10:00:00Z",
                      "observed_at": "2026-09-28T09:58:12Z"},
    },
    "devices": [
        {
            "device_id": "dev-mac-001", "hostname": "mac-01", "platform": "macos",
            "state": "not_passing",
            "state_reasons": ["outstanding_items", "control_not_passing"],
            "reporting": {"bucket": "active", "source": "devices.last_seen",
                          "observed_at": "2026-09-28T09:58:12Z"},
            "cve_evidence": {"state": "evidenced", "reason": None,
                             "source": "device_cve_findings",
                             "observed_at": "2026-09-28T01:10:00Z"},
            "os_update_evidence": {"state": "unknown",
                                   "reason": "version_evidence_pending",
                                   "source": "device_os_update", "observed_at": None},
            "items": [{
                "kind": "cve", "cve_id": "CVE-2026-1234", "severity": "critical",
                "product": "Example App", "installed_version": "1.0.0",
                "fixed_version": "1.0.5", "published_at": "2026-09-08T10:00:00Z",
                "due_basis": "advisory_published_plus_14_days",
                "due_at": "2026-09-22T10:00:00Z", "age_days": 20, "days_overdue": 6,
                "kev": {"state": "not_listed", "source": "cisa_kev",
                        "fetched_at": "2026-09-28T00:30:00Z", "reason": None},
                "source": "device_cve_findings", "observed_at": "2026-09-28T09:58:12Z",
            }],
            "controls": [
                {"control": "xprotect_running", "category": "malware_protection",
                 "state": "not_evidenced", "reason": "no_evaluation",
                 "source": "compliance_evaluations",
                 "rule_key": "cis_macos_5_10_xprotect_running", "observed_at": None},
                {"control": "firewall", "category": "firewalls",
                 "state": "not_passing", "reason": "evaluation_failed",
                 "source": "compliance_evaluations",
                 "rule_key": "cis_macos_2_5_2_2_firewall",
                 "observed_at": "2026-09-28T01:00:00Z"},
            ],
        },
        {
            "device_id": "dev-win-002", "hostname": "win-02", "platform": "windows",
            "state": "unknown", "state_reasons": ["cve_match_pending"],
            "reporting": {"bucket": "stale", "source": "devices.last_seen",
                          "observed_at": "2026-09-20T09:00:00Z"},
            "cve_evidence": {"state": "unknown", "reason": "cve_match_pending",
                             "source": "device_cve_findings", "observed_at": None},
            "os_update_evidence": {"state": "unknown",
                                   "reason": "version_evidence_pending",
                                   "source": "device_os_update", "observed_at": None},
            "items": [],
            "controls": [
                {"control": "defender_realtime_protection",
                 "category": "malware_protection", "state": "evidenced_ok",
                 "reason": None, "source": "compliance_evaluations",
                 "rule_key": "cis_win_18_9_45_defender_realtime",
                 "observed_at": "2026-09-20T08:00:00Z"},
                {"control": "firewall_domain", "category": "firewalls",
                 "state": "not_evidenced", "reason": "no_evaluation",
                 "source": "compliance_evaluations",
                 "rule_key": "cis_win_9_1_1_firewall_domain", "observed_at": None},
            ],
        },
        {
            "device_id": "dev-mac-003", "hostname": "mac-03", "platform": "macos",
            "state": "no_outstanding_items_evidenced", "state_reasons": [],
            "reporting": {"bucket": "active", "source": "devices.last_seen",
                          "observed_at": "2026-09-28T09:50:00Z"},
            "cve_evidence": {"state": "evidenced", "reason": None,
                             "source": "device_cve_findings",
                             "observed_at": "2026-09-28T01:10:00Z"},
            "os_update_evidence": {"state": "unknown",
                                   "reason": "version_evidence_pending",
                                   "source": "device_os_update", "observed_at": None},
            "items": [],
            "controls": [
                {"control": "xprotect_running", "category": "malware_protection",
                 "state": "evidenced_ok", "reason": None,
                 "source": "compliance_evaluations",
                 "rule_key": "cis_macos_5_10_xprotect_running",
                 "observed_at": "2026-09-28T01:00:00Z"},
            ],
        },
    ],
}

CE_READINESS_REPORT_EMPTY = {
    "generated_at": "2026-09-28T10:00:00Z",
    "thresholds": {"update_due_after_days": 14, "active_within_hours": 24,
                   "silent_after_days": 14},
    "cve_matching": {"state": "evidenced", "reason": None,
                     "source": "cve_match_runs.full_match",
                     "observed_at": "2026-09-28T01:10:00Z"},
    "estate": {
        "devices_total": 0, "not_passing": 0, "with_outstanding_items": 0,
        "with_controls_not_passing": 0, "unknown": 0,
        "no_outstanding_items_evidenced": 0, "retired_excluded": 0,
        "source": "devices",
        "freshness": {"generated_at": "2026-09-28T10:00:00Z", "observed_at": None},
    },
    "devices": [],
}

# CSV columns per contract exactly. The product cell carries a leading '='
# already escaped by the platform (a leading '=' etc gets a "'" prefix) -
# the portal must forward it byte-for-byte, never re-encode it.
CE_READINESS_CSV = (
    "device_id,hostname,platform,device_state,state_reasons,reporting_bucket,"
    "device_last_seen,cve_evidence_state,cve_evidence_observed_at,"
    "os_update_evidence_state,row_kind,cve_id,severity,product,installed_version,"
    "fixed_version,published_at,due_basis,due_at,age_days,days_overdue,kev_state,"
    "kev_fetched_at,item_source,item_observed_at,controls_not_passing,"
    "controls_not_evidenced,generated_at\r\n"
    "dev-mac-001,mac-01,macos,not_passing,outstanding_items;control_not_passing,"
    "active,2026-09-28T09:58:12Z,evidenced,2026-09-28T01:10:00Z,unknown,item,"
    "CVE-2026-1234,critical,'=Example App,1.0.0,1.0.5,2026-09-08T10:00:00Z,"
    "advisory_published_plus_14_days,2026-09-22T10:00:00Z,20,6,not_listed,"
    "2026-09-28T00:30:00Z,device_cve_findings,2026-09-28T09:58:12Z,firewall,"
    "xprotect_running,2026-09-28T10:00:00Z\r\n"
)

# PAT-2258: GET /v1/portal/insurance-evidence (contracts/portal-api.md). The
# JSON fixture is the platform's real response for a seeded four-device
# estate (go-service/internal/handlers/portal_insurance_evidence_db_test.go's
# ieSeed) with timestamps pinned, so the portal renders exactly the shape the
# platform sends; the CSV is the header and first row of the platform's real
# CSV, forwarded byte-for-byte.
_PAT2258_FIXTURES = Path(__file__).resolve().parent / "fixtures"
INSURANCE_EVIDENCE = json.loads(
    (_PAT2258_FIXTURES / "pat2258_insurance_evidence.json").read_text(encoding="utf-8"))
INSURANCE_EVIDENCE_CSV = (
    _PAT2258_FIXTURES / "pat2258_insurance_evidence.csv").read_bytes().decode("utf-8")
CE_READINESS_PDF = b"%PDF-1.7\n% synthetic dated CE readiness evidence pack\n%%EOF\n"
TABLE_PDF_BYTES = b"%PDF-1.4\n% pat2405 stub list export\n%%EOF\n"
INSURANCE_EVIDENCE_PDF = b"%PDF-1.3\n% pat2258 stub insurance evidence pack\n%%EOF\n"

# PAT-1824's shipped GET /v1/portal/exceptions contract. One unaccepted row,
# one accepted-but-review-overdue
# row (both must land in "needs attention" independently - PAT-1785's own
# rule that a review date lapsing is unrelated to acceptance), one clean
# accepted row, and one row carrying a status this page doesn't recognise.
EXCEPTIONS = {
    "generated_at": "2026-09-17T12:00:00Z",
    "total": 4,
    "truncated": False,
    "exceptions": [
        {
            "id": "exc-0001",
            "product": "LegacyLedger",
            "version": "4.1.0",
            "type": "application",
            "device_count": 2,
            "devices": [
                {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk"},
                {"device_id": "dev-win-002", "hostname": "acme-win-accounts"},
            ],
            "devices_truncated": False,
            "requested_by": "jane@tenant-a.example",
            "requested_at": "2026-08-01T09:00:00Z",
            "depends_on": "Finance close process depends on the 4.1 report format",
            "acceptor": None,
            "accepted_at": None,
            "status": "unaccepted",
            "review_date": None,
            "review_overdue": False,
            "history": [
                {"actor": "jane@tenant-a.example", "action": "requested",
                 "reason": "", "at": "2026-08-01T09:00:00Z"},
            ],
        },
        {
            "id": "exc-0002",
            "product": "ShadyCoupons",
            "version": "1.2.0",
            "type": "extension",
            "device_count": 1,
            "devices": [{"device_id": "dev-mac-002", "hostname": "LT-0043"}],
            "devices_truncated": False,
            "requested_by": "priya@tenant-a.example",
            "requested_at": "2026-12-01T09:00:00Z",
            "depends_on": "",
            "acceptor": "Alex Patched",
            "accepted_at": "2026-12-03T09:00:00Z",
            "status": "accepted",
            "review_date": "2026-08-01",
            "review_overdue": True,
            "history": [
                {"actor": "priya@tenant-a.example", "action": "requested",
                 "reason": "", "at": "2026-12-01T09:00:00Z"},
                {"actor": "Alex Patched", "action": "accepted",
                 "reason": "Time-boxed pending replacement", "at": "2026-12-03T09:00:00Z"},
            ],
        },
        {
            "id": "exc-0003",
            "product": "CorpVPN",
            "version": "9.0.2",
            "type": "application",
            "device_count": 12,
            "devices": [{"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk"}],
            "devices_truncated": True,
            "requested_by": "ops@tenant-a.example",
            "requested_at": "2026-11-01T09:00:00Z",
            "depends_on": "Vendor has not certified 9.1 against our gateway yet",
            "acceptor": "Priya Shah",
            "accepted_at": "2026-11-05T09:00:00Z",
            "status": "accepted",
            "review_date": "2026-12-01",
            "review_overdue": False,
            "history": [
                {"actor": "ops@tenant-a.example", "action": "requested",
                 "reason": "", "at": "2026-11-01T09:00:00Z"},
                {"actor": "Alex Patched", "action": "accepted",
                 "reason": "", "at": "2026-11-05T09:00:00Z"},
                {"actor": "Priya Shah", "action": "acceptor_changed",
                 "reason": "Alex left the account team", "at": "2026-07-10T09:00:00Z"},
            ],
        },
        {
            "id": "exc-0004",
            "product": "MysteryTool",
            "version": "0.9",
            "type": "application",
            "device_count": 1,
            "devices": [],
            "devices_truncated": False,
            "requested_by": "",
            "requested_at": "",
            "depends_on": "",
            "acceptor": None,
            "accepted_at": None,
            "status": "withdrawn",
            "review_date": None,
            "review_overdue": False,
            "history": [],
        },
    ],
}

# PAT-2097: GET /v1/portal/software-alerts rows. One of each status/trigger
# combination, mirroring contracts/portal-api.md's software-alerts section:
# alert 1 (open, observed) has never been touched; alert 2 (acknowledged,
# marked) exercises acknowledged_by/at as a real portal_user; alert 3
# (resolved, baseline) exercises resolved_at/reason and a non-zero
# reopened_count, and its device carries no product_key (contract note: a
# baseline row the device hasn't reported since 0184 may lack one).
ALERTS = [
    {
        "id": 1, "status": "open", "trigger": "observed",
        "product": {
            "type": "application",
            "product_key": "application:macos:org.torproject.torbrowser:MADPSAYN6T",
            "name": "Tor Browser", "platform": "macos",
            "identifier": "org.torproject.torbrowser", "team_id": "MADPSAYN6T",
        },
        "policy": {"kind": "application", "id": 42},
        "device": {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk",
                   "platform": "macos", "last_seen": "2026-09-24T13:50:00Z"},
        "notification_id": 7,
        "raised_at": "2026-09-24T14:05:02Z", "status_changed_at": "2026-09-24T14:05:02Z",
        "acknowledged_at": None, "acknowledged_by": None,
        "resolved_at": None, "resolved_reason": None,
        "reopened_count": 0, "last_reopened_at": None,
    },
    {
        "id": 2, "status": "acknowledged", "trigger": "marked",
        "product": {
            "type": "browser_extension",
            "product_key": "browser_extension:chrome:shadycoupons-ext-id",
            "name": "ShadyCoupons", "browser": "chrome", "extension_id": "shadycoupons-ext-id",
        },
        "policy": {"kind": "browser_extension", "id": 7},
        "device": {"device_id": "dev-mac-002", "hostname": "LT-0043",
                   "platform": "macos", "last_seen": "2026-09-24T12:00:00Z"},
        "notification_id": 8,
        "raised_at": "2026-09-20T09:00:00Z", "status_changed_at": "2026-09-21T09:00:00Z",
        "acknowledged_at": "2026-09-21T09:00:00Z", "acknowledged_by": "alice@tenant-a.example",
        "resolved_at": None, "resolved_reason": None,
        "reopened_count": 0, "last_reopened_at": None,
    },
    {
        "id": 3, "status": "resolved", "trigger": "baseline",
        "product": {
            "type": "application", "product_key": None,
            "name": "LegacyLedger", "platform": "windows", "identifier": "legacyledger",
        },
        "policy": {"kind": "application", "id": 9},
        "device": {"device_id": "dev-win-002", "hostname": "acme-win-accounts",
                   "platform": "windows", "last_seen": "2026-08-05T09:00:00Z"},
        "notification_id": None,
        "raised_at": "2026-08-01T09:00:00Z", "status_changed_at": "2026-08-05T09:00:00Z",
        "acknowledged_at": "2026-08-02T09:00:00Z", "acknowledged_by": "operator",
        "resolved_at": "2026-08-05T09:00:00Z", "resolved_reason": "Product approved.",
        "reopened_count": 1, "last_reopened_at": "2026-08-03T09:00:00Z",
    },
]

# GET /v1/portal/software-alerts/{id}'s own additive `history`, oldest
# first. Alert 2's second row is a real portal_user note (escaping-worthy
# HTML in the note is exercised in tests/, not baked into this fixture).
ALERT_HISTORY = {
    1: [
        {"id": 1, "from": None, "to": "open", "actor_kind": "system", "actor": None,
         "reason": None, "note": None, "at": "2026-09-24T14:05:02Z"},
    ],
    2: [
        {"id": 2, "from": None, "to": "open", "actor_kind": "system", "actor": None,
         "reason": None, "note": None, "at": "2026-09-20T09:00:00Z"},
        {"id": 3, "from": "open", "to": "acknowledged", "actor_kind": "portal_user",
         "actor": "alice@tenant-a.example", "reason": None,
         "note": "Raised with the service desk", "at": "2026-09-21T09:00:00Z"},
    ],
    3: [
        {"id": 4, "from": None, "to": "open", "actor_kind": "system", "actor": None,
         "reason": None, "note": None, "at": "2026-08-01T09:00:00Z"},
        {"id": 5, "from": "open", "to": "acknowledged", "actor_kind": "operator",
         "actor": None, "reason": None, "note": None, "at": "2026-08-02T09:00:00Z"},
        {"id": 6, "from": "acknowledged", "to": "open", "actor_kind": "system",
         "actor": None, "reason": None, "note": None, "at": "2026-08-03T09:00:00Z"},
        {"id": 7, "from": "open", "to": "resolved", "actor_kind": "system", "actor": None,
         "reason": "Product approved.", "note": None, "at": "2026-08-05T09:00:00Z"},
    ],
}

def _alerts_view() -> list:
    """ALERTS (or a test's STUB_STATE["alerts_data"] replacement) with any
    stub acknowledge writes applied on top, the same non-mutating overlay
    pattern _applications_view()/_extensions_view() use above - never
    mutate the fixture list in place, since ALERTS is one shared module-
    level object reused (by reference, when alerts_data is unset) across
    every test in the session."""
    source = STUB_STATE.get("alerts_data")
    if source is None:
        source = ALERTS
    overrides = STUB_STATE.get("alert_overrides") or {}
    return [{**a, **overrides[a["id"]]} if a["id"] in overrides else a for a in source]


def _apply_retirement_override(device: dict) -> dict:
    """PAT-2135: layer a stub retirement PUT on top of a static device
    fixture - the same non-mutating overlay shape _applications_view/
    _extensions_view already use for approval writes, so a device retired
    or unretired mid-test is reflected the next time the roster or that
    device's own detail is read, without mutating any shared fixture."""
    overrides = STUB_STATE.get("retirement_overrides") or {}
    device_id = device.get("device_id")
    if not device_id or device_id not in overrides:
        return device
    return {**device, "retirement": overrides[device_id]}


# PAT-2135: GET /v1/portal/device-list default fixture - both reconciliation
# groups non-empty, so the walker and e2e exercise the populated card by
# default (a test that wants the "no list uploaded yet" state sets
# STUB_STATE["device_list_data"] to NO_DEVICE_LIST instead).
DEVICE_LIST_VIEW = {
    "generated_at": "2026-09-25T12:00:00Z",
    "list": {"uploaded_at": "2026-09-20T10:00:00Z", "uploaded_by": "admin@tenant-a.example",
             "filename": "estate.csv", "entry_count": 4},
    "cleared": None,
    "match_basis": "serial_then_hostname",
    "matched_count": 3, "matched_retired_count": 1,
    # PAT-2271: itemised matches - one row per matched entry, always exactly
    # matched_count long, each entry plus the device it matched. Reuses real
    # devices from the DEVICES fixture (dev-mac-001 active, dev-mac-004
    # already retired there, dev-mac-003 active) so a matched-device link
    # resolves to a real detail page for the walker's own link check.
    "matched": [
        {"entry_id": 201, "index": 0, "hostname": "acme-mbp-frontdesk",
         "serial": "C02XL0GTJGH5",
         "device": {"device_id": "dev-mac-001", "hostname": "acme-mbp-frontdesk",
                    "serial": "C02XL0GTJGH5", "retired": False}},
        {"entry_id": 202, "index": 1, "hostname": "acme-mbp-retired", "serial": None,
         "device": {"device_id": "dev-mac-004", "hostname": "acme-mbp-retired",
                    "serial": None, "retired": True}},
        {"entry_id": 203, "index": 4, "hostname": "acme-mbp-storeroom", "serial": None,
         "device": {"device_id": "dev-mac-003", "hostname": "acme-mbp-storeroom",
                    "serial": None, "retired": False}},
    ],
    "on_list_never_seen": [
        {"entry_id": 204, "index": 2, "hostname": None, "serial": "PF3ABCDE"},
        {"entry_id": 205, "index": 3, "hostname": "ghost-01", "serial": None},
    ],
    "on_list_never_seen_total": 2,
    "seen_not_on_list": [
        {"device_id": "dev-win-002", "hostname": "acme-win-accounts", "serial": None},
    ],
    "seen_not_on_list_total": 1,
    "limit": 500, "truncated": False,
    "on_list_never_seen_truncated": False, "seen_not_on_list_truncated": False,
}
# PAT-2271: the pre-upgrade platform shape - no `matched` array and no
# `entry_id` on never_seen rows - so the portal's own fallback (count-only
# matched group, no "Remove from list" control) can be exercised and stays
# green whichever side of the platform deploy lands first.
DEVICE_LIST_VIEW_OLD_API = {
    key: value for key, value in DEVICE_LIST_VIEW.items() if key != "matched"
} | {
    "on_list_never_seen": [
        {"index": 2, "hostname": None, "serial": "PF3ABCDE"},
        {"index": 3, "hostname": "ghost-01", "serial": None},
    ],
}
NO_DEVICE_LIST = {
    "generated_at": "2026-09-25T12:00:00Z", "list": None, "cleared": None,
    "match_basis": "serial_then_hostname", "matched_count": 0, "matched_retired_count": 0,
    "on_list_never_seen": [], "on_list_never_seen_total": 0,
    "seen_not_on_list": [], "seen_not_on_list_total": 0,
    "limit": 500, "truncated": False,
    "on_list_never_seen_truncated": False, "seen_not_on_list_truncated": False,
}


PDF_BYTES = b"%PDF-1.4 test-report-bytes"

# A declared size well beyond what "stream_fail" mode actually writes, so the
# forwarded Content-Length is provably larger than the bytes the client
# receives (PAT-888).
STREAM_FAIL_DECLARED_LENGTH = 50_000
STREAM_FAIL_ACTUAL_BYTES = b"%PDF-1.4 " + b"A" * 2_000

ENROLMENT_TOKEN = {
    "enrollment_token": "enr-tok-abc123xyz789",
    "tenant_id": "11111111-2222-3333-4444-555555555555",
    "token_id": "tok-0001",
    "expires_at": "2026-07-13T09:00:00Z",
}

# PAT-2251: a pre-existing estate enrolment key, the shape
# GET /v1/portal/enrolment-keys returns for each row (never a plaintext).
ENROLMENT_KEY_ROW = {
    "key_id": "6d75459e-1111-4111-8111-111111111111",
    "label": "Intune rollout",
    "key_hint": "pek_Ab3x",
    "max_devices": 250,
    "devices_enrolled": 3,
    "status": "active",
    "expires_at": "2026-10-28T11:26:21Z",
    "created_at": "2026-09-01T11:26:21Z",
    "created_by": "alice@tenant-a.example",
    "revoked_at": None,
    "revoked_by": None,
}


APPROVAL_STUB_DEFAULTS = {
    # PAT-2393: software declarations (see StubPlatformHandler._declarations_*).
    # Empty by default, so no page changes until a test or the e2e layout
    # check seeds a row.
    "declarations": [],
    "declaration_history": {},
    "declaration_posts": [],
    "portal_role": "admin",
    "me_status": None,
    "me_requests": 0,
    "approval_puts": [],
    "approval_put_error": None,
    "approval_put_extra": None,
    "approval_overrides": {},
    "approval_history": [],
    "approval_history_requests": [],
    "approval_history_status": None,
    "protected_identifiers": set(),
    "applications_data": None,
    # PAT-2135: device retirement + device-list stub state, reset the same
    # way and by the same fixtures (tests/ `client`, e2e's reset_stub_state)
    # as the role/approval state above - retirement and device-list writes
    # are gated by the same admin-role read.
    "retirement_overrides": {},
    "retirement_history": {},
    "retirement_puts": [],
    "retirement_status_override": None,
    "retirement_history_status_override": None,
    "device_list_data": None,
    "device_list_puts": [],
    "device_list_delete_calls": 0,
    "device_list_status_override": None,
    "device_list_error_body": None,
    # PAT-2271: single-entry removal.
    "device_list_entry_delete_calls": [],
    "device_list_entry_delete_status_override": None,
    "device_list_entry_delete_404_ids": set(),
}


def reset_approval_stub():
    """PAT-2008: fresh approval-write stub state. Called by tests/ and e2e/
    fixtures so no test sees another's writes or role."""
    for key, value in APPROVAL_STUB_DEFAULTS.items():
        STUB_STATE[key] = type(value)() if isinstance(value, (list, dict, set)) else value


reset_approval_stub()


FEEDBACK_STUB_DEFAULTS = {
    "feedback_enabled": False,
    "feedback_rows": [],
    "feedback_status": None,
    "feedback_gets": 0,
    "feedback_posts": [],
    "feedback_post_status": None,
    # PAT-2216: a platform refusal body, so a test can prove the portal
    # shows the platform's own reason rather than a generic message.
    "feedback_post_body": None,
}


def reset_feedback_stub():
    for key, value in FEEDBACK_STUB_DEFAULTS.items():
        STUB_STATE[key] = type(value)() if isinstance(value, (list, dict, set)) else value


reset_feedback_stub()


def _approval_key(item: dict) -> tuple:
    kind = item.get("type")
    if kind == "application":
        return ("application", item.get("platform"), (item.get("identifier") or "").casefold())
    if kind == "browser_extension":
        return ("browser_extension", item.get("browser"), item.get("extension_id"))
    # homebrew_formula / homebrew_cask (PAT-2058): identity is (kind, name,
    # tap), matching main.py's own _approval_item_key.
    return (kind, (item.get("name") or "").casefold(), item.get("tap") or "")


def _applications_view() -> dict:
    """APPLICATIONS with any stub approval writes applied the way the real
    platform reads them back: a marked undecided application becomes a
    policy row (identifier "" - policy rows never carry one) in its new
    state, `ignored` stored as policy `unmanaged`."""
    source = STUB_STATE.get("applications_data") or APPLICATIONS
    overrides = STUB_STATE.get("approval_overrides") or {}
    if not overrides:
        return source
    rows = []
    for row in source["applications"]:
        key = ("application", row.get("platform"), (row.get("identifier") or "").casefold())
        if row.get("identifier") and key in overrides:
            state = overrides[key]
            row = {**row, "identifier": "", "policy_state": {
                "ignored": "unmanaged"}.get(state, state),
                "decided_at": "2026-09-24T10:00:00Z", "decided_by": None,
                "justification": None}
        rows.append(row)
    return {**source, "applications": rows}


def _overview_view() -> dict:
    """OVERVIEW (or a test's STUB_STATE["overview_data"] replacement) with
    any stub approval writes reflected in its own additive new_software
    block - the same non-mutating overlay _applications_view()/
    _extensions_view() above already apply for their own endpoints.
    PAT-2139's e2e coverage needs a product approved from the Overview's
    own New software card to actually leave that card on the very next
    read, the way the real platform's new_software.excluded.approved
    counter implies it does (contracts/portal-api.md "New software by
    urgency") - without this, the stub would keep echoing back a product
    the portal just marked approved, which no live platform would do."""
    source = STUB_STATE.get("overview_data") or OVERVIEW
    new_software = source.get("new_software")
    overrides = STUB_STATE.get("approval_overrides") or {}
    if not overrides or not isinstance(new_software, dict):
        return source
    products = new_software.get("products")
    if not isinstance(products, list):
        return source
    kept = []
    for p in products:
        if not isinstance(p, dict):
            kept.append(p)
            continue
        key = ("application", p.get("platform"), (p.get("identifier") or "").casefold())
        if p.get("identifier") and key in overrides:
            continue
        kept.append(p)
    return {**source, "new_software": {**new_software, "products": kept}}


def _extensions_view() -> dict:
    overrides = STUB_STATE.get("approval_overrides") or {}
    rows = []
    for row in EXTENSIONS["extensions"]:
        key = ("browser_extension", row.get("browser"), row.get("extension_id"))
        if key in overrides:
            row = {**row, "approval_state": overrides[key],
                   "decided_by": "e2e-harness@example.com",
                   "decided_at": "2026-09-24T10:00:00Z"}
        rows.append(row)
    return {**EXTENSIONS, "extensions": rows}


def _homebrew_formulae_view() -> dict:
    """PAT-2058: HOMEBREW_FORMULAE (or a test's own override) with any stub
    approval writes applied, the same non-mutating overlay
    _extensions_view() above already gives browser extensions."""
    source = STUB_STATE.get("homebrew_formulae_data") or HOMEBREW_FORMULAE
    overrides = STUB_STATE.get("approval_overrides") or {}
    if not overrides:
        return source
    rows = []
    for row in source.get("formulae", []):
        key = ("homebrew_formula", (row.get("name") or "").casefold(), row.get("tap") or "")
        if key in overrides:
            row = {**row, "approval_state": overrides[key]}
        rows.append(row)
    return {**source, "formulae": rows}


def _homebrew_casks_view() -> dict:
    source = STUB_STATE.get("homebrew_casks_data") or HOMEBREW_CASKS
    overrides = STUB_STATE.get("approval_overrides") or {}
    if not overrides:
        return source
    rows = []
    for row in source.get("casks", []):
        key = ("homebrew_cask", (row.get("name") or "").casefold(), row.get("tap") or "")
        if key in overrides:
            row = {**row, "approval_state": overrides[key]}
        rows.append(row)
    return {**source, "casks": rows}


# PAT-2393: curated products the declaration lookup and resolve accept, the
# shape of GET /v1/portal/software-products (contracts: PREPARATION.md).
DECLARATION_PRODUCTS = [
    {"alias_id": "00000000-0000-4000-8000-000000002394",
     "canonical_name": "Synthetic known editor", "vendor_name": "Synthetic Publisher",
     "platform": "macos", "identity_kind": "macos_bundle_team",
     "identity_value_normalized": "com.synthetic.editor",
     "companion_value_normalized": "SYNTHETIC1"},
    {"alias_id": "00000000-0000-4000-8000-000000002395",
     "canonical_name": "Synthetic known browser", "vendor_name": "Synthetic Publisher",
     "platform": "windows", "identity_kind": "windows_publisher",
     "identity_value_normalized": "synthetic-browser",
     "companion_value_normalized": ""},
]
# One declared, not yet observed row: what the e2e layout checks and the
# walker seed (the default stub holds none).
DECLARATION_FIXTURE = {
    "id": "00000000-0000-4000-8000-000000000001",
    "declaration_id": "00000000-0000-4000-8000-000000000001",
    "name": "Synthetic unseen editor", "publisher": "Synthetic Publisher",
    "platform": "macos", "approval_state": "approved", "source": "portal",
    "identity_state": "unmatched", "observation_state": "not_observed",
    "observed_installation_count": 0, "outside_constraint_count": 0,
    "unknown_version_count": 0, "min_version": "2.0", "review_date": "2099-12-31",
    "justification": "Accepted before deployment",
}
DECLARATION_FIXTURE_HISTORY = [{
    "action": "created", "actor_email": "alice@tenant-a.example",
    "decided_at": "2026-10-04T09:00:00Z", "justification": "Accepted before deployment"}]


def seed_declaration():
    """Put DECLARATION_FIXTURE (and its history) in the stub."""
    STUB_STATE["declarations"] = [dict(DECLARATION_FIXTURE)]
    STUB_STATE["declaration_history"] = {
        DECLARATION_FIXTURE["id"]: [dict(h) for h in DECLARATION_FIXTURE_HISTORY]}


DECLARATION_CREATE_KEYS = {"name", "publisher", "platform", "justification", "alias_id",
                           "min_version", "review_date"}


class StubPlatformHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _fail_if_wrong_jwt(self) -> bool:
        sent = self.headers.get("Cf-Access-Jwt-Assertion")
        if STUB_STATE["expected_jwt"] is not None and sent != STUB_STATE["expected_jwt"]:
            self._send(401, {"error": "jwt missing or altered"})
            return True
        return False

    def _send(self, code, payload, content_type="application/json", raw=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        if raw is None:
            raw = json.dumps(payload).encode()
        if content_type == "application/pdf":
            self.send_header(
                "Content-Disposition", 'attachment; filename="acme-report.pdf"'
            )
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _declarations_get(self, path, query) -> bool:
        """PAT-2393: GET list, detail, history and the curated product lookup."""
        if path == "/v1/portal/software-products":
            text = (query.get("query", [""])[0]).casefold()
            platform = query.get("platform", [""])[0]
            # The real platform requires macos or windows and answers 400
            # without it. The stub was lenient once, and the portal's "Any
            # platform" search shipped broken because of it.
            if platform not in ("macos", "windows"):
                self._send(400, {"error": "invalid_request"})
                return True
            found = [p for p in DECLARATION_PRODUCTS
                     if text in p["canonical_name"].casefold()
                     and p["platform"] == platform]
            self._send(200, {"total": len(found), "products": found})
            return True
        base = "/v1/portal/software-declarations"
        if path == base:
            rows = STUB_STATE["declarations"]
            self._send(200, {"total": len(rows), "declarations": rows})
            return True
        if not path.startswith(base + "/"):
            return False
        parts = path[len(base) + 1:].split("/")
        row = next((r for r in STUB_STATE["declarations"] if r["id"] == parts[0]), None)
        if row is None:
            self._send(404, {"error": "not found"})
        elif len(parts) == 1:
            self._send(200, row)
        elif parts[1:] == ["history"]:
            decisions = STUB_STATE["declaration_history"].get(row["id"], [])
            self._send(200, {"total": len(decisions), "decisions": decisions})
        else:
            return False
        return True

    def _declarations_post(self) -> bool:
        """PAT-2393: POST create and resolve. Admin only, strict fields, 409 for
        a duplicate create or an already matched declaration, 422 for an alias
        that is not a curated product."""
        base = "/v1/portal/software-declarations"
        if self.path != base and not (
                self.path.startswith(base + "/") and self.path.endswith("/resolve")):
            return False
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        STUB_STATE["declaration_posts"].append({"path": self.path, "body": body})
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required"})
            return True
        known = {p["alias_id"] for p in DECLARATION_PRODUCTS}
        rows = STUB_STATE["declarations"]
        if self.path == base:
            if not isinstance(body, dict) or set(body) - DECLARATION_CREATE_KEYS or not all(
                    isinstance(body.get(k), str) and body[k].strip()
                    for k in ("name", "publisher", "platform", "justification")):
                self._send(400, {"error": "invalid declaration"})
            elif body.get("alias_id") and body["alias_id"] not in known:
                self._send(422, {"error": "unsafe_alias"})
            elif any(r["name"].casefold() == body["name"].casefold()
                     and r["platform"] == body["platform"] for r in rows):
                self._send(409, {"error": "already_declared"})
            else:
                number = len(rows) + 1
                declaration_id = f"00000000-0000-4000-8000-{number:012d}"
                row = {
                    "id": declaration_id, "declaration_id": declaration_id,
                    "name": body["name"], "publisher": body["publisher"],
                    "platform": body["platform"], "approval_state": "approved",
                    "source": "portal",
                    "identity_state": "matched" if body.get("alias_id") else "unmatched",
                    "observation_state": "not_observed", "observed_installation_count": 0,
                    "outside_constraint_count": 0, "unknown_version_count": 0,
                    "min_version": body.get("min_version"),
                    "review_date": body.get("review_date"),
                    "justification": body["justification"],
                }
                rows.append(row)
                STUB_STATE["declaration_history"][declaration_id] = [{
                    "action": "created", "actor_email": "alice@tenant-a.example",
                    "decided_at": "2026-10-04T09:00:00Z",
                    "justification": body["justification"]}]
                self._send(201, row)
            return True
        row = next((r for r in rows
                    if r["id"] == self.path[len(base) + 1:-len("/resolve")]), None)
        if row is None:
            self._send(404, {"error": "not found"})
        elif set(body) != {"alias_id", "justification"} or body["alias_id"] not in known:
            self._send(422, {"error": "unsafe_resolution"})
        elif row["identity_state"] == "matched":
            self._send(409, {"error": "already_resolved"})
        else:
            row["identity_state"] = "matched"
            STUB_STATE["declaration_history"].setdefault(row["id"], []).append({
                "action": "resolved", "actor_email": "alice@tenant-a.example",
                "decided_at": "2026-10-04T10:00:00Z",
                "justification": body["justification"]})
            self._send(200, row)
        return True

    def do_GET(self):
        if STUB_STATE["mode"] == "down503":
            self._send(503, {"error": "portal not enabled"})
            return
        if STUB_STATE["mode"] == "auth401":
            self._send(401, {"error": "identity rejected"})
            return
        if STUB_STATE["mode"] == "forbidden403":
            self._send(403, {"error": "no estate linked to identity"})
            return
        if STUB_STATE["mode"] == "rate429":
            self._send(429, {"error": "rate limited"})
            return
        if self._fail_if_wrong_jwt():
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/v1/portal/feedback":
            STUB_STATE["feedback_gets"] += 1
            if not STUB_STATE["feedback_enabled"]:
                self._send(404, {"error": "feedback disabled"})
                return
            if STUB_STATE["feedback_status"]:
                self._send(STUB_STATE["feedback_status"], {"error": "feedback failed"})
                return
            door = query.get("door", [""])[0]
            if door not in {"", "support", "feedback"}:
                self._send(400, {"error": "invalid door"})
                return
            rows = STUB_STATE["feedback_rows"]
            if door:
                types = ({"support", "bug", "question"} if door == "support"
                         else {"feature", "design"})
                rows = [row for row in rows if row.get("type") in types]
            self._send(200, {"feedback": rows})
            return
        if path == "/v1/portal/me":
            STUB_STATE["me_requests"] += 1
            if STUB_STATE["me_status"]:
                self._send(STUB_STATE["me_status"], {"error": "boom"})
                return
            self._send(200, {"email": "alice@tenant-a.example",
                             "tenant_id": "11111111-2222-3333-4444-555555555555",
                             "role": STUB_STATE["portal_role"]})
            return
        if self._declarations_get(path, query):
            return
        if path == "/v1/portal/software-approvals/history":
            STUB_STATE["approval_history_requests"].append(
                {k: v[0] for k, v in query.items()})
            if STUB_STATE["approval_history_status"]:
                self._send(STUB_STATE["approval_history_status"], {"error": "boom"})
                return
            wanted = {k: v[0] for k, v in query.items() if k not in ("limit", "offset")}
            decisions = [d for d in STUB_STATE["approval_history"]
                         if all(str(d.get(k) or "") == v for k, v in wanted.items()
                                if k != "type") and d.get("product_type") == wanted.get("type")]
            decisions = list(reversed(decisions))
            self._send(200, {"product_key": None, "total": len(decisions), "limit": 100,
                             "offset": 0, "returned": len(decisions), "decisions": decisions})
            return
        if path == "/v1/portal/applications" and STUB_STATE["mode"] == "ok":
            self._send(200, _applications_view())
            return
        if path == "/v1/portal/extensions" and query.get("device_id"):
            status, payload = _device_extensions_response(query["device_id"][0])
            self._send(status, payload)
            return
        if path == "/v1/portal/extensions" and STUB_STATE["mode"] == "ok":
            self._send(200, _extensions_view())
            return
        if path == "/v1/portal/devices":
            try:
                limit = int((query.get("limit") or ["500"])[0])
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                self._send(400, {"error": "invalid pagination"})
                return
            STUB_STATE["device_request_jwts"].append(
                self.headers.get("Cf-Access-Jwt-Assertion")
            )
            STUB_STATE["device_request_offsets"].append(offset)
            if offset in STUB_STATE["devices_page_statuses"]:
                self._send(STUB_STATE["devices_page_statuses"][offset], {"error": "page failed"})
                return
            if offset in STUB_STATE["devices_page_responses"]:
                self._send(200, STUB_STATE["devices_page_responses"][offset])
                return
            source = STUB_STATE.get("devices_data")
            if source is None:
                source = DEVICES
            rows = source.get("devices", []) if isinstance(source, dict) else source
            page_rows = [_apply_retirement_override(d) for d in rows[offset:offset + limit]]
            self._send(200, {
                "generated_at": "2026-07-02T10:15:00Z",
                "total": len(rows), "limit": limit, "offset": offset,
                "devices": page_rows,
            })
            return
        if path.startswith("/v1/portal/devices/") and path.endswith("/retirement/history"):
            # PAT-2135: GET /v1/portal/devices/{id}/retirement/history -
            # every role.
            device_id = path[len("/v1/portal/devices/"):-len("/retirement/history")]
            if STUB_STATE.get("retirement_history_status_override"):
                self._send(STUB_STATE["retirement_history_status_override"], {"error": "boom"})
                return
            decisions = (STUB_STATE.get("retirement_history") or {}).get(device_id, [])
            retirement = (STUB_STATE.get("retirement_overrides") or {}).get(device_id)
            self._send(200, {
                "device_id": device_id, "retirement": retirement,
                "total": len(decisions), "limit": 100, "offset": 0,
                "returned": len(decisions), "decisions": decisions,
            })
            return
        if path == "/v1/portal/device-list":
            # PAT-2135: GET /v1/portal/device-list - every role.
            if STUB_STATE.get("device_list_status_override"):
                self._send(STUB_STATE["device_list_status_override"], {"error": "boom"})
                return
            source = STUB_STATE.get("device_list_data")
            if source is None:
                source = DEVICE_LIST_VIEW
            self._send(200, source)
            return
        if path == "/v1/portal/mdm/jamf/setup":
            # PAT-2145: GET /v1/portal/mdm/jamf/setup - every role, no query
            # parameters.
            if query:
                self._send(400, {"error": "invalid_request",
                                 "message": "this endpoint takes no query parameters"})
                return
            if STUB_STATE.get("jamf_setup_status_override"):
                self._send(STUB_STATE["jamf_setup_status_override"], {"error": "boom"})
                return
            self._send(200, _jamf_setup_response())
            return
        if path == "/v1/portal/mdm/jamf/coverage":
            # PAT-2145: GET /v1/portal/mdm/jamf/coverage - every role.
            if STUB_STATE.get("jamf_coverage_status_override"):
                self._send(STUB_STATE["jamf_coverage_status_override"], {"error": "boom"})
                return
            bucket = (query.get("bucket") or [""])[0]
            if bucket not in ("", "gap", "not_reported_by_jamf", "covered"):
                self._send(400, {"error": "invalid_request",
                                 "message": "bucket must be gap, not_reported_by_jamf or covered"})
                return
            fmt = (query.get("format") or ["json"])[0]
            try:
                limit = int((query.get("limit") or ["100"])[0])
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                self._send(400, {"error": "invalid_request", "message": "invalid pagination"})
                return
            STUB_STATE["jamf_coverage_requests"].append(
                {"bucket": bucket, "limit": limit, "offset": offset, "format": fmt,
                 "jwt": self.headers.get("Cf-Access-Jwt-Assertion")})
            if fmt == "csv":
                rows = _jamf_coverage_csv_rows(bucket)
                buf = io.StringIO()
                csv.writer(buf).writerows(rows)
                csv_bytes = buf.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition", 'attachment; filename="jamf-coverage.csv"')
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            self._send(200, _jamf_coverage_response(bucket, limit, offset))
            return
        if path == "/v1/portal/software" and query.get("device_id"):
            status, payload = _device_software_response(query["device_id"][0], query)
            self._send(status, payload)
            return
        if path == "/v1/portal/software":
            if STUB_STATE["mode"] == "software500":
                self._send(500, {"error": "boom"})
                return
            source = STUB_STATE.get("software_inventory_data") or SOFTWARE_INVENTORY
            if STUB_STATE["mode"] == "software_malformed":
                self._send(200, {"products": "not a list"})
                return
            if STUB_STATE["mode"] == "software_early_empty":
                source = STUB_STATE.get("software_inventory_data") or SOFTWARE_INVENTORY
                self._send(200, {**source, "total": len(source["products"]),
                                 "limit": 1, "offset": 0, "products": []})
                return
            try:
                limit = int((query.get("limit") or ["500"])[0])
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                self._send(400, {"error": "invalid pagination"})
                return
            search = (query.get("search") or [""])[0]
            STUB_STATE["software_inventory_requests"].append({
                "limit": limit, "offset": offset, "search": search,
                "jwt": self.headers.get("Cf-Access-Jwt-Assertion"),
            })
            products = source.get("products", [])
            if search:
                needle = search.casefold()
                products = [p for p in products if needle in p.get("name", "").casefold()
                            or needle in p.get("identifier", "").casefold()]
            self._send(200, {**source, "total": len(products), "limit": limit,
                             "offset": offset, "products": products[offset:offset + limit]})
            return
        if path == "/v1/portal/ai-tooling/summary":
            if STUB_STATE["mode"] == "ai_tooling_not_found":
                self._send(404, {"error": "not found"})
                return
            self._send(200, STUB_STATE.get("ai_tooling_summary_data") or AI_TOOLING_SUMMARY)
            return
        if path == "/v1/portal/software-notifications":
            if STUB_STATE["software_notifications_error"]:
                code, payload = STUB_STATE["software_notifications_error"]
                self._send(code, payload)
                return
            self._send(200, STUB_STATE.get("software_notifications_data")
                       or SOFTWARE_NOTIFICATIONS)
            return
        if path == "/v1/portal/tagged-products":
            if STUB_STATE["mode"] == "ai_tagged_products_fail":
                self._send(500, {"error": "boom"})
                return
            if STUB_STATE["mode"] == "ai_tagged_products_malformed":
                self._send(200, {**AI_TAGGED_PRODUCTS, "total": "4"})
                return
            if STUB_STATE["mode"] == "ai_tagged_products_bad_row":
                self._send(200, {**AI_TAGGED_PRODUCTS, "total": 1,
                                 "products": ["bad-row"]})
                return
            source = STUB_STATE.get("ai_tagged_products_data") or AI_TAGGED_PRODUCTS
            limit = int((query.get("limit") or ["200"])[0])
            offset = int((query.get("offset") or ["0"])[0])
            STUB_STATE["ai_tagged_product_requests"].append({
                "limit": limit, "offset": offset,
            })
            products = source.get("products", [])
            page = products[offset:offset + limit]
            if STUB_STATE["ai_tagged_products_reorder_after_first"] and offset:
                # An independently generated second page may be reordered
                # while retaining the same total and page size. This models
                # the live contract's lack of a shared snapshot token.
                page = products[:len(page)]
            self._send(200, {**source, "total": len(products), "limit": limit,
                             "offset": offset, "products": page})
            return
        if path == "/v1/portal/ai-tooling/devices":
            if STUB_STATE["mode"] == "ai_tooling_devices_fail":
                self._send(500, {"error": "boom"})
                return
            if STUB_STATE["mode"] == "ai_tooling_devices_malformed":
                self._send(200, {**AI_TOOLING_DEVICES, "total": "3"})
                return
            if STUB_STATE["mode"] == "ai_tooling_devices_bad_row":
                self._send(200, {**AI_TOOLING_DEVICES, "total": 1,
                                 "devices": ["bad-row"]})
                return
            source = STUB_STATE.get("ai_tooling_devices_data") or AI_TOOLING_DEVICES
            limit = int((query.get("limit") or ["500"])[0])
            offset = int((query.get("offset") or ["0"])[0])
            devices = source.get("devices", [])
            self._send(200, {**source, "total": len(devices), "limit": limit,
                             "offset": offset, "devices": devices[offset:offset + limit]})
            return
        tooling_items_prefix = "/v1/portal/ai-tooling/devices/"
        if path.startswith(tooling_items_prefix) and path.endswith("/items"):
            device_id = path[len(tooling_items_prefix):-len("/items")]
            STUB_STATE["ai_tooling_item_requests"].append({
                "device_id": device_id, "query": query,
                "jwt": self.headers.get("Cf-Access-Jwt-Assertion"),
            })
            if STUB_STATE["mode"] == "ai_tooling_items_not_found":
                self._send(404, {"error": "not found"})
                return
            source = STUB_STATE.get("ai_tooling_device_items_data") or AI_TOOLING_DEVICE_ITEMS
            if (STUB_STATE.get("ai_tooling_device_items_data") is None
                    and device_id != AI_TOOLING_DEVICE_ITEMS["device_id"]):
                source = {
                    **AI_TOOLING_DEVICE_ITEMS, "device_id": device_id,
                    "total": 0, "items": [],
                }
            if (query.get("format") or [""])[0] == "csv":
                raw = (b"item_id,device_id,hostname,block,name,assessment_state,finding_count\r\n"
                       b"ati_app_1,dev-mac-001,acme-mbp-frontdesk,desktop_apps,ChatGPT,,\r\n"
                       b"ati_ext_1,dev-mac-001,acme-mbp-frontdesk,browser_extensions,"
                       b"AI Search Helper,,\r\n"
                       b"ati_mcp_1,dev-mac-001,acme-mbp-frontdesk,mcp_servers,GitHub,"
                       b"assessed,1\r\n")
                self._send(200, {}, content_type="text/csv", raw=raw)
                return
            limit = int((query.get("limit") or ["100"])[0])
            offset = int((query.get("offset") or ["0"])[0])
            items = source.get("items", [])
            self._send(200, {**source, "total": len(items), "limit": limit,
                             "offset": offset, "items": items[offset:offset + limit]})
            return
        if path == "/v1/portal/homebrew/summary":
            if STUB_STATE["mode"] == "homebrew_not_found":
                self._send(404, {"error": "not found"})
                return
            self._send(200, STUB_STATE.get("homebrew_summary_data") or HOMEBREW_SUMMARY)
            return
        if path == "/v1/portal/homebrew/formulae":
            if STUB_STATE["mode"] == "homebrew_formulae_fail":
                self._send(500, {"error": "boom"})
                return
            source = _homebrew_formulae_view()
            limit = int((query.get("limit") or ["500"])[0])
            offset = int((query.get("offset") or ["0"])[0])
            rows = source.get("formulae", [])
            self._send(200, {**source, "total": len(rows), "limit": limit,
                             "offset": offset, "formulae": rows[offset:offset + limit]})
            return
        if path == "/v1/portal/homebrew/casks":
            if STUB_STATE["mode"] == "homebrew_casks_fail":
                self._send(500, {"error": "boom"})
                return
            source = _homebrew_casks_view()
            limit = int((query.get("limit") or ["500"])[0])
            offset = int((query.get("offset") or ["0"])[0])
            rows = source.get("casks", [])
            self._send(200, {**source, "total": len(rows), "limit": limit,
                             "offset": offset, "casks": rows[offset:offset + limit]})
            return
        if path == "/v1/portal/homebrew/taps":
            if STUB_STATE["mode"] == "homebrew_taps_fail":
                self._send(500, {"error": "boom"})
                return
            self._send(200, STUB_STATE.get("homebrew_taps_data") or HOMEBREW_TAPS)
            return
        if path == "/v1/portal/homebrew/devices":
            if STUB_STATE["mode"] == "homebrew_devices_fail":
                self._send(500, {"error": "boom"})
                return
            self._send(200, STUB_STATE.get("homebrew_devices_data") or HOMEBREW_DEVICES)
            return
        if path == "/v1/portal/local-admins":
            STUB_STATE["local_admins_requests"] = STUB_STATE.get("local_admins_requests", [])
            STUB_STATE["local_admins_requests"].append(dict(query))
            # PAT-2215: the platform's own GET checks the role itself and
            # 403s a viewer - mirrored here the same way, not via a separate
            # /v1/portal/me round trip (this route makes exactly one call).
            if STUB_STATE["portal_role"] != "admin":
                self._send(403, {"error": "admin_role_required",
                                 "message": "only a portal admin can view the local "
                                            "administrators roster; your role is "
                                            + STUB_STATE["portal_role"]})
                return
            if STUB_STATE.get("local_admins_status"):
                self._send(STUB_STATE["local_admins_status"], {"error": "boom"})
                return
            self._send(200, STUB_STATE.get("local_admins_data") or LOCAL_ADMINS_DATA)
            return
        if path.startswith("/v1/portal/homebrew/devices/"):
            device_id = path.rsplit("/", 1)[-1]
            if device_id == "hb-mac-01":
                self._send(
                    200, STUB_STATE.get("homebrew_device_detail_data") or HOMEBREW_DEVICE_DETAIL)
                return
            # PAT-2128 follow-up: hb-mac-02 is the other id HOMEBREW_DEVICES
            # links to (/homebrew's device list) - it needs a detail
            # response too, or a real broken link and walker noise are
            # indistinguishable. No test overrides this one, unlike
            # hb-mac-01's homebrew_device_detail_data.
            if device_id == "hb-mac-02":
                self._send(200, HOMEBREW_DEVICE_DETAIL_HB_MAC_02)
                return
            self._send(404, {"error": "device not found"})
            return
        if path == "/v1/portal/software-alerts":
            if STUB_STATE["alert_list_status_override"]:
                self._send(STUB_STATE["alert_list_status_override"], {"error": "boom"})
                return
            STUB_STATE["alert_list_requests"].append({k: v[0] for k, v in query.items()})
            try:
                limit = int((query.get("limit") or ["100"])[0])
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                self._send(400, {"error": "invalid pagination"})
                return
            source = _alerts_view()
            product_key = (query.get("product_key") or [""])[0]
            device_id = (query.get("device_id") or [""])[0]
            status_param = (query.get("status") or [""])[0]
            statuses = [s for s in status_param.split(",") if s]
            # counts apply product/device but not status (contract).
            pd_filtered = [
                a for a in source
                if (not product_key or (a.get("product") or {}).get("product_key") == product_key)
                and (not device_id or (a.get("device") or {}).get("device_id") == device_id)
            ]
            counts = {
                "open": sum(1 for a in pd_filtered if a["status"] == "open"),
                "acknowledged": sum(1 for a in pd_filtered if a["status"] == "acknowledged"),
                "resolved": sum(1 for a in pd_filtered if a["status"] == "resolved"),
            }
            filtered = [a for a in pd_filtered if not statuses or a["status"] in statuses]
            order = {"open": 0, "acknowledged": 1, "resolved": 2}
            filtered = sorted(filtered, key=lambda a: (order.get(a["status"], 9), -a["id"]))
            total = len(filtered)
            page_rows = filtered[offset:offset + limit]
            self._send(200, {
                "total": total if page_rows or offset == 0 else 0,
                "limit": limit, "offset": offset, "returned": len(page_rows),
                "counts": counts, "alerts": page_rows,
            })
            return
        if path.startswith("/v1/portal/software-alerts/"):
            rest = path[len("/v1/portal/software-alerts/"):]
            if STUB_STATE["alert_detail_status_override"]:
                self._send(STUB_STATE["alert_detail_status_override"], {"error": "boom"})
                return
            source = _alerts_view()
            match = next((a for a in source if rest.isdigit() and a["id"] == int(rest)), None)
            if match is None:
                self._send(404, {"error": "not_found", "message": "no such alert"})
                return
            history_overrides = STUB_STATE.get("alert_history_overrides") or {}
            history = history_overrides.get(match["id"], ALERT_HISTORY.get(match["id"], []))
            self._send(200, {**match, "history": history})
            return
        if path == "/v1/portal/overview/cards":
            # PAT-2190/PAT-2207: recorded per-request (jwt + query) so tests
            # can assert the JWT is forwarded verbatim and that no tenant
            # identifier ever rides on the query string, the same tenant-
            # isolation shape every other upstream call in this repo is held
            # to. cards500/cards404/cards_timeout simulate the three failure
            # modes PAT-2190 names explicitly (5xx, 404 because the platform
            # isn't deployed yet, and a network-level failure the portal's
            # own requests.RequestException handling already turns into
            # "unavailable" - cards_timeout resets the connection outright
            # rather than answering, which is what a real timeout looks like
            # from the client's side).
            STUB_STATE["overview_cards_requests"].append({
                "jwt": self.headers.get("Cf-Access-Jwt-Assertion"),
                "query": query,
            })
            if STUB_STATE["mode"] == "cards500":
                self._send(500, {"error": "boom"})
                return
            if STUB_STATE["mode"] == "cards404":
                self._send(404, {"error": "not found"})
                return
            if STUB_STATE["mode"] == "cards_timeout":
                self.close_connection = True
                return
            self._send(200, STUB_STATE.get("overview_cards_data") or OVERVIEW_CARDS)
            return
        routes = {
            "/v1/portal/overview": _overview_view(),
            "/v1/portal/control-coverage": (
                CONTROL_COVERAGE if STUB_STATE.get("control_coverage_data") is None
                else STUB_STATE["control_coverage_data"]
            ),
            "/v1/portal/devices/dev-mac-001": STUB_STATE.get("device_detail_data") or DEVICE_DETAIL,
            # PAT-2156: the UUID alias for the same device (see
            # DEVICE_SOFTWARE_UUID_ID above).
            f"/v1/portal/devices/{DEVICE_SOFTWARE_UUID_ID}": DEVICE_DETAIL,
            # PAT-2128 follow-up: every device id DEVICES/EXTENSIONS/ALERTS
            # link to needs a detail response, or a real broken link and
            # walker noise are indistinguishable.
            "/v1/portal/devices/dev-win-002": DEVICE_DETAIL_DEV_WIN_002,
            "/v1/portal/devices/dev-mac-002": DEVICE_DETAIL_DEV_MAC_002,
            "/v1/portal/devices/dev-mac-003": DEVICE_DETAIL_DEV_MAC_003,
            "/v1/portal/devices/dev-mac-004": DEVICE_DETAIL_DEV_MAC_004,
            "/v1/portal/devices/dev-mac-005": DEVICE_DETAIL_DEV_MAC_005,
            "/v1/portal/devices/dev-mac-006": DEVICE_DETAIL_DEV_MAC_006,
            "/v1/portal/devices/dev-mac-007": DEVICE_DETAIL_DEV_MAC_007,
            "/v1/portal/devices/dev-mac-008": DEVICE_DETAIL_DEV_MAC_008,
            "/v1/portal/devices/dev-mac-009": DEVICE_DETAIL_DEV_MAC_009,
            "/v1/portal/devices/dev-win-101": DEVICE_DETAIL_DEV_WIN_101,
            "/v1/portal/devices/dev-win-102": DEVICE_DETAIL_DEV_WIN_102,
            "/v1/portal/unapproved-apps": UNAPPROVED_APPS,
            "/v1/portal/applications": APPLICATIONS,
            "/v1/portal/extensions": EXTENSIONS,
            "/v1/portal/reports": REPORTS,
            "/v1/portal/exceptions": STUB_STATE.get("exceptions_data") or EXCEPTIONS,
            "/v1/portal/protected-software": STUB_STATE.get("protected_data") or PROTECTED_SOFTWARE,
        }
        if path == "/v1/portal/reports/catalogue":
            STUB_STATE["catalogue_request_jwts"].append(
                self.headers.get("Cf-Access-Jwt-Assertion"))
            if STUB_STATE["mode"] == "catalogue500":
                self._send(500, {"error": "boom"})
                return
            self._send(200, STUB_STATE.get("catalogue") or REPORT_CATALOGUE)
            return
        if path == "/v1/portal/reports/schedules":
            if STUB_STATE["mode"] == "schedule500":
                self._send(500, {"error": "boom"})
                return
            self._send(200, {"schedules": STUB_STATE["schedules"] or []})
            return
        if path == "/v1/portal/reports/schedule":
            if STUB_STATE["mode"] == "schedule500":
                self._send(500, {"error": "boom"})
                return
            self._send(200, STUB_STATE["schedule"] or {"configured": False, "enabled": False})
            return
        report_match = re.fullmatch(r"/v1/portal/reports/(rep-[A-Za-z0-9_-]+)", path)
        if report_match:
            # PAT-2405: GET /v1/portal/reports/{id}?format=pdf|csv.
            report_id = report_match.group(1)
            fmt = (query.get("format") or [""])[0] or "pdf"
            STUB_STATE.setdefault("report_download_calls", []).append((report_id, fmt))
            if fmt not in ("pdf", "csv"):
                self._send(400, {"error": "invalid_format"})
                return
            if report_id not in REPORT_KNOWN_IDS:
                self._send(404, {"error": "not_found"})
                return
            if fmt == "csv" and report_id not in REPORT_CSV_AVAILABLE:
                self._send(404, {"error": "csv_not_available",
                                 "detail": "stub-platform-internal-body"})
                return
            if report_id == "rep-0001" and STUB_STATE["mode"] == "stream_fail":
                # Simulate a real upstream reset partway through a download
                # (PAT-888): promise a full-size body via Content-Length, write
                # only a fraction of it, then close the socket without sending
                # the rest - no clean chunked terminator, just a dead connection.
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8" if fmt == "csv"
                                 else "application/pdf")
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="acme-report.{fmt}"'
                )
                self.send_header("Content-Length", str(STREAM_FAIL_DECLARED_LENGTH))
                self.end_headers()
                self.wfile.write(STREAM_FAIL_ACTUAL_BYTES)
                self.wfile.flush()
                try:
                    self.connection.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                self.close_connection = True
                return
            if fmt == "csv":
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition",
                                 'attachment; filename="acme-report.csv"')
                self.send_header("Content-Length", str(len(CSV_BYTES)))
                self.end_headers()
                self.wfile.write(CSV_BYTES)
                return
            self._send(200, None, content_type="application/pdf", raw=PDF_BYTES)
            return
        if path == "/v1/portal/findings" and STUB_STATE["mode"] == "malformed":
            # Neither documented shape (bare array or {key: [...]}) - a
            # platform contract drift, not an empty tenant (PAT-888).
            self._send(200, {"unexpected": "shape"})
            return
        if path == "/v1/portal/findings" and STUB_STATE["mode"] == "findings500":
            # PAT-2025: isolates a failure of just this call (used by the
            # overview page's lightweight cve_assessment probe) while
            # /v1/portal/overview itself still responds normally.
            self._send(500, {"error": "boom"})
            return
        if path == "/v1/portal/findings":
            # PAT-1201: mimics the real paginated contract - `limit`
            # (default/clamp 500) and `offset` (default/clamp 0), rows
            # pre-sorted cvss desc then cve_id/app, and the documented
            # caveat that an offset past the last row comes back with
            # findings=[] and total=0 rather than the true total.
            source = STUB_STATE.get("findings_data")
            if source is None:
                source = FINDINGS
            sorted_source = sorted(
                source,
                key=lambda f: (-(f.get("cvss") or 0), f.get("cve_id", ""), f.get("app", "")),
            )
            try:
                limit = int((query.get("limit") or ["500"])[0])
            except ValueError:
                limit = 500
            if limit <= 0 or limit > 500:
                limit = 500
            try:
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                offset = 0
            if offset < 0:
                offset = 0
            page_rows = sorted_source[offset:offset + limit]
            findings_response = {
                "generated_at": "2026-07-02T17:00:00Z",
                "total": len(sorted_source) if page_rows else 0,
                "limit": limit,
                "offset": offset,
                "findings": page_rows,
            }
            # PAT-2025: tenant-level cve_assessment rides on every page of
            # this same response - estate-wide, not per-page. Omitted
            # entirely in "findings_omit_cve_assessment" mode, simulating a
            # platform deployment that predates PAT-2024.
            if STUB_STATE["mode"] != "findings_omit_cve_assessment":
                findings_response["cve_assessment"] = (
                    STUB_STATE.get("cve_assessment_data") or CVE_ASSESSMENT_TENANT
                )
            self._send(200, findings_response)
            return
        if path == "/v1/portal/driver-findings":
            STUB_STATE["driver_findings_requests"].append(dict(query))
            status = STUB_STATE.get("driver_findings_status")
            if status:
                self._send(status, {"error": "boom"})
                return
            source = STUB_STATE.get("driver_findings_data")
            findings_rows = source["findings"] if isinstance(source, dict) else (
                source if source is not None else DRIVER_FINDINGS
            )
            lists_rows = (
                source.get("lists", DRIVER_LISTS) if isinstance(source, dict) else DRIVER_LISTS
            )
            summary = (
                source.get("summary") if isinstance(source, dict) and source.get("summary") else {
                    "devices_reporting": 40, "devices_unavailable": 1,
                    "devices_with_listed_drivers": len(findings_rows),
                    "devices_with_unhashed_drivers": 3,
                    "listed_drivers": len(findings_rows),
                    "listed_malicious_drivers": sum(
                        1 for r in findings_rows if r.get("category") == "malicious"),
                    "blocklist_enforced": {"yes": 31, "no": 6, "unknown": 3},
                }
            )
            self._send(200, {
                "generated_at": "2026-09-29T10:00:00Z",
                "limit": 50, "offset": 0, "total": len(findings_rows),
                "lists": lists_rows, "summary": summary, "findings": findings_rows,
            })
            return
        if path == "/v1/portal/extensions" and STUB_STATE["mode"] == "malformed":
            # Same contract-drift simulation for the extensions page (PAT-933).
            self._send(200, {"unexpected": "shape"})
            return
        if path == "/v1/portal/applications" and STUB_STATE["mode"] == "applications404":
            # PAT-1742: simulate the applications endpoint being unavailable
            # while extensions still respond, to exercise fail-soft on just
            # that half of the /software page.
            self._send(404, {"error": "not found"})
            return
        if path == "/v1/portal/applications" and STUB_STATE["mode"] == "malformed":
            self._send(200, {"unexpected": "shape"})
            return
        if path == "/v1/portal/exceptions" and STUB_STATE["mode"] == "malformed":
            self._send(200, {"unexpected": "shape"})
            return
        if path == "/v1/portal/protected-software" and STUB_STATE["mode"] == "protected500":
            # PAT-1821: protected-software is an enhancement to /software's
            # existing rows, not primary data - this isolates a failure of
            # just that call so /software's fail-soft handling can be
            # exercised while applications/extensions still respond.
            self._send(500, {"error": "boom"})
            return
        if path == "/v1/portal/overview" and STUB_STATE["mode"] == "overview500":
            # PAT-1602: simulate the overview rollup being unavailable while
            # /v1/portal/findings still responds, to exercise fail-soft on
            # just the findings page's secondary CIS summary section.
            self._send(500, {"error": "boom"})
            return
        if path == "/v1/portal/control-coverage" and STUB_STATE["mode"] == "coverage500":
            # PAT-1859: coverage explains the established overview score;
            # an outage here must not take the overview down with it.
            self._send(500, {"error": "boom"})
            return
        if path in ("/v1/portal/finding-lifecycle", "/v1/portal/finding-lifecycle/history"):
            # PAT-1969's portal-facing finding-lifecycle read pair. A
            # dedicated status override (independent of STUB_STATE["mode"],
            # which fails every route identically) lets a test fail just
            # these two calls while the page's primary content still
            # succeeds - proving the portal's error handling belongs to
            # these calls specifically, not just inherited from the page's
            # existing upstream read.
            kind = (query.get("finding_kind") or [""])[0]
            STUB_STATE["lifecycle_requests"].append({
                "path": path, "finding_kind": kind,
                "device_id": (query.get("device_id") or [None])[0],
            })
            if STUB_STATE["lifecycle_status_override"]:
                self._send(
                    STUB_STATE["lifecycle_status_override"],
                    {"error": "lifecycle unavailable"},
                )
                return
            is_history = path.endswith("/history")
            if is_history:
                overrides = STUB_STATE["lifecycle_history_overrides"]
                default_by_kind = {"cis": LIFECYCLE_CIS_HISTORY, "cve": LIFECYCLE_CVE_HISTORY}
                key = "events"
            else:
                overrides = STUB_STATE["lifecycle_current_overrides"]
                default_by_kind = {"cis": LIFECYCLE_CIS_CURRENT, "cve": LIFECYCLE_CVE_CURRENT}
                key = "findings"
            rows = overrides.get(kind, default_by_kind.get(kind, []))
            self._send(200, {key: rows, "total": len(rows), "limit": 500, "offset": 0,
                             "returned": len(rows)})
            return
        if path in ("/v1/portal/reports/software/unsupported",
                    "/v1/portal/reports/software/unsupported/devices"):
            # PAT-2147: covers both the summary/products read and the
            # per-device drill-down with one filter+page implementation -
            # the two share the same query shape (contracts/portal-api.md:
            # "Same query as above plus device_id and product_key").
            is_devices = path.endswith("/devices")
            status_override = (STUB_STATE["sam_devices_status"] if is_devices
                               else STUB_STATE["sam_unsupported_status"])
            if status_override:
                self._send(status_override, {"error": "boom"})
                return
            requests_log = (STUB_STATE["sam_devices_requests"] if is_devices
                           else STUB_STATE["sam_unsupported_requests"])
            requests_log.append({k: v[0] for k, v in query.items()})
            override = (STUB_STATE.get("sam_devices_data") if is_devices
                       else STUB_STATE.get("sam_unsupported_data"))
            base = override if override is not None else (
                SAM_UNSUPPORTED_DEVICES if is_devices else SAM_UNSUPPORTED_SUMMARY)
            rows_key = "rows" if is_devices else "products"
            all_rows = base.get(rows_key, [])
            state = (query.get("state") or [None])[0]
            kind = (query.get("kind") or [None])[0]
            platform = (query.get("platform") or [None])[0]
            product_key = (query.get("product_key") or [None])[0]
            device_id = (query.get("device_id") or [None])[0]
            filtered = [
                r for r in all_rows
                if (not state or r.get("state") == state)
                and (not kind or r.get("kind") == kind)
                and (not platform or r.get("platform") == platform)
                and (not product_key or r.get("product_key") == product_key)
                and (not device_id or r.get("device_id") == device_id)
            ]
            if (query.get("format") or ["json"])[0] == "csv":
                # Unpaged (contract: limit/offset are ignored for CSV) -
                # X-Patched-Export-Rows carries the true filtered row count.
                csv_bytes = (STUB_STATE.get("sam_csv_data") or SAM_UNSUPPORTED_CSV).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="unsupported-software.csv"')
                self.send_header("X-Patched-Export-Rows", str(len(filtered)))
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            try:
                limit = int((query.get("limit") or ["100"])[0])
            except ValueError:
                limit = 100
            if limit <= 0 or limit > 500:
                limit = 100
            try:
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                offset = 0
            if offset < 0:
                offset = 0
            page_rows = filtered[offset:offset + limit]
            response = {
                **base, rows_key: page_rows,
                "total": len(filtered), "limit": limit, "offset": offset,
            }
            self._send(200, response)
            return
        if path in ("/v1/portal/reports/software/remote-access",
                    "/v1/portal/reports/software/remote-access/devices"):
            # PAT-2148: same shared filter+page shape as PAT-2147 above, but
            # keyed on approval_state/category rather than state/kind.
            is_devices = path.endswith("/devices")
            status_override = (STUB_STATE["remote_access_devices_status"] if is_devices
                               else STUB_STATE["remote_access_status"])
            if status_override:
                self._send(status_override, {"error": "boom"})
                return
            requests_log = (STUB_STATE["remote_access_devices_requests"] if is_devices
                           else STUB_STATE["remote_access_requests"])
            requests_log.append({k: v[0] for k, v in query.items()})
            override = (STUB_STATE.get("remote_access_devices_data") if is_devices
                       else STUB_STATE.get("remote_access_data"))
            base = override if override is not None else (
                REMOTE_ACCESS_DEVICES if is_devices else REMOTE_ACCESS_SUMMARY)
            rows_key = "rows" if is_devices else "products"
            all_rows = base.get(rows_key, [])
            category = (query.get("category") or [None])[0]
            kind = (query.get("kind") or [None])[0]
            state = (query.get("state") or [None])[0]
            platform = (query.get("platform") or [None])[0]
            product_key = (query.get("product_key") or [None])[0]
            device_id = (query.get("device_id") or [None])[0]
            filtered = [
                r for r in all_rows
                if (not category or r.get("category") == category)
                and (not kind or r.get("kind") == kind)
                and (not state or r.get("approval_state") == state)
                and (not platform or r.get("platform") == platform)
                and (not product_key or r.get("product_key") == product_key)
                and (not device_id or r.get("device_id") == device_id)
            ]
            if (query.get("format") or ["json"])[0] == "csv":
                default_csv = (STUB_STATE.get("remote_access_devices_csv_data")
                               if is_devices else STUB_STATE.get("remote_access_csv_data"))
                csv_bytes = (default_csv or REMOTE_ACCESS_CSV).encode()
                filename = "remote-access-devices.csv" if is_devices else "remote-access.csv"
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("X-Patched-Export-Rows", str(len(filtered)))
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            try:
                limit = int((query.get("limit") or ["100"])[0])
            except ValueError:
                limit = 100
            if limit <= 0 or limit > 500:
                limit = 100
            try:
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                offset = 0
            if offset < 0:
                offset = 0
            page_rows = filtered[offset:offset + limit]
            response = {
                **base, rows_key: page_rows,
                "total": len(filtered), "limit": limit, "offset": offset,
            }
            self._send(200, response)
            return
        if path == "/v1/portal/reports/software/version-sprawl":
            # PAT-2150.
            if STUB_STATE["version_sprawl_status"]:
                self._send(STUB_STATE["version_sprawl_status"], {"error": "boom"})
                return
            STUB_STATE["version_sprawl_requests"].append({k: v[0] for k, v in query.items()})
            base = STUB_STATE.get("version_sprawl_data") or VERSION_SPRAWL_SUMMARY
            all_rows = base.get("products", [])
            platform = (query.get("platform") or [None])[0]
            filtered = [r for r in all_rows if not platform or r.get("platform") == platform]
            if (query.get("format") or ["json"])[0] == "csv":
                csv_bytes = (
                    STUB_STATE.get("version_sprawl_csv_data") or VERSION_SPRAWL_CSV).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition", 'attachment; filename="version-sprawl.csv"')
                self.send_header("X-Patched-Export-Rows", str(len(filtered)))
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            try:
                limit = int((query.get("limit") or ["100"])[0])
            except ValueError:
                limit = 100
            if limit <= 0 or limit > 500:
                limit = 100
            try:
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                offset = 0
            if offset < 0:
                offset = 0
            page_rows = filtered[offset:offset + limit]
            response = {
                **base, "products": page_rows,
                "total": len(filtered), "limit": limit, "offset": offset,
            }
            self._send(200, response)
            return
        if path == "/v1/portal/reports/software/duplicate-tools":
            # PAT-2151. The JSON listing pages/filters categories only by
            # category (product_key is a CSV-only filter, matching the real
            # handler's own matchCategory/matchRow split); the CSV export is
            # the unpaged per-device row list filtered by category AND
            # product_key.
            if STUB_STATE["duplicate_tools_status"]:
                self._send(STUB_STATE["duplicate_tools_status"], {"error": "boom"})
                return
            STUB_STATE["duplicate_tools_requests"].append({k: v[0] for k, v in query.items()})
            base = STUB_STATE.get("duplicate_tools_data") or DUPLICATE_TOOLS_SUMMARY
            category = (query.get("category") or [None])[0]
            product_key = (query.get("product_key") or [None])[0]
            if (query.get("format") or ["json"])[0] == "csv":
                filtered = [
                    r for r in DUPLICATE_TOOLS_ROWS
                    if (not category or r.get("category") == category)
                    and (not product_key or r.get("product_key") == product_key)
                ]
                csv_bytes = (
                    STUB_STATE.get("duplicate_tools_csv_data") or DUPLICATE_TOOLS_CSV).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition", 'attachment; filename="duplicate-tools.csv"')
                self.send_header("X-Patched-Export-Rows", str(len(filtered)))
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            all_categories = base.get("categories", [])
            filtered = [c for c in all_categories if not category or c.get("category") == category]
            try:
                limit = int((query.get("limit") or ["50"])[0])
            except ValueError:
                limit = 50
            if limit <= 0 or limit > 200:
                limit = 50
            try:
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                offset = 0
            if offset < 0:
                offset = 0
            page_categories = filtered[offset:offset + limit]
            response = {
                **base, "categories": page_categories,
                "total": len(filtered), "limit": limit, "offset": offset,
            }
            self._send(200, response)
            return
        if path in ("/v1/portal/reports/software/publishers",
                    "/v1/portal/reports/software/publishers/devices"):
            # PAT-2152: same shared filter+page shape as PAT-2147/PAT-2148
            # above, keyed on group/platform/publisher_key (+ device_id and
            # product_key on the /devices drill-down). The non-devices CSV
            # is, per the real contract, the same per-installation row
            # export as /devices - never the publisher-summary rows.
            is_devices = path.endswith("/devices")
            status_override = (STUB_STATE["publishers_devices_status"] if is_devices
                               else STUB_STATE["publishers_status"])
            if status_override:
                self._send(status_override, {"error": "boom"})
                return
            requests_log = (STUB_STATE["publishers_devices_requests"] if is_devices
                           else STUB_STATE["publishers_requests"])
            requests_log.append({k: v[0] for k, v in query.items()})
            override = (STUB_STATE.get("publishers_devices_data") if is_devices
                       else STUB_STATE.get("publishers_data"))
            base = override if override is not None else (
                PUBLISHERS_DEVICES if is_devices else PUBLISHERS_SUMMARY)
            group = (query.get("group") or [None])[0]
            platform = (query.get("platform") or [None])[0]
            publisher_key = (query.get("publisher_key") or [None])[0]
            device_id = (query.get("device_id") or [None])[0]
            product_key = (query.get("product_key") or [None])[0]

            def _row_matches(r):
                return ((not group or r.get("group") == group)
                        and (not platform or r.get("platform") == platform)
                        and (not publisher_key or r.get("publisher_key") == publisher_key)
                        and (not device_id or r.get("device_id") == device_id)
                        and (not product_key or r.get("product_key") == product_key))

            if (query.get("format") or ["json"])[0] == "csv":
                filtered_rows = [r for r in PUBLISHERS_DEVICES["rows"] if _row_matches(r)]
                default_csv = (STUB_STATE.get("publishers_devices_csv_data")
                               if is_devices else STUB_STATE.get("publishers_csv_data"))
                csv_bytes = (default_csv or PUBLISHERS_CSV).encode()
                filename = (
                    "software-publishers-devices.csv" if is_devices else "software-publishers.csv")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("X-Patched-Export-Rows", str(len(filtered_rows)))
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            rows_key = "rows" if is_devices else "publishers"
            all_rows = base.get(rows_key, [])
            filtered = [r for r in all_rows if _row_matches(r)]
            try:
                limit = int((query.get("limit") or ["100"])[0])
            except ValueError:
                limit = 100
            if limit <= 0 or limit > 500:
                limit = 100
            try:
                offset = int((query.get("offset") or ["0"])[0])
            except ValueError:
                offset = 0
            if offset < 0:
                offset = 0
            page_rows = filtered[offset:offset + limit]
            response = {
                **base, rows_key: page_rows,
                "total": len(filtered), "limit": limit, "offset": offset,
            }
            self._send(200, response)
            return
        if path == "/v1/portal/software/new":
            # PAT-2009: GET /v1/portal/software/new (contracts/portal-api.md
            # "Software governance reporting"). Unknown query parameters are
            # refused with 400 per the contract; only `since`/`format` are
            # recognised here.
            if set(query) - {"since", "format"}:
                self._send(400, {"error": "invalid_request",
                                 "message": "unknown query parameter"})
                return
            if STUB_STATE["new_software_status"]:
                self._send(STUB_STATE["new_software_status"], {"error": "boom"})
                return
            STUB_STATE["new_software_requests"].append({
                "query": {k: v[0] for k, v in query.items()},
                "jwt": self.headers.get("Cf-Access-Jwt-Assertion")})
            if (query.get("format") or ["json"])[0] == "csv":
                csv_bytes = (STUB_STATE.get("new_software_csv_data")
                            or NEW_SOFTWARE_CSV).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition", 'attachment; filename="new-software.csv"')
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            self._send(200, STUB_STATE.get("new_software_data") or NEW_SOFTWARE_REPORT)
            return
        if path == "/v1/portal/software/drift":
            # PAT-2009: GET /v1/portal/software/drift.
            if STUB_STATE["software_drift_status"]:
                self._send(STUB_STATE["software_drift_status"], {"error": "boom"})
                return
            STUB_STATE["software_drift_requests"].append({
                "query": {k: v[0] for k, v in query.items()},
                "jwt": self.headers.get("Cf-Access-Jwt-Assertion")})
            if (query.get("format") or ["json"])[0] == "csv":
                csv_bytes = (STUB_STATE.get("software_drift_csv_data")
                            or SOFTWARE_DRIFT_CSV).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition", 'attachment; filename="software-drift.csv"')
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            self._send(200, STUB_STATE.get("software_drift_data") or SOFTWARE_DRIFT_REPORT)
            return
        if path == "/v1/portal/software/approved":
            # PAT-2009: GET /v1/portal/software/approved.
            if STUB_STATE["software_approved_status"]:
                self._send(STUB_STATE["software_approved_status"], {"error": "boom"})
                return
            STUB_STATE["software_approved_requests"].append({
                "query": {k: v[0] for k, v in query.items()},
                "jwt": self.headers.get("Cf-Access-Jwt-Assertion")})
            if (query.get("format") or ["json"])[0] == "csv":
                csv_bytes = (STUB_STATE.get("software_approved_csv_data")
                            or SOFTWARE_APPROVED_CSV).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition", 'attachment; filename="approved-software.csv"')
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            self._send(200, STUB_STATE.get("software_approved_data") or SOFTWARE_APPROVED_REPORT)
            return
        if path == "/v1/portal/ce-readiness":
            # PAT-1927: only `format` is a recognised query parameter - a
            # tenant is never accepted from the caller (contracts/portal-api.md
            # "Single tenant only").
            if set(query) - {"format"}:
                self._send(400, {"error": "invalid_request",
                                 "message": "unknown query parameter"})
                return
            if STUB_STATE["ce_readiness_status"]:
                self._send(STUB_STATE["ce_readiness_status"], {"error": "boom"})
                return
            STUB_STATE["ce_readiness_requests"].append({
                "query": {k: v[0] for k, v in query.items()},
                "jwt": self.headers.get("Cf-Access-Jwt-Assertion")})
            if (query.get("format") or ["json"])[0] == "pdf":
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="ce-readiness-2026-10-02.pdf"')
                self.send_header("Content-Length", str(len(CE_READINESS_PDF)))
                self.end_headers()
                self.wfile.write(CE_READINESS_PDF)
                return
            if (query.get("format") or ["json"])[0] == "csv":
                csv_bytes = (STUB_STATE.get("ce_readiness_csv_data")
                            or CE_READINESS_CSV).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="ce-readiness-2026-09-28.csv"')
                self.send_header("Content-Length", str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return
            self._send(200, STUB_STATE.get("ce_readiness_data") or CE_READINESS_REPORT)
            return
        if path == "/v1/portal/insurance-evidence":
            # PAT-2258: only  is recognised; a tenant is never
            # accepted from the caller.
            if set(query) - {"format"}:
                self._send(400, {"error": "invalid_request",
                                 "message": "unknown query parameter"})
                return
            if STUB_STATE["insurance_evidence_status"]:
                self._send(STUB_STATE["insurance_evidence_status"], {"error": "boom"})
                return
            fmt = (query.get("format") or ["json"])[0]
            STUB_STATE["insurance_evidence_requests"].append({
                "format": fmt, "jwt": self.headers.get("Cf-Access-Jwt-Assertion")})
            if fmt in ("csv", "pdf"):
                body = (INSURANCE_EVIDENCE_CSV.encode() if fmt == "csv"
                        else INSURANCE_EVIDENCE_PDF)
                self.send_response(200)
                self.send_header("Content-Type", "text/csv" if fmt == "csv" else "application/pdf")
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="insurance-evidence-2026-09-29.{fmt}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._send(200, STUB_STATE.get("insurance_evidence_data") or INSURANCE_EVIDENCE)
            return
        if path == "/v1/portal/enrolment-keys":
            STUB_STATE["enrolment_keys_list_requests"] += 1
            if STUB_STATE["enrolment_keys_list_status_override"]:
                self._send(STUB_STATE["enrolment_keys_list_status_override"], {"error": "boom"})
                return
            self._send(200, {"keys": STUB_STATE.get("enrolment_keys_data") or []})
            return
        if path in routes:
            payload = routes[path]
            # PAT-2135: a single device's own detail response gets the same
            # stub retirement overlay the roster does above, so a device
            # retired mid-test shows it when opened directly too.
            if path.startswith("/v1/portal/devices/") and isinstance(payload, dict):
                payload = _apply_retirement_override(payload)
            self._send(200, payload)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if STUB_STATE["mode"] == "down503":
            self._send(503, {"error": "portal not enabled"})
            return
        if STUB_STATE["mode"] == "auth401":
            self._send(401, {"error": "identity rejected"})
            return
        if STUB_STATE["mode"] == "forbidden403":
            self._send(403, {"error": "no estate linked to identity"})
            return
        if STUB_STATE["mode"] == "rate429":
            self._send(429, {"error": "rate limited"})
            return
        if self._fail_if_wrong_jwt():
            return
        if self._declarations_post():
            return
        if self.path == "/v1/portal/feedback":
            if not STUB_STATE["feedback_enabled"]:
                self._send(404, {"error": "feedback disabled"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length)
            # PAT-2233: mirror the platform, which calls ParseMultipartForm
            # unconditionally and answers 400 to any other body. The old
            # stub accepted urlencoded, so a text-only submission passed
            # here and failed in production.
            if "multipart/form-data" not in (self.headers.get("Content-Type") or ""):
                self._send(400, {"error": "invalid multipart form"})
                return
            STUB_STATE["feedback_posts"].append({
                "body": raw, "content_type": self.headers.get("Content-Type", ""),
                "portal_build": self.headers.get("X-Portal-Build"),
                "user_agent": self.headers.get("User-Agent"),
            })
            if STUB_STATE["feedback_post_status"]:
                self._send(
                    STUB_STATE["feedback_post_status"],
                    STUB_STATE["feedback_post_body"] or {"error": "feedback failed"},
                )
                return
            reference = f"FB-{len(STUB_STATE['feedback_posts']):04d}"
            self._send(201, {"reference": reference, "status": "received"})
            return
        if self.path == "/v1/portal/reports":
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            STUB_STATE["generate_calls"] += 1
            STUB_STATE["generate_posts"].append(body)
            self._send(202, {"id": "rep-0002", "status": "queued"})
            return
        if self.path == "/v1/portal/enrolment":
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            STUB_STATE["enrolment_calls"] += 1
            STUB_STATE["enrolment_posts"].append(body)
            if STUB_STATE.get("enrolment_admin_required"):
                # PAT-2407: the platform now refuses a non-admin mint.
                self._send(403, {
                    "error": "admin_role_required",
                    "message": "only a portal admin can mint an enrolment token; "
                               "your role is viewer"})
                return
            self._send(201, ENROLMENT_TOKEN)
            return
        if self.path == "/v1/portal/enrolment-keys":
            self._enrolment_key_create_post()
            return
        key_prefix, key_suffix = "/v1/portal/enrolment-keys/", "/revoke"
        if self.path.startswith(key_prefix) and self.path.endswith(key_suffix):
            self._enrolment_key_revoke_post(self.path[len(key_prefix):-len(key_suffix)])
            return
        alert_prefix, alert_suffix = "/v1/portal/software-alerts/", "/acknowledge"
        if self.path.startswith(alert_prefix) and self.path.endswith(alert_suffix):
            self._alert_acknowledge(self.path[len(alert_prefix):-len(alert_suffix)])
            return
        if self.path == "/v1/portal/mdm/jamf/token":
            self._jamf_token_post()
            return
        if self.path == "/v1/portal/exports/table-pdf":
            self._table_pdf_post()
            return
        self._send(404, {"error": "not found"})

    def _table_pdf_post(self):
        """PAT-2405: POST /v1/portal/exports/table-pdf. Mirrors the platform's
        documented limits (1..40 columns, every row exactly len(columns)
        strings, at most 10000 rows, at most 20 filters, body under 16 MiB)
        so a portal that breaks one is refused here as it would be there."""
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        STUB_STATE["table_pdf_posts"].append({
            "body": body, "raw_length": len(raw),
            "jwt": self.headers.get("Cf-Access-Jwt-Assertion"),
            "content_type": self.headers.get("Content-Type", ""),
        })
        if STUB_STATE["table_pdf_status"]:
            self._send(STUB_STATE["table_pdf_status"], {"error": "boom"})
            return
        if len(raw) >= 16 * 1024 * 1024:
            self._send(400, {"error": "invalid_request", "message": "body too large"})
            return
        if (isinstance(body, dict) and body.get("export") == "local-admins"
                and STUB_STATE["portal_role"] != "admin"):
            self._send(403, {"error": "admin_role_required"})
            return

        def _strings(value):
            return isinstance(value, list) and all(isinstance(v, str) for v in value)

        columns, rows, filters = (body or {}).get("columns"), (body or {}).get("rows"), (
            (body or {}).get("filters", []))
        total_rows = (body or {}).get("total_rows")
        valid = (
            isinstance(body, dict) and isinstance(body.get("export"), str) and body["export"]
            and _strings(columns) and 1 <= len(columns) <= 40
            and isinstance(rows, list) and len(rows) <= 10000
            and all(_strings(r) and len(r) == len(columns) for r in rows)
            and isinstance(filters, list) and len(filters) <= 20
            and all(isinstance(f, dict) and isinstance(f.get("label"), str)
                    and isinstance(f.get("value"), str) for f in filters)
            and (total_rows is None or (type(total_rows) is int and total_rows >= len(rows)))
        )
        if not valid:
            self._send(400, {"error": "invalid_request"})
            return
        if STUB_STATE["table_pdf_content_type"]:
            self._send(200, None, content_type=STUB_STATE["table_pdf_content_type"],
                       raw=b"<html>not a pdf</html>")
            return
        self._send(200, None, content_type="application/pdf", raw=TABLE_PDF_BYTES)

    def _enrolment_key_create_post(self):
        """PAT-2251: POST /v1/portal/enrolment-keys - admin only, returns the
        plaintext once. Mirrors _jamf_token_post's shape: status override for
        error injection, then role, then field validation."""
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw.strip() else {}
        except ValueError:
            self._send(400, {"error": "invalid_request", "message": "invalid JSON"})
            return
        STUB_STATE["enrolment_key_create_posts"].append(body)
        if STUB_STATE["enrolment_key_create_status_override"]:
            code, payload = STUB_STATE["enrolment_key_create_status_override"]
            self._send(code, payload)
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can create an enrolment key"})
            return
        label = body.get("label") if isinstance(body, dict) else None
        max_devices = body.get("max_devices") if isinstance(body, dict) else None
        if not isinstance(label, str) or not label.strip() or len(label) > 100:
            self._send(400, {"error": "invalid_label",
                             "message": "label is required, at most 100 characters"})
            return
        if type(max_devices) is not int or max_devices < 1 or max_devices > 100000:
            self._send(400, {"error": "invalid_max_devices",
                             "message": "max_devices must be between 1 and 100000"})
            return
        expires_in_days = body.get("expires_in_days", 30)
        if expires_in_days is None:
            expires_in_days = 30
        if type(expires_in_days) is not int or expires_in_days < 1 or expires_in_days > 365:
            self._send(400, {"error": "invalid_expires_in_days",
                             "message": "expires_in_days must be between 1 and 365"})
            return
        STUB_STATE["enrolment_key_creates"] += 1
        n = STUB_STATE["enrolment_key_creates"]
        key_id = f"6d75459e-0000-4000-8000-{n:012d}"
        plaintext = f"pek_teststubkey{n:04d}0000000000000000000000000000"
        view = {
            "key_id": key_id, "label": label, "key_hint": f"pek_{plaintext[4:8]}",
            "max_devices": max_devices, "devices_enrolled": 0, "status": "active",
            "expires_at": "2026-10-28T11:26:21Z", "created_at": "2026-09-28T11:26:21Z",
            "created_by": "alice@tenant-a.example", "revoked_at": None, "revoked_by": None,
        }
        if STUB_STATE.get("enrolment_keys_data") is None:
            STUB_STATE["enrolment_keys_data"] = []
        STUB_STATE["enrolment_keys_data"].insert(0, dict(view))
        resp = dict(view)
        resp["enrollment_key"] = plaintext
        resp["warning"] = "This key is shown once. Store it now; Patched keeps only a hash."
        self._send(201, resp)

    def _enrolment_key_revoke_post(self, key_id):
        """PAT-2251: POST /v1/portal/enrolment-keys/{keyID}/revoke - admin
        only. A key that doesn't exist (or another tenant's) is 404."""
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if raw.strip():
            try:
                json.loads(raw)
            except ValueError:
                self._send(400, {"error": "invalid_request", "message": "invalid JSON"})
                return
        STUB_STATE["enrolment_key_revoke_posts"].append(key_id)
        if STUB_STATE["enrolment_key_revoke_status_override"]:
            code, payload = STUB_STATE["enrolment_key_revoke_status_override"]
            self._send(code, payload)
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can revoke an enrolment key"})
            return
        rows = STUB_STATE.get("enrolment_keys_data") or []
        row = next((r for r in rows if r.get("key_id") == key_id), None)
        if row is None:
            self._send(404, {"error": "not_found", "message": "enrolment key not found"})
            return
        STUB_STATE["enrolment_key_revokes"] += 1
        changed = row.get("revoked_at") is None
        if changed:
            row["revoked_at"] = "2026-09-28T12:00:00Z"
            row["revoked_by"] = "alice@tenant-a.example"
            row["status"] = "revoked"
        self._send(200, {"key_id": key_id, "revoked_at": row["revoked_at"], "changed": changed})

    def _jamf_token_post(self):
        """PAT-2145: POST /v1/portal/mdm/jamf/token - create or rotate,
        admin only. The plaintext is in this response only; Cache-Control:
        no-store, matching the real handler."""
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if raw.strip():
            try:
                json.loads(raw)
            except ValueError:
                self._send(400, {"error": "invalid_request", "message": "invalid JSON"})
                return
        STUB_STATE["jamf_token_posts"].append(raw.decode("utf-8", "replace"))
        if STUB_STATE.get("jamf_token_post_status"):
            code, payload = STUB_STATE["jamf_token_post_status"]
            self._send(code, payload)
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can create or rotate the Jamf "
                                        "webhook token"})
            return
        was_configured = STUB_STATE.get("jamf_mode", "not_configured") != "not_configured"
        had_active_token = was_configured and STUB_STATE.get("jamf_token_state") == "active"
        action = "token_rotated" if had_active_token else "token_created"
        STUB_STATE["jamf_mode"] = "ok"
        STUB_STATE["jamf_token_state"] = "active"
        STUB_STATE["jamf_token_revoked_at"] = None
        if had_active_token:
            STUB_STATE["jamf_token_rotated_at"] = "2026-09-26T12:00:00Z"
        STUB_STATE["jamf_instance_reset"] = was_configured
        if was_configured:
            # Existing records retain their first-seen token generation.
            STUB_STATE["jamf_current_token_ids"] = set()
        token = "pjwh_teststubtoken0000000000000000000000001"
        payload = {
            "action": action, "token": token, "webhook_url": JAMF_WEBHOOK_URL,
            "note": ("This token is shown once. Paste it into the Jamf Pro webhook's Header "
                    "Authentication now; Patched keeps only a hash."),
            "setup": _jamf_setup_response(),
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(201 if action == "token_created" else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _alert_acknowledge(self, alert_id_raw):
        """PAT-2097: POST /v1/portal/software-alerts/{id}/acknowledge -
        closely enough to drive the portal: admin-only (the caller checks
        role itself before ever POSTing here, but the stub still records
        every attempt), idempotent on an already-acknowledged alert, 409 on
        a resolved one, 404 for an unknown or another tenant's id."""
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        STUB_STATE["alert_acknowledge_posts"].append({
            "alert_id": alert_id_raw, "body": body,
            "jwt": self.headers.get("Cf-Access-Jwt-Assertion"),
        })
        if STUB_STATE["alert_acknowledge_status_override"]:
            code, payload = STUB_STATE["alert_acknowledge_status_override"]
            self._send(code, payload)
            return
        if not alert_id_raw.isdigit():
            self._send(404, {"error": "not_found", "message": "no such alert"})
            return
        match = next((a for a in _alerts_view() if a["id"] == int(alert_id_raw)), None)
        if match is None:
            self._send(404, {"error": "not_found", "message": "no such alert"})
            return
        if match["status"] == "resolved":
            self._send(409, {"error": "alert_resolved", "message": "alert already resolved"})
            return
        changed = match["status"] != "acknowledged"
        if changed:
            override = {
                "status": "acknowledged", "acknowledged_at": "2026-09-24T15:00:00Z",
                "acknowledged_by": "alice@tenant-a.example",
            }
            STUB_STATE.setdefault("alert_overrides", {})[match["id"]] = override
            match = {**match, **override}
        history = STUB_STATE.setdefault("alert_history_overrides", {}).setdefault(
            match["id"], list(ALERT_HISTORY.get(match["id"], [])))
        if changed:
            history.append({
                "id": len(history) + 1, "from": "open", "to": "acknowledged",
                "actor_kind": "portal_user", "actor": "alice@tenant-a.example",
                "reason": None, "note": body.get("note") or None,
                "at": "2026-09-24T15:00:00Z",
            })
        self._send(200, {"changed": changed, **match, "history": history})

    def _approval_put(self):
        """PAT-2007's PUT /v1/portal/software-approvals, closely enough to
        drive the portal: strict keys, all-or-nothing, a history row per
        changed product, protected_warning for listed identifiers."""
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        STUB_STATE["approval_puts"].append({
            "body": body, "jwt": self.headers.get("Cf-Access-Jwt-Assertion")})
        if STUB_STATE["approval_put_error"]:
            code, payload = STUB_STATE["approval_put_error"]
            self._send(code, payload)
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can change approval state"})
            return
        if set(body) - {"state", "reason", "items"}:
            self._send(400, {"error": "invalid_request", "message": "unknown key"})
            return
        results = []
        for index, item in enumerate(body.get("items", [])):
            key = _approval_key(item)
            previous = STUB_STATE["approval_overrides"].get(key, "unreviewed")
            state = body["state"]
            protected = (item.get("identifier") in STUB_STATE["protected_identifiers"]
                         and state == "unapproved")
            changed = previous != state
            STUB_STATE["approval_overrides"][key] = state
            product_key = ":".join(str(part) for part in key)
            if changed:
                STUB_STATE["approval_history"].append({
                    "id": len(STUB_STATE["approval_history"]) + 1, "batch_id": "b-1",
                    "product_type": item.get("type"), "product_key": product_key,
                    "platform": item.get("platform"), "identifier": item.get("identifier"),
                    "team_id": item.get("team_id"), "browser": item.get("browser"),
                    "extension_id": item.get("extension_id"),
                    # PAT-2058: homebrew_formula/homebrew_cask address by
                    # name/tap, not platform/identifier - stored so
                    # GET /v1/portal/software-approvals/history's own
                    # query-param filter (below) can match a Homebrew item
                    # the same way it already matches an app/extension one.
                    "name": item.get("name"), "tap": item.get("tap"),
                    "previous_state": previous, "new_state": state,
                    "reason": body.get("reason"), "actor_email": "alice@tenant-a.example",
                    "protected_warning": protected, "decided_at": "2026-09-24T10:00:00Z",
                })
            result = {
                "index": index, "type": item.get("type"), "product_key": product_key,
                "previous_state": previous, "new_state": state, "changed": changed,
                "protected_warning": protected,
                "protected": ({"category": "edr", "vendor": "Acme", "product_name": "Acme EDR"}
                              if protected else None),
            }
            if item.get("type") in ("homebrew_formula", "homebrew_cask"):
                # contracts/portal-api.md "PUT /v1/portal/software-
                # approvals": "resolved_alerts on a Homebrew result is
                # always 0" - Homebrew never opens or resolves an
                # unapproved-alert episode.
                result["resolved_alerts"] = 0
            if STUB_STATE["approval_put_extra"]:
                result.update(STUB_STATE["approval_put_extra"])
            results.append(result)
        self._send(200, {"batch_id": "b-1", "state": body["state"],
                         "changed_count": sum(1 for r in results if r["changed"]),
                         "warning_count": sum(1 for r in results if r["protected_warning"]),
                         "results": results})

    def _retirement_put(self, device_id):
        """PAT-2135: PUT /v1/portal/devices/{id}/retirement - admin only,
        no-op (changed: false) when already in the requested state,
        otherwise one new append-only history row."""
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._send(400, {"error": "invalid_request", "message": "malformed JSON body"})
            return
        STUB_STATE["retirement_puts"].append({"device_id": device_id, "body": body})
        if STUB_STATE.get("retirement_status_override"):
            self._send(STUB_STATE["retirement_status_override"], {"error": "boom"})
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can change retirement state"})
            return
        if not isinstance(body, dict) or "retired" not in body or not isinstance(
                body.get("retired"), bool):
            self._send(400, {"error": "invalid_request", "message": "retired is required"})
            return
        reason = body.get("reason")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 500):
            self._send(400, {"error": "invalid_request",
                             "message": "reason must be a string up to 500 characters"})
            return
        known_ids = {row["device_id"] for row in DEVICES["devices"]}
        if device_id not in known_ids:
            self._send(404, {"error": "not_found", "message": "no such device"})
            return
        overrides = STUB_STATE["retirement_overrides"]
        if device_id in overrides:
            current = overrides[device_id]
        else:
            fixture = next((row for row in DEVICES["devices"]
                            if row["device_id"] == device_id), {})
            current = fixture.get("retirement")
        currently_retired = current is not None
        if body["retired"] == currently_retired:
            self._send(200, {"device_id": device_id, "retired": currently_retired,
                             "changed": False, "retirement": current})
            return
        now = "2026-09-25T12:00:00Z"
        if body["retired"]:
            new_retirement = {"retired_at": now, "retired_by": "alice@tenant-a.example",
                              "reason": reason, "reported_after_retirement": False}
            action = "retire"
        else:
            new_retirement = None
            action = "unretire"
        overrides[device_id] = new_retirement
        history = STUB_STATE["retirement_history"].setdefault(device_id, [])
        history.insert(0, {
            "id": len(history) + 1, "action": action, "reason": reason,
            "actor_email": "alice@tenant-a.example", "decided_at": now,
        })
        self._send(200, {"device_id": device_id, "retired": body["retired"], "changed": True,
                         "retirement": new_retirement})

    def _device_list_put(self):
        """PAT-2135: PUT /v1/portal/device-list - admin only, strict shape
        close enough to drive the portal's own upload flow and error
        mapping (invalid_entry with an index, too_many_entries, etc)."""
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._send(400, {"error": "invalid_request", "message": "malformed JSON body"})
            return
        STUB_STATE["device_list_puts"].append(body)
        if STUB_STATE.get("device_list_status_override"):
            code = STUB_STATE["device_list_status_override"]
            self._send(code, STUB_STATE.get("device_list_error_body") or {"error": "boom"})
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can change the device list"})
            return
        if not isinstance(body, dict) or not isinstance(body.get("entries"), list):
            self._send(400, {"error": "invalid_request", "message": "entries is required"})
            return
        entries = body["entries"]
        if not entries:
            self._send(400, {"error": "empty_list", "message": "entries must not be empty"})
            return
        if len(entries) > 10000:
            self._send(400, {"error": "too_many_entries", "message": "at most 10000 entries"})
            return
        stored = {"uploaded_at": "2026-09-25T12:00:00Z", "uploaded_by": "alice@tenant-a.example",
                  "filename": body.get("filename"), "entry_count": len(entries)}
        STUB_STATE["device_list_data"] = {
            **DEVICE_LIST_VIEW, "list": stored, "cleared": None,
        }
        self._send(200, {"list": stored, "received_count": len(entries),
                         "duplicates_collapsed": 0})

    def _jamf_setup_put(self):
        """PAT-2145: PUT /v1/portal/mdm/jamf/setup - admin only, 409 before a
        connector exists."""
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._send(400, {"error": "invalid_request", "message": "malformed JSON body"})
            return
        STUB_STATE["jamf_setup_puts"].append(body)
        if STUB_STATE.get("jamf_setup_put_status"):
            code, payload = STUB_STATE["jamf_setup_put_status"]
            self._send(code, payload)
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can change the Jamf webhook "
                                        "settings"})
            return
        if STUB_STATE.get("jamf_mode", "not_configured") == "not_configured":
            self._send(409, {"error": "not_configured", "message": "create a Jamf webhook "
                                                                    "token first"})
            return
        if not isinstance(body, dict) or (
                "check_in_enabled" not in body and "reset_jamf_instance" not in body):
            self._send(400, {"error": "invalid_request",
                             "message": "send check_in_enabled, reset_jamf_instance, or both"})
            return
        changed = False
        if "check_in_enabled" in body:
            value = body["check_in_enabled"]
            if not isinstance(value, bool):
                self._send(400, {"error": "invalid_request",
                                 "message": "check_in_enabled must be a boolean"})
                return
            if STUB_STATE.get("jamf_check_in_enabled", False) != value:
                changed = True
            STUB_STATE["jamf_check_in_enabled"] = value
        if "reset_jamf_instance" in body:
            if body["reset_jamf_instance"] is not True:
                self._send(400, {"error": "invalid_request",
                                 "message": "reset_jamf_instance can only be true"})
                return
            if _jamf_setup_response()["jamf_instance"].get("url"):
                changed = True
            STUB_STATE["jamf_instance_reset"] = True
        self._send(200, {"changed": changed, "setup": _jamf_setup_response()})

    def do_PUT(self):
        """PAT-703: PUT /v1/portal/reports/schedule — records the payload and
        mimics the platform's validation + response shape."""
        if STUB_STATE["mode"] == "down503":
            self._send(503, {"error": "portal not enabled"})
            return
        if self._fail_if_wrong_jwt():
            return
        if self.path == "/v1/portal/software-approvals":
            self._approval_put()
            return
        if self.path == "/v1/portal/software-notifications":
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            STUB_STATE["software_notification_puts"].append({
                "body": body, "jwt": self.headers.get("Cf-Access-Jwt-Assertion"),
            })
            if STUB_STATE["software_notifications_error"]:
                code, payload = STUB_STATE["software_notifications_error"]
                self._send(code, payload)
                return
            if STUB_STATE["portal_role"] != "admin":
                self._send(403, {"error": "admin_role_required"})
                return
            current = dict(STUB_STATE.get("software_notifications_data")
                           or SOFTWARE_NOTIFICATIONS)
            current.update(body)
            current.update({"is_default": False, "updated_at": "2026-09-27T13:00:00Z",
                            "updated_by": "alice@tenant-a.example"})
            STUB_STATE["software_notifications_data"] = current
            self._send(200, current)
            return
        if self.path == "/v1/portal/device-list":
            self._device_list_put()
            return
        if self.path.startswith("/v1/portal/devices/") and self.path.endswith("/retirement"):
            device_id = self.path[len("/v1/portal/devices/"):-len("/retirement")]
            self._retirement_put(device_id)
            return
        if self.path == "/v1/portal/mdm/jamf/setup":
            self._jamf_setup_put()
            return
        typed_prefix = "/v1/portal/reports/schedules/"
        is_typed = self.path.startswith(typed_prefix)
        if self.path != "/v1/portal/reports/schedule" and not is_typed:
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if is_typed:
            STUB_STATE["typed_schedule_puts"].append((self.path[len(typed_prefix):], body))
        else:
            STUB_STATE["schedule_puts"].append(body)
        if body.get("cadence") not in ("daily", "weekly", "monthly"):
            self.send_response(400)
            raw = b"cadence must be one of: daily, weekly, monthly"
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        stored = {"configured": True, "enabled": bool(body.get("enabled")),
                  "cadence": body["cadence"], "weekday": body.get("weekday"),
                  "month_day": body.get("month_day"), "hour_utc": body.get("hour_utc"),
                  "last_run_at": None, "next_run_at": "2026-07-06T07:00:00Z",
                  "updated_at": "2026-07-03T12:00:00Z"}
        if is_typed:
            stored["report_type"] = self.path[len(typed_prefix):]
            stored["report_label"] = next(
                (r["label"] for r in REPORT_CATALOGUE["reports"]
                 if r["type"] == stored["report_type"]), "Report")
            schedules = [s for s in (STUB_STATE["schedules"] or [])
                         if s.get("report_type") != stored["report_type"]]
            schedules.append(stored)
            STUB_STATE["schedules"] = schedules
        else:
            STUB_STATE["schedule"] = stored
        self._send(200, stored)

    def do_DELETE(self):
        """PAT-2135: DELETE /v1/portal/device-list - admin only, clears the
        current list (recorded, not erased - contracts/portal-api.md)."""
        if STUB_STATE["mode"] == "down503":
            self._send(503, {"error": "portal not enabled"})
            return
        if self._fail_if_wrong_jwt():
            return
        if self.path == "/v1/portal/mdm/jamf/token":
            self._jamf_token_delete()
            return
        if self.path == "/v1/portal/mdm/jamf/devices":
            self._jamf_devices_delete()
            return
        entries_prefix = "/v1/portal/device-list/entries/"
        if self.path.startswith(entries_prefix):
            self._device_list_entry_delete(self.path[len(entries_prefix):])
            return
        if self.path != "/v1/portal/device-list":
            self._send(404, {"error": "not found"})
            return
        STUB_STATE["device_list_delete_calls"] += 1
        if STUB_STATE.get("device_list_status_override"):
            self._send(STUB_STATE["device_list_status_override"], {"error": "boom"})
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can clear the device list"})
            return
        current = STUB_STATE.get("device_list_data")
        had_list = current is None or (isinstance(current, dict) and current.get("list"))
        if not had_list:
            self._send(200, {"changed": False, "cleared": None})
            return
        cleared = {"cleared_at": "2026-09-25T12:00:00Z", "cleared_by": "alice@tenant-a.example"}
        STUB_STATE["device_list_data"] = {**NO_DEVICE_LIST, "cleared": cleared}
        self._send(200, {"changed": True, "cleared": cleared})

    def _device_list_entry_delete(self, raw_entry_id):
        """PAT-2271: DELETE /v1/portal/device-list/entries/{entryID} - admin
        only, removes one entry from the current list. 404 covers an
        unknown/cross-tenant/superseded-upload id and "no current list at
        all" alike, all indistinguishable, per contracts/portal-api.md."""
        STUB_STATE["device_list_entry_delete_calls"].append(raw_entry_id)
        if STUB_STATE.get("device_list_entry_delete_status_override"):
            code, payload = STUB_STATE["device_list_entry_delete_status_override"]
            self._send(code, payload)
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can change the device list"})
            return
        if not raw_entry_id.isdigit() or int(raw_entry_id) in STUB_STATE.get(
            "device_list_entry_delete_404_ids", set(),
        ):
            self._send(404, {"error": "not_found"})
            return
        entry_id = int(raw_entry_id)
        current = STUB_STATE.get("device_list_data")
        source = current if isinstance(current, dict) else DEVICE_LIST_VIEW
        matched = [m for m in (source.get("matched") or []) if isinstance(m, dict)]
        never_seen = [e for e in (source.get("on_list_never_seen") or []) if isinstance(e, dict)]
        if not any(m.get("entry_id") == entry_id for m in matched) and not any(
            e.get("entry_id") == entry_id for e in never_seen
        ):
            self._send(404, {"error": "not_found"})
            return
        new_matched = [m for m in matched if m.get("entry_id") != entry_id]
        new_never_seen = [e for e in never_seen if e.get("entry_id") != entry_id]
        was_retired_match = any(
            m.get("entry_id") == entry_id and isinstance(m.get("device"), dict)
            and m["device"].get("retired")
            for m in matched
        )
        STUB_STATE["device_list_data"] = {
            **source,
            "matched": new_matched, "matched_count": len(new_matched),
            "matched_retired_count": (
                source.get("matched_retired_count", 0) - (1 if was_retired_match else 0)
            ),
            "on_list_never_seen": new_never_seen,
            "on_list_never_seen_total": len(new_never_seen),
        }
        self._send(200, {"deleted": True, "entry_id": entry_id})

    def _jamf_token_delete(self):
        """PAT-2145: DELETE /v1/portal/mdm/jamf/token - revoke, admin only.
        Deletes the fixture records first seen under the current token."""
        if STUB_STATE.get("jamf_token_delete_status"):
            code, payload = STUB_STATE["jamf_token_delete_status"]
            self._send(code, payload)
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can revoke the Jamf webhook "
                                        "token"})
            return
        STUB_STATE["jamf_token_delete_calls"] += 1
        if STUB_STATE.get("jamf_token_state") != "active":
            self._send(200, {"action": "token_revoked", "changed": False, "devices_deleted": 0,
                             "note": "There was no active token, so nothing was revoked or "
                                     "deleted.", "setup": _jamf_setup_response()})
            return
        rows = _jamf_bucket_rows(STUB_STATE.get("jamf_mode", "not_configured"))
        ids = {r["jamf_id"] for r in rows["gap"] + rows["covered"]
               if r["jamf_id"] in STUB_STATE["jamf_current_token_ids"]}
        n = len(ids)
        STUB_STATE["jamf_deleted_ids"].update(ids)
        STUB_STATE["jamf_token_state"] = "revoked"
        STUB_STATE["jamf_token_revoked_at"] = "2026-09-26T12:05:00Z"
        self._send(200, {"action": "token_revoked", "changed": True, "devices_deleted": n,
                         "note": (f"Revoking deleted the {n} Jamf device records first seen "
                                 "under this token. Jamf events are refused until a new token "
                                 "is created; coverage then refills from Jamf's next events."),
                         "setup": _jamf_setup_response()})

    def _jamf_devices_delete(self):
        """PAT-2145: DELETE /v1/portal/mdm/jamf/devices - purge, admin only,
        409 before a connector exists."""
        if STUB_STATE.get("jamf_devices_delete_status"):
            code, payload = STUB_STATE["jamf_devices_delete_status"]
            self._send(code, payload)
            return
        if STUB_STATE["portal_role"] != "admin":
            self._send(403, {"error": "admin_role_required",
                             "message": "only a portal admin can delete the Jamf device "
                                        "records"})
            return
        if STUB_STATE.get("jamf_mode", "not_configured") == "not_configured":
            self._send(409, {"error": "not_configured", "message": "Jamf is not connected"})
            return
        STUB_STATE["jamf_devices_purge_calls"] += 1
        rows = _jamf_bucket_rows(STUB_STATE.get("jamf_mode", "not_configured"))
        ids = {r["jamf_id"] for r in rows["gap"] + rows["covered"]}
        n = len(ids)
        STUB_STATE["jamf_deleted_ids"].update(ids)
        self._send(200, {"action": "devices_purged", "changed": n > 0, "devices_deleted": n,
                         "setup": _jamf_setup_response()})


@pytest.fixture(scope="session")
def stub_platform():
    server = ThreadingHTTPServer(("127.0.0.1", 0), StubPlatformHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture
def client(stub_platform, monkeypatch):
    from fastapi.testclient import TestClient

    import main

    monkeypatch.setenv("PLATFORM_BASE_URL", stub_platform)
    STUB_STATE["mode"] = "ok"
    STUB_STATE["expected_jwt"] = None
    STUB_STATE["generate_calls"] = 0
    STUB_STATE["report_download_calls"] = []
    STUB_STATE["schedule"] = None
    STUB_STATE["schedule_puts"] = []
    STUB_STATE["catalogue"] = None
    STUB_STATE["schedules"] = None
    STUB_STATE["typed_schedule_puts"] = []
    STUB_STATE["generate_posts"] = []
    STUB_STATE["catalogue_request_jwts"] = []
    STUB_STATE["enrolment_calls"] = 0
    STUB_STATE["enrolment_posts"] = []
    STUB_STATE["enrolment_admin_required"] = False
    STUB_STATE["findings_data"] = None
    STUB_STATE["overview_data"] = None
    STUB_STATE["control_coverage_data"] = None
    STUB_STATE["overview_cards_data"] = None
    STUB_STATE["overview_cards_requests"] = []
    STUB_STATE["devices_data"] = None
    STUB_STATE["devices_page_responses"] = {}
    STUB_STATE["devices_page_statuses"] = {}
    STUB_STATE["device_request_jwts"] = []
    STUB_STATE["device_request_offsets"] = []
    STUB_STATE["device_detail_data"] = None
    STUB_STATE["exceptions_data"] = None
    STUB_STATE["protected_data"] = None
    STUB_STATE["software_inventory_data"] = None
    STUB_STATE["software_inventory_requests"] = []
    STUB_STATE["lifecycle_current_overrides"] = {}
    STUB_STATE["lifecycle_history_overrides"] = {}
    STUB_STATE["lifecycle_status_override"] = None
    STUB_STATE["lifecycle_requests"] = []
    STUB_STATE["cve_assessment_data"] = None
    STUB_STATE["ai_tooling_summary_data"] = None
    STUB_STATE["ai_tagged_products_data"] = None
    STUB_STATE["ai_tagged_product_requests"] = []
    STUB_STATE["ai_tagged_products_reorder_after_first"] = False
    STUB_STATE["ai_tooling_devices_data"] = None
    STUB_STATE["ai_tooling_device_items_data"] = None
    STUB_STATE["ai_tooling_item_requests"] = []
    STUB_STATE["software_notifications_data"] = None
    STUB_STATE["software_notification_puts"] = []
    STUB_STATE["software_notifications_error"] = None
    STUB_STATE["homebrew_summary_data"] = None
    STUB_STATE["homebrew_formulae_data"] = None
    STUB_STATE["homebrew_casks_data"] = None
    STUB_STATE["homebrew_taps_data"] = None
    STUB_STATE["homebrew_devices_data"] = None
    STUB_STATE["homebrew_device_detail_data"] = None
    STUB_STATE["local_admins_data"] = None
    STUB_STATE["local_admins_status"] = None
    STUB_STATE["local_admins_requests"] = []
    STUB_STATE["table_pdf_posts"] = []
    STUB_STATE["table_pdf_status"] = None
    STUB_STATE["table_pdf_content_type"] = None
    STUB_STATE["alerts_data"] = None
    STUB_STATE["alert_overrides"] = {}
    STUB_STATE["alert_history_overrides"] = {}
    STUB_STATE["alert_list_requests"] = []
    STUB_STATE["alert_list_status_override"] = None
    STUB_STATE["alert_detail_status_override"] = None
    STUB_STATE["alert_acknowledge_posts"] = []
    STUB_STATE["alert_acknowledge_status_override"] = None
    STUB_STATE["sam_unsupported_data"] = None
    STUB_STATE["sam_unsupported_status"] = None
    STUB_STATE["sam_unsupported_requests"] = []
    STUB_STATE["sam_devices_data"] = None
    STUB_STATE["sam_devices_status"] = None
    STUB_STATE["sam_devices_requests"] = []
    STUB_STATE["sam_csv_data"] = None
    STUB_STATE["remote_access_data"] = None
    STUB_STATE["remote_access_status"] = None
    STUB_STATE["remote_access_requests"] = []
    STUB_STATE["remote_access_devices_data"] = None
    STUB_STATE["remote_access_devices_status"] = None
    STUB_STATE["remote_access_devices_requests"] = []
    STUB_STATE["remote_access_csv_data"] = None
    STUB_STATE["remote_access_devices_csv_data"] = None
    STUB_STATE["version_sprawl_data"] = None
    STUB_STATE["version_sprawl_status"] = None
    STUB_STATE["version_sprawl_requests"] = []
    STUB_STATE["version_sprawl_csv_data"] = None
    STUB_STATE["duplicate_tools_data"] = None
    STUB_STATE["duplicate_tools_status"] = None
    STUB_STATE["duplicate_tools_requests"] = []
    STUB_STATE["duplicate_tools_csv_data"] = None
    STUB_STATE["publishers_data"] = None
    STUB_STATE["publishers_status"] = None
    STUB_STATE["publishers_requests"] = []
    STUB_STATE["publishers_devices_data"] = None
    STUB_STATE["publishers_devices_status"] = None
    STUB_STATE["publishers_devices_requests"] = []
    STUB_STATE["publishers_csv_data"] = None
    STUB_STATE["publishers_devices_csv_data"] = None
    STUB_STATE["new_software_data"] = None
    STUB_STATE["new_software_status"] = None
    STUB_STATE["new_software_requests"] = []
    STUB_STATE["new_software_csv_data"] = None
    STUB_STATE["software_drift_data"] = None
    STUB_STATE["software_drift_status"] = None
    STUB_STATE["software_drift_requests"] = []
    STUB_STATE["software_drift_csv_data"] = None
    STUB_STATE["software_approved_data"] = None
    STUB_STATE["software_approved_status"] = None
    STUB_STATE["software_approved_requests"] = []
    STUB_STATE["software_approved_csv_data"] = None
    STUB_STATE["jamf_mode"] = "not_configured"
    STUB_STATE["jamf_token_state"] = "active"
    STUB_STATE["jamf_token_rotated_at"] = None
    STUB_STATE["jamf_token_revoked_at"] = None
    STUB_STATE["jamf_check_in_enabled"] = False
    STUB_STATE["jamf_instance_reset"] = False
    STUB_STATE["jamf_deleted_ids"] = set()
    STUB_STATE["jamf_current_token_ids"] = {
        r["jamf_id"] for r in JAMF_GAP_ROWS + JAMF_COVERED_ROWS}
    STUB_STATE["jamf_coverage_requests"] = []
    STUB_STATE["jamf_coverage_status_override"] = None
    STUB_STATE["jamf_setup_status_override"] = None
    STUB_STATE["jamf_token_posts"] = []
    STUB_STATE["jamf_token_post_status"] = None
    STUB_STATE["jamf_token_delete_calls"] = 0
    STUB_STATE["jamf_token_delete_status"] = None
    STUB_STATE["jamf_setup_puts"] = []
    STUB_STATE["jamf_setup_put_status"] = None
    STUB_STATE["jamf_devices_purge_calls"] = 0
    STUB_STATE["jamf_devices_delete_status"] = None
    STUB_STATE["ce_readiness_data"] = None
    STUB_STATE["ce_readiness_status"] = None
    STUB_STATE["ce_readiness_requests"] = []
    STUB_STATE["ce_readiness_csv_data"] = None
    STUB_STATE["insurance_evidence_data"] = None
    STUB_STATE["insurance_evidence_status"] = None
    STUB_STATE["insurance_evidence_requests"] = []
    STUB_STATE["enrolment_keys_data"] = None
    STUB_STATE["enrolment_keys_list_status_override"] = None
    STUB_STATE["enrolment_keys_list_requests"] = 0
    STUB_STATE["enrolment_key_creates"] = 0
    STUB_STATE["enrolment_key_create_posts"] = []
    STUB_STATE["enrolment_key_create_status_override"] = None
    STUB_STATE["enrolment_key_revokes"] = 0
    STUB_STATE["enrolment_key_revoke_posts"] = []
    STUB_STATE["enrolment_key_revoke_status_override"] = None
    # PAT-2263: GET /v1/portal/driver-findings, the Findings page's estate
    # driver-findings section - None falls back to DRIVER_FINDINGS below,
    # a status override simulates the fail-soft (secondary content) path.
    STUB_STATE["driver_findings_data"] = None
    STUB_STATE["driver_findings_status"] = None
    STUB_STATE["driver_findings_requests"] = []
    reset_approval_stub()
    reset_feedback_stub()
    main._clear_feedback_availability_cache()
    main._clear_report_catalogue_cache()
    return TestClient(main.app, raise_server_exceptions=False)
