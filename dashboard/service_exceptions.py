"""Bounded service-evidence projection. No collectors, providers or mutations.

The API contract is deliberately partial. A successful read is not a successful
job, a send attempt is not delivery, and a heartbeat is not a restore test.
"""
import re
import sqlite3
import time
from datetime import datetime

CATEGORIES = {
    "outgoing_email": "Outgoing email",
    "scheduled_jobs": "Scheduled jobs",
    "customer_access": "Customer access setup",
    "device_reports": "Device reports",
    "assurance_processing": "Assurance processing",
    "vulnerability_data": "Vulnerability data updates",
    "reports": "Report generation and delivery",
    "backups": "Backups and restore tests",
    "server_health": "Server health",
    "version_checks": "Software version checks",
    "billing": "Billing connection",
}
RESULTS = {"ok", "failed", "stale", "unknown", "unavailable"}
LINKS = {"/console#ops", "/console#automations"}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")
_TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)\Z")


class InvalidEvidence(ValueError):
    """Wire evidence does not satisfy the fixed source contract."""


def text(value, limit=2048):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise InvalidEvidence("Invalid text")
    return value


def identifier(value, tenant=False):
    if not isinstance(value, str) or not (_TENANT if tenant else _IDENTIFIER).fullmatch(value):
        raise InvalidEvidence("Invalid identifier")
    return value


def timestamp(value, now, nullable=True):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        raise InvalidEvidence("Invalid UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidEvidence("Invalid calendar timestamp") from exc
    if parsed.year < 1970 or parsed > now:
        raise InvalidEvidence("Invalid source time")
    return value


def _unknown(key, reason):
    return dict(id=key, name=CATEGORIES[key], explanation="Checks recorded " + CATEGORIES[key].lower() + " evidence.",
                source="Service evidence validation", scope="Platform service / " + CATEGORIES[key],
                availability="unavailable", result="unknown", checked_at=None, last_success_at=None,
                next_expected_at=None, reason=reason,
                next_action="Inspect the source evidence in Operations and retry this read.")


def _observation(row, now):
    if not isinstance(row, dict) or row.get("result") not in RESULTS:
        raise InvalidEvidence("Invalid observation")
    result = {"id": identifier(row.get("id")), "scope": text(row.get("scope")), "result": row["result"]}
    for field in ("evidence_at", "last_success_at"):
        if field not in row:
            raise InvalidEvidence("Missing observation time")
        result[field] = timestamp(row[field], now)
    if result["result"] in {"ok", "failed", "stale"} and result["evidence_at"] is None:
        raise InvalidEvidence("Observation has no evidence")
    return result


def _check(row, now):
    if not isinstance(row, dict) or row.get("availability") not in {"available", "degraded", "unavailable"} or row.get("result") not in RESULTS:
        raise InvalidEvidence("Invalid check")
    out = {k: text(row.get(k)) for k in ("id", "name", "explanation", "source", "scope", "reason", "next_action")}
    out.update(availability=row["availability"], result=row["result"])
    for field in ("checked_at", "last_success_at", "next_expected_at"):
        if field not in row:
            raise InvalidEvidence("Missing check time")
        out[field] = timestamp(row[field], now)
    # This version of the API has no authoritative next-run source.
    if out["next_expected_at"] is not None:
        raise InvalidEvidence("Unsupported schedule")
    if out["availability"] == "unavailable" and out["result"] not in {"unknown", "unavailable"}:
        raise InvalidEvidence("Unavailable evidence cannot be healthy")
    if out["result"] in {"ok", "failed", "stale"} and out["checked_at"] is None:
        raise InvalidEvidence("Check has no observation time")
    if "observations" in row:
        observations = row["observations"]
        if not isinstance(observations, list) or len(observations) > 128:
            raise InvalidEvidence("Invalid observations")
        out["observations"] = [_observation(v, now) for v in observations]
        if len({v["id"] for v in out["observations"]}) != len(observations):
            raise InvalidEvidence("Duplicate observations")
    return out


def _exception(row, now):
    if not isinstance(row, dict) or row.get("check_id") not in CATEGORIES:
        raise InvalidEvidence("Unknown exception source")
    key = row["check_id"]
    eid = identifier(row.get("id"))
    if not eid.startswith(key + ":") or row.get("deep_link") not in LINKS:
        raise InvalidEvidence("Invalid exception identity or destination")
    if "tenant_id" not in row or "since" not in row:
        raise InvalidEvidence("Missing nullable exception fields")
    tenant = row["tenant_id"]
    if tenant is not None:
        identifier(tenant, tenant=True)
    since = timestamp(row["since"], now)
    at = timestamp(row.get("evidence_at"), now, nullable=False)
    if since is not None and datetime.fromisoformat(since.replace("Z", "+00:00")) > datetime.fromisoformat(at.replace("Z", "+00:00")):
        raise InvalidEvidence("Onset after evidence")
    return dict(id=eid, check_id=key, tenant_id=tenant, scope=text(row.get("scope")), since=since,
                evidence_at=at, reason=text(row.get("reason")), deep_link=row["deep_link"])


def project(body, now):
    """Discard uncontracted fields; quarantine bad sources without clearing peers."""
    if not isinstance(body, dict) or body.get("coverage") != "partial":
        raise InvalidEvidence("Invalid coverage")
    observed = timestamp(body.get("observed_at"), now, nullable=False)
    rows, exceptions = body.get("checks"), body.get("exceptions")
    if not isinstance(rows, list) or len(rows) != len(CATEGORIES) or not isinstance(exceptions, list) or len(exceptions) > 256:
        raise InvalidEvidence("Invalid arrays")
    if any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows):
        raise InvalidEvidence("Invalid categories")
    if {row["id"] for row in rows} != set(CATEGORIES):
        raise InvalidEvidence("Missing or duplicated categories")
    checks, invalid, accepted = {}, set(), []
    for row in rows:
        key = row["id"]
        try:
            checks[key] = _check(row, now)
        except (InvalidEvidence, TypeError):
            invalid.add(key)
    ids = set()
    for row in exceptions:
        if not isinstance(row, dict) or not isinstance(row.get("check_id"), str) or row["check_id"] not in CATEGORIES:
            raise InvalidEvidence("Unknown exception source")
        key = row["check_id"]
        try:
            value = _exception(row, now)
            if value["id"] in ids or checks.get(key, {}).get("result") not in {"failed", "stale"}:
                raise InvalidEvidence("Inconsistent exception")
            ids.add(value["id"])
            accepted.append(value)
        except (InvalidEvidence, TypeError):
            invalid.add(key)
    for key in invalid:
        checks[key] = _unknown(key, "Source evidence is invalid or unavailable; its exceptions cannot be verified.")
    return dict(observed_at=observed, coverage="partial", checks=[checks[k] for k in CATEGORIES],
                exceptions=[e for e in accepted if e["check_id"] not in invalid]), invalid


# Fixed, currently emitted sources only. No arbitrary check name is published.
LOCAL_CHECKS = {
    "email_delivery": ("outgoing_email", "Email sending and authentication", "patched-prod-01 / outgoing email"),
    "deploy_drift": ("version_checks", "Deployed revision and tracked files", "patched-prod-01 / dashboard revision"),
    "maintenance_prod01": ("server_health", "Server maintenance checks", "patched-prod-01 / maintenance"),
    "maintenance_api01": ("server_health", "Server maintenance checks", "patched-api-01 / maintenance"),
    "maintenance_portal01": ("server_health", "Server maintenance checks", "patched-portal-01 / maintenance"),
}
for _name, _label in {
    "email_delivery_check": "Email check job", "report_tick": "Report processing tick",
    "report_schedules": "Report schedule check", "cert_digest": "Certificate digest check",
    "stale_digest": "Device report digest check", "automation_alerts": "Automation alert check",
    "automation_digest": "Automation digest check", "health_alerts": "Health alert check",
    "portal_auth_check": "Portal authentication check", "deploy_drift_check": "Deployment verification job",
    "maintenance_drift_check": "Maintenance verification job",
}.items():
    LOCAL_CHECKS["tick_" + _name] = ("scheduled_jobs", _label, "patched-prod-01 / " + _label.lower())

LIMITATIONS = {
    "outgoing_email": "The recorded check covers sending configuration and authentication. Queue, provider acceptance, rejection, bounces and recipient delivery remain unknown.",
    "scheduled_jobs": "Local rows are the latest recorded tick outcomes, not full run history. Next expected runs, missed schedules and repeated failures remain unknown.",
    "version_checks": "This is a recorded revision and file verification result, not the latest release comparison or deployment history. Stale verification does not mean an old release.",
    "server_health": "These are recorded maintenance checks for the named hosts. They do not establish all service availability, disk capacity or certificate expiry.",
    "reports": "These are recorded send attempts, not generation-job or recipient delivery evidence. Recipient delivery and schedule coverage remain unknown.",
}


def _read(connect, sql, params=()):
    """One bounded read, with explicit failure separate from a successful empty."""
    conn = None
    try:
        conn = connect()
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA busy_timeout=1000")
        deadline = time.monotonic() + 1
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        return [dict(row) for row in conn.execute(sql, params).fetchall()]
    except sqlite3.Error:
        return None
    finally:
        if conn is not None:
            conn.close()


def _local_exception(key, source_id, scope, at, reason, tenant=None):
    return dict(id=key + ":dashboard:" + source_id, check_id=key, tenant_id=tenant,
                scope=scope, since=None, evidence_at=at, reason=reason + " The onset time is unknown.",
                deep_link="/console#automations" if key == "scheduled_jobs" else "/console#ops")


def join_local(body, invalid, connect, freshness, now):
    """Supplement validated upstream evidence; never overwrite supported failures."""
    checks = {row["id"]: row for row in body["checks"]}
    names = tuple(LOCAL_CHECKS)
    rows = _read(connect, "SELECT name,state,evaluated_at FROM check_statuses WHERE name IN (" + ",".join("?" for _ in names) + ") ORDER BY name LIMIT 64", names)
    groups = {k: [] for k in LIMITATIONS if k != "reports"}
    if rows is not None:
        for row in rows:
            key, label, scope = LOCAL_CHECKS[row["name"]]
            try:
                at = timestamp(row["evaluated_at"], now, nullable=False)
            except InvalidEvidence:
                at = None
            result = "unknown"
            if at is not None:
                _, stale = freshness(row["name"], at, now)
                result = "stale" if stale else {"ok": "ok", "degraded": "failed"}.get(row["state"], "unknown")
            groups[key].append(dict(id="dashboard:" + row["name"], scope=scope, result=result,
                                    evidence_at=at, last_success_at=at if row["state"] == "ok" and at else None))
            if key not in invalid and result in {"failed", "stale"}:
                reason = label + (" recorded a degraded result." if result == "failed" else " has stale recorded evidence; current state is unknown.")
                body["exceptions"].append(_local_exception(key, row["name"], scope, at, reason))
    for key, observations in groups.items():
        if key in invalid:
            continue
        check = checks[key]
        if rows is None:
            check.update(availability="degraded", last_success_at=None)
            if check["result"] not in {"failed", "stale"}:
                check["result"] = "unknown"
            check["reason"] += " Dashboard check evidence could not be read; local state is unknown."
        elif observations:
            check["observations"] = check.get("observations", []) + observations
            check["availability"] = "degraded"
            check["source"] += "; dashboard check_statuses"
            check["scope"] += "; recorded dashboard checks for named hosts"
            check["last_success_at"] = None  # A category is not a single job.
            times = [v["evidence_at"] for v in observations if v["evidence_at"]]
            if times:
                check["checked_at"] = max(times, key=lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")))
            results = {check["result"], *(v["result"] for v in observations)}
            check["result"] = "failed" if "failed" in results else "stale" if "stale" in results else "unknown"
            check["reason"] = "Recorded dashboard checks are available with partial coverage. " + LIMITATIONS[key]
        else:
            check["reason"] += " No dashboard check observations are recorded."
    attempts = _read(connect, "SELECT id,ts,tenant_id,outcome FROM report_send_audit_log ORDER BY ts DESC,id DESC LIMIT 101")
    check = checks["reports"]
    if "reports" not in invalid:
        if attempts is None:
            check.update(availability="degraded", last_success_at=None)
            if check["result"] not in {"failed", "stale"}:
                check["result"] = "unknown"
            check["reason"] += " Dashboard attempt evidence could not be read; delivery is unknown."
        elif attempts:
            observations = []
            for row in attempts[:100]:
                try:
                    rid = identifier(row["id"])
                    tenant = row["tenant_id"]
                    if tenant is not None:
                        identifier(tenant, tenant=True)
                    at = timestamp(row["ts"], now, nullable=False)
                    result = "failed" if row["outcome"] == "failed" else "unknown"
                    scope = "patched-prod-01 / report send attempt" + (" / tenant " + tenant if tenant else "")
                    observations.append(dict(id="send:" + rid, scope=scope, result=result, evidence_at=at, last_success_at=None))
                    if result == "failed":
                        body["exceptions"].append(_local_exception("reports", rid, scope, at,
                            "A recorded report send attempt failed. Current recipient delivery is unknown.", tenant))
                except InvalidEvidence:
                    observations.append(dict(id="invalid-attempt:" + str(len(observations)), scope="patched-prod-01 / report attempt", result="unknown", evidence_at=None, last_success_at=None))
            check.update(availability="degraded", observations=check.get("observations", []) + observations,
                         last_success_at=None, source=check["source"] + "; dashboard report_send_audit_log",
                         reason=LIMITATIONS["reports"] + (" Only the latest 100 attempts are shown; older history is unavailable here." if len(attempts) > 100 else ""))
            results = {check["result"], *(v["result"] for v in observations)}
            check["result"] = "failed" if "failed" in results else "stale" if "stale" in results else "unknown"
            times = [v["evidence_at"] for v in observations if v["evidence_at"]]
            if times:
                check["checked_at"] = max(times, key=lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")))
        else:
            check["reason"] += " No dashboard send attempts are recorded; recipient delivery is unknown."
    return body
