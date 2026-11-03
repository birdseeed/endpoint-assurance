"""Presentation only for current customer report/digest mail (PAT-2354).

No delivery, database, provider, or PDF dependencies. Links are supplied by the
existing callers and escaped by Jinja, never reconstructed by this layer.
"""
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

# Existing public PNG, verified against branding adf89fd8 (see docs/report-email/README.md).
# Do not use staff-authenticated dashboard assets or an SVG in email.
REPORT_EMAIL_LOGO_URL = "https://patched.im/apple-touch-icon.png?v=2026-09-26-brand-v3"
_UUID = re.compile(
    r"(?:urn:uuid:)?(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"
    r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f]))", re.IGNORECASE,
)
_env = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    autoescape=select_autoescape(["html"]),
)


def email_display_label(value: object, fallback: str = "Your estate") -> str:
    """Readable, single-line display copy; internal identifiers are not names.

    Strip UUIDs even when embedded in a label. This applies only to copy, never
    link targets, report payloads, audit identity or recipient selection.
    """
    if not isinstance(value, str):
        return fallback
    label = _UUID.sub("", value)
    had_uuid = label != value
    label = "".join(c if c.isprintable() else " " for c in label)
    if had_uuid:
        label = re.sub(r"\(\s*\)|\{\s*\}|\[\s*\]", " ", label)
    label = " ".join(label.split()).strip(" -:;(){}[]")
    return label or fallback


def render_report_email(template: str, *, estate_name: object, report_label: str,
                        period: str, **context) -> tuple[str, str, str]:
    """Return a consistent subject, escaped HTML and unescaped plain-text part."""
    estate = email_display_label(estate_name)
    title = email_display_label(report_label, "Report")
    period = email_display_label(period, "")
    ctx = dict(context, tenant_name=estate, report_label=title, period=period,
               brand_logo_url=REPORT_EMAIL_LOGO_URL)
    subject = f"Patched | {estate} | {title} | {period}"
    return (subject, _env.get_template(f"{template}.html").render(**ctx),
            _env.get_template(f"{template}.txt").render(**ctx))
