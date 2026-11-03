"""db.py — schema for the standalone scan service.

public_scans (the CVE-scan funnel) and public_uploads (the Intune-upload
funnel) are ported verbatim from the dashboard's init_db (main.py, PAT-457).
public_pricing_enquiries (PAT-1978) is native to this service -- the
receiving end of the website's /pricing enquiry form. waitlist_signups and
waitlist_attempts (PAT-2560) are native too: the Mac app waitlist and its
rate-limit ledger. No dashboard.db
tables (scans, clients, kv, report_subscriptions) exist here — this box
holds no tenant/admin state.
"""

from shared import get_db


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS public_uploads (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                ip TEXT NOT NULL,
                upload_type TEXT NOT NULL,
                status TEXT DEFAULT 'processing',
                report_path TEXT,
                error TEXT,
                created_at TEXT NOT NULL
            )
        """)
        # Public CVE-scan requests. Lifecycle:
        #   pending_verify → verified → scanning → complete | error → deleted
        # Files (devices_path, apps_path, report_path) and DB rows are purged
        # after PUBLIC_RETENTION_DAYS by the retention sweep.
        db.execute("""
            CREATE TABLE IF NOT EXISTS public_scans (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                company TEXT NOT NULL,
                ip TEXT,
                status TEXT NOT NULL DEFAULT 'pending_verify',
                otp_code TEXT,
                otp_attempts INTEGER DEFAULT 0,
                otp_expires_at TEXT,
                devices_path TEXT,
                apps_path TEXT,
                report_path TEXT,
                download_token TEXT,
                delete_token TEXT,
                job_id TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                verified_at TEXT,
                completed_at TEXT,
                deleted_at TEXT,
                report_emailed_at TEXT
            )
        """)
        # Erasure keeps only the remainder of each scan's original 24h quota
        # window. A per-record key plus domain-separated HMACs is pseudonymous,
        # not irreversibly anonymous: the stored key permits candidate checks.
        # No original identifiers, file paths or bearer capabilities belong here.
        db.execute("""
            CREATE TABLE IF NOT EXISTS public_scan_erasure_limits (
                scan_hash TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                mac_key BLOB NOT NULL,
                email_mac BLOB,
                ip_mac BLOB
            )
        """)
        # Pricing / design-partner enquiry form (PAT-1978): a rate-limiting
        # ledger only. Submitted field content (name, organisation, device
        # counts, etc.) is never persisted here -- it goes out in the email
        # to PRICING_ENQUIRY_TO and nowhere else. Rows are enough to count
        # attempts per email/IP in a rolling 24h window and to record
        # whether delivery actually succeeded. Purged by the same retention
        # sweep as the other two tables.
        db.execute("""
            CREATE TABLE IF NOT EXISTS public_pricing_enquiries (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                ip TEXT NOT NULL,
                created_at TEXT NOT NULL,
                delivered_at TEXT
            )
        """)
        # Mac app waitlist (PAT-2560). Two tables on purpose.
        #
        # waitlist_signups IS the list: one row per person, keyed by the
        # lower-cased email address (UNIQUE), holding exactly what the form
        # asks for and when. It deliberately has no ip column. It is the one
        # table in this service the retention sweep must never touch: the
        # privacy notice promises these details are kept until the app has
        # launched and the person has been told, or until they ask to leave
        # (scan/bin/waitlist.py remove). notified_at records that the "new
        # sign up" email to the owner was accepted for delivery; NULL means it
        # was not, and /healthz counts those so a dead mailer is visible.
        #
        # waitlist_attempts is the rate-limit ledger: email, ip and time for
        # every counted submission, a repeat included. It is purged on the same
        # schedule as the other ledgers (PUBLIC_RETENTION_DAYS).
        db.execute("""
            CREATE TABLE IF NOT EXISTS waitlist_signups (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                devices TEXT NOT NULL DEFAULT '',
                tool TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                notified_at TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS waitlist_attempts (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                ip TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        # public_scans lookup indexes (rate limits, status polling, token routes)
        # plus public_uploads and public_pricing_enquiries rate-limit indexes.
        for name, table, col in [
            ("idx_public_scans_email", "public_scans", "email"),
            ("idx_public_scans_ip", "public_scans", "ip"),
            ("idx_public_scans_status", "public_scans", "status"),
            ("idx_public_scans_created_at", "public_scans", "created_at"),
            ("idx_public_scans_download", "public_scans", "download_token"),
            ("idx_public_scans_delete", "public_scans", "delete_token"),
            ("idx_scan_erasure_limits_created_at", "public_scan_erasure_limits", "created_at"),
            ("idx_public_uploads_email", "public_uploads", "email"),
            ("idx_public_uploads_ip", "public_uploads", "ip"),
            ("idx_public_uploads_created_at", "public_uploads", "created_at"),
            ("idx_public_pricing_enquiries_email", "public_pricing_enquiries", "email"),
            ("idx_public_pricing_enquiries_ip", "public_pricing_enquiries", "ip"),
            ("idx_public_pricing_enquiries_created_at", "public_pricing_enquiries", "created_at"),
            ("idx_waitlist_attempts_email", "waitlist_attempts", "email"),
            ("idx_waitlist_attempts_ip", "waitlist_attempts", "ip"),
            ("idx_waitlist_attempts_created_at", "waitlist_attempts", "created_at"),
        ]:
            db.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table}({col})")
