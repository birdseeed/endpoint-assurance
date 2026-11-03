"""Offline source-shaped fixtures. No fabricated aggregate fields or startup."""
import importlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from functools import lru_cache
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAMP = '2026-10-03T12:34:56Z'
ATTACK = '<img data-pat2374-injected src=x onerror="window.__injected=true">'


def assert_owner():
    # This only guards isolated test fixtures, never queue or source-write authority.
    owner_path = os.environ.get("QUEUE_RUN_TEST_OWNER_PATH")
    nonce = os.environ.get("QUEUE_RUN_TEST_OWNER_NONCE")
    if owner_path is None and nonce is None:
        return
    assert owner_path and nonce, "Both test owner environment values must be nonempty"
    try:
        actual_nonce = json.loads(Path(owner_path).read_text())["owner_nonce"]
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise AssertionError("Test owner record is unreadable or malformed") from exc
    assert actual_nonce == nonce, "Test owner nonce mismatch"



@lru_cache(maxsize=1)
def artifact_dir():
    # Allocate only when a screenshot is needed; each standalone run owns its path.
    assert_owner()
    configured = os.environ.get("QUEUE_RUN_TEST_ARTIFACT_DIR")
    if configured is not None:
        assert configured, "Test artifact directory must be nonempty"
        directory = Path(configured)
        directory.mkdir(parents=True, exist_ok=True)
        return directory
    return Path(tempfile.mkdtemp(prefix="pat2374-current-"))


def tenant(tid, **extra):
    row = dict(id=tid, name='Tenant ' + tid.upper(), tier='assurance', macos_enabled=True,
               windows_enabled=True, device_count=7, active_last_7d=4,
               compliance_pct=82, crit_high_fail_count=2, is_trial=False, trial_expires_at=None)
    row.update(extra)
    return row


TENANTS = [tenant('a'), tenant('b',device_count=3,active_last_7d=2), tenant('new', device_count=0, active_last_7d=0,
           compliance_pct=None), tenant('trial', is_trial=True, trial_expires_at='2099-10-01T00:00:00Z'),
           tenant('degraded', device_count=None, active_last_7d=None, compliance_pct=None)]


def account(tid):
    return dict(company='Company ' + tid.upper(), company_phone=None,
                primary_contact_name='Contact ' + tid.upper(), primary_contact_email=tid+'@example.invalid',
                technical_contact_name='Technical B' if tid=='b' else None,
                technical_contact_email='technical-b@example.invalid' if tid=='b' else None, billing_contact_name=None,
                billing_contact_email=None, onboarding_state='prospect' if tid=='new' else 'active',
                contract_renewal_date=None, contract_notes=None, account_notes=None,
                agent_config_tier='assurance', billing_tier='report', app_control_enabled=False,
                billing_frequency='monthly', subscription_tier='assurance')


def users(tid):
    return {'users': [] if tid=='new' else [dict(email=tid+'@example.invalid', tenant_id=tid,
            tenant_name='Tenant '+tid.upper(), role='viewer', created_at=STAMP, disabled_at=None)],
            'total':0 if tid=='new' else 1}


def deliveries(tid):
    return [dict(id='delivery-'+tid, report_type='Report '+tid.upper(), recipient=tid+'@example.invalid',
                 generated_at=STAMP, sent_at=None, status='failed')]


@contextmanager
def isolated_app(tmp_path, monkeypatch):
    # Copy only git-tracked Python, never .env, ignored state or a venv.
    assert_owner()
    runtime = tmp_path/'app'; runtime.mkdir()
    names = []
    paths = subprocess.check_output(['git','ls-files','-z','*.py'], cwd=ROOT).decode().split('\0')
    for name in paths:
        if name and '/' not in name:
            assert_owner(); shutil.copyfile(ROOT/name, runtime/name); names.append(Path(name).stem)
    for name in ('templates','static','truth_manifest.yaml'):
        assert_owner(); (runtime/name).symlink_to(ROOT/name)
    previous = {n:sys.modules.pop(n) for n in names if n in sys.modules}
    monkeypatch.syspath_prepend(str(runtime))
    monkeypatch.setenv('DASHBOARD_DB_PATH', str(tmp_path/'owned.db'))
    monkeypatch.delenv('DASHBOARD_STATE_DIR', raising=False)
    monkeypatch.setenv('PATCHED_API_INTERNAL','http://127.0.0.1:9')
    monkeypatch.setenv('DASHBOARD_API_KEY','test-key')
    monkeypatch.setenv('ADMIN_API_TOKEN','test-key')
    monkeypatch.setenv('EMAIL_DRY_RUN','1')
    assert_owner()
    with sqlite3.connect(tmp_path/'owned.db') as db:
        db.execute('CREATE TABLE clients(tenant_id TEXT, company TEXT)')
        db.execute('INSERT INTO clients VALUES (?,?)',('4b0102ec-1047-5edc-8594-15d1a25720c6','Company A'))
        db.execute('CREATE TABLE admin_audit_log(id TEXT PRIMARY KEY,ts TEXT,actor_email TEXT,role TEXT,method TEXT,path TEXT,resource TEXT,outcome TEXT,resource_name TEXT,reason TEXT,before_value TEXT,after_value TEXT)')
    dashboard = importlib.import_module('main')
    monkeypatch.setattr(dashboard,'DASHBOARD_OPERATORS',frozenset({'owner@example.invalid'}))
    calls=[]
    def forbidden(*a, **kw):
        calls.append('active effect'); raise AssertionError('No lifecycle/provider/collector effect authorised')
    for name in ('_send_email','scheduler_loop','fast_check_loop','check_report_schedules'):
        monkeypatch.setattr(dashboard,name,forbidden)
    for method in ('post','put','patch','delete'):
        monkeypatch.setattr(dashboard.http,method,forbidden)
    try:
        yield dashboard, tmp_path/'owned.db'
    finally:
        for n in names: sys.modules.pop(n,None)
        sys.modules.update(previous)
        assert not calls, calls
