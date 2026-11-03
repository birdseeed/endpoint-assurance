"""Real middleware denial/audit controls. Never dispatch a lifecycle mutation."""
import sqlite3
import time
import pytest
from fastapi.testclient import TestClient
from tests.pat2374_support import isolated_app, assert_owner

@pytest.mark.parametrize('method,path',[('DELETE','/admin/tenants/4b0102ec-1047-5edc-8594-15d1a25720c6')])
@pytest.mark.parametrize('credential,confirm,status,outcome',[
    ('none',None,401,None),('consultant','Company A',403,'denied_rbac'),
    ('owner',None,428,'confirm_missing'),('owner','Wrong tenant',409,'confirm_mismatch')])
def test_control_lifecycle_denial_prevents_dispatch_and_preserves_audit(tmp_path,monkeypatch,method,path,credential,confirm,status,outcome):
    with isolated_app(tmp_path,monkeypatch) as (app,dbpath):
        headers={}
        if credential!='none':
            cookie=app._session_encode(credential+'@example.invalid',int(time.time())+600)
            headers['Cookie']=app.SESSION_COOKIE+'='+cookie
        if confirm is not None: headers['X-Confirm-Resource']=confirm
        # No context manager: deliberately do not execute app startup/lifespan.
        assert_owner()
        response=TestClient(app.app).request(method,path,headers=headers)
        assert response.status_code==status,response.text
        with sqlite3.connect(dbpath) as db:
            rows=db.execute('SELECT actor_email,role,method,path,outcome FROM admin_audit_log').fetchall()
            assert db.execute('SELECT * FROM clients').fetchall()==[('4b0102ec-1047-5edc-8594-15d1a25720c6','Company A')]
        assert rows==([] if outcome is None else [(credential+'@example.invalid',credential,method,path,outcome)])


def test_control_read_only_session_rejects_account_write(tmp_path,monkeypatch):
    with isolated_app(tmp_path,monkeypatch) as (app,dbpath):
        from starlette.requests import Request
        import asyncio
        # Exercise the actual inner read-only middleware, not a success fake.
        seen=[]
        async def downstream(req):
            seen.append(req); raise AssertionError('Read-only write reached handler')
        scope={'type':'http','method':'POST','path':'/admin/tenants/4b0102ec-1047-5edc-8594-15d1a25720c6/account','headers':[],'query_string':b''}
        from datetime import datetime,timedelta,timezone
        signed=app._imp_encode({'tenant_id':'4b0102ec-1047-5edc-8594-15d1a25720c6','write_mode':False,'expires_at':(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()})
        scope['headers']=[(b'cookie',(app.IMP_COOKIE+'='+signed).encode())]
        req=Request(scope)
        response=asyncio.run(app.impersonation_write_guard(req,downstream))
        assert response.status_code==403
        assert not seen

@pytest.mark.parametrize('credential,status,outcome',[('none',401,None),('consultant',403,'denied_rbac')])
def test_control_restore_auth_and_role_denial_without_mutation(tmp_path,monkeypatch,credential,status,outcome):
    with isolated_app(tmp_path,monkeypatch) as (app,dbpath):
        headers={}
        if credential!='none':
            headers['Cookie']=app.SESSION_COOKIE+'='+app._session_encode(credential+'@example.invalid',int(time.time())+600)
        assert_owner()
        response=TestClient(app.app).post('/admin/tenants/4b0102ec-1047-5edc-8594-15d1a25720c6/restore',headers=headers)
        assert response.status_code==status
        with sqlite3.connect(dbpath) as db:
            rows=db.execute('SELECT outcome FROM admin_audit_log').fetchall()
        assert rows==([] if outcome is None else [(outcome,)])
