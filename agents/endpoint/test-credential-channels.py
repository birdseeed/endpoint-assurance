#!/usr/bin/env python3
"""Synthetic-only shell credential checks. No network, installers or root writes.

Requires an explicit scratch directory. Copies/rebases the source under test;
installer checks execute only credential-selection/handoff blocks, never install
or daemon operations. Privileged/network commands are replaced with local stubs.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(os.environ["TEST_SOURCE_ROOT"]).resolve()
BASE = Path(sys.argv[1]).resolve()
assert BASE.is_dir() and str(BASE).startswith('/private/var/folders/'), 'explicit private scratch required'
BASE.chmod(0o700)
TOKEN = 'SYNTHETIC-q"u\\ote-$dollar-`tick`'
PERSONAL = 'SYNTHETIC-personal-"\\'


def source(path):
    if '--baseline' in sys.argv:
        return subprocess.check_output(['git', 'show', 'HEAD:' + path], cwd=ROOT, text=True)
    return (ROOT / path).read_text()


def put(path, text):
    path.write_text(text)
    path.chmod(0o700)
    return path


def run(script, args=(), env=None, shell='/bin/bash'):
    result = subprocess.run([shell, str(script), *args], env=env, capture_output=True, text=True, timeout=15)
    assert TOKEN not in result.stdout + result.stderr and PERSONAL not in result.stdout + result.stderr
    return result


def assert_no_secret_log(log):
    def check(value):
        if isinstance(value, dict):
            for v in value.values(): check(v)
        elif isinstance(value, list):
            for v in value: check(v)
        elif isinstance(value, str):
            assert TOKEN not in value and PERSONAL not in value, 'secret leaked in argv/env'
            if value.startswith('{'):
                try: parsed=json.loads(value)
                except ValueError: return
                check(parsed)
    for line in log.read_text().splitlines(): check(json.loads(line))


with tempfile.TemporaryDirectory(dir=BASE) as tmp:
    work = Path(tmp)
    tools = work / 'tools'
    tools.mkdir()
    log = work / 'argv.jsonl'
    env = dict(PATH=str(tools) + ':/usr/bin:/bin', LOG=str(log), WORK=str(work))
    # The only real child interpreter executes local copied code. It records
    # argv/env; the synthetic secret must not appear there.
    put(tools / 'python3', '#!/usr/bin/python3\nimport os,sys,json\nwith open(os.environ["LOG"],"a") as f: f.write(json.dumps({"argv":sys.argv,"envtoken":os.environ.get("PATCHED_ENROLLMENT_TOKEN")})+"\\n")\nos.execv("/usr/bin/python3",["/usr/bin/python3",*sys.argv[1:]])\n')
    put(tools / 'curl', '''#!/usr/bin/python3
import os,sys,json,pathlib,stat
w=pathlib.Path(os.environ['WORK']); args=sys.argv[1:]
with open(os.environ['LOG'],'a') as f: f.write(json.dumps({'argv':sys.argv})+'\\n')
if '--config' in args:
 p=pathlib.Path(args[args.index('--config')+1]); assert stat.S_IMODE(p.stat().st_mode)==0o600
 (w/'curl-config').write_text(p.read_text())
 print('[]' if 'page=2' in args[-1] else '[{"name":"sample"}]')
else:
 assert stat.S_IMODE(os.fstat(0).st_mode)==0o600
 (w/'request').write_bytes(sys.stdin.buffer.read())
 response=w/'enroll-response'
 pathlib.Path(args[args.index('-o')+1]).write_bytes(response.read_bytes() if response.exists() else b'{}')
 print(os.environ.get('HTTP_CODE','503'),end='')
''')
    put(tools / 'jq', '#!/usr/bin/python3\nimport json,sys\nfor r in json.load(sys.stdin): print(r["name"])\n')
    put(tools / 'git', '''#!/usr/bin/python3
import os,sys,json,pathlib,subprocess
args=sys.argv[1:]; w=pathlib.Path(os.environ['WORK'])
with open(os.environ['LOG'],'a') as f: f.write(json.dumps({'argv':sys.argv,'orgenv':os.environ.get('GITHUB_TOKEN_PATCHED_LTD'),'personalenv':os.environ.get('GITHUB_TOKEN_ANDYBRIDSON_PATCHED')})+'\\n')
if 'config' in args:
 if os.environ.get('CONFIG_FAIL')=='1': sys.exit(1)
 p=pathlib.Path(args[args.index('-C')+1])/'config'
 if '--unset-all' in args: p.write_text('')
 else: p.write_text(args[-1])
 sys.exit(0)
helper=next(x.split('=',1)[1] for x in args if x.startswith('credential.helper=') and x!='credential.helper=')
secret=subprocess.check_output([helper,'get'],input=b'protocol=https\\nhost=github.com\\n\\n')
assert b'password=SYNTHETIC-' in secret
(w/'helper-results').open('ab').write(secret)
assert not subprocess.run([helper,'get'],input=b'protocol=https\\nhost=untrusted.invalid\\n\\n',capture_output=True).returncode==0
if 'clone' in args:
 d=pathlib.Path(args[-1]); d.mkdir(parents=True); (d/'config').write_text(args[-2])
sys.exit(int(os.environ.get('GIT_FAIL','0')))
''')
    for name in ('install', 'chown'):
        put(tools/name, '#!/bin/bash\nexit 0\n')
    put(tools/'ioreg', '#!/bin/bash\nprintf \'"IOPlatformUUID" = "synthetic-device"\\n\'\n')

    # Full enrollment flow with transient and terminal responses; all filesystem
    # targets rebased, install/chown/network/hardware commands stubbed.
    creds = work/'creds'; creds.mkdir(mode=0o700)
    state = work/'state'; state.mkdir()
    enroll = source('agents/endpoint/patched-enroll.sh')
    enroll = enroll.replace('export PATH="/usr/bin:/bin:/usr/sbin:/sbin"', 'export PATH="'+str(tools)+':/usr/bin:/bin"')
    enroll = enroll.replace('PYTHON3="/usr/bin/python3"', 'PYTHON3="'+str(tools/'python3')+'"')
    enroll = enroll.replace('/tmp/.patched-enroll-', str(work/'enroll-'))
    script = put(work/'enroll.sh', enroll)
    e = dict(env, PATCHED_CREDS_DIR=str(creds), PATCHED_STATE_DIR=str(state), PATCHED_BUNDLE_DIR=str(work))
    token_file = creds/'enrollment-token'
    for code in ('503','401','410'):
        token_file.write_text(' \t'+TOKEN+' \nignored-second-line\n'); token_file.chmod(0o600)
        result = run(script, env=dict(e, HTTP_CODE=code), shell='/bin/zsh')
        assert result.returncode == (0 if code=='503' else 1), result
        assert_no_secret_log(log)
        assert json.loads((work/'request').read_text())['enrollment_token'] == TOKEN
        assert token_file.exists() == (code=='503')
        assert not list(work.glob('enroll-payload.*'))
    # HTTP 200 consumes a token even when its body cannot be used.
    token_file.write_text(TOKEN+'\n'); token_file.chmod(0o600)
    (creds/'suspended').unlink(missing_ok=True)
    (work/'enroll-response').write_text('malformed synthetic JSON')
    result=run(script,env=dict(e,HTTP_CODE='200'),shell='/bin/zsh')
    assert result.returncode==1 and (creds/'suspended').exists()
    assert not token_file.exists() and (creds/'enrollment-token.rejected').read_text()==TOKEN+'\n'
    assert 'PATCHED_ENROLLMENT_UNUSABLE_RESPONSE' in result.stdout
    assert not (creds/'bearer-token').exists()

    # A valid response must complete the full copied enrollment flow and
    # install all four local credentials privately. The deliberately absent
    # floor reader keeps the existing floor and reports its failure, matching
    # the source's existing conservative recovery behaviour.
    response={'tenant_id':'synthetic-tenant', 'bearer_token':'synthetic-returned-bearer',
              'hmac_secret':'synthetic-returned-hmac', 'device_id':'synthetic-device'}
    response_file=work/'enroll-response'
    response_file.write_text(json.dumps(response)); response_file.chmod(0o600)
    token_file.write_text(' \t'+TOKEN+' \nignored-second-line\n'); token_file.chmod(0o600)
    (creds/'suspended').unlink()
    floor=state/'agent-config.version'; floor.write_text('synthetic-existing-floor')
    result=run(script,env=dict(e,HTTP_CODE='200'),shell='/bin/zsh')
    assert result.returncode==0 and 'Enrolled: tenant synthetic-tenant' in result.stdout
    assert not token_file.exists() and not (creds/'suspended').exists()
    assert json.loads((work/'request').read_text())=={'enrollment_token':TOKEN,'device_id':'synthetic-device'}
    for field,filename in [('tenant_id','tenant-id'),('bearer_token','bearer-token'),
                           ('hmac_secret','hmac-secret'),('device_id','device-id')]:
        credential=creds/filename
        assert credential.read_text()==response[field]+'\n'
        assert credential.stat().st_mode & 0o777 == 0o600
    assert response['bearer_token'] not in result.stdout+result.stderr
    assert response['hmac_secret'] not in result.stdout+result.stderr
    assert floor.read_text()=='synthetic-existing-floor' and 'floor reader failed' in result.stdout
    assert not list(work.glob('enroll-payload.*')) and not list(work.glob('enroll-resp.*'))
    assert_no_secret_log(log)

    # Full backup flow against stub git/curl/jq. Includes existing dirty legacy
    # remotes, success/failure, both credential identities and private cleanup.
    backup = source('platform/api-vps-artefacts/pat-backup-01/bin/backup-github.sh')
    mirror = work/'mirrors'
    for owner, repo in [('Patched-LTD','sample'),('andybridson-patched','openclaw')]:
        d=mirror/owner/(repo+'.git'); d.mkdir(parents=True)
        (d/'config').write_text('https://legacy-secret@github.com/old')
    credential_source = put(work/'github.env', 'export GITHUB_TOKEN_PATCHED_LTD='+ __import__('shlex').quote(TOKEN)+'\nexport GITHUB_TOKEN_ANDYBRIDSON_PATCHED='+__import__('shlex').quote(PERSONAL)+'\n')
    backup = backup.replace('/tmp/patched-github-auth.',str(work/'patched-github-auth.')).replace('/srv/backup/git-mirrors',str(mirror)).replace('/etc/patched-backup/github.env',str(credential_source))
    script = put(work/'backup.sh',backup)
    for fail in ('0','1'):
        result=run(script,env=dict(env,TMPDIR=str(work),GIT_FAIL=fail))
        assert result.returncode == int(fail), result
        assert not list(work.glob('patched-github-auth.*'))
        for config in mirror.glob('*/*.git/config'):
            assert config.read_text().startswith('https://github.com/')
            assert TOKEN not in config.read_text() and 'legacy-secret' not in config.read_text()
    # A config failure must not reach network/helper operations, and clone
    # failures must never persist credential-bearing URLs.
    before=(work/'helper-results').read_text()
    assert run(script,env=dict(env,CONFIG_FAIL='1')).returncode != 0
    assert (work/'helper-results').read_text()==before
    assert not list(work.glob('patched-github-auth.*'))
    import shutil
    shutil.rmtree(mirror)
    assert run(script,env=dict(env,GIT_FAIL='1')).returncode != 0
    for stored in mirror.glob('*/*.git/config'):
        assert stored.read_text().startswith('https://github.com/')
        assert TOKEN not in stored.read_text() and PERSONAL not in stored.read_text()
    assert not list(work.glob('patched-github-auth.*'))
    assert_no_secret_log(log)
    assert PERSONAL in (work/'helper-results').read_text()
    config=(work/'curl-config').read_text()
    assert '\\\\' in config and '\\"' in config

    # Multiline credentials fail closed before curl/git, without diagnostics.
    credential_source.write_text('GITHUB_TOKEN_PATCHED_LTD='+__import__('shlex').quote(TOKEN+'\nheader-injection')+'\n')
    before=log.read_text()
    assert run(script,env=env).returncode != 0
    assert log.read_text()==before
    assert not list(work.glob('patched-github-auth.*'))

    # Execute only the wrapper's actual resolution and child-handoff blocks.
    wrapper=source('agents/macos/install.sh')
    resolve=wrapper[wrapper.index('while [ $# -gt 0 ]; do'):wrapper.index('# ---------------------------------------------------------------------------\n# Pre-flight')]
    handoff=wrapper[wrapper.index('unset PATCHED_ENROLLMENT_TOKEN') if 'unset PATCHED_ENROLLMENT_TOKEN' in wrapper else wrapper.index('ENDPOINT_INSTALL_ARGS=()'):wrapper.index('# ---------------------------------------------------------------------------\n# Summary')]
    capture=put(work/'child.sh','#!/bin/bash\nprintf \'%s\\n\' "$@" > "'+str(work/'child-args')+'"\nprintf \'%s\' "${PATCHED_ENROLLMENT_TOKEN:-}" > "'+str(work/'child-env')+'"\n')
    for mode in ('env','json'):
        (work/'enrollment.json').write_text(json.dumps({'enrollment_token': TOKEN if mode=='json' else 'stale-json'}))
        text='#!/bin/bash\nset -eu\nSCRIPT_DIR='+__import__('shlex').quote(str(work))+'\nENROLLMENT_TOKEN="${PATCHED_ENROLLMENT_TOKEN:-}"\nNO_START=0\n'+resolve+'\nENDPOINT_INSTALL_SRC='+__import__('shlex').quote(str(capture))+'\ndie() { exit 1; }\n'+handoff
        text=text.replace('/usr/bin/python3',str(tools/'python3'))
        result=run(put(work/'wrapper.sh',text),('--no-start',),dict(env,**({'PATCHED_ENROLLMENT_TOKEN':TOKEN} if mode=='env' else {})))
        assert result.returncode==0, result
        assert (work/'child-args').read_text()=='--enrollment-token-provisioned\n--no-start\n'
        assert not (work/'child-env').read_text()
    # Child's explicit mode must suppress adjacent JSON and reject an unsafe
    # canonical file. Run only its pre-install prefix (no install operations).
    endpoint=source('agents/endpoint/install.sh')
    prefix=endpoint[:endpoint.index('# LaunchDaemon plists')]
    prefix=prefix.replace('/etc/patched',str(creds)).replace('os.path.realpath("/etc")','os.path.realpath('+json.dumps(str(work))+')').replace('os.path.join(parent, "patched")','os.path.join(parent, "creds")').replace('st.st_uid != 0','st.st_uid != os.getuid()')
    prefix+='\nprintf "%s" "$ENROLLMENT_TOKEN" > "'+str(work/'child-selection')+'"\n'
    token_file.write_text(TOKEN+'\n'); token_file.chmod(0o600)
    script=put(work/'endpoint-prefix.sh',prefix)
    result=run(script,('--enrollment-token-provisioned',),env)
    assert result.returncode==0, result
    assert not (work/'child-selection').read_text(), 'stale adjacent JSON selected'
    # Deterministic lifecycle race: the earlier successful enrollment has
    # already established the exact private credential set. Its consumed token
    # disappears before the endpoint child starts. Never replay/recreate it.
    token_file.unlink()
    assert run(script,('--enrollment-token-provisioned',),env).returncode==0, 'consumed-token handoff refused'
    assert not token_file.exists() and not (work/'child-selection').read_text()
    for field,filename in [('tenant_id','tenant-id'),('bearer_token','bearer-token'),
                           ('hmac_secret','hmac-secret'),('device_id','device-id')]:
        credential=creds/filename
        assert credential.read_text()==response[field]+'\n'
        original=credential.read_text()
        credential.unlink()
        assert run(script,('--enrollment-token-provisioned',),env).returncode != 0
        credential.write_text(original); credential.chmod(0o644)
        assert run(script,('--enrollment-token-provisioned',),env).returncode != 0
        credential.chmod(0o600)
        credential.write_text(' \t\n')
        assert run(script,('--enrollment-token-provisioned',),env).returncode != 0
        credential.unlink(); credential.symlink_to(work/'enrollment.json')
        assert run(script,('--enrollment-token-provisioned',),env).returncode != 0
        credential.unlink(); credential.write_text(original); credential.chmod(0o600)
    token_file.write_text(TOKEN+'\n'); token_file.chmod(0o644)
    assert run(script,('--enrollment-token-provisioned',),env).returncode != 0
    token_file.write_text(' \t\n'); token_file.chmod(0o600)
    assert run(script,('--enrollment-token-provisioned',),env).returncode != 0
    token_file.unlink(); token_file.symlink_to(work/'enrollment.json')
    assert run(script,('--enrollment-token-provisioned',),env).returncode != 0
print('PASS: synthetic enrollment, backup, wrapper and canonical handoff checks')
