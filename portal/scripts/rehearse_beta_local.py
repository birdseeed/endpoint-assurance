"""Run synthetic checks on a new private PostgreSQL cluster; never use an input DSN."""
import argparse
import datetime
import json
import os
import pwd
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--platform', type=Path, required=True, help='Platform go-service checkout')
args = parser.parse_args()
repo = args.platform.resolve()
# Resolve source identity before allocating any cluster or starting PostgreSQL.
platform_commit = subprocess.check_output(
    ['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
root = Path(tempfile.mkdtemp(prefix='pat2371-pg-'))
out = Path(__file__).resolve().parents[1] / 'docs/evidence/pat2371-platform-local.json'
env = os.environ.copy()
for key in tuple(env):
    if key.startswith('PG') or key in ('DATABASE_URL', 'TEST_DATABASE_URL'):
        env.pop(key, None)
env['DEVELOPER_DIR'] = '/Library/Developer/CommandLineTools'
env['TEST_DATABASE_URL'] = (
    f'postgresql://{pwd.getpwuid(os.getuid()).pw_name}@/postgres'
    f'?host={root}&port=55471&sslmode=disable'
)
pg = Path('/opt/homebrew/opt/postgresql@17/bin')
rows = []


def run(name, argv, cwd=None):
    start = time.monotonic()
    log = root / (name + '.log')
    with log.open('w') as stream:
        try:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
            exit_code = result.returncode
        except OSError as exc:
            stream.write(str(exc))
            exit_code = 1
    data = log.read_text()
    row = dict(name=name, exit=exit_code, seconds=round(time.monotonic()-start, 2),
               log=str(log), passes=data.count('--- PASS:'), skips=data.count('--- SKIP:'))
    if row['exit'] or row['skips']:
        row['diagnostic_tail'] = data[-8192:]
    rows.append(row)
    print(name, row['exit'], row['seconds'], flush=True)
    return row


def require(name, argv, cwd=None):
    row = run(name, argv, cwd)
    if row['exit'] or row['skips']:
        raise RuntimeError(f'{name} failed/skipped; inspect {row["log"]}')


def check(name, package, pattern, tags=False):
    argv = ['go', 'test', package, '-count=1', '-v', '-run', pattern]
    if tags:
        argv += ['-tags=integration']
    require(name, argv, repo)
    if not rows[-1]["passes"]:
        rows[-1]["exit"] = 4
        raise RuntimeError(f"{name} selected no tests; inspect {rows[-1]['log']}")


failure = None
cleanup = 'pending'
started = datetime.datetime.now(datetime.UTC).isoformat()
try:
    require('initdb', [str(pg/'initdb'), '-D', str(root/'data'),
                       '--auth-local=trust', '--auth-host=reject'])
    require('start', [str(pg/'pg_ctl'), '-D', str(root/'data'), '-l', str(root/'server.log'),
                      '-o', f"-k {root} -p 55471 -h ''", '-w', 'start'])
    require('role', ['/opt/homebrew/bin/psql', env['TEST_DATABASE_URL'],
                     '-v', 'ON_ERROR_STOP=1', '-c', 'CREATE ROLE patched NOLOGIN;'])
    check('integration', './integration',
          'TestPortal(AuthFailureModes|CrossTenantIsolationMatrix|EmailDomainAutoBinding|'
          'ControlCoverageExplicitZeroState|ReportCatalogueAndTypedGeneration|DeviceRetirement)$',
          tags=True)
    check('feedback-local', './internal/feedback',
          'Test(DeliverFeedback|LinearDiscoveryAndCreateContract)')
    check('keys', './internal/handlers', 'Test(EnrolmentKey|PortalEnrolmentGenerateHandler_)')
except Exception as exc:
    failure = str(exc)[:2048]
finally:
    # Failed starts may still leave a postmaster, so inspect our own data dir.
    stopped = True
    if (root / 'data/postmaster.pid').exists():
        stopped = run('stop', [str(pg/'pg_ctl'), '-D', str(root/'data'),
                               '-m', 'fast', '-w', 'stop'])['exit'] == 0
    if stopped and not (root / 'data/postmaster.pid').exists():
        try:
            shutil.rmtree(root)
            cleanup = 'removed'
        except OSError as exc:
            cleanup = 'failed'
            failure = failure or str(exc)[:2048]
    else:
        cleanup = 'retained: stop failed or postmaster still present'
    receipt = dict(scope='Synthetic; private Unix socket; TCP disabled; no customer data',
                   platform_commit=platform_commit,
                   started_at=started, finished_at=datetime.datetime.now(datetime.UTC).isoformat(),
                   cluster=str(root), cleanup=cleanup, failure=failure, checks=rows)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2)+'\n')

raise SystemExit(1 if failure or cleanup != 'removed' or
                 any(row['exit'] or row['skips'] for row in rows) else 0)
