# verifier/

Supply-chain and operational tooling that runs on Patched infrastructure, never
on client endpoints.

**Retired 2026-09-30 (PAT-2304).** The daily vendor verification agent
(`verify.py`), its unit suite and fixtures were deleted along with the Windows
allowlist chain and the mirror pipelines that imported it. The Windows
allowlist mapped labels to winget installers for the Windows install path,
which is patching, and Patched does not patch (Andy, 2026-09-28). The
allowlist's validator in `validate-labels.yml` was the last live caller of
`verify.py`; with it gone nothing reached the verifier except its own tests.
The last copies are at commit `f852810b`: `git show f852810b:verifier/verify.py`
for the code and `git show f852810b:verifier/README.md` for its full
documentation (run options, catalogue format, shard rotation, classification).
The design record is `docs/verification-agent-design.md`, history only.

## Files

| File | Role | Status |
|---|---|---|
| `sign-artifact-metadata.py` | Signs Windows agent self-update artifact metadata with Ed25519 key `1c6ffd04c60dd94d` (PAT-1248) | Live: `windows-agent-release.yml`, `agent-release-promote.yml` |
| `test_sign_artifact_metadata.py` | Unit tests for the above | Runs in `test-suite.yml` |
| `done_audit.py` | Done-without-evidence detector (PAT-985), below | Live: `done-audit.yml`, daily |
| `test_done_audit.py` | Unit tests for `done_audit.py`, Linear client stubbed, no network | Runs in `test-suite.yml` |
| `linear_client.py` | Minimal stdlib-only Linear GraphQL client | Used by `done_audit.py` |
| `upstream-diff.py`, `upstream-diff/` | Upstream Installomator label-set diff (PAT-53) | Quarantined: manual `upstream-label-diff.yml` only |

**Also retired 2026-09-30 (PAT-2308).** `analyze-behavior.py` and its test went
with the manual `smoke-test.yml` and `behavioral-analysis.yml` workflows, which
installed catalogue apps on hosted runners to gate catalogue promotion. The
files nothing called after PAT-2304 went too: `alerting.py` and its test,
`windows_evidence_attestation.py` and `windows-evidence-public-key.json`, and
the retired verifier's inputs (`catalogue-coverage-baseline.json`,
`catalogue-label-presence-baseline.json`, `resolver-retirements.json`,
`acknowledged-findings.json`, `state/verification-state.json`). The last copies
are at commit `914a290d`. `ci/test_legacy_workflow_quarantine.py` fails if any
of them returns.

## Done-without-evidence audit (PAT-985)

Unrelated to the retired vendor verification, `done_audit.py` targets a
different failure mode: the estate's rule is "Done means operating, not merged" (root
`CLAUDE.md`), but Linear's GitHub integration flips an issue to Done the
moment its linked PR merges — branch names carry the issue identifier (e.g.
`andy/pat-954-slug`), so the automation fires with total reliability. That
setting has proven hard to locate, and it would not help retroactively or
for a manual close either. So this doesn't try to prevent the false Done;
it detects it after the fact, which also catches manual closes and
pre-existing rot a settings change never would.

Once a day (`.github/workflows/done-audit.yml`) it pulls every issue on team
**PAT** completed within a lookback window (default 30 days), flags the ones
that look **runtime-affecting** — something that must actually run somewhere
to have any effect — but carry no comment **evidence** anyone confirmed it
running, and posts the list as a comment on **PAT-985** itself.

**Runtime-affecting:** a `repo:*` label, or title/description mentioning
deploy, monitor, alert, backup, timer, cron, systemd, migration, endpoint,
agent, certificate, credential, env var, or scheduled. Pure documentation /
test-only / explicit no-runtime-effect signals are excluded — unless a
`repo:*` label is also present, which overrides the text-based exclusion.

**Evidence:** each comment (not the whole thread concatenated, so a SHA has
to sit next to deploy language in the *same* comment) is scanned for a 7-40
hex commit SHA alongside deploy language, "deployed" / "verified" /
"confirmed on", a Patched hostname (`example-api-host`, `example-prod-host`,
`example-portal-host`, or a numbered sibling), `systemctl` / `HTTP 200` /
`snapshot` / `exit 0`, or a fenced code block. "merged" or "PR #123" alone
matches none of these.

**Flag = runtime-affecting AND no evidence.** This is a heuristic over
titles/descriptions/comment text, not a proof — an earlier automated sweep
in this estate had roughly 4 of its top 6 findings wrong on the same kind of
text-proxy reasoning. Every flagged issue is reported as **"worth
checking"**, never "broken", with the cheapest concrete check that would
settle it, and the list is sorted with protective work (backups, monitoring,
alerting, security gates, credential handling, DR) first — a false Done
there is far more dangerous than on a UI tweak.

**No git-committed state.** Instead of a state branch, the audit reads its
own previous run back out of PAT-985's comment history: each posted comment
embeds an HTML-comment fingerprint of the sorted flagged-identifier set. A
run whose fingerprint matches the most recent prior one exits quietly and
posts nothing — a daily repeat of yesterday's list is noise, not signal. The
run's `examined` / `runtime_affecting` / `flagged` counts are always logged,
so a legitimate zero-finding run is distinguishable from a broken one.

**Auth.** Reads `LINEAR_API_TOKEN` from the environment, scoped to the
canonical scheduled run only. This tool's entire job *is* Linear, so a
missing token is fatal rather than a graceful no-op:
`done_audit.py`'s own `main()` refuses to run without one, and
`done-audit.yml`'s `Assert Linear API token present` step is the second,
independent guard on the canonical scheduled run.

**Not yet exercised against the live API.** Built and unit-tested against
local fixtures only (`test_done_audit.py`); there is no `LINEAR_API_TOKEN`
available in the environment this was written in, so the actual GraphQL
query shapes in `linear_client.py`'s `get_completed_issues()` /
`get_issue_by_number()` have not been run against a real Linear workspace.
