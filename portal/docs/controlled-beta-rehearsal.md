# Controlled beta rehearsal: PAT-2371

Local audit on 2 October 2026. **External acceptance remains gated; this is not Done.**
Requested leaf tier: `gpt-6.1-sol`, medium, fresh context; CLI header confirms model `gpt-6.1-sol` and reasoning effort `medium`.
Portal source: `757c1f1735591c00e6b85c5573e37094ee3096c3` plus the checks in this change.
Platform parent replay source: `132360cc0e18159f40f078c0e83615331a1a3021` (isolated PAT-2369 checkout, no product implementation changes).
No product implementation, production/customer data, shared database, credentials, real messages,
invitations, payments, tenant creation on production or endpoint installation was used.

## Repeat the local audit

From this portal checkout, use its test environment or the sibling portal environment:

```sh
../portal/.venv/bin/python -m pytest -o addopts='' -q tests/test_pat2371_beta_rehearsal.py
python3 scripts/rehearse_beta_local.py --platform ../patched.im/go-service
../portal/.venv/bin/python -m pytest -o addopts='' -q
../portal/.venv/bin/ruff check scripts/rehearse_beta_local.py tests/test_pat2371_beta_rehearsal.py
```

Prerequisites: installed portal test dependencies, Go matching platform `go.mod`, Homebrew
PostgreSQL 17 server binaries and `/opt/homebrew/bin/psql`. The generic `initdb` here belongs to
libpq 18.6 and has no server binary. The script uses PostgreSQL 17 explicitly, creates a private
0700 temporary cluster and Unix socket, disables TCP, and supplies its own DSN instead of using
an inherited database URL. It creates only the scratch `patched NOLOGIN` role; integration
TestMain applies migrations and uses local HTTP servers and a synthetic signing key/IdP.
It resolves the platform commit before creating the cluster, stops PostgreSQL in `finally`,
and removes its owned temporary cluster/logs after confirmed stop on success or test failure.
The receipt retains exit/time/pass/skip counts, cleanup status and up to 8 KiB of diagnostics
per failed or skipped command. Failed stop returns nonzero and retains the cluster for safe
operator recovery; never remove a cluster that may still be running.
Do not point these tests at a shared database. A missing DSN can otherwise yield a false green skip.

## Measured receipts and limits

[Platform receipt](evidence/pat2371-platform-local.json) records the exact UTC window and source.
The leaf replay ran 20:49:05.211570 to 20:49:10.517627 UTC: 5.31 seconds elapsed. Parent independently repeated the platform checks; the linked receipt records the later UTC window and exact source commit.
Integration: exit 0, 43 PASS markers (including subtests), no skips; key/enrolment: exit 0,
25 PASS markers, no skips; local feedback delivery/Linear mock: exit 0, 11 PASS markers, no skips.
Initial setup attempts failed because generic initdb lacked postgres, the login-name lookup
returned root instead of effective user and the scratch schema required role patched. These
were local harness issues, corrected before the successful receipts; no successful proof is
inferred from them. All clusters that started were stopped with exit 0.

Portal sequence: exit 0, 6 passed in 0.95 seconds. Full portal/scan suite: exit 0,
2208 passed in 32.80 seconds, two deprecation warnings. Logs: `/tmp/pat2371-sequence.log` and
`/tmp/pat2371-full.log`. These timings measure automated local checks, **not customer onboarding**.
No measured human first-login/install/support/offboard duration exists in this audit.

| Step | Actual local evidence | Limit |
| --- | --- | --- |
| Account mapping/login | Platform signed fake-IdP JWT tests: explicit mapping, domain fallback/override, isolation, auth failures | No Cloudflare/Entra/Google/OTP session |
| Empty portal | New sequence supplies zero roster, zero findings and valid empty new-software response; root/routes/CSV render | Ancillary upstream cards retain shared fixtures; not a wholly empty platform integration |
| Partial/error states | Missing/malformed new-software read never claims verified empty; upstream 401/403/503 stop writes | Not every partial collector or outage shape |
| Enrolment | Create/list/revoke, one-time no-store plaintext; DB tests cap, expiry, tenant binding, concurrency, mint/redeem | Synthetic enrolment only, no MSI/pkg installation |
| Report | Typed generation/history persisted on scratch PG; own PDF prefix/download and foreign-tenant 404 in isolation matrix | Portal sequence download uses pre-existing PDF stub, not its queued job; no human usefulness review |
| Feedback/support | Guarded fixture submission returns FB-0001; worker and Linear discovery/create use local mocks | No external Linear issue or mailbox delivery |
| Disable/offboard | Mapping disable/isolation tests, key revoked, retirement write persisted, decommissioned tenant enrolment refused | Retirement does not uninstall/revoke existing device credentials; no endpoint offboard |

Known security gate: PAT-2367 independently reproduced an explicit disabled-user mapping falling through to a claimed domain, including another synthetic tenant. PAT-2379 prepares the fix; no deployed denial receipt is claimed here. Treat next-request access denial as unproven until that fix is deployed and rechecked. PAT-2380 tenant-purge redaction is separately blocked Security waiting at Andy request.

## Operator checklist for the externally authorised staging rehearsal

Every step below is a pending gate, requiring explicit owner authority for the named staging
resources. Stop on a failed gate, preserve its receipt and leave acceptance incomplete.
Record UTC start/end and elapsed seconds for each step plus total wall time, including waiting.

1. [ ] Owner names an isolated disposable staging tenant, approved test email, Windows machine
   and Mac, retention period, rollback owner and deletion approval. Record deployed SHAs.
   Use platform admin `/admin/portal-users` for an exact email mapping and explicit admin role;
   check `/v1/portal/me` role and tenant display. Contract: platform `contracts/portal-api.md`,
   “Admin CRUD”. Do not infer tenant from portal inputs or silently grant domain-wide access.
2. [ ] Log in through actual Cloudflare Access with that account. Capture issuer/audience
   validation outcome without JWT/secret contents, correct estate and admin/viewer controls.
   Verify unrelated authorised test account cannot read this estate. Capture fresh zero-device,
   no-findings and unavailable/partial evidence pages without treating unknown as healthy.
3. [ ] In Install create a short-lived, two-device estate key. Securely hand it to the approved
   installer channel, capture hint/id/cap/expiry only, confirm plaintext disappears on later GET.
   Test viewer and Origin/CSRF refusals. Revoke and confirm a fresh enrolment is refused.
4. [ ] Obtain the exact published MSI/pkg and hash; independently verify Authenticode trust on
   Windows and Apple Developer ID plus notarisation/Gatekeeper on Mac. Record version, publisher,
   trust result, installer exit and rollback. PAT-2252 download surface must be verified first:
   this portal checkout offers MDM commands and says installer is provided during onboarding;
   no signed self-service download or current signing readiness is proven here.
5. [ ] Install on both approved clean staging endpoints and capture service/jobs, installed-file
   hashes, first collection and server receipt timestamps, version and device binding. Compare
   local and server telemetry, collection gaps and coverage. No fabricated “fresh Windows” proof.
6. [ ] Generate a report after telemetry. Download the same report id, open it and confirm estate,
   period, device count, timestamp, real finding/unknown distinctions and a useful next action
   routed to the customer's existing management tool. Keep a redacted report/hash receipt.
7. [ ] Resolve support destination before contact: this checkout uses `hello@patched.im` and
   “not a ticket queue”; PAT-2222 requests `support@patched.im` into Linear support intake.
   Owner must verify the intended mailbox/alias, intake rule, monitoring and reply ownership.
   With separately authorised test mail, prove received email -> correct support issue -> human
   reply. PAT-2347 separation and PAT-2348 written-reply visibility remain unproven here:
   `/requests` shows status/last update, with no written-reply rendering in this checkout.
   Submit separately authorised test feedback and verify customer-scoped status and written reply.
8. [ ] Revoke all beta enrolment keys; disable explicit account mappings and any domain fallback
   that would still grant access; invalidate Access session and test a fresh JWT remains denied.
   Separately approve platform decommission and uninstall/credential revocation for the named
   staging endpoints. Verify no new ingestion/config access, jobs stopped and secret-bearing
   files removed. Retire device records for evidence history; apply approved retention policy.
   Do not delete evidence or assert retirement alone is offboarding. Record rollback and cleanup.

## Historical installed evidence, bounded reuse

Existing owner-approved evidence directory (outside this repo):
`../.claude/linear-runs/evidence/macos-beta2-local-install-20261002/`.
`accepted-installed-canary.md`: Mac 0.19.24.2 reused existing enrolment; 23 installed files matched
published bundle; collection began 19:21:23 UTC, upload HTTP 200 (141611 bytes), server last seen
19:24:33 UTC on 2 October. Browser partial/FDA missing and extension warning remain; no new
permissions, Apple signing/notarisation or new-tenant onboarding acceptance was claimed.
`windows-final-readback.json`, observed 19:31:22.208527 UTC: HOMESERVER 0.15.1.4 last seen
15:40:38.608695 UTC; WINDOWS11 0.0.0-dev last seen 19:26:54.989841 UTC, usage not reported.
These are earlier read-backs, **not a new Windows beta install** or a controlled two-OS rollout.

Recommendation: keep beta acceptance open until the eight owner-authorised staging receipts
exist. Signing/download, Windows installation, actual IdP login, mailbox routing/reply and safe
endpoint disable are the exact remaining proof. This avoids inviting a beta customer into a
workflow whose acquisition/support/offboard chain has only synthetic coverage. Public signup,
automated billing, partner rollup and closing the Cyber Essentials update obligation are outside
this rehearsal. Parent owns independent review, commits, Linear judgement and acceptance.
