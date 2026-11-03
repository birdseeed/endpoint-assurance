# Portfolio authentication fixes, 1 November 2026

These changes harden the portfolio copy after the initial source import. They do not update the retired repositories, install agents, restart development or deploy a service. The original snapshot remains available in commit `501ada339f474c551f320adfe120ea6dd47ccd41`.

## Agent request replay

The shared request verifier previously accepted legacy signatures over body bytes alone. A captured body, signature and still-valid bearer could be replayed with a current timestamp and new nonce. The fix removes that acceptance branch and its enablement flag. Regressions exercise both verifier APIs with original headers, a changed timestamp, a changed nonce and both changed. The trigger failed before the patch and passes afterwards. Valid v3 requests still pass, while changed method, operation, body and replay headers fail. The separately controlled timestamp/nonce-bound v2 form remains supported; its lack of operation binding is a separate historical compatibility limit.

Four handler fixture signers now generate genuine v3 requests. The standalone body-only primitive and historical telemetry names are retained for documentary/test compatibility, but the primitive has no production callers. Legacy body-only clients are intentionally rejected. This change is not permission to reconnect historical agents.

Local checks used Go 1.27.1, the original module checksums and a disposable PostgreSQL 16 fixture. The auth package passed with all database cases enabled. The handlers package passed its substantive cases; three database safety preflights required a loopback fixture address and passed when rerun with that address. The temporary database was stopped afterwards. Missing module cache, initial database schema and Unix-socket-only safety checks were prerequisite failures, preserved separately from implementation results.

Independent review also found an older retention gap: a signed request from a clock-ahead client could stay timestamp-valid after its nonce record was pruned. Nonces now remain for at least twice the configured skew, rounded upward; nonpositive windows fail before database work. Database regressions reproduced this replay for v3 and v2 before the change, then rejected it afterwards. They also cover normal duplicates, per-tenant independence and expiry beyond the full window. All production routes share the configured window, as required by the global nonce-pruning table.

## Dashboard identity and existing sessions

A dashboard-specific verifier now checks the RSA-signed Access token, configured team issuer and dashboard audience, required lifetime and identity claims, bounded token/key responses and key-cache lifetime. Raw identity-email headers are never promoted to authenticated users. Tests use generated RSA fixture keys and a stubbed local key set, without contacting Cloudflare.

The console aliases, actor helpers and impersonation navigation use verified identity or an authenticated session. A versioned session MAC rejects cookies minted by the previous implementation, including cookies obtained through the forged-header path. Valid new sessions and explicit Bearer administration remain supported. Certificate and report-record downloads remain session-only; the deliberately public single-use report-token route is unchanged. Explicit development mode remains an operator setting, not request input.

Production identity now requires `DASHBOARD_ACCESS_TEAM_DOMAIN` and `DASHBOARD_ACCESS_AUD`. Missing configuration, incorrect signatures, wrong issuer/audience, expired or malformed claims, ambiguous assertions and legacy cookies fail closed. No live configuration or credentials were supplied or changed.

Regression tests reproduced forged-header session creation and old-cookie acceptance before the fix. Focused checks now reject those triggers and exercise legitimate signed identities, new cookies and Bearer paths. The wider dashboard test suite is also checked locally. Seven mechanical test-path substitutions point historical contract checks at the snapshot's already renamed instruction/workflow files; their old-path failures were reproduced in the initial commit. No active workflow was restored.

## Provenance and limits

`PORTFOLIO-PROVENANCE.json` still pins the original inputs. These fixes are later portfolio work, distinct from historical implementation and validation claims.

The original security scan remains historical and partial. These targeted tests and independent patch review do not certify the whole codebase, current dependencies or any former deployment. Public redistribution still needs privacy/licensing review. The repositories remain private, with Actions disabled and no product deployment path activated.

## Final local verification

- `go test hmac.go hmac_test.go`: passed in the authentication directory, including both replay regressions and legitimate signature controls.
- `go test ./internal/auth`: 44 test/subtest events passed with the disposable database, zero skips.
- `go test ./internal/handlers`: the final full run passed 1,715 test/subtest events with zero failures or skips, using the loopback disposable database. Earlier fixture-only failures and their recovery are retained separately.
- `python3 -m pytest -q -rs tests`, from `dashboard`: **3,124 passed, 3 skipped**, 112 warnings. The skips require two absent sibling-repository script paths and one historical commit not imported into this clean repository. They do not cover the changed authentication paths.
- Independent parent run of `tests/test_dashboard_access.py`: 64 passed. Syntax and whitespace checks passed.

Go commands used a temporary verified module cache; database-backed commands set `TEST_DATABASE_URL` to the disposable fixture. Dashboard checks used temporary SQLite storage and the existing outbound-network guard. No hosted runner, live provider identity or product service was used.
