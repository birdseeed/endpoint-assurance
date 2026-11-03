# Historical upstream Installomator review — Patched fork

> **Retired operating process (PAT-1474/PAT-1481):** This is an historical
> record of the fork review procedure, not a standing maintenance
> obligation. The broad Installomator execution and catalogue-maintenance model
> is quarantined. There is no scheduled or manually-dispatched upstream-review
> workflow, and retaining the hard fork does not authorise periodic upstream
> review or issue creation. Any future security work must be demand-driven by a
> separately approved, bounded PAT-1481 operation and retain its supply-chain
> review.

`engine/` is a **hard fork** of [Installomator](https://github.com/Installomator/Installomator).
No upstream tracking remote exists; never run `git subtree pull` from upstream.

## Import baseline

| Field | Value |
|---|---|
| Import tag | `engine-import` |
| Upstream repo | `https://github.com/Installomator/Installomator` |

## What diverges (Patched-specific, not cherry-pickable from upstream)

| Change | Ticket | Location |
|---|---|---|
| Exit code contract (62=Team ID, 63=notarization, 64=SHA-256 mismatch) | PAT-43, PAT-495 | `Installomator.sh` header + `cleanupAndExit` callers |
| `expectedTeamID` enforcement — strict exact-match, fail-closed | PAT-43 | MARK: PAT-43 block |
| Structured log lines (`PATCHED_VERIFICATION_FAILED`, `PATCHED_POSTURE_WARNING`) | PAT-43 | `printlog` callers |
| Runtime HTTPS preflight before `curl` | PAT-494 | MARK: PAT-494 block |
| `PINNED_SHA256` positional-arg SHA-256 content hash check | PAT-495 | MARK: PAT-495 block |

## What is NOT applicable from upstream (label-only or feature changes)

Upstream commits that only add or modify files under `engine/labels/` are not applicable —
Patched maintains its own label manifest at `engine/labels/` and does not pull from upstream labels.

Upstream feature additions (MDM variables, new install types, UI changes) are reviewed
case-by-case but are not automatically applicable.

## Historical quarterly security review process (retired)

**Former cadence:** first week of January, April, July, and October. The
issue-creating GitHub Actions workflow was deleted when the broad maintenance
model was quarantined.

**Reviewer:** Andy Bridson — rotate to whoever owns the security backlog at review time.

### Step 1 — diff the core install logic

```bash
# Fetch upstream without adding a tracking remote
git fetch https://github.com/Installomator/Installomator.git main:refs/remotes/upstream-installomator/main

# Diff only the core script (ignore label additions)
git diff <import-commit>..refs/remotes/upstream-installomator/main \
    -- Installomator.sh \
    | grep -E "^(\+|-)" \
    | grep -v "^(---|\+\+\+)" \
    | head -200
```

### Step 2 — flag security-relevant commits

Look for commits from upstream that mention `security`, `fix`, `CVE`, `vuln`, or `inject` in
their subject. Inspect each one:

```bash
git log <import-commit>..refs/remotes/upstream-installomator/main \
    --grep="security\|fix\|CVE\|vuln\|inject" --oneline
```

### Step 3 — cherry-pick decision

For each flagged commit, decide:

| Applies to fork? | Action |
|---|---|
| Yes — shared logic, security-relevant | Cherry-pick manually; adapt to Patched exit-code contract; document in commit message with `Upstream-commit: <sha>` trailer |
| No — label-only change | Skip; note in the review issue comment |
| Unclear | Discuss in the review issue before merging |

### Step 4 — close the reminder issue (historical)

The former process posted a summary to its auto-created reminder issue before
closing it. No such issue is created under the current boundary.

## Cherry-pick commit format

```
fix(engine): cherry-pick upstream security fix for <short description>

Upstream-commit: <full sha>
Upstream-pr: <PR URL if applicable>
Applies-to-fork: yes — <reason>
Divergence-preserved: exit code contract / expectedTeamID / structured logging intact
```
