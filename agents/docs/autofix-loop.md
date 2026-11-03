# PAT-492: Gate auto-fix loop

One-page description of the automated fix loop that fires when the
GitHub-Non-Author-Review gate sets `patched/non-author-review` to failure.

## Trigger

GitHub emits a `status` event whenever any commit status is updated. The
`autofix` workflow ignores all events except those where:

- `state == 'failure'`
- `context == 'patched/non-author-review'`

That context name is set by the `patched-reviewer` App in
`.github/workflows/github-non-author-review-scan.yml` — it is un-fakeable
because the App private key (never in the repository) signs the status.

## What Claude sees

Claude receives a single, structured prompt assembled at runtime:

1. **Static prefix** — who it is, what criteria the gate uses
   (pointer to `.github/github-non-author-review-criteria.md`), and the section header
   `## Review findings`.
2. **Review text** — the body of the most recent `patched-reviewer[bot]`
   comment on the PR (truncated to 8 000 chars). This is the structured
   findings text the gate wrote after its diff-aware review.
3. **Static suffix** — instructions: fix only what is listed, root-cause
   fixes only, no refactoring, no committing, no pushing, no touching
   `.github/`.

The review text is appended with `printf` (not interpolated in a heredoc),
so shell metacharacters in the comment body cannot break the prompt or
inject shell commands.

## Steps

```
status event (failure, patched/non-author-review)
  │
  ├─► [loop guard 1] Is "[autofix]" in the HEAD commit message?
  │     Yes → exit 0  (gate reviewed a fixup and still failed; human needed)
  │
  ├─► Find open PR whose head.sha matches the failing SHA.
  │   Fork check: PR head repo must equal the base repo (no fork PRs).
  │   No PR found → exit 0
  │
  ├─► [loop guard 2] Count patched-reviewer[bot] comments on the PR.
  │     ≥ 2 comments → exit 0  (gate ran twice; human needed)
  │
  ├─► Checkout PR branch (fetch-depth: 0, persist-credentials: true)
  │
  ├─► npm install -g @anthropic-ai/claude-code@latest
  │
  ├─► Run: claude --dangerously-skip-permissions "<prompt>"
  │   ANTHROPIC_API_KEY available only in this step's env.
  │
  └─► Stage all changes (git add -A).
        Nothing staged → exit 0 (gate may have already passed)
        Changes staged → git commit -m "fix: ... [autofix]" && git push
                          └─► re-triggers CI and the gate automatically
```

## Anti-loop guards

Two independent guards prevent runaway API credit burn:

| Guard | Condition | Action |
|---|---|---|
| Commit message | HEAD commit contains `[autofix]` | Exit 0 — the gate reviewed the fixup and still failed; leave for human |
| Comment count | `patched-reviewer[bot]` has posted ≥ 2 comments on this PR | Exit 0 — the gate ran at least twice; leave for human |

If both guards pass but Claude makes no changes, nothing is pushed and
the gate is not re-triggered.

## Human escalation

Human resolution is needed when:

- The autofix commit triggered CI but the gate still found issues
  (identified by the `[autofix]` marker — the second gate run is the last
  automated attempt).
- The gate ran twice before the autofix even fired, meaning someone manually
  pushed a fixup that still failed (comment count guard).
- Claude made no changes and the gate still fails (nothing was committed;
  the gate is not re-triggered — it sits failed until a human pushes).

## Security constraints

- **No fork PRs.** The `find_pr` step verifies that `pr.head.repo.full_name`
  equals the base repository's full name before proceeding. The `status`
  event fires repo-wide; this check is the fork gate.
- **API key scoped to one step.** `ANTHROPIC_API_KEY` is set only in the
  `Run Claude autofix` step's `env:` block, not exported at the job level.
- **Claude cannot modify `.github/`.** The prompt explicitly prohibits it,
  and Claude Code runs with `--dangerously-skip-permissions` (needed to
  write files) in a checked-out working tree where the only writable surface
  is the repo content — it cannot write outside the working directory.
- **Prompt injection hardening.** The review text is not interpolated inside
  a heredoc or double-quoted string; it is appended with `printf '%s\n'`
  to a temp file that is then passed as the prompt argument. Shell
  metacharacters in the comment body are inert.
- **npm install rationale.** `@anthropic-ai/claude-code` is distributed via
  npm only; there is no SHA-pinnable binary or container alternative.
  `npm install -g @anthropic-ai/claude-code@latest` is the canonical install
  path documented by Anthropic. This is noted in a workflow comment.

## Required secrets

| Secret | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Authenticates Claude Code to the Anthropic API during the autofix run |

No other secrets are needed — the workflow uses `github.token` (the
built-in GITHUB_TOKEN) for all GitHub API operations.
