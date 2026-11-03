# patched-mirror-bot GitHub App — setup (PAT-749)

The nightly mirror pipeline opens its pin PRs (`chore(mirror): pin <label> …`)
and auto-merges them. Those PRs **must** be authored by a non-`GITHUB_TOKEN`
identity: GitHub does not trigger `pull_request` workflows for events created by
the default `GITHUB_TOKEN`, so the GitHub-Non-Author-Review scan/gate would never run and, under an
active ruleset, auto-merge would hang forever on a check that never posts.

We use a **dedicated** GitHub App — deliberately *not* `patched-reviewer` (that
identity is the *reviewer*; author == reviewer would collapse the non-author
invariant).

Until the secrets below are set, the workflow falls back to `github.token`, which
keeps working while GitHub-Non-Author-Review is in **evaluate** mode. Set them before restoring the
`updater` ruleset to **active**.

## 1. Create the App (org: Patched-LTD)

GitHub → Organizations → **Patched-LTD** → Settings → Developer settings →
**GitHub Apps** → **New GitHub App**.

- **Name:** `patched-mirror-bot`
- **Homepage URL:** `https://patched.im` (anything valid)
- **Webhook:** **uncheck Active** (no webhook needed)
- **Repository permissions:**
  - **Contents:** Read and write
  - **Pull requests:** Read and write
  - (everything else: No access)
- **Where can this App be installed:** Only on this account.

Create the App, then note the **App ID**.

## 2. Install it on the updater repo

App → **Install App** → install on **Patched-LTD**, scoped to **only
`Patched-LTD/updater`**. (The workflow auto-derives the installation for this
repo, so no installation ID is needed as a secret.)

## 3. Generate a private key

App → **Private keys** → **Generate a private key**. A `.pem` downloads. Store
the whole PEM including the `-----BEGIN/END … PRIVATE KEY-----` lines.

## 4. Add the two secrets to Patched-LTD/updater

Repo → Settings → Secrets and variables → Actions → **New repository secret**
(or via `gh`):

```bash
gh secret set MIRROR_BOT_APP_ID  --repo Patched-LTD/updater --body '<app id>'
gh secret set MIRROR_BOT_KEY_PEM --repo Patched-LTD/updater < path/to/mirror-bot.private-key.pem
```

The workflow's **Mint mirror-bot token** step
(`actions/create-github-app-token`, pinned) turns these into a short-lived
(~1 h) installation token and authors the pin PR with it. The step is skipped
until `MIRROR_BOT_APP_ID` is set, so the pipeline safely falls back to
`github.token` in the meantime.

## 5. Verify

Run the workflow manually (`workflow_dispatch`, `dry_run=false`, an eligible
`only_label`) and confirm:

- the pin PR's author is **patched-mirror-bot[bot]** (not github-actions[bot]);
- the `GitHub-Non-Author-Review (scan)` workflow **runs** on that PR.

## Still to do before launch (PAT-750)

Even with this App, a pin PR touches `engine/labels/` — a **sensitive path** in
`github-non-author-review-gate.yml`. Once `PRODUCTION_LAUNCHED=true` the gate demands a non-author
*human* review for sensitive paths, which would re-block the nightly. PAT-750
adds a narrow, corroborated carve-out for bot-authored pin-only PRs. It must land
before the ruleset is restored to active with `PRODUCTION_LAUNCHED=true`.
