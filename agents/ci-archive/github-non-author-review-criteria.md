# GitHub-Non-Author-Review criteria

The reviewer is a separate, clean-context pass — adversarially re-derive findings, don't rubber-stamp. Review **only** the files listed in the PR diff — do not open, read, or report on any file that is not modified by this PR. If you are uncertain whether a file is in the diff, skip it. Mark **failure** if any blocking issue exists in a **diffed file**; otherwise **success**. Surface nits separately.

## Endpoint trust (this code can reach customer machines)

- **Signature / TeamID verification.** Any vendor-package or binary install path verifies the notarisation / `expectedTeamID` (or Authenticode equivalent) before execution, with a pinned, non-overridable value. No unverified download is executed.
- **Fail closed.** On verification failure, network failure, or missing config the agent must refuse the action, not proceed. Flag any fail-open path.
- **No MDM / remote-control dependence.** Functionality must not depend on MDM/DDM or any forced remote execution. OS-update handling is Nudge-style, not forced.
- **Close-to-update (blocking-process) policy.** A tenant may configure, via the signed agent-config, an `action_on_timeout` for an app that blocks an update. `notify_only` and `skip_run` never quit or kill. `prompt_then_quit` MAY quit the blocking app, but only after **both** (a) the user has exhausted the configured deferrals **and** (b) a final, explicit user confirmation (an affirmative "Quit and Update" choice; declining or timing out must abort without quitting) — i.e. the quit is always **user-actioned**, never a silent or forced kill. Absent, malformed, or unknown policy must default to a non-quitting action. A quit path that skips the final confirmation, or any `kill`/force-terminate without that user consent, remains a blocking issue. (This bounded, user-confirmed quit is a sanctioned exception to the "no forced local action" boundary — approved 2026-07-12.)
- **Privilege & filesystem boundaries.** Runs at least privilege; no needless root; no world-writable paths; no shell injection from filenames/paths/remote content; no `eval` of fetched data.
- **Supply chain.** Any new or changed download source is **either** (a) a first-party, vendor-owned HTTPS URL, **or** (b) the **verified Patched mirror** — an `https://mirror.patched.im/…` URL that carries a pinned `pinned_sha256` and was produced by the mirror pipeline (vendor download → ClamAV scan → notarisation/Authenticode + publisher verification → independent cross-hash → SHA-256-pinned re-host). The verified mirror is a supply-chain *hardening* control (pinned, scanned, publisher-verified), not a risk. Arbitrary third-party mirrors or caches remain **forbidden**, and a `mirror.patched.im` source presented **without** a pinned `pinned_sha256` is a blocking issue. Flag every new/changed source with its domain. Dropped sources must be removed cleanly (no dangling refs).

## Platform / API

- **Auth + HMAC.** New or changed endpoints reuse the established bearer + HMAC + timestamp + nonce middleware. Tenant/device identity resolves from credentials, never from the request body. Wrong/unknown/revoked creds → 401.
- **Cross-tenant isolation.** Every read and write is tenant-scoped; no query path can return or store another tenant's data. Admin/internal read-APIs are bound to the internal listener, not the public port.
- **Secret handling.** No secrets, keys, tokens, or credentials committed. Signing/private keys come from the secret store/env, never the repo or the payload body. CI uses throwaway creds only.
- **Payload schema / contract.** Changes conform to the payload schema; the schema/contract on the agent↔platform seam is not changed without it being an explicit, approved decision. No second, hand-rolled copy of a contract that can drift from the canonical schema.
- **SQL safety & migrations.** Parameterised queries only. Migrations apply cleanly from zero and are transactional.
- **Abuse resistance.** Size caps enforced before buffering; no decompression amplification; concurrency-safe enforcement of any per-tenant ceiling (no TOCTOU read-then-write). PII has an enforced retention path that actually runs.

## Cross-platform

- Contracts stay platform-neutral (macOS + Windows feed the same shape). Flag macOS-only or Windows-only assumptions baked into shared contracts.

## Ticket fit

- The change meets the acceptance criteria of its Linear ticket and stays within the ticket's declared scope (no smuggled-in behaviour/contract changes the ticket forbids).
