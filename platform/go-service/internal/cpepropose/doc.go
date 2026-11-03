// Package cpepropose proposes CPE mappings for installed products that have
// none (PAT-2138), so new software is CVE-checked without waiting for a person
// to hand-map it, and without letting a guess become a CVE claim.
//
// The path, end to end:
//
//  1. Record (RecordUnmapped, from the extractor's ingest transaction, and
//     Backfill, over existing inventory). A product whose name no mapping
//     covers on its platform gets one cpe_mapping_proposals row per
//     normalised (platform, name). Database only: ingest never waits on the
//     network, and never on another ingest's proposal row. Admission is
//     capped per payload, per tenant per day and by the open queue.
//  2. Privacy gate (Evidence.Eligible). A product leaves the platform only
//     when MinOutboundTenants (two) tenants report it; otherwise it goes
//     straight to staff as single_tenant. An aliased signer is corroboration
//     only. Browser web-app wrappers are never recorded (IsWebAppWrapper).
//     For an eligible product only ProductEvidence leaves: the normalised
//     name and aliased signer values.
//  3. Candidates (Dictionary). The worker searches NVD's CPE dictionary
//     (/rest/json/cpes/2.0 keywordSearch) for application CPEs, cached in
//     cpe_dictionary_cache, paced by a database-wide budget (NVDBudget, a
//     tenth of NVD's limit) and retried like the CVE feed sync. Candidates
//     are the only CPEs that can ever be chosen.
//  4. Choice (AnthropicChooser, OpenAICompatibleChooser). CPE_MODEL_PROVIDER
//     selects which: anthropic (ANTHROPIC_API_KEY, back-compat default when
//     it alone is set), or nvidia/openai, both served by
//     OpenAICompatibleChooser against their shared chat-completions API
//     shape (CPE_MODEL_API_KEY, CPE_MODEL, optional CPE_MODEL_BASE_URL).
//     Either way a model picks one candidate by its list id, or none, with a
//     confidence and a short rationale, from the identical prompt
//     (buildUserContent): the evidence is still endpoint-derived and
//     untrusted, so it is passed as JSON-escaped data inside a delimited
//     block the model is told to treat as data only, and the reply is
//     validated again here: an id that is not in the supplied list is
//     rejected (ErrInvalidModelResponse), never mapped, by the same
//     validation (decodeAndValidateAnswer) regardless of provider. A model
//     id recorded on the proposal is prefixed with its provider
//     ("nvidia:meta/llama-...").
//  5. Gate (Decide). Auto-publish needs ALL of: high model confidence, a
//     non-deprecated candidate, the candidate's CPE product naming the
//     product by word tokens (ProductMatches, which decides the product
//     outside the model), no richer same-vendor candidate that also names
//     it, at least one CVE filed under it locally, every current installation's public-distribution
//     signer resolving through cpe_vendor_aliases to the chosen CPE vendor
//     (Corroborate, which pins the vendor), no other installed name with the
//     same tokens, and auto-publish enabled. The model's output alone never
//     publishes. Anything else is needs_review with a reason.
//  6. Publish. An auto-published mapping is an app_cpe_mappings row with
//     review_state 'auto', which covers only names with exactly its word
//     tokens (cvematch.MappingCovers). The extractor's mapping-snapshot diff
//     (cvepipeline.SyncMappingSnapshot) re-matches every device carrying the
//     product within one drain cycle, and its findings are stored with
//     mapping_basis 'auto'. Revoking it (Reject on a published proposal)
//     deletes the row; the same diff re-matches, the findings disappear while
//     the software is unchanged, and the lifecycle reducer records them as
//     withdrawn (PAT-2107), never verified_fixed, with no notification.
//  7. Maintenance (maintain, also when proposing is disabled). Automatic
//     mappings are re-checked tenant by tenant every few hours (absent
//     evidence neutral, truncated evidence never acted on) and demoted when
//     two tenants contradict them or contradicting tenants are at least as
//     many as corroborating ones; a demoted proposal is re-offered once its
//     signer evidence changes; a proposal whose mapping another path deleted
//     (auto_published, approved, superseded) returns to staff; open
//     proposals unseen for 30 days expire, and reopen when reported again.
//  8. Review. Admin API (List, Get, Approve, Reject; every action audited),
//     a daily Linear digest (RunDigest: one run at a time under an advisory
//     lock, only ever adopts an issue its own token created, and never names
//     a proposal fewer than two tenants report) and the portal's not_assessed reason
//     mapping_under_review.
package cpepropose
