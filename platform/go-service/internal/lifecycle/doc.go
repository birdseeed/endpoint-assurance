// Package lifecycle owns PAT-2147's software lifecycle (end of support) data
// and the SAM unsupported software report built on it (PAT-2146: pre-staged
// software asset management reports).
//
// Three concerns, kept apart:
//
//   - Source data. fetch.go refreshes endoflife.date product cycles into
//     lifecycle_products / lifecycle_cycles, for the slugs referenced by a
//     proposed or published mapping only. A request carries only the public
//     product slug, never tenant data. A failed fetch keeps the previous
//     data; data older than CacheTTL is stale and reads Unknown.
//   - Reviewed mappings. store.go holds lifecycle_mappings: one canonical
//     product identity (platform, identity kind, normalised identifier and
//     companion, the key software_installations already carries, or 'os' for
//     the operating system) linked to an endoflife.date slug and a
//     version-to-cycle rule. Proposed mappings never affect customer output;
//     only published ones do (the PAT-2046 / PAT-2138 staff review pattern).
//   - Evaluation. match.go is pure: version to cycle, cycle to state. State
//     is Supported, Ending within 90 days, Unsupported, or Unknown. Unknown
//     means Patched could not determine support (no published mapping, no
//     lifecycle data, stale data, a version that matches no cycle, an
//     unreported Windows edition whose cycles' dates differ). It is never
//     read as Supported. report.go applies it to one tenant's current
//     inventory and states the basis of the answer.
//
// A mapping may opt into the rolling-release rule (PAT-2171,
// lifecycle_mappings.rolling_window_days) for products such as browsers, whose
// source dates every major as ending when the next one ships: release order
// decides instead of the end of support date (RollingCycleState).
//
// Nothing here changes a device or tells an agent to act.
package lifecycle
