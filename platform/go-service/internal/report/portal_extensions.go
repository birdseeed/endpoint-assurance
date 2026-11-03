package report

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// GitHub-Non-Author-Review abuse-resistance caps (PAT-933 gate finding): one authenticated
// portal GET must never force an unbounded DB aggregate, memory allocation,
// or response body.
//
// Five-part argument for why this endpoint is bounded (parts (a)-(d)) and
// operationally honest about it (part (e)):
//
//	(a) All array/JSON aggregation happens strictly AFTER the row cap. The
//	    query first selects the winning <=500 extension identities with a
//	    streaming GROUP BY computing only scalar aggregates (MAX(name),
//	    BOOL_OR(risk), COUNT(DISTINCT ...)) — no ARRAY_AGG, no jsonb_agg,
//	    no window functions — then LATERAL subqueries build the version
//	    list (<=20) and device drill-down (<=50) for those survivors only.
//	    Worst-case materialized output is 500 x (50 devices + 20
//	    versions), a constant. The exact total is a separate streaming
//	    scalar count of the identity groups, not a COUNT(*) OVER() that
//	    would materialize every group into the result set.
//
//	(b) CORRECTED (PAT-933 gate round 4): this part previously argued the
//	    pre-cap work was structurally bounded because each inventory upload
//	    is capped at 6 MB (maxBodyBytes, internal/handlers/inventory.go) and
//	    tenant device counts are bounded at enrolment (trial_device_cap /
//	    contracted estate size). That bounds the rows a device can report
//	    IN ONE UPLOAD, and the number of devices — but NOT the number of
//	    rows a tenant accumulates OVER TIME. upsertBrowserExtensions
//	    (internal/extractor/upsert.go) is an INSERT ... ON CONFLICT (...)
//	    DO UPDATE keyed on (device_id, browser, user_account, profile,
//	    extension_id) with NO corresponding DELETE for stale/uninstalled
//	    extensions, ever. So the distinct-tuple count for a tenant grows
//	    monotonically for the tenant's entire lifetime: a device reporting a
//	    fresh fake extension_id on every upload accumulates one permanent
//	    row per upload, forever. The ident CTE's GROUP BY and the separate
//	    total_count subquery's GROUP BY (both `GROUP BY dbe.extension_id,
//	    dbe.browser`) each scan and group ALL of a tenant's accumulated rows
//	    — genuinely unbounded over time, not merely large. See part (d)
//	    below for the actual bound now in place.
//
//	    NEW (PAT-933 gate round 6): this part's ROW COUNT growing without
//	    bound was fixed by part (d)'s pre-check, but round 6 correctly
//	    pointed out that row count alone doesn't bound this query's cost:
//	    the ident CTE's GROUP BY key (dbe.extension_id, dbe.browser) and the
//	    picked CTE's ORDER BY key (LOWER(i.name), i.browser, i.extension_id)
//	    all operate on the RAW, untruncated device_browser_extensions
//	    columns — part (c) below deliberately never truncates a join/GROUP
//	    BY/ORDER BY key, only the final output projection, to avoid two
//	    distinct long identities colliding into one wrong aggregated row.
//	    So even a tenant safely under portalExtensionsMaxSourceRows could,
//	    prior to this fix, make Postgres group/sort on arbitrarily large
//	    text values. Fixed at the WRITE path, not another read-side patch:
//	    upsertBrowserExtensions (internal/extractor/upsert.go) now truncates
//	    extension_id/browser/name/version to extMaxIDLen (128) /
//	    extMaxBrowserLen (32) / extMaxNameLen (256) / extMaxVersionLen (64)
//	    — chosen to match this file's own portalExtensionsMaxIDLen /
//	    portalExtensionsMaxBrowserLen / portalExtensionsMaxNameLen /
//	    portalExtensionsMaxVersionLen — BEFORE those values are used as the
//	    ON CONFLICT key or written, so device_browser_extensions itself now
//	    has a structural per-field bound. That means the GROUP BY/ORDER BY
//	    keys this part is about are ALSO now bounded (at the same 128/32/256
//	    byte-ish ceilings as the display caps), closing the gap round 6
//	    identified in this file's documented proof, not just in the read-side
//	    code. See upsertBrowserExtensions's doc comment for the full
//	    collision-risk reasoning on why truncating fields that are part of an
//	    ON CONFLICT key is safe in practice.
//
//	    NEW (PAT-933 gate round 7): round 6's ingestion-time truncation only
//	    bounds rows written AFTER that fix ("fix(PAT-933): bound extension
//	    field lengths at ingestion") shipped. device_browser_extensions is a
//	    live table that has been collecting browser extension telemetry
//	    since migration 0018 — any row written before that fix could still
//	    hold unbounded-length browser/extension_id/name/version, and this
//	    ident CTE's GROUP BY and the picked CTE's
//	    ORDER BY still operate on those raw legacy values exactly as round 6
//	    described, undoing the round-6 fix for every pre-existing row. Closed
//	    by migration 0085
//	    (migrations/0085_device_browser_extensions_length_bounds.sql), which
//	    (1) backfills every existing row exceeding the caps down to the same
//	    32/128/256/64 lengths upsert.go now enforces at write time, and (2)
//	    adds CHECK constraints on all four columns so no future write path —
//	    not just upsertBrowserExtensions — can reintroduce unbounded text.
//	    With both the ingestion-time truncation (round 6) and the legacy
//	    backfill + DB-level CHECK constraints (0085) in place, EVERY row this
//	    query can ever GROUP BY/ORDER BY, past or future, is bounded at the
//	    source, not just at the output projection part (c) below covers.
//
//	(c) Row and device/version COUNTS being capped is not enough on its
//	    own: device_browser_extensions stores extension_id, name, browser,
//	    version, and (via devices) hostname as plain `text` — a tenant
//	    fully controls the bytes in every one of those columns via its own
//	    agent uploads, so an uncapped column could still blow up the
//	    response even with the row/device/version counts held constant.
//	    Every tenant-controlled text field emitted into JSON is therefore
//	    also truncated with SQL LEFT() in the query's OUTPUT projection —
//	    never on a join key or GROUP BY column, so identity matching stays
//	    exact (see the per-field comments below and in portalExtensionsQuery
//	    for exactly where). With that in place the response has a hard
//	    compile-time-constant ceiling:
//
//	        <=500 rows x (
//	            portalExtensionsMaxIDLen (128) +           // extension_id
//	            portalExtensionsMaxNameLen (256) +         // name
//	            portalExtensionsMaxBrowserLen (32) +       // browser
//	            portalExtensionsMaxVersions (20) x portalExtensionsMaxVersionLen (64) +  // versions[]
//	            portalExtensionsMaxDevices (50) x portalExtensionsMaxHostnameLen (256)    // devices[].hostname
//	        ) characters
//	        = 500 x (128 + 256 + 32 + 1280 + 12800) = 500 x 14.5K chars ~= 7M chars
//
//	    Postgres LEFT(text, n) counts characters, not bytes, and these
//	    columns are UTF-8 — a character can take up to 4 bytes. The true
//	    worst-case BYTE ceiling is therefore up to 4x the above if a tenant
//	    fills every capped field with multi-byte characters: ~28 MB, not
//	    ~7 MB. Still a fixed compile-time constant either way — bounded, not
//	    unbounded — which is the GitHub-Non-Author-Review invariant this comment exists to
//	    establish; the 4x just means "bounded at ~28 MB", not "unbounded".
//
//	(d) NEW (PAT-933 gate round 4), CORRECTED (round 6): since part (b) does
//	    NOT bound the tenant's total accumulated row count,
//	    FetchPortalExtensions runs a fail-closed pre-check BEFORE
//	    portalExtensionsQuery, against portalExtensionsMaxSourceRows. Round 4
//	    implemented this pre-check as a plain `SELECT COUNT(*) FROM
//	    device_browser_extensions dbe JOIN devices d ON ... WHERE d.tenant_id
//	    = $1` and reasoned that because it has no GROUP BY, no sort, and no
//	    per-key aggregation it stays "cheap". Round 6 correction: that
//	    reasoning was wrong. COUNT(*) is not free just because there is no
//	    GROUP BY — Postgres must still visit every matching row (at best via
//	    an index-only scan) to produce an exact count, so the pre-check
//	    itself was exactly the same O(tenant's lifetime row count) unbounded
//	    scan the guard exists to prevent; a tenant with tens of millions of
//	    accumulated rows would make the "cheap pre-check" the new unbounded
//	    bottleneck. The fix is a bounded EXISTENCE PROBE, not a count: `SELECT
//	    COUNT(*) FROM (SELECT 1 FROM device_browser_extensions dbe JOIN
//	    devices d ON ... WHERE d.tenant_id = $1 LIMIT
//	    portalExtensionsMaxSourceRows+1) capped`. Postgres's LIMIT stops the
//	    inner scan as soon as it has produced cap+1 rows, so this probe's own
//	    cost is bounded by the threshold regardless of how many rows the
//	    tenant has actually accumulated — the guard itself now has a hard
//	    cap, closing the gate finding that round 4/5 left open. Consequence:
//	    sourceRows is the tenant's EXACT row count only while it is at or
//	    below the threshold (the LIMIT never binds); at or above the
//	    threshold it reads exactly portalExtensionsMaxSourceRows+1 — a floor
//	    ("at least this many"), not the true count — which is all the
//	    threshold comparison below needs, but callers of SourceRowCount must
//	    not treat it as exact in that branch (see SourceRowCount's doc
//	    comment). sourceRows is scanned into an int64, not cast to ::int in
//	    SQL: the below-threshold value can still be large and Postgres
//	    COUNT(*) is bigint; scanning straight into Go's int64 avoids any risk
//	    of a Postgres int4-range error. Above the threshold the request
//	    returns a clean, successful, degraded response (empty extensions,
//	    Truncated=true, EstateTooLarge=true — see the PortalExtensionsResult
//	    doc comment for why the latter exists and is logged, not just
//	    returned) instead of ever starting the GROUP BY/sort in
//	    portalExtensionsQuery. This is what actually establishes the
//	    "bounded, not unbounded" invariant now, for the guard itself as well
//	    as the query it gates; parts (a) and (c) still hold for the accepted
//	    range below the threshold.
//
//	(e) NEW (PAT-933 gate round 5): part (d)'s fail-closed branch has no
//	    recovery path — device_browser_extensions rows are never deleted
//	    (part (b)), so a tenant's raw row count can only grow, never shrink,
//	    and once it crosses portalExtensionsMaxSourceRows this branch fires
//	    permanently. A genuinely large or long-lived LEGITIMATE tenant
//	    (thousands of devices accumulating distinct extension identities over
//	    years, zero abuse involved) can cross this threshold organically. The
//	    resulting response (Total 0, Extensions empty) is otherwise byte-for-
//	    byte identical to a tenant that has simply never reported an
//	    extension, and FetchPortalExtensions previously logged nothing when
//	    this fired — permanent, silent, and indistinguishable from "customer
//	    genuinely has zero extensions" to both the portal user and anyone
//	    debugging it. EstateTooLarge (JSON: estate_too_large) plus a
//	    Warn-level server log in PortalExtensionsHandler (tenant_id, the
//	    row count observed by the bounded probe — a floor, "at least this
//	    many", once part (d)'s round-6 probe caps at
//	    portalExtensionsMaxSourceRows+1, not necessarily the tenant's true
//	    total — and the threshold) close that gap: the
//	    condition is now distinguishable in the API contract and
//	    operationally discoverable, even though it is still not something a
//	    customer-facing GET can recover from — that requires either raising
//	    portalExtensionsMaxSourceRows, adding a real bound (e.g. deleting
//	    stale rows) to device_browser_extensions, or a paginated/streaming
//	    version of this endpoint, none of which are in scope here.
const (
	// portalExtensionsMaxRows caps how many extension rows one response
	// carries. The ORDER BY puts unapproved, then unreviewed, extensions
	// first (they are the page's point), so the cap bites the
	// approved/ignored tail.
	portalExtensionsMaxRows = 500
	// portalExtensionsMaxDevices caps the per-extension device drill-down
	// list at the first N devices by hostname. DeviceCount stays the exact
	// distinct-device total.
	portalExtensionsMaxDevices = 50
	// portalExtensionsMaxVersions caps the per-extension distinct version
	// list (lowest-sorting first). VersionsTrunc flags a cut.
	portalExtensionsMaxVersions = 20

	// The following length caps bound the tenant-controlled `text` columns
	// on device_browser_extensions (and devices.hostname) that are emitted
	// into the JSON response. They are applied with SQL LEFT() strictly in
	// the query's final OUTPUT projection — never on the join predicates
	// (dbe.extension_id = p.extension_id AND dbe.browser = p.browser) or
	// the ident CTE's GROUP BY, both of which must keep operating on full,
	// untruncated values or two distinct long identities sharing a
	// truncated prefix would wrongly collide into one aggregated row.

	// portalExtensionsMaxIDLen caps the emitted extension_id length.
	portalExtensionsMaxIDLen = 128
	// portalExtensionsMaxNameLen caps the emitted extension name length.
	portalExtensionsMaxNameLen = 256
	// portalExtensionsMaxBrowserLen caps the emitted browser field length.
	// The real value space ('chrome' | 'edge' | 'firefox') is tiny; this is
	// a defensive ceiling, not a validation of the value.
	portalExtensionsMaxBrowserLen = 32
	// portalExtensionsMaxVersionLen caps each emitted version string's
	// length (applied to the aggregated array element, not the ORDER BY).
	portalExtensionsMaxVersionLen = 64
	// portalExtensionsMaxHostnameLen caps each emitted device hostname's
	// length in the drill-down list.
	portalExtensionsMaxHostnameLen = 256
)

// portalExtensionsMaxSourceRows fails the request closed, before any GROUP
// BY/sort, if the tenant's raw (ungrouped) device_browser_extensions row
// count exceeds this. Needed because upsertBrowserExtensions
// (internal/extractor/upsert.go) never deletes stale/uninstalled extension
// rows — total distinct (device_id, browser, user_account, profile,
// extension_id) tuples for a tenant grows monotonically over its lifetime,
// so the per-upload 6MB body cap and per-tenant device cap do NOT bound this
// table's total size the way the rest of this file's doc comment assumed
// (see part (b) above, corrected). var, not const, so tests can lower it
// without seeding hundreds of thousands of rows.
var portalExtensionsMaxSourceRows = 100_000

// SetPortalExtensionsMaxSourceRowsForTest overrides portalExtensionsMaxSourceRows
// and returns a func that restores the original value. Test-only: exported
// (rather than the var itself) so the integration test suite — a separate
// package — can lower the threshold and exercise the GitHub-Non-Author-Review round-4
// fail-closed guard without seeding hundreds of thousands of rows. Not
// safe for concurrent (t.Parallel) use against this package's tests, since
// it mutates shared package state; portal_test.go's TestPortalExtensions*
// suite does not run parallel subtests today.
func SetPortalExtensionsMaxSourceRowsForTest(n int) (restore func()) {
	orig := portalExtensionsMaxSourceRows
	portalExtensionsMaxSourceRows = n
	return func() { portalExtensionsMaxSourceRows = orig }
}

// PortalExtensionsMaxSourceRows returns the current fail-closed threshold.
// Exported read-only so callers outside this package (specifically
// PortalExtensionsHandler, internal/handlers/portal.go) can include the
// threshold value in an operator-facing log line without duplicating the
// constant or reaching into unexported package state.
func PortalExtensionsMaxSourceRows() int { return portalExtensionsMaxSourceRows }

// PortalExtensionDevice is one device running a given extension, for the
// portal's drill-down (customer-scoped analogue of TenantBrowserExtensionDevice
// in browser_extensions.go).
type PortalExtensionDevice struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
}

// PortalExtension is one browser extension aggregated across a tenant's
// estate, keyed by (extension_id, browser), carrying its PAT-826 policy
// state.
//
// ApprovalState is one of "approved", "unapproved", "ignored" (all three are
// persisted tenant_extension_policies rows) or "unreviewed" (no policy row
// matches — the implicit fourth state; never written to the table). This
// mirrors the state space TenantExtensionPolicyScanHandler already exposes
// on the staff side (internal/handlers/extension_policies.go) so "approved"
// on the portal never gets confused with "nobody has looked at this yet".
type PortalExtension struct {
	ExtensionID   string   `json:"extension_id"`
	Name          string   `json:"name"`
	Browser       string   `json:"browser"`
	RiskLevel     string   `json:"risk_level"` // 'normal' | 'elevated'; elevated when ANY install is (BOOL_OR)
	Versions      []string `json:"versions"`   // first portalExtensionsMaxVersions distinct versions
	VersionsTrunc bool     `json:"versions_truncated"`
	// VersionCount (PAT-1799) is the exact distinct-version count for this
	// (extension_id, browser) pair across the tenant's estate, before the
	// portalExtensionsMaxVersions display cap — i.e. the count
	// VersionsTrunc is derived from, not len(Versions). Lets the portal show
	// "N devices on M versions" without the client having to infer M from a
	// possibly-truncated Versions list.
	VersionCount  int                     `json:"version_count"`
	DeviceCount   int                     `json:"device_count"` // exact, never capped
	Devices       []PortalExtensionDevice `json:"devices"`      // first portalExtensionsMaxDevices by hostname
	DevicesTrunc  bool                    `json:"devices_truncated"`
	ApprovalState string                  `json:"approval_state"`
	// RemovalState (PAT-1726) says whether removal of this extension has
	// been requested, is in progress, or the targeted scope has completed —
	// derived from tenant_extension_removal_requests/_targets (0074/0093),
	// never from ApprovalState. Only meaningful when ApprovalState is
	// "unapproved"; still populated for every row (see
	// contracts/portal-api.md) so the portal has a uniform shape to render,
	// but a removal request against an approved/ignored/unreviewed
	// extension would be an operator error upstream of this endpoint, not
	// something this field validates.
	//
	// One of "not_requested", "requested", "in_progress",
	// "removal_completed". IMPORTANT: this row exists in the response AT
	// ALL only because the extension is still present in current inventory
	// (the ident CTE this file builds aggregates device_browser_extensions,
	// i.e. currently-installed rows) — so "removal_completed" can never
	// mean "gone from the estate". It means every device/user/profile
	// captured by an active request's scope at request time now has
	// verified extension_removed audit evidence. The extension is still
	// installed somewhere outside that captured scope (a narrower
	// one_profile/one_user request, a device that installed it after the
	// request was made, or a reinstall) — that is exactly why the row is
	// still here. A fully-removed extension does not get relabelled; it
	// simply stops appearing in this list on the next fetch, once no
	// device reports it anymore. The portal must not present
	// "removal_completed" as proof the extension is gone from the estate —
	// only the underlying audit evidence (targets/*_completed) is that
	// proof, and only for the devices it actually covers.
	RemovalState string `json:"removal_state"`
	// RemovalTargetsTotal / RemovalTargetsCompleted (PAT-1726) are the
	// device/user/profile target counts behind RemovalState, summed across
	// every non-cancelled removal request for this (extension_id, browser)
	// pair. Both zero when RemovalState is "not_requested".
	// RemovalTargetsCompleted only counts targets with verified
	// extension_removed audit evidence (completed_at is never set without
	// audit_event_id — see enforcement_audit.go's applyExtensionRemovalEvidence).
	RemovalTargetsTotal     int `json:"removal_targets_total"`
	RemovalTargetsCompleted int `json:"removal_targets_completed"`
	// DecidedBy / DecidedAt / Justification (PAT-1800): provenance for
	// ApprovalState. Sourced from the matched tenant_extension_policies row
	// (approved_by / updated_at / notes) when one exists; all three nil for
	// an "unreviewed" row, since there is no policy row to carry them.
	// approved_by and notes are NOT NULL DEFAULT '' on that table — an empty
	// string is treated as absent (nil), never surfaced as a real value.
	// updated_at is NOT NULL, so DecidedAt is populated whenever a policy
	// row exists, even one nobody has edited since creation (creation counts
	// as "last decided").
	DecidedBy     *string    `json:"decided_by"`
	DecidedAt     *time.Time `json:"decided_at"`
	Justification *string    `json:"justification"`
}

// Removal-state vocabulary for PortalExtension.RemovalState (PAT-1726).
const (
	// PortalExtensionRemovalNotRequested means no non-cancelled removal
	// request exists for this (extension_id, browser) pair. A
	// cancelled-only history also reads as this state — see
	// extensionRemovalState's doc comment for why cancellation is folded in
	// here rather than exposed as its own value.
	PortalExtensionRemovalNotRequested = "not_requested"
	// PortalExtensionRemovalRequested means at least one active request
	// exists and zero of its captured targets have completed with
	// verified evidence yet.
	PortalExtensionRemovalRequested = "requested"
	// PortalExtensionRemovalInProgress means at least one target has
	// completed with verified evidence but not every captured target has.
	PortalExtensionRemovalInProgress = "in_progress"
	// PortalExtensionRemovalCompleted means every target captured by an
	// active request's scope, at request time, has completed with
	// verified extension_removed audit evidence. It does NOT mean the
	// extension is gone from the tenant's estate — this row only exists
	// because the extension is still present in current inventory outside
	// that completed scope (see PortalExtension.RemovalState's doc
	// comment for the full reasoning). A genuinely fully-removed extension
	// never reaches "removal_completed": it simply stops appearing in this
	// list once no device reports it.
	PortalExtensionRemovalCompleted = "removal_completed"
)

// extensionRemovalState derives PortalExtension.RemovalState from the
// aggregated request/target counts for one (extension_id, browser) pair.
//
// requests is the count of DISTINCT non-cancelled
// tenant_extension_removal_requests rows; targetsTotal/targetsCompleted sum
// tenant_extension_removal_targets across those same requests.
// targetsCompleted only counts rows with completed_at set, which (per
// applyExtensionRemovalEvidence in enforcement_audit.go) is NEVER written
// without a matching audit_event_id from a real, non-dry-run
// extension_removed audit event — so "completed" here always means
// verified post-removal evidence, never an assumption from a target simply
// no longer appearing in inventory (root AGENTS.md: absence requires
// authority).
//
// A cancelled-only history (every request for this pair has cancelled_at
// set) is folded into "not_requested" rather than given its own "cancelled"
// value: the create-handler's active-request unique index means a new
// removal can always be requested again after a cancellation, so from the
// customer's point of view a cancelled request and no request ever having
// been made are the same actionable state — "nothing outstanding". The
// distinct cancellation history remains visible to staff via
// GET /admin/tenants/{id}/extension-removals?include_history=true.
func extensionRemovalState(requests, targetsTotal, targetsCompleted int) string {
	switch {
	case requests == 0:
		return PortalExtensionRemovalNotRequested
	case targetsTotal == 0:
		// An active request exists but the LEFT JOIN found no captured
		// target rows for it. The create handler never commits a request
		// like this (see portalExtensionsRemovalJoin's doc comment), so
		// this branch is defence in depth, not a case seen in practice
		// today. "requested" — not "not_requested" — is the only safe
		// reading: the request is real, and treating it as absent would
		// hide a live directive from the customer. This also falls out of
		// the targetsCompleted == 0 case below (0 == 0), but is spelled
		// out explicitly because a request existing with nothing to
		// complete is a distinct reason to be at "requested", not merely
		// the same reason as "some targets, none done yet".
		return PortalExtensionRemovalRequested
	case targetsCompleted == 0:
		return PortalExtensionRemovalRequested
	case targetsCompleted < targetsTotal:
		return PortalExtensionRemovalInProgress
	default:
		return PortalExtensionRemovalCompleted
	}
}

// PortalExtensionsResult carries the capped extension list plus the exact
// pre-cap total and a truncation flag.
//
// Total is normally the exact count of (extension, browser) rows before the
// cap. EXCEPTION: when FetchPortalExtensions' portalExtensionsMaxSourceRows
// pre-check fails closed (tenant's raw row count too large to safely group),
// Extensions is empty, Truncated is true, EstateTooLarge is true, and Total
// is deliberately left 0 rather than either the raw (ungrouped) pre-check
// count — which is not the same number this field otherwise means and would
// be misleading — or the true grouped count, which would require running the
// very GROUP BY the pre-check exists to avoid.
//
// EstateTooLarge (PAT-933 gate round 5) is the field callers must check to
// distinguish that fail-closed branch from an ordinary empty-extensions
// tenant: both cases produce Total == 0, Extensions == [] and (today)
// Truncated == true, and are otherwise indistinguishable in this struct.
// Without EstateTooLarge, a tenant that has genuinely never reported an
// extension and a tenant whose estate has permanently exceeded
// portalExtensionsMaxSourceRows (device_browser_extensions rows are
// upserted but never deleted — see part (b)/(d) of the doc comment above —
// so once a legitimate, non-abusive tenant crosses the threshold this is
// permanent, not transient) render an IDENTICAL response. Callers should
// treat EstateTooLarge as the authoritative signal for the fail-closed
// branch, Truncated as the ordinary "some rows were cut after a real fetch"
// signal, and Total as meaningless (0, not a real count) whenever
// EstateTooLarge is true.
type PortalExtensionsResult struct {
	Extensions []PortalExtension
	Total      int  // exact count of (extension, browser) rows before the cap; see exception above
	Truncated  bool // Total > len(Extensions), OR the fail-closed source-row-cap branch
	// EstateTooLarge is true only when the portalExtensionsMaxSourceRows
	// pre-check fired: the tenant's raw row count exceeded the threshold and
	// the GROUP BY/sort was never run at all. Distinct from Truncated, which
	// already means "a real fetch ran and some of its rows were cut" for the
	// ordinary 500-row display cap — do not conflate the two.
	EstateTooLarge bool
	// SourceRowCount is the raw (ungrouped) device_browser_extensions row
	// count observed by the fail-closed pre-check. Only meaningful when
	// EstateTooLarge is true; zero otherwise. Not part of the customer-facing
	// JSON contract — it exists so the caller (PortalExtensionsHandler) can
	// log the count for operational visibility, since the portal page itself
	// can never show real data in this branch.
	//
	// CAVEAT (PAT-933 gate round 6): since the pre-check itself is now a
	// bounded existence probe capped at portalExtensionsMaxSourceRows+1 rows
	// (see part (d) of the file doc comment) rather than a plain COUNT(*),
	// this field is the tenant's EXACT row count only in the — impossible by
	// construction, since EstateTooLarge is only ever true above the
	// threshold — case it would be under the threshold. Whenever
	// EstateTooLarge is true, SourceRowCount reads exactly
	// portalExtensionsMaxSourceRows+1 for every tenant at or beyond that
	// size: a floor ("at least this many rows"), not the tenant's true
	// lifetime total. Log lines and any future consumer must say "at least
	// N", never "exactly N", when reporting this value.
	SourceRowCount int64
}

// portalExtensionsQuery aggregates the tenant's extension estate with the
// abuse-resistance caps applied BEFORE any heavy aggregation (see the
// five-part argument on the consts above). %s is the policy lateral join —
// the real tenant_extension_policies lookup normally, or a NULL stub when
// that table has not been migrated yet (both fragments are compile-time
// constants; nothing user-supplied is ever interpolated).
//
// Stage 1 (ident -> picked): streaming GROUP BY computing only scalar
// aggregates, joined to the policy state for ordering, LIMIT $3. Stage 2:
// LATERAL subqueries build the capped version list (LIMIT $4) and device
// drill-down (LIMIT $2) for the <=$3 survivors only. total_count is a
// separate streaming scalar count of the identity groups. Truncation flags
// derive from the exact counts (device_count/version_count > cap), so no
// over-cap row is ever ranked or aggregated just to detect the cut.
//
// The policy match mirrors TenantExtensionPolicyScanHandler exactly: a row
// applies when extension_id is equal AND (browser 'any' or exact), and a
// browser-specific row wins over an 'any' row. No matching row means
// "unreviewed".
//
// $5-$9 are the text-length caps (portalExtensionsMaxIDLen/MaxNameLen/
// MaxBrowserLen/MaxVersionLen/MaxHostnameLen). LEFT() is applied ONLY in the
// final outer SELECT's projection, the version LATERAL's ARRAY_AGG element,
// and the device LATERAL's jsonb_build_object — i.e. only to values that get
// scanned into Go and marshaled to JSON. It is never applied to join
// predicates (dbe.extension_id = p.extension_id AND dbe.browser = p.browser
// in either LATERAL) or to the ident CTE's GROUP BY columns: truncating
// those would let two distinct long extension_ids sharing a truncated
// prefix collide into one wrong aggregated identity.
//
// $10 (PAT-2156) is the optional device_id filter: "" means unfiltered (see
// fetchPortalExtensions' doc comment). Applied in the ident CTE, the
// total_count subquery, and both LATERALs, so a device-scoped request's
// device_count/version_count/versions/devices all agree with each other and
// with ident's own row set — never a mix of "this device's identities" and
// "every device's versions/drill-down for those identities".
const portalExtensionsQuery = `
WITH ident AS NOT MATERIALIZED (
    SELECT
        dbe.extension_id,
        dbe.browser,
        MAX(dbe.name)                                                  AS name,
        CASE WHEN BOOL_OR(dbe.risk_level = 'elevated')
             THEN 'elevated' ELSE 'normal' END                         AS risk_level,
        COUNT(DISTINCT dbe.device_id)::int                             AS device_count,
        COUNT(DISTINCT dbe.version)::int                               AS version_count
    FROM device_browser_extensions dbe
    JOIN devices d ON d.id = dbe.device_id
    WHERE d.tenant_id = $1::uuid
      AND (NULLIF($10, '') IS NULL OR dbe.device_id = NULLIF($10, '')::uuid)
    GROUP BY dbe.extension_id, dbe.browser
),
picked AS (
    SELECT i.*, COALESCE(pol.policy, 'unreviewed') AS approval_state,
           pol.approved_by AS decided_by, pol.updated_at AS decided_at, pol.notes AS justification
    FROM ident i
    %s
    ORDER BY CASE COALESCE(pol.policy, 'unreviewed')
                 WHEN 'unapproved' THEN 0
                 WHEN 'unreviewed' THEN 1
                 WHEN 'approved'   THEN 2
                 ELSE 3 END,
             i.device_count DESC, LOWER(i.name), i.browser, i.extension_id
    LIMIT $3
)
SELECT LEFT(p.extension_id, $5), LEFT(p.name, $6), LEFT(p.browser, $7), p.risk_level,
       COALESCE(vers.versions, '{}')                                   AS versions,
       p.version_count > $4                                            AS versions_truncated,
       p.version_count,
       p.device_count,
       devs.devices,
       p.device_count > $2                                             AS devices_truncated,
       p.approval_state,
       p.decided_by, p.decided_at, p.justification,
       COALESCE(rem.requests, 0),
       COALESCE(rem.targets_total, 0),
       COALESCE(rem.targets_completed, 0),
       (SELECT COUNT(*)::int FROM (
            SELECT 1
            FROM device_browser_extensions dbe
            JOIN devices d ON d.id = dbe.device_id
            WHERE d.tenant_id = $1::uuid
              AND (NULLIF($10, '') IS NULL OR dbe.device_id = NULLIF($10, '')::uuid)
            GROUP BY dbe.extension_id, dbe.browser
       ) g)                                                            AS total_count
FROM picked p
-- NOTE (both LATERALs below): DISTINCT/MIN establish exact, genuinely
-- distinct pre-truncation values; LEFT() then truncates each for display
-- only. If two distinct versions (or two distinct devices' hostnames)
-- happen to share an identical prefix at the cap length, they render as
-- duplicate-looking strings in the emitted array — a cosmetic artifact of
-- adversarial-length input, not a correctness issue in the counts:
-- version_count/device_count and the *_truncated flags are computed
-- separately from untruncated aggregates (see the outer SELECT) and stay
-- exact regardless. Devices additionally keep a distinct device_id even
-- when hostname collides. Not de-duplicating the truncated display array
-- is deliberate: doing so would silently drop a real entry with no flag
-- indicating the display array is shorter than the exact count for a
-- reason other than the existing rows/devices/versions caps.
LEFT JOIN LATERAL (
    SELECT ARRAY_AGG(LEFT(v.version, $8) ORDER BY v.version) AS versions
    FROM (
        SELECT DISTINCT dbe.version
        FROM device_browser_extensions dbe
        JOIN devices d ON d.id = dbe.device_id
        WHERE d.tenant_id = $1::uuid
          AND (NULLIF($10, '') IS NULL OR dbe.device_id = NULLIF($10, '')::uuid)
          AND dbe.extension_id = p.extension_id
          AND dbe.browser = p.browser
          AND dbe.version IS NOT NULL
        ORDER BY dbe.version
        LIMIT $4
    ) v
) vers ON true
LEFT JOIN LATERAL (
    SELECT jsonb_agg(jsonb_build_object('device_id', dd.device_id, 'hostname', LEFT(dd.hostname, $9))
                     ORDER BY dd.hostname, dd.device_id) AS devices
    FROM (
        SELECT dbe.device_id,
               MIN(COALESCE(d.hostname, d.serial, dbe.device_id::text)) AS hostname
        FROM device_browser_extensions dbe
        JOIN devices d ON d.id = dbe.device_id
        WHERE d.tenant_id = $1::uuid
          AND (NULLIF($10, '') IS NULL OR dbe.device_id = NULLIF($10, '')::uuid)
          AND dbe.extension_id = p.extension_id
          AND dbe.browser = p.browser
        GROUP BY dbe.device_id
        ORDER BY MIN(COALESCE(d.hostname, d.serial, dbe.device_id::text)), dbe.device_id
        LIMIT $2
    ) dd
) devs ON true
-- PAT-1726 removal state: bounded by admin-driven removal-request volume
-- (queued only via the explicit "Remove now" action, never customer
-- telemetry), unlike the abuse-hardened LATERALs above — no row/length
-- caps needed here. cancelled_at IS NULL is the "active" filter; a request
-- that later becomes fulfilled stays counted (that's how "removal_completed"
-- is reached), only a cancelled one drops out. Note this row only exists
-- because ident's GROUP BY found current inventory for this
-- (extension_id, browser) — see PortalExtension.RemovalState's doc comment
-- for why "removal_completed" therefore never means "gone from the
-- estate". The substitution below is either the real 0074/0093 join or a
-- NULL stub on an install predating those migrations.
%s
ORDER BY CASE p.approval_state
             WHEN 'unapproved' THEN 0
             WHEN 'unreviewed' THEN 1
             WHEN 'approved'   THEN 2
             ELSE 3 END,
         p.device_count DESC, LOWER(p.name), p.browser, p.extension_id
`

// portalExtensionsPolicyJoin also carries approved_by/updated_at/notes
// (PAT-1800) through to the outer query as this row's decision provenance —
// see PortalExtension.DecidedBy's doc comment. NULLIF converts the table's
// NOT NULL DEFAULT (empty string) sentinels to a real NULL so an unset approved_by/notes
// never renders as an empty-string "decision".
const portalExtensionsPolicyJoin = `
    LEFT JOIN LATERAL (
        SELECT p.policy, NULLIF(p.approved_by, '') AS approved_by,
               p.updated_at, NULLIF(p.notes, '') AS notes
        FROM tenant_extension_policies p
        WHERE p.tenant_id = $1::uuid
          AND p.extension_id = i.extension_id
          AND (p.browser = i.browser OR p.browser = 'any')
        ORDER BY (p.browser = i.browser) DESC
        LIMIT 1
    ) pol ON true`

// portalExtensionsPolicyStub stands in when tenant_extension_policies has
// not been migrated: everything derives as "unreviewed", decision
// provenance included.
const portalExtensionsPolicyStub = `
    LEFT JOIN LATERAL (
        SELECT NULL::text AS policy, NULL::text AS approved_by,
               NULL::timestamptz AS updated_at, NULL::text AS notes
    ) pol ON true`

// portalExtensionsRemovalJoin computes the PAT-1726 removal-state counts for
// each survivor row from the real 0074/0093 removal-lifecycle tables.
//
// LEFT JOIN to tenant_extension_removal_targets (not an inner join): an
// active request with zero captured targets must still count toward
// `requests` so extensionRemovalState reads it as "requested", not
// "not_requested" — a request existing but nothing yet confirmed removed is
// exactly what "requested" means, and "not_requested" would be a false
// negative (a real request would go invisible). COUNT(rt.request_id) and
// COUNT(rt.completed_at) both correctly read 0 across a LEFT JOIN with no
// matching target rows (COUNT of a column ignores NULLs), so targets_total
// and targets_completed stay accurate without any special-casing.
//
// Defence in depth, not the primary guarantee: today
// TenantExtensionRemovalCreateHandler (internal/handlers/extension_removals.go:310-314)
// already prevents a zero-target request from ever being committed — it
// checks the target-capture INSERT's RowsAffected and, if it is 0, returns
// a 409 WITHOUT calling tx.Commit, so the deferred tx.Rollback (line 253)
// discards both the target insert and the request insert in the same
// transaction. No other code path writes tenant_extension_removal_requests.
// This LEFT JOIN means the read side does not silently misreport even if
// that write-side invariant is ever weakened (a future bulk-import path, a
// manual SQL fix-up, a relaxed validation) — it fails toward "requested"
// (visible, actionable) rather than "not_requested" (invisible, the worse
// direction to be wrong in).
const portalExtensionsRemovalJoin = `
LEFT JOIN LATERAL (
    SELECT COUNT(DISTINCT r.id)::int      AS requests,
           COUNT(rt.request_id)::int      AS targets_total,
           COUNT(rt.completed_at)::int    AS targets_completed
    FROM tenant_extension_removal_requests r
    LEFT JOIN tenant_extension_removal_targets rt ON rt.request_id = r.id
    WHERE r.tenant_id = $1::uuid
      AND r.cancelled_at IS NULL
      AND r.browser = p.browser
      AND r.extension_id = p.extension_id
) rem ON true`

// portalExtensionsRemovalStub stands in when tenant_extension_removal_requests
// has not been migrated: every row reads removal_state "not_requested".
const portalExtensionsRemovalStub = `
LEFT JOIN LATERAL (SELECT NULL::int AS requests, NULL::int AS targets_total, NULL::int AS targets_completed) rem ON true`

// FetchPortalExtensions returns the tenant's browser extension estate with
// each extension's PAT-826 approval state (PAT-933), capped per the GitHub-Non-Author-Review
// abuse-resistance constants above.
//
// Query logic joins the same two tables the staff-side estate scan
// (TenantExtensionPolicyScanHandler) already joins — device_browser_extensions
// (0018) and tenant_extension_policies (0071) — with the identical matching
// rule, so the customer-facing approval state can never drift from the admin
// view.
//
// Degrades to an empty result if the extensions table is absent, and to
// all-"unreviewed" if only the policy table is absent — same convention as
// the sibling portal fetchers, so a platform build predating PAT-561/PAT-826
// serves a clean page rather than a 500. Also degrades (empty, Truncated
// true, EstateTooLarge true) if the tenant's raw device_browser_extensions
// row count exceeds portalExtensionsMaxSourceRows — see part (d) of the doc
// comment above and the PortalExtensionsResult.EstateTooLarge doc comment
// for why that flag exists and must not be conflated with the "table
// absent"/ordinary-empty case above, which leaves EstateTooLarge false.
func FetchPortalExtensions(ctx context.Context, pool *pgxpool.Pool, tenantID string) (PortalExtensionsResult, error) {
	return fetchPortalExtensions(ctx, pool, tenantID, "")
}

// FetchPortalExtensionsForDevice is FetchPortalExtensions narrowed to one
// device's own current extensions (PAT-2156's GET /v1/portal/extensions
// ?device_id= filter). deviceID must already be validated as a well-formed
// UUID owned by tenantID (report.DeviceTenant) by the caller, the same
// division of responsibility FetchPortalSoftwareForDevice's caller follows.
//
// Every cap and abuse-resistance guard above (row/device/version caps, the
// source-row fail-closed pre-check) still applies, now scoped to the one
// device — a single device's device_browser_extensions rows are smaller in
// practice but not structurally bounded any more than the tenant's are (see
// part (b)/(e) above), so this deliberately reuses the same guarded query
// rather than a separate unguarded one.
func FetchPortalExtensionsForDevice(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string) (PortalExtensionsResult, error) {
	return fetchPortalExtensions(ctx, pool, tenantID, deviceID)
}

// fetchPortalExtensions is shared by FetchPortalExtensions and
// FetchPortalExtensionsForDevice. deviceID == "" means unfiltered — every
// `$10 = ” OR dbe.device_id = $10::uuid` predicate in portalExtensionsQuery
// (and the matching predicate in the source-row probe below) then always
// takes its first branch, so the unfiltered query text and result are
// unchanged from before PAT-2156's device_id filter existed.
func fetchPortalExtensions(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string) (PortalExtensionsResult, error) {
	res := PortalExtensionsResult{Extensions: []PortalExtension{}}

	var haveExtensions, havePolicies, haveRemovals bool
	err := pool.QueryRow(ctx, `
		SELECT to_regclass('device_browser_extensions') IS NOT NULL,
		       to_regclass('tenant_extension_policies') IS NOT NULL,
		       to_regclass('tenant_extension_removal_targets') IS NOT NULL
	`).Scan(&haveExtensions, &havePolicies, &haveRemovals)
	if err != nil {
		return res, fmt.Errorf("probe extension tables: %w", err)
	}
	if !haveExtensions {
		return res, nil
	}

	// GitHub-Non-Author-Review gate round 4: fail closed BEFORE the GROUP BY/sort in
	// portalExtensionsQuery if the tenant's raw (ungrouped) row count is
	// large enough that grouping/sorting it is no longer cheap, since (per
	// the corrected part (b) above) the underlying table has no structural
	// bound of its own.
	//
	// CORRECTED (round 6): round 4 implemented this as a plain `SELECT
	// COUNT(*) ... WHERE d.tenant_id = $1` and reasoned it was cheap because
	// it has no GROUP BY, no sort, no per-key aggregation. That reasoning
	// was wrong — a plain COUNT(*) is not free just because there is no
	// GROUP BY: Postgres still has to visit every matching row (at best via
	// an index-only scan) to produce an exact count, so the "cheap
	// pre-check" was itself exactly the same O(tenant's lifetime row count)
	// unbounded scan this whole guard exists to prevent. A tenant with tens
	// of millions of accumulated rows made the guard the new bottleneck.
	//
	// Fixed by turning the pre-check into a bounded EXISTENCE PROBE instead
	// of a count: select at most portalExtensionsMaxSourceRows+1 matching
	// rows with LIMIT, then COUNT(*) only that already-capped result set.
	// Postgres stops scanning the inner query as soon as it has produced
	// cap+1 rows, so the probe's own cost is bounded by the threshold
	// regardless of how many rows the tenant has actually accumulated — the
	// guard itself now has a hard cap, not just the query it gates. See
	// part (d) of the file doc comment above for the full rationale.
	//
	// Consequence: sourceRows is the tenant's EXACT row count only while it
	// is at or below the threshold (the LIMIT never binds there). At or
	// above the threshold it reads exactly portalExtensionsMaxSourceRows+1
	// for every such tenant — a floor ("at least this many"), not the true
	// count — which is all the `>` comparison below needs, but
	// SourceRowCount's doc comment on PortalExtensionsResult carries this
	// caveat forward for anyone logging or otherwise consuming that field.
	//
	// Still scanned into an int64, not cast to ::int in SQL (round 4 did
	// this; corrected in round 5, still true here): the below-threshold
	// value can legitimately be large and Postgres COUNT(*) is bigint, so
	// scanning straight into Go's int64 avoids any risk of a Postgres
	// int4-range error. Go's int is 64-bit on every build target this
	// service ships for, but int64 is used explicitly so the type doesn't
	// silently narrow if that ever changed.
	var sourceRows int64
	err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
			SELECT 1
			FROM device_browser_extensions dbe
			JOIN devices d ON d.id = dbe.device_id
			WHERE d.tenant_id = $1::uuid
			  AND (NULLIF($3, '') IS NULL OR dbe.device_id = NULLIF($3, '')::uuid)
			LIMIT $2
		) capped
	`, tenantID, int64(portalExtensionsMaxSourceRows)+1, deviceID).Scan(&sourceRows)
	if err != nil {
		return res, fmt.Errorf("probe extension source row count: %w", err)
	}
	if sourceRows > int64(portalExtensionsMaxSourceRows) {
		// Degrade gracefully, don't 500 — same convention as the
		// missing-table case above. Total is deliberately left 0: see the
		// PortalExtensionsResult doc comment for why sourceRows itself
		// would misrepresent it. EstateTooLarge and SourceRowCount are the
		// signals that make this branch distinguishable from an ordinary
		// empty tenant and operationally visible; the caller
		// (PortalExtensionsHandler) is expected to log SourceRowCount since
		// this function has no logger of its own. Note SourceRowCount is a
		// floor here (== portalExtensionsMaxSourceRows+1), not the tenant's
		// true row count — see its doc comment.
		res.Truncated = true
		res.EstateTooLarge = true
		res.SourceRowCount = sourceRows
		return res, nil
	}

	policyJoin := portalExtensionsPolicyJoin
	if !havePolicies {
		policyJoin = portalExtensionsPolicyStub
	}
	removalJoin := portalExtensionsRemovalJoin
	if !haveRemovals {
		removalJoin = portalExtensionsRemovalStub
	}

	rows, err := pool.Query(ctx, fmt.Sprintf(portalExtensionsQuery, policyJoin, removalJoin),
		tenantID, portalExtensionsMaxDevices, portalExtensionsMaxRows,
		portalExtensionsMaxVersions, portalExtensionsMaxIDLen, portalExtensionsMaxNameLen,
		portalExtensionsMaxBrowserLen, portalExtensionsMaxVersionLen, portalExtensionsMaxHostnameLen,
		deviceID)
	if err != nil {
		return res, fmt.Errorf("fetch portal extensions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ext PortalExtension
		var versions []string
		var devicesBytes []byte
		var removalRequests, removalTargetsTotal, removalTargetsCompleted int
		if err := rows.Scan(
			&ext.ExtensionID, &ext.Name, &ext.Browser, &ext.RiskLevel,
			&versions, &ext.VersionsTrunc, &ext.VersionCount, &ext.DeviceCount, &devicesBytes,
			&ext.DevicesTrunc, &ext.ApprovalState,
			&ext.DecidedBy, &ext.DecidedAt, &ext.Justification,
			&removalRequests, &removalTargetsTotal, &removalTargetsCompleted,
			&res.Total,
		); err != nil {
			return res, fmt.Errorf("scan portal extension: %w", err)
		}
		if versions == nil {
			versions = []string{}
		}
		ext.Versions = versions
		if len(devicesBytes) > 0 {
			if err := json.Unmarshal(devicesBytes, &ext.Devices); err != nil {
				return res, fmt.Errorf("decode devices for extension %s: %w", ext.ExtensionID, err)
			}
		}
		ext.RemovalTargetsTotal = removalTargetsTotal
		ext.RemovalTargetsCompleted = removalTargetsCompleted
		ext.RemovalState = extensionRemovalState(removalRequests, removalTargetsTotal, removalTargetsCompleted)
		res.Extensions = append(res.Extensions, ext)
	}
	if err := rows.Err(); err != nil {
		return res, err
	}

	res.Truncated = res.Total > len(res.Extensions)
	return res, nil
}
