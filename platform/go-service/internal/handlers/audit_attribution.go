package handlers

import (
	"net"
	"net/http"
	"strings"
)

// adminSharedTokenActor is the server-established identity for every write
// authenticated by the shared ADMIN_API_TOKEN bearer secret (see
// requireAdminToken, cmd/patched-api/main.go). The /admin/* surface has NO
// per-person identity today: every request that presents the correct token
// is indistinguishable from any other to the server, whatever the caller's
// JSON body claims about who they are. This constant — never a
// caller-supplied string — is therefore the only actor value the audit
// trail can actually vouch for, and is what every audit table's existing
// actor/changed_by/admin_id column receives.
//
// PAT-1135. Per-person identity for this surface is expected to arrive with
// PAT-700 (DASHBOARD_OPERATORS); until then, a human name in an audit row is
// only ever a claim, never a verified fact — see claimedActor below. See
// also docs/AUDIT_STORE.md ("Actor attribution is not authenticated
// (PAT-1135)") and docs/API.md ("Admin audit attribution (PAT-1135)").
const adminSharedTokenActor = "admin_shared_token"

// legacyUnauthenticatedActor is the sentinel migration 0092 backfilled into
// every pre-PAT-1135 row's authoritative actor column (see
// migrations/0092_audit_attribution.sql). It is never written by Go code —
// only by that one-time backfill UPDATE — and exists here purely so tests
// and any future reader can name it without hardcoding the string. It can
// never collide with adminSharedTokenActor or a caller-supplied claim.
const legacyUnauthenticatedActor = "legacy_unauthenticated"

// auditAttribution splits admin-write attribution into what the server can
// prove and what the caller merely claims, for every handler that writes an
// admin audit row (tenant_decommission_audit, tenant_tier_changes,
// tenant_platform_changes, tenant_rule_changes, tenant_app_policy_changes,
// device_revocations — see migrations/0092_audit_attribution.sql).
//
//   - actor is always adminSharedTokenActor. Callers must write this, not
//     req.Actor/req.ChangedBy/req.AdminID/etc, into the table's existing
//     actor-type column — that column predates this change and other
//     readers still depend on it being populated and NOT NULL.
//   - claimedActor is the caller-supplied string from the request body,
//     unmodified, or nil when empty. It is UNTRUSTED — the server has no
//     way to verify it — and must be written only into a column named
//     claimed_actor, never into the authoritative actor column.
//   - sourceAddr is the observed client IP with any port stripped, or nil
//     when unavailable. See observedSourceAddr for the extraction and why
//     it deliberately does NOT match inventory.go / provenance.go's
//     r.RemoteAddr-based extraction.
func auditAttribution(r *http.Request, claimed string) (actor string, claimedActor *string, sourceAddr *string) {
	actor = adminSharedTokenActor

	if claimed != "" {
		c := claimed
		claimedActor = &c
	}

	sourceAddr = observedSourceAddr(r)

	return actor, claimedActor, sourceAddr
}

// observedSourceAddr extracts the best-effort client IP for an admin-surface
// request, port stripped.
//
// This is deliberately NOT the inventory.go / provenance.go pattern of
// reading r.RemoteAddr directly. Those handlers sit on the PUBLIC router
// (newPublicRouter, cmd/patched-api/main.go), which mounts chi's
// middleware.RealIP — RealIP itself rewrites r.RemoteAddr from
// X-Forwarded-For before the handler ever runs, so reading r.RemoteAddr
// there already gets the real client IP.
//
// The admin surface is different: newInternalRouter (cmd/patched-api/main.go)
// does NOT mount middleware.RealIP. r.RemoteAddr on that router is always
// the immediate TCP peer, which in production is Caddy's internal site
// block reverse-proxying 127.0.0.1:8081 (api-vps-artefacts/Caddyfile.api) —
// so r.RemoteAddr alone would always read "127.0.0.1", never the operator's
// real address. Caddy's reverse_proxy, with no explicit header_up override
// in that site block, appends the client IP it observed to
// X-Forwarded-For itself by default, so that header — not r.RemoteAddr — is
// where the real client address actually lands on this router.
//
// The RIGHTMOST comma-separated X-Forwarded-For entry is the one to trust:
// it is the hop Caddy itself appended from the TCP connection it accepted,
// which the admin listener only ever accepts from Caddy (bound to
// 127.0.0.1, Caddy's site bound to the Tailscale interface only, Tailscale
// ACL tag:main → tag:api:8443 — see docs/NETWORK_TOPOLOGY.md). Any entries
// to the LEFT of it are whatever the client itself sent in its own
// X-Forwarded-For header and are trivially spoofable — reading the
// leftmost entry instead would let any caller lie about its own source
// address in the audit trail. Falls back to r.RemoteAddr (then the raw
// value) when no X-Forwarded-For header is present, so this still degrades
// sanely if a future admin router change ever adds chi's RealIP middleware
// or removes Caddy from the path (e.g. local dev / tests hitting the
// handler directly via httptest, which is exactly the case the fallback
// exercises today).
//
// Best-effort audit metadata only — see auditAttribution's doc comment;
// never used for any control-flow decision anywhere in this codebase.
func observedSourceAddr(r *http.Request) *string {
	if r == nil {
		return nil
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		last := strings.TrimSpace(parts[len(parts)-1])
		if last != "" {
			if host, _, err := net.SplitHostPort(last); err == nil && host != "" {
				return &host
			}
			return &last
		}
	}

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return &host
	}
	if r.RemoteAddr != "" {
		addr := r.RemoteAddr
		return &addr
	}
	return nil
}
