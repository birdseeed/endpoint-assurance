package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestObservedSourceAddr_XForwardedForRightmostWins pins the PAT-1135
// review finding: the admin router (newInternalRouter, cmd/patched-api/
// main.go) does not mount chi's middleware.RealIP, so r.RemoteAddr is
// always the immediate TCP peer -- in production that's Caddy
// (api-vps-artefacts/Caddyfile.api's internal site block, reverse-proxying
// 127.0.0.1:8081), never the real caller. Caddy appends the client IP it
// actually observed to X-Forwarded-For by default, as the RIGHTMOST entry.
// Anything to the left of that is whatever the client itself claimed in its
// own X-Forwarded-For header and must NOT be trusted -- a caller that wants
// to frame a different IP in the audit trail only has to set
// "X-Forwarded-For: <victim-ip>" and let Caddy append its own hop after it.
func TestObservedSourceAddr_XForwardedForRightmostWins(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/whatever", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.9")
	req.RemoteAddr = "127.0.0.1:54321" // Caddy's own loopback hop to the app

	got := observedSourceAddr(req)
	if got == nil {
		t.Fatal("observedSourceAddr = nil, want \"10.0.0.9\"")
	}
	if *got != "10.0.0.9" {
		t.Errorf("observedSourceAddr = %q, want %q (rightmost X-Forwarded-For hop, not the spoofable leftmost entry)", *got, "10.0.0.9")
	}
}

// TestObservedSourceAddr_XForwardedForSingleEntryWithPort covers the
// rightmost entry itself carrying a port (some proxies append host:port,
// not just host) -- the port must still be stripped.
func TestObservedSourceAddr_XForwardedForSingleEntryWithPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/whatever", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.9:5555")
	req.RemoteAddr = "127.0.0.1:54321"

	got := observedSourceAddr(req)
	if got == nil || *got != "10.0.0.9" {
		t.Errorf("observedSourceAddr = %v, want \"10.0.0.9\" (port stripped from the XFF entry)", got)
	}
}

// TestObservedSourceAddr_FallsBackToRemoteAddr covers the no-XFF case (e.g.
// a test hitting the handler directly, or a future admin-router change that
// removes Caddy from the path): RemoteAddr's port must still be stripped.
func TestObservedSourceAddr_FallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/whatever", nil)
	req.RemoteAddr = "203.0.113.7:54321"

	got := observedSourceAddr(req)
	if got == nil || *got != "203.0.113.7" {
		t.Errorf("observedSourceAddr = %v, want \"203.0.113.7\" (port stripped from RemoteAddr)", got)
	}
}

// TestObservedSourceAddr_RemoteAddrWithoutPort covers a RemoteAddr that
// isn't a valid host:port pair (SplitHostPort fails) -- the raw value must
// still be returned rather than silently dropped to nil.
func TestObservedSourceAddr_RemoteAddrWithoutPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/whatever", nil)
	req.RemoteAddr = "not-a-host-port"

	got := observedSourceAddr(req)
	if got == nil || *got != "not-a-host-port" {
		t.Errorf("observedSourceAddr = %v, want the raw RemoteAddr value as a fallback", got)
	}
}

// TestObservedSourceAddr_Empty covers no RemoteAddr and no X-Forwarded-For:
// must return nil (writes a NULL source_addr), never an empty string.
func TestObservedSourceAddr_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/whatever", nil)
	req.RemoteAddr = ""

	if got := observedSourceAddr(req); got != nil {
		t.Errorf("observedSourceAddr = %q, want nil", *got)
	}
}

// TestObservedSourceAddr_NilRequest guards the defensive nil check in
// observedSourceAddr / auditAttribution.
func TestObservedSourceAddr_NilRequest(t *testing.T) {
	if got := observedSourceAddr(nil); got != nil {
		t.Errorf("observedSourceAddr(nil) = %q, want nil", *got)
	}
}

// TestAuditAttribution_Basics covers the three-way split for a typical
// caller-claimed request: actor is always the constant, claimedActor
// carries the caller's string verbatim, sourceAddr comes from the request.
func TestAuditAttribution_Basics(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/whatever", nil)
	req.RemoteAddr = "203.0.113.7:54321"

	actor, claimedActor, sourceAddr := auditAttribution(req, "alice")
	if actor != adminSharedTokenActor {
		t.Errorf("actor = %q, want %q", actor, adminSharedTokenActor)
	}
	if claimedActor == nil || *claimedActor != "alice" {
		t.Errorf("claimedActor = %v, want \"alice\"", claimedActor)
	}
	if sourceAddr == nil || *sourceAddr != "203.0.113.7" {
		t.Errorf("sourceAddr = %v, want \"203.0.113.7\"", sourceAddr)
	}
}

// TestAuditAttribution_EmptyClaimed covers the no-body / no-actor-field
// handlers (RevokeDeviceHandler, TenantPlatformsPutHandler,
// TenantRulesPutHandler/DeleteHandler): claimedActor must be nil, not a
// pointer to an empty string.
func TestAuditAttribution_EmptyClaimed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/admin/whatever", nil)
	req.RemoteAddr = "203.0.113.7:54321"

	actor, claimedActor, _ := auditAttribution(req, "")
	if actor != adminSharedTokenActor {
		t.Errorf("actor = %q, want %q", actor, adminSharedTokenActor)
	}
	if claimedActor != nil {
		t.Errorf("claimedActor = %q, want nil for an empty claim", *claimedActor)
	}
}
