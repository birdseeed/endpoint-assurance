package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/cvepipeline"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

func TestPortalSoftwareHandlerRejectsOversizedSearchBeforeDatabaseAccess(t *testing.T) {
	h := PortalSoftwareHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/portal/software?search="+strings.Repeat("x", 257), nil)
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{TenantID: "tenant"}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestPortalSoftwareHandlerFailsClosedWithoutPortalIdentity(t *testing.T) {
	h := PortalSoftwareHandler(nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/portal/software", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d: %s", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
}

func TestPortalSoftwareResponseUsesQueryTimestamp(t *testing.T) {
	queryAt := time.Date(2026, time.September, 20, 12, 34, 56, 0, time.UTC)
	response := portalSoftwareResponse(report.PortalSoftwarePage{GeneratedAt: queryAt},
		map[cvepipeline.EstateProductKey]cvepipeline.EstateAssessment{}, 10, 0)
	if !response.GeneratedAt.Equal(queryAt) {
		t.Errorf("generated_at = %s, want query timestamp %s", response.GeneratedAt, queryAt)
	}
}
