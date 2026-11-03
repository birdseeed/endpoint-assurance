package handlers

// GET /admin/tenants/{tenantID}/intune-config-changes — PAT-1684: the HTTP
// surface PAT-1664's diff engine (internal/intune/diff.go) shipped without.
// That file's own header comment says exactly what was deferred: "A later
// ticket can add the Store queries and HTTP handler that fetch a specific
// pair of snapshots and expose this as an endpoint; that is
// presentation-layer work, not part of this engine." This is that ticket.
//
// Diffs the tenant's two most recent COMPLETE Intune config snapshots for
// one object_type (only compliance_policy exists today — PAT-1662) via
// intune.Diff, and returns the resulting change list filtered per PAT-1664's
// own "Surface" section: by object, by kind of change, and by date range.
// Internal listener only (:8081), protected by requireInternalToken
// (ADMIN_API_TOKEN) applied to the whole internal router in main.go — same
// application-layer auth as every other /admin/* route (see AGENTS.md
// "Auth model" and audit_events_admin.go's precedent for this exact route
// shape). Network placement on :8081 is defence in depth, not the only
// control.
//
// Every entry's field-level summary (setting_changes/assignment_changes)
// comes straight from intune.Diff, unchanged. full_payload.before/after is
// added at this layer: the whole raw object body from each snapshot, keyed
// by graph_object_id off the same intune.Snapshot pair the diff was
// computed from — Diff itself only ever returns the fields that changed,
// per PAT-1664's own scope ("here specifically is what changed"), so a link
// through to the complete before/after document is presentation work on top
// of the engine's output, not a change to it.
//
// Filtering happens entirely at this layer, after intune.Diff has already
// produced its full (deterministic, honesty-rule-bound) ChangeList — the
// engine itself takes no query parameters and its output does not change
// shape depending on what a caller asks for.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/intune"
)

var intuneConfigChangeValidObjectTypes = map[string]bool{
	string(intune.ObjectTypeCompliancePolicy): true,
}

var intuneConfigChangeValidKinds = map[string]bool{
	string(intune.EntryCreated):           true,
	string(intune.EntryDeleted):           true,
	string(intune.EntryRenamed):           true,
	string(intune.EntrySettingsChanged):   true,
	string(intune.EntryAssignmentChanged): true,
}

type intuneSettingChangeResponse struct {
	Key    string          `json:"key"`
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
}

type intuneAssignmentChangeResponse struct {
	Action   string `json:"action"`
	GroupID  string `json:"group_id"`
	Excluded bool   `json:"excluded"`
}

type intuneFullPayloadResponse struct {
	// Before/After are the whole raw object body from the prior/current
	// snapshot, omitted (not null) on the side that has none — an
	// EntryCreated-only entry has no Before, an EntryDeleted-only entry has
	// no After, matching Diff's own "no counterpart to compare against"
	// rule for those two kinds.
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
}

type intuneConfigChangeEntryResponse struct {
	GraphObjectID       string                           `json:"graph_object_id"`
	DisplayName         string                           `json:"display_name"`
	PreviousDisplayName string                           `json:"previous_display_name,omitempty"`
	Kinds               []string                         `json:"kinds"`
	SettingChanges      []intuneSettingChangeResponse    `json:"setting_changes,omitempty"`
	AssignmentChanges   []intuneAssignmentChangeResponse `json:"assignment_changes,omitempty"`
	FullPayload         intuneFullPayloadResponse        `json:"full_payload"`
}

// IntuneConfigChangesHandler serves GET /admin/tenants/{tenantID}/intune-config-changes.
//
// Query params:
//
//	object_type      optional, default "compliance_policy" (the only type
//	                 PAT-1662 pulls today).
//	graph_object_id  optional — only the entry for this object, if any.
//	kind             optional — only entries whose kinds include this one
//	                 (created | deleted | renamed | settings_changed |
//	                 assignment_changed).
//	since, until     optional RFC3339 — only return entries when the diffed
//	                 snapshot pair's detection window overlaps [since,
//	                 until]. A diff's window is the whole pair's window
//	                 (see intune.ChangeList's own doc comment: a change is
//	                 only ever known to have happened somewhere inside it,
//	                 never at a precise instant), so this is a window-level
//	                 filter, not a per-entry one — there is no per-entry
//	                 timestamp to filter on without fabricating one, which
//	                 is exactly what PAT-1664's honesty rules forbid.
func IntuneConfigChangesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	store := intune.NewPostgresStore(pool)
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		logger := slog.With("req_id", reqID, "handler", "intune_config_changes", "tenant_id", tenantID)

		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		q := r.URL.Query()

		objectType := strings.TrimSpace(q.Get("object_type"))
		if objectType == "" {
			objectType = string(intune.ObjectTypeCompliancePolicy)
		}
		if !intuneConfigChangeValidObjectTypes[objectType] {
			http.Error(w, "object_type must be one of: compliance_policy", http.StatusBadRequest)
			return
		}

		kindFilter := strings.TrimSpace(q.Get("kind"))
		if kindFilter != "" && !intuneConfigChangeValidKinds[kindFilter] {
			http.Error(w, "kind must be one of: created, deleted, renamed, settings_changed, assignment_changed", http.StatusBadRequest)
			return
		}
		objectFilter := strings.TrimSpace(q.Get("graph_object_id"))

		var since, until time.Time
		if s := q.Get("since"); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				http.Error(w, "since must be RFC3339", http.StatusBadRequest)
				return
			}
			since = t
		}
		if s := q.Get("until"); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				http.Error(w, "until must be RFC3339", http.StatusBadRequest)
				return
			}
			until = t
		}
		if !since.IsZero() && !until.IsZero() && !until.After(since) {
			http.Error(w, "until must be after since", http.StatusBadRequest)
			return
		}

		prior, current, ok, err := store.LatestCompletePair(r.Context(), tenantID, intune.ObjectType(objectType))
		if err != nil {
			logger.Error("load latest complete snapshot pair failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			logger.Info("fewer than two complete snapshots on record; nothing to diff")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tenant_id":         tenantID,
				"object_type":       objectType,
				"has_snapshot_pair": false,
				"entries":           []intuneConfigChangeEntryResponse{},
			})
			return
		}

		changeList, err := intune.Diff(prior, current)
		if err != nil {
			logger.Error("diff failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		inRange := true
		if !since.IsZero() && changeList.WindowEnd.Before(since) {
			inRange = false
		}
		if !until.IsZero() && changeList.WindowStart.After(until) {
			inRange = false
		}

		priorByID := indexIntuneObjects(prior.Objects)
		currentByID := indexIntuneObjects(current.Objects)

		entries := make([]intuneConfigChangeEntryResponse, 0, len(changeList.Entries))
		if inRange {
			for _, e := range changeList.Entries {
				if objectFilter != "" && e.GraphObjectID != objectFilter {
					continue
				}
				if kindFilter != "" && !intuneEntryHasKind(e.Kinds, intune.ChangeEntryKind(kindFilter)) {
					continue
				}
				entries = append(entries, buildIntuneChangeEntryResponse(e, priorByID, currentByID))
			}
		}

		logger.Info("intune config changes listed", "count", len(entries), "unfiltered_count", len(changeList.Entries))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id":         tenantID,
			"object_type":       objectType,
			"has_snapshot_pair": true,
			"window_start":      changeList.WindowStart.UTC().Format(time.RFC3339Nano),
			"window_end":        changeList.WindowEnd.UTC().Format(time.RFC3339Nano),
			"entries":           entries,
		})
	}
}

func indexIntuneObjects(objs []intune.ObjectRecord) map[string]intune.ObjectRecord {
	out := make(map[string]intune.ObjectRecord, len(objs))
	for _, o := range objs {
		out[o.GraphObjectID] = o
	}
	return out
}

func intuneEntryHasKind(kinds []intune.ChangeEntryKind, want intune.ChangeEntryKind) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}

func buildIntuneChangeEntryResponse(e intune.ChangeEntry, priorByID, currentByID map[string]intune.ObjectRecord) intuneConfigChangeEntryResponse {
	kinds := make([]string, 0, len(e.Kinds))
	for _, k := range e.Kinds {
		kinds = append(kinds, string(k))
	}

	settingChanges := make([]intuneSettingChangeResponse, 0, len(e.SettingChanges))
	for _, sc := range e.SettingChanges {
		settingChanges = append(settingChanges, intuneSettingChangeResponse{
			Key:    sc.Key,
			Before: sc.Before,
			After:  sc.After,
		})
	}

	assignmentChanges := make([]intuneAssignmentChangeResponse, 0, len(e.AssignmentChanges))
	for _, ac := range e.AssignmentChanges {
		assignmentChanges = append(assignmentChanges, intuneAssignmentChangeResponse{
			Action:   string(ac.Action),
			GroupID:  ac.GroupID,
			Excluded: ac.Excluded,
		})
	}

	var full intuneFullPayloadResponse
	if before, ok := priorByID[e.GraphObjectID]; ok {
		full.Before = before.RawBody
	}
	if after, ok := currentByID[e.GraphObjectID]; ok {
		full.After = after.RawBody
	}

	return intuneConfigChangeEntryResponse{
		GraphObjectID:       e.GraphObjectID,
		DisplayName:         e.DisplayName,
		PreviousDisplayName: e.PreviousDisplayName,
		Kinds:               kinds,
		SettingChanges:      settingChanges,
		AssignmentChanges:   assignmentChanges,
		FullPayload:         full,
	}
}
