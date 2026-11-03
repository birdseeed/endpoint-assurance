package appliedconfig

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Fixture tests for PAT-1668's diff engine. Everything here runs against
// hand-built snapshots shaped exactly like the macOS agent's
// applied_configuration object (PAT-1667) — no live tenant, no database, no
// enrolled Mac.

var (
	t0 = time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)
	t1 = time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	t2 = time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
)

const (
	tenantA  = "11111111-1111-1111-1111-111111111111"
	deviceA  = "aaaaaaaa-0000-0000-0000-000000000001"
	deviceB  = "bbbbbbbb-0000-0000-0000-000000000002"
	deviceC  = "cccccccc-0000-0000-0000-000000000003"
	mdmJamf  = "https://jamf.example.org/mdm"
	mdmIntne = "https://a.manage.microsoft.com/devicegatewayproxy"
)

// fwPayload is the serialised payload-items text the agent emits for a
// firewall profile: a JSON array, because ProfileItems is a list.
const fwPayload = `[{"PayloadType":"com.apple.security.firewall","PayloadIdentifier":"org.example.fw","PayloadContent":{"EnableFirewall":true}}]`

// fwPayloadReordered is byte-different but semantically identical to
// fwPayload — the same keys, serialised in a different order. A repeated
// collection that produces this must diff to nothing.
const fwPayloadReordered = `[{"PayloadContent":{"EnableFirewall":true},"PayloadIdentifier":"org.example.fw","PayloadType":"com.apple.security.firewall"}]`

// fwPayloadChanged flips the firewall setting.
const fwPayloadChanged = `[{"PayloadType":"com.apple.security.firewall","PayloadIdentifier":"org.example.fw","PayloadContent":{"EnableFirewall":false}}]`

const passcodePayload = `[{"PayloadType":"com.apple.mobiledevice.passwordpolicy","PayloadContent":{"minLength":8}}]`

func profileFirewall(payload string) Profile {
	return Profile{
		Identifier:   "org.example.firewall",
		DisplayName:  "Firewall",
		Organization: "Example Ltd",
		Payload:      payload,
	}
}

func profilePasscode() Profile {
	return Profile{
		Identifier:   "org.example.passcode",
		DisplayName:  "Passcode Policy",
		Organization: "Example Ltd",
		Payload:      passcodePayload,
	}
}

// snapshot builds an ok snapshot for deviceA unless overridden.
func snapshot(observedAt time.Time, profiles ...Profile) Snapshot {
	return Snapshot{
		TenantID:         tenantA,
		DeviceID:         deviceA,
		ObservedAt:       observedAt,
		CollectionStatus: CollectionOK,
		ProfilesCount:    len(profiles),
		MDMServerURL:     mdmJamf,
		MDMSupervised:    SupervisedYes,
		Profiles:         profiles,
	}
}

func kindsOf(e ProfileChange) []string {
	out := make([]string, 0, len(e.Kinds))
	for _, k := range e.Kinds {
		out = append(out, string(k))
	}
	return out
}

// ── Acceptance: a profile appeared ───────────────────────────────────────────

func TestDiff_ProfileAppeared(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload))
	current := snapshot(t2, profileFirewall(fwPayload), profilePasscode())

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 1 {
		t.Fatalf("got %d changes, want 1: %+v", len(set.Changes), set.Changes)
	}
	e := set.Changes[0]
	if e.ProfileIdentifier != "org.example.passcode" {
		t.Errorf("identifier = %q, want org.example.passcode", e.ProfileIdentifier)
	}
	if got := kindsOf(e); len(got) != 1 || got[0] != string(ProfileAppeared) {
		t.Errorf("kinds = %v, want [profile_appeared]", got)
	}
	if e.DisplayName != "Passcode Policy" {
		t.Errorf("display name = %q", e.DisplayName)
	}
	if e.PayloadComparison != ComparisonNotCompared {
		t.Errorf("payload comparison = %q, want not_compared (only one side exists)", e.PayloadComparison)
	}
	// The window, not an event time.
	if !e.ObservedBetweenStart.Equal(t1) || !e.ObservedBetweenEnd.Equal(t2) {
		t.Errorf("window = (%s, %s), want (%s, %s)", e.ObservedBetweenStart, e.ObservedBetweenEnd, t1, t2)
	}
	if e.DeviceID != deviceA {
		t.Errorf("device id = %q, want %q", e.DeviceID, deviceA)
	}
	if e.MDMServerURL != mdmJamf {
		t.Errorf("mdm server url = %q, want %q", e.MDMServerURL, mdmJamf)
	}
}

// ── Acceptance: a profile is no longer present ───────────────────────────────

func TestDiff_ProfileNoLongerPresent(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload), profilePasscode())
	current := snapshot(t2, profileFirewall(fwPayload))

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 1 {
		t.Fatalf("got %d changes, want 1: %+v", len(set.Changes), set.Changes)
	}
	e := set.Changes[0]
	if e.ProfileIdentifier != "org.example.passcode" {
		t.Errorf("identifier = %q", e.ProfileIdentifier)
	}
	if got := kindsOf(e); len(got) != 1 || got[0] != string(ProfileNoLongerPresent) {
		t.Errorf("kinds = %v, want [profile_no_longer_present]", got)
	}
	// Last-known display name, since there is no newer side.
	if e.DisplayName != "Passcode Policy" {
		t.Errorf("display name = %q, want the last observed name", e.DisplayName)
	}
}

// ── Acceptance: a profile's payload changed ──────────────────────────────────

func TestDiff_PayloadChanged(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload))
	current := snapshot(t2, profileFirewall(fwPayloadChanged))

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 1 {
		t.Fatalf("got %d changes, want 1: %+v", len(set.Changes), set.Changes)
	}
	e := set.Changes[0]
	if got := kindsOf(e); len(got) != 1 || got[0] != string(ProfilePayloadChanged) {
		t.Errorf("kinds = %v, want [profile_payload_changed]", got)
	}
	if e.PayloadComparison != ComparisonCanonicalJSON {
		t.Errorf("payload comparison = %q, want canonical_json", e.PayloadComparison)
	}
	if len(e.FieldChanges) != 1 || e.FieldChanges[0].Key != fieldPayload {
		t.Fatalf("field changes = %+v, want exactly one payload change", e.FieldChanges)
	}
	before := string(e.FieldChanges[0].Before)
	after := string(e.FieldChanges[0].After)
	if !strings.Contains(before, `"EnableFirewall":true`) {
		t.Errorf("before = %s, want the prior firewall value", before)
	}
	if !strings.Contains(after, `"EnableFirewall":false`) {
		t.Errorf("after = %s, want the current firewall value", after)
	}
	if e.PayloadCapped {
		t.Error("payload capped = true for two uncapped payloads")
	}
}

func TestDiff_DisplayNameAndOrganizationChanged(t *testing.T) {
	before := profileFirewall(fwPayload)
	after := profileFirewall(fwPayload)
	after.DisplayName = "Firewall (v2)"
	after.Organization = "Example Holdings Ltd"

	set, err := Diff(snapshot(t1, before), snapshot(t2, after))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(set.Changes))
	}
	e := set.Changes[0]
	want := []string{string(ProfileDisplayNameChanged), string(ProfileOrganizationChanged)}
	if got := kindsOf(e); !reflect.DeepEqual(got, want) {
		t.Errorf("kinds = %v, want %v", got, want)
	}
	if e.PreviousDisplayName != "Firewall" {
		t.Errorf("previous display name = %q, want Firewall", e.PreviousDisplayName)
	}
	if e.DisplayName != "Firewall (v2)" {
		t.Errorf("display name = %q", e.DisplayName)
	}
}

// ── Acceptance: no change ────────────────────────────────────────────────────

func TestDiff_NoChange(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload), profilePasscode())
	current := snapshot(t2, profileFirewall(fwPayload), profilePasscode())

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 0 {
		t.Errorf("got %d changes, want 0: %+v", len(set.Changes), set.Changes)
	}
	if !set.Notes.Empty() {
		t.Errorf("notes = %+v, want empty", set.Notes)
	}
}

// TestDiff_ReorderedPayloadIsNotAChange is the canonical-JSON property this
// package inherits from internal/configdiff: a profile re-serialised with its
// keys in a different order has not changed.
func TestDiff_ReorderedPayloadIsNotAChange(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload))
	current := snapshot(t2, profileFirewall(fwPayloadReordered))

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 0 {
		t.Errorf("reordered-but-identical payload produced %d changes: %+v", len(set.Changes), set.Changes)
	}
}

// TestDiff_ProfileOrderIsNotAChange: the agent's list order carries no
// meaning, so the same profiles reported in a different order is not change.
func TestDiff_ProfileOrderIsNotAChange(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload), profilePasscode())
	current := snapshot(t2, profilePasscode(), profileFirewall(fwPayload))

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 0 {
		t.Errorf("reordered profile list produced %d changes: %+v", len(set.Changes), set.Changes)
	}
}

// ── Acceptance: a device whose collection failed produces no change entries ──

func TestDiff_FailedCollectionIsNeverADiffInput(t *testing.T) {
	good := snapshot(t1, profileFirewall(fwPayload), profilePasscode())

	for _, status := range []CollectionStatus{CollectionRateLimited, CollectionUnavailable} {
		t.Run(string(status), func(t *testing.T) {
			// The shape that matters: a failed collection whose (cached or
			// empty) profile list would otherwise read as a mass removal.
			failed := Snapshot{
				TenantID:         tenantA,
				DeviceID:         deviceA,
				ObservedAt:       t2,
				CollectionStatus: status,
				MDMServerURL:     mdmJamf,
			}
			set, err := Diff(good, failed)
			if !errors.Is(err, ErrCollectionNotOK) {
				t.Fatalf("Diff(ok, %s) error = %v, want ErrCollectionNotOK", status, err)
			}
			if len(set.Changes) != 0 {
				t.Errorf("a rejected diff still produced %d change entries", len(set.Changes))
			}

			// And the same in the baseline position.
			failedPrior := failed
			failedPrior.ObservedAt = t0
			if _, err := Diff(failedPrior, good); !errors.Is(err, ErrCollectionNotOK) {
				t.Errorf("Diff(%s, ok) error = %v, want ErrCollectionNotOK", status, err)
			}
		})
	}
}

// TestDiff_EmptyOKCollectionIsARealObservation is the other half of that
// rule: an unenrolled Mac genuinely reporting zero profiles IS evidence, and
// a profile leaving that list is a real disappearance.
func TestDiff_EmptyOKCollectionIsARealObservation(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload))
	current := snapshot(t2)
	current.MDMServerURL = ""

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 1 || set.Changes[0].Kinds[0] != ProfileNoLongerPresent {
		t.Fatalf("changes = %+v, want one profile_no_longer_present", set.Changes)
	}
	if set.MDMServerURL != "" || set.PreviousMDMServerURL != mdmJamf {
		t.Errorf("mdm url = %q, previous = %q; want unenrolment to be visible",
			set.MDMServerURL, set.PreviousMDMServerURL)
	}
}

// ── Truncation: a short list cannot support an absence claim ─────────────────

func TestDiff_TruncatedListSuppressesAbsenceConclusions(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload), profilePasscode())
	current := snapshot(t2, profileFirewall(fwPayload))
	current.ProfilesTruncated = true
	current.ProfilesCount = 900

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 0 {
		t.Errorf("a truncated current list produced %d change entries; a capped list cannot prove absence: %+v",
			len(set.Changes), set.Changes)
	}
	if got := set.Notes.SuppressedByTruncation; len(got) != 1 || got[0] != "org.example.passcode" {
		t.Errorf("SuppressedByTruncation = %v, want [org.example.passcode]", got)
	}
}

func TestDiff_TruncatedPriorListSuppressesAppearance(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload))
	prior.ProfilesTruncated = true
	prior.ProfilesCount = 900
	current := snapshot(t2, profileFirewall(fwPayload), profilePasscode())

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 0 {
		t.Errorf("a truncated prior list produced %d appearance entries: %+v", len(set.Changes), set.Changes)
	}
	if got := set.Notes.SuppressedByTruncation; len(got) != 1 {
		t.Errorf("SuppressedByTruncation = %v, want one entry", got)
	}
}

// TestDiff_TruncationDoesNotSuppressFieldChanges: a profile present on both
// sides is fully comparable whatever the cap did to the rest of the list.
func TestDiff_TruncationDoesNotSuppressFieldChanges(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload))
	prior.ProfilesTruncated = true
	current := snapshot(t2, profileFirewall(fwPayloadChanged))
	current.ProfilesTruncated = true

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 1 || set.Changes[0].Kinds[0] != ProfilePayloadChanged {
		t.Fatalf("changes = %+v, want the payload change to survive truncation", set.Changes)
	}
}

// ── Capped and undecodable payloads ──────────────────────────────────────────

func TestDiff_CappedPayloadsCompareAsRawText(t *testing.T) {
	// A head-capped payload is a fragment that does not parse as JSON.
	before := profileFirewall(`[{"PayloadType":"com.apple.security.firew`)
	before.PayloadCapped = true
	after := profileFirewall(`[{"PayloadType":"com.apple.security.firew`)
	after.PayloadCapped = true

	set, err := Diff(snapshot(t1, before), snapshot(t2, after))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 0 {
		t.Errorf("identical capped fragments produced %d changes", len(set.Changes))
	}
	// The caveat must still be visible: equality only holds up to the cap.
	if got := set.Notes.CapLimitedIdentifiers; len(got) != 1 || got[0] != "org.example.firewall" {
		t.Errorf("CapLimitedIdentifiers = %v, want [org.example.firewall]", got)
	}

	after2 := profileFirewall(`[{"PayloadType":"com.apple.security.DIFFE`)
	after2.PayloadCapped = true
	set2, err := Diff(snapshot(t1, before), snapshot(t2, after2))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set2.Changes) != 1 {
		t.Fatalf("differing capped fragments produced %d changes, want 1", len(set2.Changes))
	}
	if set2.Changes[0].PayloadComparison != ComparisonRawText {
		t.Errorf("payload comparison = %q, want raw_text", set2.Changes[0].PayloadComparison)
	}
	if !set2.Changes[0].PayloadCapped {
		t.Error("PayloadCapped = false on a capped comparison")
	}
}

// TestDiff_UndecodablePayloadIsNeverReadAsEmpty: the agent's decode_error
// shape sends an empty payload string for a profile it could not serialise.
// That must not read as "the payload was emptied".
func TestDiff_UndecodablePayloadIsNeverReadAsEmpty(t *testing.T) {
	before := profileFirewall(fwPayload)
	after := Profile{
		Identifier:  "org.example.firewall",
		DisplayName: "Firewall",
		Payload:     "",
		DecodeError: true,
	}
	// Keep organization equal so only the payload could produce an entry.
	after.Organization = before.Organization

	set, err := Diff(snapshot(t1, before), snapshot(t2, after))
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 0 {
		t.Errorf("an undecodable payload produced %d change entries: %+v", len(set.Changes), set.Changes)
	}
	if got := set.Notes.UnreadablePayloadIdentifiers; len(got) != 1 || got[0] != "org.example.firewall" {
		t.Errorf("UnreadablePayloadIdentifiers = %v, want [org.example.firewall]", got)
	}
}

// ── Malformed identity ───────────────────────────────────────────────────────

func TestDiff_UnidentifiedAndAmbiguousProfiles(t *testing.T) {
	blank := Profile{Identifier: "", DisplayName: "", Payload: "", DecodeError: true}
	dupA := profileFirewall(fwPayload)
	dupB := profileFirewall(fwPayloadChanged)

	prior := snapshot(t1, dupA, dupB, blank)
	current := snapshot(t2, dupA, dupB, blank)

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 0 {
		t.Errorf("changes = %+v, want none", set.Changes)
	}
	if set.Notes.UnidentifiedProfiles != 2 {
		t.Errorf("UnidentifiedProfiles = %d, want 2 (one per snapshot)", set.Notes.UnidentifiedProfiles)
	}
	if got := set.Notes.AmbiguousIdentifiers; len(got) != 1 || got[0] != "org.example.firewall" {
		t.Errorf("AmbiguousIdentifiers = %v, want [org.example.firewall]", got)
	}
}

// ── Input validation ─────────────────────────────────────────────────────────

func TestDiff_RejectsMismatchedAndOutOfOrderInputs(t *testing.T) {
	a := snapshot(t1, profileFirewall(fwPayload))

	otherDevice := snapshot(t2, profileFirewall(fwPayload))
	otherDevice.DeviceID = deviceB
	if _, err := Diff(a, otherDevice); !errors.Is(err, ErrSnapshotMismatch) {
		t.Errorf("cross-device diff error = %v, want ErrSnapshotMismatch", err)
	}

	otherTenant := snapshot(t2, profileFirewall(fwPayload))
	otherTenant.TenantID = "22222222-2222-2222-2222-222222222222"
	if _, err := Diff(a, otherTenant); !errors.Is(err, ErrSnapshotMismatch) {
		t.Errorf("cross-tenant diff error = %v, want ErrSnapshotMismatch", err)
	}

	newer := snapshot(t2, profileFirewall(fwPayload))
	if _, err := Diff(newer, a); !errors.Is(err, ErrSnapshotOutOfOrder) {
		t.Errorf("reversed diff error = %v, want ErrSnapshotOutOfOrder", err)
	}
	if _, err := Diff(a, a); !errors.Is(err, ErrSnapshotOutOfOrder) {
		t.Errorf("same-instant diff error = %v, want ErrSnapshotOutOfOrder", err)
	}
}

// ── Acceptance: deterministic output ─────────────────────────────────────────

func TestDiff_IsDeterministic(t *testing.T) {
	// Profiles deliberately supplied in an order that does not match their
	// identifier ordering, so unsorted output would show up.
	zed := Profile{Identifier: "zz.example.vpn", DisplayName: "VPN", Payload: `[{"a":1}]`}
	mid := Profile{Identifier: "mm.example.dns", DisplayName: "DNS", Payload: `[{"b":2}]`}
	prior := snapshot(t1, zed, profileFirewall(fwPayload))
	current := snapshot(t2, mid, profileFirewall(fwPayloadChanged))

	first, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	firstJSON, _ := json.Marshal(first)
	for i := 0; i < 20; i++ {
		again, err := Diff(prior, current)
		if err != nil {
			t.Fatalf("Diff (run %d): %v", i, err)
		}
		againJSON, _ := json.Marshal(again)
		if string(firstJSON) != string(againJSON) {
			t.Fatalf("Diff is not deterministic.\nrun 0: %s\nrun %d: %s", firstJSON, i, againJSON)
		}
	}

	var ids []string
	for _, c := range first.Changes {
		ids = append(ids, c.ProfileIdentifier)
	}
	want := []string{"mm.example.dns", "org.example.firewall", "zz.example.vpn"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("entries = %v, want them sorted by identifier %v", ids, want)
	}
}

// ── Acceptance: honesty rules, checked structurally ──────────────────────────

// outputTypes is every type this package emits. New output types belong in
// this list so the honesty checks below cover them automatically.
func outputTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(ProfileChange{}),
		reflect.TypeOf(DeviceChangeSet{}),
		reflect.TypeOf(DiffNotes{}),
		reflect.TypeOf(ProfileChangeGroup{}),
		reflect.TypeOf(DeviceObservation{}),
		reflect.TypeOf(EstateReport{}),
		reflect.TypeOf(Snapshot{}),
		reflect.TypeOf(Profile{}),
	}
}

// TestOutput_NoActorFieldAnywhere mirrors internal/intune's
// TestDiff_NoActorFieldAnywhere. A Mac reports what is installed, never who
// installed it, so no output type may carry or imply an actor.
func TestOutput_NoActorFieldAnywhere(t *testing.T) {
	suspect := []string{"actor", "who", "author", "changedby", "modifiedby", "performedby", "initiatedby", "admin", "operator"}
	for _, typ := range outputTypes() {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, s := range suspect {
				if strings.Contains(name, s) {
					t.Errorf("%s.%s looks like an actor field; the honesty rule forbids one",
						typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}

// TestOutput_NoAuthoredPolicyVocabulary guards the rule the whole package is
// built around. Applied configuration and authored policy are different
// things; a field named for a policy would be the first step to presenting
// them as the same thing.
func TestOutput_NoAuthoredPolicyVocabulary(t *testing.T) {
	suspect := []string{"policy", "policies", "assignment", "graphobject", "intune"}
	for _, typ := range outputTypes() {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, s := range suspect {
				if strings.Contains(name, s) {
					t.Errorf("%s.%s uses authored-policy vocabulary (%q); this path observes applied configuration only",
						typ.Name(), typ.Field(i).Name, s)
				}
			}
		}
	}
}

// TestOutput_EveryRowIsLabelledAndAttributedToADevice: every emitted row
// must say what kind of observation it is, and every per-device row must say
// which device and between which two observations.
func TestOutput_EveryRowIsLabelledAndAttributedToADevice(t *testing.T) {
	prior := snapshot(t1, profileFirewall(fwPayload), profilePasscode())
	current := snapshot(t2, profileFirewall(fwPayloadChanged))

	set, err := Diff(prior, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if set.ObservationKind != ObservationKind {
		t.Errorf("change set kind = %q, want %q", set.ObservationKind, ObservationKind)
	}
	if len(set.Changes) == 0 {
		t.Fatal("expected change entries to check")
	}
	for _, e := range set.Changes {
		if e.ObservationKind != ObservationKind {
			t.Errorf("entry %s kind = %q, want %q", e.ProfileIdentifier, e.ObservationKind, ObservationKind)
		}
		if e.DeviceID == "" {
			t.Errorf("entry %s has no device id", e.ProfileIdentifier)
		}
		if e.ObservedBetweenStart.IsZero() || e.ObservedBetweenEnd.IsZero() {
			t.Errorf("entry %s has an incomplete observation window", e.ProfileIdentifier)
		}
		if !e.ObservedBetweenEnd.After(e.ObservedBetweenStart) {
			t.Errorf("entry %s window does not advance", e.ProfileIdentifier)
		}
	}

	report, err := Rollup(tenantA, []DeviceChangeSet{set})
	if err != nil {
		t.Fatalf("Rollup: %v", err)
	}
	if report.ObservationKind != ObservationKind {
		t.Errorf("report kind = %q", report.ObservationKind)
	}
	for _, g := range report.Groups {
		if g.ObservationKind != ObservationKind {
			t.Errorf("group %s/%s kind = %q", g.ProfileIdentifier, g.Kind, g.ObservationKind)
		}
	}
}

// TestChangeKindVocabularyIsObservational: the wire-visible kind strings must
// describe what was seen, not an action someone took.
func TestChangeKindVocabularyIsObservational(t *testing.T) {
	forbidden := []string{"removed", "deleted", "installed", "deployed", "assigned", "revoked", "pushed"}
	for _, k := range []ChangeKind{
		ProfileAppeared, ProfileNoLongerPresent, ProfilePayloadChanged,
		ProfileDisplayNameChanged, ProfileOrganizationChanged,
	} {
		for _, f := range forbidden {
			if strings.Contains(string(k), f) {
				t.Errorf("change kind %q implies an action nobody observed", k)
			}
		}
	}
}
