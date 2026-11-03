package removal

import (
	"fmt"
	"time"
)

// DryRunMaxAge is the absolute ceiling on how old a dry run may be and still
// support an authorisation.
//
// Twenty-four hours, chosen against how this estate actually reports: agents
// upload inventory on a daily cycle, so a preview older than one full cycle
// has almost certainly missed at least one upload, and one that has not is
// from an estate quiet enough that the watermark rule below cannot vouch for
// it either. The ceiling is the backstop for exactly that quiet case. The
// watermark rule is the precise one and does the real work; this catches the
// estate where nothing reported at all, where "no new inventory" is
// indistinguishable from "no inventory is arriving any more".
//
// PAT-1598's own rule is that a stale preview is worse than none, so
// re-running is the remedy for every staleness verdict here. Re-running a
// dry run is cheap, appends a fresh snapshot and costs an operator one
// request; proceeding on a stale one risks deleting software from a device
// that was never previewed.
const DryRunMaxAge = 24 * time.Hour

// Staleness is the verdict on whether one dry run may still be authorised
// against, plus every reason it may not. All reasons are collected rather
// than short-circuiting on the first, because an operator fixing one cause
// should not have to discover the next one on the retry.
type Staleness struct {
	Stale   bool
	Reasons []string
}

// CheckStaleness decides whether a dry run computed at computedAt, over a
// tenant whose inventory watermark was then, is still usable now that the
// tenant's watermark is current.
//
// Pure on purpose: the DB reads that produce its inputs are in
// InventoryWatermark, so the rule itself is unit-testable without a database
// and cannot drift between the endpoint that enforces it and the test that
// proves it.
func CheckStaleness(computedAt time.Time, then *time.Time, now time.Time, current Watermark) Staleness {
	var s Staleness

	if age := now.Sub(computedAt); age > DryRunMaxAge {
		s.Reasons = append(s.Reasons, fmt.Sprintf(
			"dry run was computed %s ago, beyond the %s ceiling",
			age.Round(time.Minute), DryRunMaxAge))
	}

	switch {
	case then == nil && current.DeviceCount > 0:
		// The preview was computed over an estate with no devices in it. Any
		// device present now is a device the preview never considered.
		s.Reasons = append(s.Reasons, fmt.Sprintf(
			"the tenant had no devices when the dry run was computed and now has %d", current.DeviceCount))
	case then != nil && current.LastUpload == nil:
		// Devices the preview was computed over are gone. Whatever the
		// preview enumerated, it is not the current estate.
		s.Reasons = append(s.Reasons, "the devices the dry run was computed over no longer exist")
	case then != nil && current.LastUpload != nil && current.LastUpload.After(*then):
		s.Reasons = append(s.Reasons, fmt.Sprintf(
			"inventory has been uploaded since the dry run was computed (latest upload %s, dry run watermark %s)",
			current.LastUpload.UTC().Format(time.RFC3339), then.UTC().Format(time.RFC3339)))
	}

	s.Stale = len(s.Reasons) > 0
	return s
}
