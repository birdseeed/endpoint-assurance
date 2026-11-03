package extractor

// PAT-2067: absence authority for Safari app extensions.
//
// PAT-2064 stores Safari app-extension rows in device_browser_extensions
// (browser = 'safari', user_account and profile the SafariSystemSentinel).
// browser_extensions_status only speaks for chrome, edge and firefox, so
// until now no report could prove a Safari extension gone, and
// internal/extpresence never marked a Safari row absent. A removed Safari
// extension therefore stayed present for ever.
//
// collection_status.safari_extensions is Safari's own signal. It says
// whether the agent walked every Safari app-extension location without an
// error:
//
//   - "complete" on a schema v3 payload that also sent a browser_extensions
//     array, and whose browser_extensions_status (if sent) did not hit the
//     row cap, is authority: every stored Safari row this report did not
//     list is gone. An empty list (no Safari rows at all) is a valid
//     complete claim and makes every stored Safari row absent, the same as
//     apps "complete" with an empty array.
//   - "partial" and "unavailable" record that the report happened and grant
//     nothing.
//   - An absent key (every agent before PAT-2067) is a strict no-op: Safari
//     rows keep today's behaviour and are never marked absent.
//
// Authority is stored as browser_extension_device_state.safari_complete_at
// (migration 0179), stamped with the same seenAt this report wrote into
// device_browser_extensions.last_seen. extpresence compares strictly after
// last_seen, so a report never proves its own Safari rows gone. Each trusted
// complete sets the column to its own stamp (not GREATEST: a server clock
// step back must never leave an older, larger stamp that outranks rows this
// report just listed), and safari_reported_at (the payload received_at,
// forward-only) keeps an older replay from stamping authority over a newer
// report.
//
// The per-device state row is created by upsertBrowserExtensionsStatus.
// When a device has never sent browser_extensions_status there is no row,
// the signal is not recorded, and extpresence keeps the reader's legacy rule
// for that device (StatusKnownSQL is false), exactly as before. Current
// macOS agents send both in the same report.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// browserExtensionAgentRowCap is the agents' shared browser_extensions row
// cap (macOS browser_extensions.sh, Windows BrowserExtensionScanner). A
// report that reaches it may have skipped Safari, which is walked last.
const browserExtensionAgentRowCap = 1000

// safariSignal is collection_status.safari_extensions, resolved.
type safariSignal struct {
	// sent: the payload carried a safari_extensions value.
	sent bool
	// authoritative: the value grants Safari absence authority.
	authoritative bool
	// withheld is a fixed reason token when a "complete" (or an
	// inconsistent value) was not trusted. Never a payload value.
	withheld string
}

// resolveSafariSignal reads collection_status.safari_extensions against the
// rest of the payload.
func resolveSafariSignal(p *payload) safariSignal {
	raw := ""
	if p.CollectionStatus != nil {
		raw = p.CollectionStatus.SafariExtensions
	}
	if raw == "" {
		return safariSignal{}
	}
	status, known := normaliseCollectionStatus(raw)
	if !known {
		// ValidatePayload rejects an unknown value with a 400 before
		// storage; this is defence in depth for rows stored earlier.
		return safariSignal{sent: true, withheld: "unrecognised_status"}
	}
	switch status {
	case statusComplete:
		switch {
		case p.SchemaVersion < 3:
			// Inventory authority is a schema v3 contract, as for apps.
			return safariSignal{sent: true, withheld: "legacy_schema"}
		case !p.BrowserExtensionsPresent:
			return safariSignal{sent: true, withheld: "complete_without_browser_extensions_array"}
		case p.BrowserExtensionsStatus == nil:
			// Without the block there is no cap_reached to check, and
			// the macOS agent walks Safari last under one shared row
			// cap: a cap hit by Chrome, Edge and Firefox skips Safari
			// entirely, so an unguarded complete would wipe it.
			return safariSignal{sent: true, withheld: "complete_without_browser_extensions_status"}
		case p.BrowserExtensionsStatus.CapReached:
			// A capped collector may have cut Safari rows too.
			return safariSignal{sent: true, withheld: "cap_reached"}
		case len(p.BrowserExtensions) >= browserExtensionAgentRowCap:
			// A full array is a cap in all but name, whatever the block says.
			return safariSignal{sent: true, withheld: "row_cap_full"}
		}
		return safariSignal{sent: true, authoritative: true}
	case statusUnavailable:
		for _, e := range p.BrowserExtensions {
			if e.Browser == safariBrowser {
				return safariSignal{sent: true, withheld: "unavailable_with_safari_rows_listed"}
			}
		}
	}
	return safariSignal{sent: true}
}

// upsertSafariExtensionsAuthority records collection_status.safari_extensions
// on browser_extension_device_state. seenAt is the stamp
// upsertBrowserExtensions wrote into last_seen for every row of this report.
func upsertSafariExtensionsAuthority(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID string, p *payload, seenAt time.Time, logger *slog.Logger) error {
	sig := resolveSafariSignal(p)
	if !sig.sent {
		return nil
	}
	if sig.withheld != "" && logger != nil {
		logger.Warn("collection_status.safari_extensions not trusted; no Safari absence authority",
			"device_id", deviceID, "tenant_id", row.TenantID, "reason", sig.withheld)
	}

	var superseded bool
	err := tx.QueryRow(ctx, `
		SELECT safari_reported_at IS NOT NULL AND safari_reported_at > $3
		FROM browser_extension_device_state
		WHERE device_id = $1::uuid AND tenant_id = $2::uuid
		FOR UPDATE
	`, deviceID, row.TenantID, row.ReceivedAt).Scan(&superseded)
	if errors.Is(err, pgx.ErrNoRows) {
		if logger != nil {
			logger.Info("collection_status.safari_extensions sent without any browser_extensions_status state; not recorded",
				"device_id", deviceID, "tenant_id", row.TenantID)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("lock browser extension device state for safari: %w", err)
	}
	if superseded {
		if logger != nil {
			logger.Info("collection_status.safari_extensions older than the device's newest Safari report; not recorded",
				"device_id", deviceID)
		}
		return nil
	}

	if _, err := tx.Exec(ctx, `
		UPDATE browser_extension_device_state SET
			safari_reported_at = $3,
			safari_complete_at = CASE WHEN $4
				THEN $5::timestamptz
				ELSE safari_complete_at END,
			updated_at         = now()
		WHERE device_id = $1::uuid AND tenant_id = $2::uuid
	`, deviceID, row.TenantID, row.ReceivedAt, sig.authoritative, seenAt); err != nil {
		return fmt.Errorf("update browser extension device state for safari: %w", err)
	}
	return nil
}
