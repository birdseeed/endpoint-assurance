package extractor

// PAT-2055: completeness of the browser_extensions array.
//
// browser_extensions[] carries no completeness state of its own. A profile
// the agent refused or could not read sends no rows, and so does a user
// crowded out by a collector cap, so the array alone never proves an
// extension is gone. The optional browser_extensions_status block says, per
// user and browser, whether the read was complete, partial, not_present or
// failed, and whether the collector hit its row cap. Absent block = an agent
// that predates PAT-2055: unknown, a strict no-op here.
//
// Storage (migration 0177) is browser_extension_device_state (one row per
// device) and browser_extension_collection_state (one row per device, user,
// browser). Readers decide presence through internal/extpresence, which
// requires a complete report after an extension's last_seen before treating
// it as absent, and keeps the pre-PAT-2055 rule for devices with no status.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/metrics"
)

// browserExtensionStatusBrowsers are the per-user browsers the status block
// covers. Safari rows carry no user and are outside the pair vocabulary.
var browserExtensionStatusBrowsers = []string{"chrome", "edge", "firefox"}

type browserExtensionsStatusPart struct {
	CollectionStatus string                            `json:"collection_status"`
	CapReached       bool                              `json:"cap_reached"`
	Users            []browserExtensionsStatusUserPart `json:"users"`
}

type browserExtensionsStatusUserPart struct {
	User             string                            `json:"user"`
	UserID           *string                           `json:"user_id"`
	CollectionStatus string                            `json:"collection_status"`
	Browsers         browserExtensionsStatusBrowserMap `json:"browsers"`
}

// browserExtensionsStatusBrowserMap is a struct, not a map, so the PAT-2021
// key walk rejects a case- or fold-variant browser key ("Chrome").
type browserExtensionsStatusBrowserMap struct {
	Chrome  *string `json:"chrome"`
	Edge    *string `json:"edge"`
	Firefox *string `json:"firefox"`
}

func (b browserExtensionsStatusBrowserMap) get(browser string) *string {
	switch browser {
	case "chrome":
		return b.Chrome
	case "edge":
		return b.Edge
	case "firefox":
		return b.Firefox
	}
	return nil
}

func browserStatusAuthoritative(status string) bool {
	return status == "complete" || status == "not_present"
}

// browserExtensionsBlockAuthoritative: a complete or not_present block that
// did not hit the cap proves the array lists every extension the agent
// collects on the device.
func browserExtensionsBlockAuthoritative(st *browserExtensionsStatusPart) bool {
	return st != nil && !st.CapReached && browserStatusAuthoritative(st.CollectionStatus)
}

type browserExtensionPairState struct {
	user, browser, status string
	authoritative         bool
}

// browserExtensionPairStates flattens the users roster into one entry per
// (stored user, browser). A failed block records no pairs. A pair is
// authoritative only when the block is uncapped and not failed, the user is
// not failed, and the pair itself is complete or not_present. Users that
// collide after the storage truncation merge, least authoritative wins.
func browserExtensionPairStates(st *browserExtensionsStatusPart) []browserExtensionPairState {
	if st == nil || st.CollectionStatus == "failed" {
		return nil
	}
	idx := map[[2]string]int{}
	var out []browserExtensionPairState
	for _, u := range st.Users {
		user := truncateExtField(u.User, extMaxUserAccountLen)
		if user == "" {
			continue
		}
		for _, browser := range browserExtensionStatusBrowsers {
			s := u.Browsers.get(browser)
			if s == nil {
				continue
			}
			ps := browserExtensionPairState{
				user: user, browser: browser, status: *s,
				authoritative: !st.CapReached && u.CollectionStatus != "failed" && browserStatusAuthoritative(*s),
			}
			key := [2]string{user, browser}
			if i, ok := idx[key]; ok {
				if !ps.authoritative {
					out[i] = ps
				}
				continue
			}
			idx[key] = len(out)
			out = append(out, ps)
		}
	}
	return out
}

// upsertBrowserExtensionsStatus records the browser_extensions_status block.
// seenAt is the stamp upsertBrowserExtensions wrote into last_seen for every
// row of this report (browserExtensionSeenAt, taken under the device row
// lock), and it is the only value written to last_complete_at, so a report
// never proves its own extensions gone (readers compare strictly after), and
// reports serialised on the device lock stamp in lock order.
//
// A payload received before the newest report already applied (a replay)
// writes nothing. Every status, failed included, is recorded, so failed and
// not_present stay distinguishable; last_complete_at only moves on an
// authoritative report and never moves back.
//
// A structurally valid block that is inconsistent, with itself or with rows
// (browserExtensionsStatusProblem), is stored as partial with its authority
// withheld and the reason in authority_withheld: the device's inventory is
// still ingested, and nothing is concluded from the block. No pair rows are
// written for it.
func upsertBrowserExtensionsStatus(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID string, st *browserExtensionsStatusPart, rows []browserExtensionPart, seenAt time.Time, logger *slog.Logger) error {
	if st == nil {
		return nil
	}
	status := st.CollectionStatus
	withheld := browserExtensionsStatusProblem(st, rows)
	if withheld != "" {
		metrics.BrowserExtensionStatusWithheldTotal.Inc()
		if logger != nil {
			logger.Warn("browser_extensions_status inconsistent; stored without absence authority",
				"device_id", deviceID, "tenant_id", row.TenantID, "reported_status", status, "reason", withheld)
		}
		status = "partial"
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO browser_extension_device_state (device_id, tenant_id, collection_status, cap_reached, reported_at)
		VALUES ($1::uuid, $2::uuid, $3, FALSE, '-infinity'::timestamptz)
		ON CONFLICT (device_id) DO NOTHING
	`, deviceID, row.TenantID, status); err != nil {
		return fmt.Errorf("create browser extension device state: %w", err)
	}
	var superseded bool
	if err := tx.QueryRow(ctx, `
		SELECT reported_at > $3 FROM browser_extension_device_state
		WHERE device_id = $1::uuid AND tenant_id = $2::uuid
		FOR UPDATE
	`, deviceID, row.TenantID, row.ReceivedAt).Scan(&superseded); err != nil {
		return fmt.Errorf("lock browser extension device state: %w", err)
	}
	if superseded {
		if logger != nil {
			logger.Info("browser_extensions_status older than the device's newest report; not recorded",
				"device_id", deviceID, "status", st.CollectionStatus)
		}
		return nil
	}

	authoritative := withheld == "" && browserExtensionsBlockAuthoritative(st)
	if _, err := tx.Exec(ctx, `
		UPDATE browser_extension_device_state SET
			collection_status  = $3,
			cap_reached        = $4,
			reported_at        = $5,
			last_complete_at   = CASE WHEN $6 THEN $7::timestamptz ELSE last_complete_at END,
			authority_withheld = NULLIF($8, ''),
			updated_at         = now()
		WHERE device_id = $1::uuid AND tenant_id = $2::uuid
	`, deviceID, row.TenantID, status, st.CapReached, row.ReceivedAt,
		authoritative, seenAt, withheld); err != nil {
		return fmt.Errorf("update browser extension device state: %w", err)
	}

	var pairs []browserExtensionPairState
	if withheld == "" {
		pairs = browserExtensionPairStates(st)
	}
	if len(pairs) > 0 {
		users := make([]string, len(pairs))
		browsers := make([]string, len(pairs))
		statuses := make([]string, len(pairs))
		auth := make([]bool, len(pairs))
		for i, p := range pairs {
			users[i], browsers[i], statuses[i], auth[i] = p.user, p.browser, p.status, p.authoritative
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO browser_extension_collection_state (
				device_id, tenant_id, user_account, browser, collection_status, reported_at, last_complete_at
			)
			SELECT $1::uuid, $2::uuid, u.usr, u.br, u.st, $3, CASE WHEN u.auth THEN $8::timestamptz END
			FROM unnest($4::text[], $5::text[], $6::text[], $7::bool[]) AS u(usr, br, st, auth)
			ON CONFLICT (device_id, user_account, browser) DO UPDATE SET
				collection_status = EXCLUDED.collection_status,
				reported_at       = EXCLUDED.reported_at,
				last_complete_at  = COALESCE(EXCLUDED.last_complete_at, browser_extension_collection_state.last_complete_at),
				updated_at        = now()
			WHERE browser_extension_collection_state.tenant_id = EXCLUDED.tenant_id
		`, deviceID, row.TenantID, row.ReceivedAt, users, browsers, statuses, auth, seenAt); err != nil {
			return fmt.Errorf("upsert browser extension collection state: %w", err)
		}
	}

	if status != "complete" && logger != nil {
		logger.Info("browser extension collection not complete",
			"device_id", deviceID, "status", status, "cap_reached", st.CapReached)
	}
	return nil
}

// browserExtensionSeenAt takes the device row lock and returns
// clock_timestamp() under it. upsertBrowserExtensions stamps last_seen and
// upsertBrowserExtensionsStatus stamps last_complete_at with this one value.
//
// now() is the transaction START time. Two extractions for one device
// serialise on the devices row lock (upsertDevice already holds it; the FOR
// UPDATE here makes the dependency explicit), but the one that started first
// can take the lock second. With now(), its extensions would be stamped
// before the other report's completion time and read as gone although its
// report is the later one (PAT-2055 review P3). A stamp read under the lock
// orders by lock acquisition instead.
func browserExtensionSeenAt(ctx context.Context, tx pgx.Tx, deviceID string) (time.Time, error) {
	var ts time.Time
	if err := tx.QueryRow(ctx, `
		SELECT clock_timestamp() FROM devices WHERE id = $1::uuid FOR UPDATE
	`, deviceID).Scan(&ts); err != nil {
		return time.Time{}, fmt.Errorf("lock device for browser extensions: %w", err)
	}
	return ts, nil
}
