package evidencecatalogue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WindowsDeliveryPublisher belongs to one handler and one pool. It caches only
// successful admission, never errors or freshness. A lock-free head read on
// cached requests still detects another process publishing a higher revision.
type WindowsDeliveryPublisher struct {
	mu       sync.Mutex
	admitted *WindowsDelivery
	publish  func(context.Context, time.Time) (*WindowsDelivery, error)
	check    func(context.Context, *WindowsDelivery) error
}

func NewWindowsDeliveryPublisher(pool *pgxpool.Pool) *WindowsDeliveryPublisher {
	return &WindowsDeliveryPublisher{
		publish: func(ctx context.Context, now time.Time) (*WindowsDelivery, error) {
			return PublishWindowsDelivery(ctx, pool, now)
		},
		check: func(ctx context.Context, candidate *WindowsDelivery) error {
			return checkWindowsDeliveryHead(ctx, pool, candidate)
		},
	}
}

func (p *WindowsDeliveryPublisher) Delivery(ctx context.Context, now time.Time) (*WindowsDelivery, error) {
	delivery, newlyAdmitted, err := p.load(ctx, now)
	if err != nil {
		return nil, err
	}
	if err := delivery.Validate(now); err != nil {
		return nil, err
	}
	if !newlyAdmitted {
		if err := p.check(ctx, delivery); err != nil {
			return nil, err
		}
	}
	return delivery, nil
}

func (p *WindowsDeliveryPublisher) load(ctx context.Context, now time.Time) (*WindowsDelivery, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	newlyAdmitted := false
	if p.admitted == nil {
		delivery, err := p.publish(ctx, now)
		if err != nil {
			return nil, false, err
		}
		if err := delivery.Validate(now); err != nil {
			return nil, false, err
		}
		p.admitted = cloneWindowsDelivery(delivery)
		newlyAdmitted = true
	}
	return cloneWindowsDelivery(p.admitted), newlyAdmitted, nil
}

func cloneWindowsDelivery(delivery *WindowsDelivery) *WindowsDelivery {
	copy := *delivery
	copy.Targets = append([]WindowsTarget{}, delivery.Targets...)
	return &copy
}

func checkWindowsDeliveryHead(ctx context.Context, pool *pgxpool.Pool, candidate *WindowsDelivery) error {
	if pool == nil {
		return errors.New("Windows delivery ledger unavailable")
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT publication FROM windows_installation_evidence_deliveries ORDER BY delivery_version DESC LIMIT 1`).Scan(&raw); err != nil {
		return fmt.Errorf("check cached Windows delivery head: %w", err)
	}
	var head WindowsDelivery
	if err := json.Unmarshal(raw, &head); err != nil {
		return fmt.Errorf("decode cached Windows delivery head: %w", err)
	}
	insert, err := compareWindowsDeliveryHead(candidate, &head, true)
	if err != nil {
		return err
	}
	if insert {
		return errors.New("Windows delivery ledger regressed behind cached admission")
	}
	return nil
}

// PublishWindowsDelivery admits only the compiled reviewed publication. No
// caller-provided document, tenant setting or admin route can publish evidence.
// Errors disable only this additive feature; callers must omit it from config.
func PublishWindowsDelivery(ctx context.Context, pool *pgxpool.Pool, now time.Time) (*WindowsDelivery, error) {
	delivery, err := EmbeddedWindowsDelivery()
	if err != nil {
		return nil, err
	}
	if err := admitWindowsDelivery(ctx, pool, delivery, now); err != nil {
		return nil, err
	}
	return delivery, nil
}

func admitWindowsDelivery(ctx context.Context, pool *pgxpool.Pool, delivery *WindowsDelivery, now time.Time) error {
	if err := delivery.Validate(now); err != nil {
		return err
	}
	if pool == nil {
		return errors.New("Windows delivery ledger unavailable")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Serialize all publications, including the initially empty ledger. The
	// database trigger takes the same lock to enforce sequential inserts.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1921, 1)`); err != nil {
		return err
	}
	var previous WindowsDelivery
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT publication FROM windows_installation_evidence_deliveries ORDER BY delivery_version DESC LIMIT 1`).Scan(&raw)
	found := !errors.Is(err, pgx.ErrNoRows)
	if err != nil && found {
		return fmt.Errorf("read Windows delivery head: %w", err)
	}
	if found {
		if err := json.Unmarshal(raw, &previous); err != nil {
			return fmt.Errorf("decode Windows delivery head: %w", err)
		}
	}
	insert, err := compareWindowsDeliveryHead(delivery, &previous, found)
	if err != nil {
		return err
	}
	if insert {
		raw, err = json.Marshal(delivery)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO windows_installation_evidence_deliveries (delivery_version, publication) VALUES ($1, $2::jsonb)`, delivery.DeliveryVersion, raw); err != nil {
			return fmt.Errorf("append Windows delivery: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func compareWindowsDeliveryHead(candidate, head *WindowsDelivery, found bool) (bool, error) {
	if !found {
		if candidate.DeliveryVersion != 1 {
			return false, errors.New("Windows delivery ledger must start at version 1")
		}
		return true, nil
	}
	if candidate.DeliveryVersion == head.DeliveryVersion {
		candidateJSON, _ := json.Marshal(candidate)
		headJSON, _ := json.Marshal(head)
		if string(candidateJSON) != string(headJSON) {
			return false, errors.New("Windows delivery version reused with different content or metadata")
		}
		return false, nil
	}
	if candidate.DeliveryVersion < head.DeliveryVersion || candidate.DeliveryVersion-head.DeliveryVersion != 1 {
		return false, errors.New("Windows delivery downgrade or nonsequential publication rejected")
	}
	return true, nil
}
