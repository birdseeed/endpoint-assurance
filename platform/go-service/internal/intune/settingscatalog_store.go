package intune

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresDefinitionStore is the production DefinitionCache/DefinitionWriter,
// backed by migrations/0125_settings_catalog_definitions.sql. Unlike
// PostgresStore (postgres_store.go), this table is upserted, not
// append-only — see that migration's comment for why: this is a resolution
// cache, not audit evidence, and re-fetching the same (definition_id,
// version) is expected to be idempotent.
//
// Chosen over an in-memory-only cache because setting definitions need to
// survive a process restart: Microsoft's full catalogue is large, and
// refetching it from Graph on every deploy/restart just to answer the next
// resolve call would turn an intentionally slow-scheduled refresh (see
// DefinitionSource's doc) into a per-restart cost. A DB table also matches
// this package's existing pattern of a small Store-shaped type per
// concern (Store for snapshots, this for definitions) rather than a
// bespoke file-cache format.
type PostgresDefinitionStore struct {
	Pool *pgxpool.Pool
}

// NewPostgresDefinitionStore wraps an existing pool. Pool lifecycle is the
// caller's, same convention as NewPostgresStore.
func NewPostgresDefinitionStore(pool *pgxpool.Pool) *PostgresDefinitionStore {
	return &PostgresDefinitionStore{Pool: pool}
}

type storedOption struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

// Get implements DefinitionCache: an exact (definitionID, version) lookup.
func (s *PostgresDefinitionStore) Get(ctx context.Context, definitionID, version string) (SettingDefinition, bool, error) {
	var def SettingDefinition
	var optionsRaw []byte
	err := s.Pool.QueryRow(ctx, `
		SELECT definition_id, version, display_name, description, options
		FROM intune_setting_definitions
		WHERE definition_id = $1 AND version = $2
	`, definitionID, version).Scan(&def.ID, &def.Version, &def.DisplayName, &def.Description, &optionsRaw)
	if err != nil {
		if err == pgx.ErrNoRows {
			return SettingDefinition{}, false, nil
		}
		return SettingDefinition{}, false, fmt.Errorf("intune: query setting definition: %w", err)
	}

	var opts []storedOption
	if len(optionsRaw) > 0 {
		if err := json.Unmarshal(optionsRaw, &opts); err != nil {
			return SettingDefinition{}, false, fmt.Errorf("intune: decode cached setting definition options: %w", err)
		}
	}
	for _, o := range opts {
		def.Options = append(def.Options, SettingOption(o))
	}
	return def, true, nil
}

// CachedVersion implements VersionAwareCache: the most recently fetched
// version on file for definitionID, regardless of what version a caller is
// actually resolving against. Purely diagnostic — see VersionAwareCache's
// doc.
func (s *PostgresDefinitionStore) CachedVersion(ctx context.Context, definitionID string) (string, bool, error) {
	var version string
	err := s.Pool.QueryRow(ctx, `
		SELECT version
		FROM intune_setting_definitions
		WHERE definition_id = $1
		ORDER BY fetched_at DESC
		LIMIT 1
	`, definitionID).Scan(&version)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", false, nil
		}
		return "", false, fmt.Errorf("intune: query cached setting definition version: %w", err)
	}
	return version, true, nil
}

// PutAll implements DefinitionWriter: upserts every definition, keyed by
// (definition_id, version). A definition previously cached under an older
// version is left untouched — this only ever inserts new rows or refreshes
// an exact (id, version) match, never deletes.
func (s *PostgresDefinitionStore) PutAll(ctx context.Context, defs []SettingDefinition) error {
	if len(defs) == 0 {
		return nil
	}

	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("intune: begin setting definition upsert: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful Commit

	batch := &pgx.Batch{}
	for _, d := range defs {
		opts := make([]storedOption, 0, len(d.Options))
		for _, o := range d.Options {
			opts = append(opts, storedOption(o))
		}
		optionsRaw, err := json.Marshal(opts)
		if err != nil {
			return fmt.Errorf("intune: marshal setting definition %s options: %w", d.ID, err)
		}
		batch.Queue(`
			INSERT INTO intune_setting_definitions
				(definition_id, version, display_name, description, options, fetched_at)
			VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (definition_id, version) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				description  = EXCLUDED.description,
				options      = EXCLUDED.options,
				fetched_at   = EXCLUDED.fetched_at
		`, d.ID, d.Version, d.DisplayName, d.Description, optionsRaw)
	}

	br := tx.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return fmt.Errorf("intune: upsert setting definition at index %d: %w", i, err)
		}
	}
	if err := br.Close(); err != nil {
		return fmt.Errorf("intune: close setting definition upsert batch: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("intune: commit setting definition upsert: %w", err)
	}
	return nil
}
