package intune

import (
	"context"
	"encoding/json"
	"fmt"

	"patched.im/api/internal/msgraph"
)

// settingDefinitionsPath is beta-only, like Settings Catalog itself (see
// intune.go's package doc on why beta surfaces get their own file). Graph's
// setting-catalog definition catalogue is shared across an Intune tenant's
// configuration policies; it is not scoped to a single policy.
const settingDefinitionsPath = "/deviceManagement/configurationSettings"

// GraphBetaBaseURL is Microsoft Graph's beta surface, where the
// setting-catalog definition endpoints live (they do not exist on v1.0).
// msgraph.Client defaults to v1.0 (see internal/msgraph/client.go), so a
// caller wiring up GraphDefinitionSource for real use needs a *msgraph.Client
// whose BaseURL is set to this — e.g.:
//
//	betaClient := msgraph.NewClient(tokens)
//	betaClient.BaseURL = intune.GraphBetaBaseURL
//
// FetchAll deliberately does not override BaseURL itself: same convention
// as CompliancePolicySource (compliance.go), which calls client.GetAll/Get
// against whatever base the caller configured rather than deciding a
// version internally. That keeps this file's only beta-specific knowledge
// to the path/shape below, and keeps FetchAll trivially testable against an
// httptest server whose URL becomes the client's BaseURL directly (see
// settingscatalog_source_test.go) — a hardcoded production host here would
// make that impossible to point at a fake server.
const GraphBetaBaseURL = "https://graph.microsoft.com/beta"

// graphOptionDefinition mirrors one entry of Graph's
// deviceManagementConfigurationOptionDefinition.
type graphOptionDefinition struct {
	ItemID      string `json:"itemId"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

// graphSettingDefinition mirrors the fields this package resolves against
// on Graph's deviceManagementConfigurationSettingDefinition (and its
// choice/simple subclasses) — deliberately narrow: this package has no use
// for the rest of the definition body (constraints, applicability,
// dependents, etc.), so it is not decoded here.
type graphSettingDefinition struct {
	ID          string                  `json:"id"`
	Version     string                  `json:"version"`
	DisplayName string                  `json:"displayName"`
	Description string                  `json:"description"`
	Options     []graphOptionDefinition `json:"options"`
}

// DefinitionSource fetches the current Settings Catalog setting-definition
// catalogue from Microsoft Graph. It is the seam PostgresDefinitionStore
// (or any other DefinitionCache/writer) refreshes itself from — see
// RefreshDefinitions.
//
// Definitions are large (Microsoft's full catalogue runs into the
// thousands) and change rarely — on Microsoft's own Intune release
// cadence, not per-diff or per-resolve-call. DefinitionSource therefore
// exposes one bulk FetchAll, not a per-id lookup: the intended usage is a
// slow-scheduled full refresh (daily/weekly; the scheduler itself is out of
// scope for this ticket, same as PAT-1662 left its own scheduling out),
// never a live call on the resolution hot path. Resolver.Resolve never
// calls this — it only ever reads from a DefinitionCache.
type DefinitionSource interface {
	FetchAll(ctx context.Context, client *msgraph.Client, tenantID string) ([]SettingDefinition, error)
}

// GraphDefinitionSource is the production DefinitionSource, backed by
// Microsoft Graph's beta setting-catalog definition endpoint.
type GraphDefinitionSource struct{}

// FetchAll fetches every setting definition Graph reports, verbatim
// paginated via client's existing @odata.nextLink handling. client must
// already be configured for the beta surface (BaseURL == GraphBetaBaseURL
// in production; an httptest server URL in tests) — see GraphBetaBaseURL's
// doc for why FetchAll does not decide that itself.
func (GraphDefinitionSource) FetchAll(ctx context.Context, client *msgraph.Client, tenantID string) ([]SettingDefinition, error) {
	raw, err := client.GetAll(ctx, tenantID, settingDefinitionsPath, nil)
	if err != nil {
		return nil, fmt.Errorf("intune: list setting definitions: %w", err)
	}

	defs := make([]SettingDefinition, 0, len(raw))
	for _, r := range raw {
		var g graphSettingDefinition
		if err := json.Unmarshal(r, &g); err != nil {
			return nil, fmt.Errorf("intune: decode setting definition: %w", err)
		}
		def := SettingDefinition{
			ID:          g.ID,
			Version:     g.Version,
			DisplayName: g.DisplayName,
			Description: g.Description,
		}
		for _, o := range g.Options {
			def.Options = append(def.Options, SettingOption{
				ID:          o.ItemID,
				DisplayName: o.DisplayName,
				Description: o.Description,
			})
		}
		defs = append(defs, def)
	}
	return defs, nil
}

// DefinitionWriter is the write half of a definition cache: populating it
// from a DefinitionSource fetch. Kept separate from DefinitionCache (the
// read half Resolver depends on) so Resolver's dependency stays exactly the
// pure, network-free surface it needs — nothing about Resolver requires a
// cache to be writable at all.
type DefinitionWriter interface {
	// PutAll (re)populates the cache with defs, keyed by (ID, Version) per
	// definition. Implementations should upsert per (id, version): refetching
	// the same version is expected to be idempotent, and a definition
	// previously cached under an older version must be left in place
	// (never deleted) so a policy still citing that older version keeps
	// resolving correctly — see the package doc on version mismatches.
	PutAll(ctx context.Context, defs []SettingDefinition) error
}

// RefreshDefinitions fetches the full setting-definition catalogue from
// source and writes it into writer. It performs exactly one fetch-and-write
// pass; scheduling a slow, recurring refresh (this package's fetch is
// intended to run far less often than resolution reads) is the caller's
// job — see DefinitionSource's doc for why that scheduler is deliberately
// not built here.
func RefreshDefinitions(ctx context.Context, client *msgraph.Client, tenantID string, source DefinitionSource, writer DefinitionWriter) error {
	defs, err := source.FetchAll(ctx, client, tenantID)
	if err != nil {
		return fmt.Errorf("intune: refresh setting definitions: %w", err)
	}
	if err := writer.PutAll(ctx, defs); err != nil {
		return fmt.Errorf("intune: write refreshed setting definitions: %w", err)
	}
	return nil
}
