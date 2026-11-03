package remediation

import (
	"encoding/json"
	"fmt"
)

// intuneChoiceSettingValue is the documented Graph
// deviceManagementConfigurationChoiceSettingValue shape.
type intuneChoiceSettingValue struct {
	ODataType string `json:"@odata.type"`
	Value     string `json:"value"`
	Children  []any  `json:"children"`
}

// intuneSettingInstance is the documented Graph
// deviceManagementConfigurationChoiceSettingInstance shape — the settings
// catalogue's wrapper around one settingDefinitionId + chosen value.
type intuneSettingInstance struct {
	ODataType           string                   `json:"@odata.type"`
	SettingDefinitionID string                   `json:"settingDefinitionId"`
	ChoiceSettingValue  intuneChoiceSettingValue `json:"choiceSettingValue"`
}

// intuneSetting wraps one settingInstance — Graph's
// deviceManagementConfigurationSetting envelope.
type intuneSetting struct {
	ODataType       string                `json:"@odata.type"`
	SettingInstance intuneSettingInstance `json:"settingInstance"`
}

// intuneSettingsCataloguePolicy is the top-level body POSTed to
// /deviceManagement/configurationPolicies to create a settings-catalogue
// policy in Intune. Field names and the "windows10"/"mdm" values are the
// documented Microsoft Graph deviceManagementConfigurationPolicy shape.
type intuneSettingsCataloguePolicy struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Platforms    string          `json:"platforms"`
	Technologies string          `json:"technologies"`
	Settings     []intuneSetting `json:"settings"`

	// PatchedProvenance is not part of the Graph schema — an extra top-level
	// field Graph ignores on import elsewhere, carried here purely so the
	// artefact is self-describing about which compliance rule it answers
	// and how confidently its definitionId is sourced, for a human reading
	// the JSON directly (e.g. before pasting it into Intune). Confidence
	// language deliberately avoids overclaiming: "policy_csp_derived" states
	// what it is, not "verified" or "tested against a live tenant".
	PatchedProvenance intuneProvenance `json:"_patched_provenance"`
}

type intuneProvenance struct {
	RuleKey          string `json:"rule_key"`
	BenchmarkVersion string `json:"benchmark_version"`
	SettingSource    string `json:"setting_source"`
	Rationale        string `json:"rationale"`
	GeneratedAt      string `json:"generated_at"`
}

// buildIntuneSettingsCatalogue renders a well-formed Intune settings-
// catalogue JSON payload for the mapped rule in in.Rule.RuleKey. Returns
// ErrNoMapping when no windowsMappings entry exists.
//
// We never touch the customer's tenant (ruling 1): this is a JSON document
// for the customer's own admin to review and import via Graph or the Intune
// admin console, never submitted anywhere by Patched itself.
func buildIntuneSettingsCatalogue(in GenerateInput) ([]byte, error) {
	spec, ok := windowsMappings[in.Rule.RuleKey]
	if !ok {
		return nil, ErrNoMapping
	}

	optionValue := spec.DefinitionID + "_" + spec.EnabledOptionSuffix

	policy := intuneSettingsCataloguePolicy{
		Name:         "Patched: " + in.Rule.Title,
		Description:  fmt.Sprintf("Patched remediation for %s. %s", in.Rule.RuleKey, spec.Rationale),
		Platforms:    "windows10",
		Technologies: "mdm",
		Settings: []intuneSetting{
			{
				ODataType: "#microsoft.graph.deviceManagementConfigurationSetting",
				SettingInstance: intuneSettingInstance{
					ODataType:           "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
					SettingDefinitionID: spec.DefinitionID,
					ChoiceSettingValue: intuneChoiceSettingValue{
						ODataType: "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
						Value:     optionValue,
						Children:  []any{},
					},
				},
			},
		},
		PatchedProvenance: intuneProvenance{
			RuleKey:          in.Rule.RuleKey,
			BenchmarkVersion: in.Rule.BenchmarkVersion,
			SettingSource:    "policy_csp_derived",
			Rationale:        spec.Rationale,
			GeneratedAt:      in.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		},
	}

	// Indented for a human reviewing the artefact before import; Graph
	// accepts either. Stable key order comes from the struct field order
	// above (encoding/json preserves declared field order), so content_hash
	// is deterministic for identical inputs.
	return json.MarshalIndent(policy, "", "  ")
}
