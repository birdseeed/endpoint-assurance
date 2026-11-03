package extractor

// PAT-2021: typed mirrors of the four blocks the agents collect under
// PAT-2017 (ide_extensions), PAT-2018 (package_managers), PAT-2019
// (local_models) and PAT-2020 (mcp_servers). The macOS collectors
// (updater macos/lib/*.sh) and the Windows contracts
// (windows/src/Shared/Contract/Inventory*.cs) emit the same keys, field for
// field. ValidatePayload (validate_tooling.go) is strict about every level;
// these structs carry only what the extractor stores.
//
// A failed block omits its item list, so the slice is nil. The extractor
// never reads a nil list as "none".

type toolingIssuePart struct {
	Code string `json:"code"`
	Path string `json:"path"`
}

// ide_extensions --------------------------------------------------------------

type ideExtensionsPart struct {
	CollectionStatus string             `json:"collection_status"`
	Truncated        bool               `json:"truncated"`
	TruncationReason *string            `json:"truncation_reason"`
	Users            []toolingUserPart  `json:"users"`
	Profiles         []ideProfilePart   `json:"profiles"`
	Issues           []toolingIssuePart `json:"issues"`
	Extensions       []ideExtensionPart `json:"extensions"`
}

type toolingUserPart struct {
	User             string  `json:"user"`
	UserID           *string `json:"user_id"`
	CollectionStatus string  `json:"collection_status"`
}

type ideProfilePart struct {
	User             string  `json:"user"`
	UserID           *string `json:"user_id"`
	Family           string  `json:"family"`
	Editor           string  `json:"editor"`
	EditorVersion    *string `json:"editor_version"`
	CollectionStatus string  `json:"collection_status"`
	ManifestSource   *string `json:"manifest_source"`
	ExtensionCount   int     `json:"extension_count"`
}

type ideExtensionPart struct {
	User                 string  `json:"user"`
	UserID               *string `json:"user_id"`
	Family               string  `json:"family"`
	Editor               string  `json:"editor"`
	EditorVersion        *string `json:"editor_version"`
	ID                   *string `json:"id"`
	Name                 *string `json:"name"`
	Publisher            *string `json:"publisher"`
	PublisherDisplayName *string `json:"publisher_display_name"`
	Version              *string `json:"version"`
	InstalledAt          *string `json:"installed_at"`
	Source               *string `json:"source"`
	PreRelease           *bool   `json:"pre_release"`
	TargetPlatform       *string `json:"target_platform"`
	Disabled             *bool   `json:"disabled"`
	Directory            *string `json:"directory"`
	ManifestSource       *string `json:"manifest_source"`
	ManifestStatus       *string `json:"manifest_status"`
}

// package_managers ------------------------------------------------------------

type packageManagersPart struct {
	CollectionStatus string                       `json:"collection_status"`
	Truncated        bool                         `json:"truncated"`
	TruncationReason *string                      `json:"truncation_reason"`
	Sources          map[string]packageSourcePart `json:"sources"`
	Users            []toolingUserPart            `json:"users"`
	Locations        []packageLocationPart        `json:"locations"`
	Issues           []toolingIssuePart           `json:"issues"`
	Packages         []packagePart                `json:"packages"`
}

type packageSourcePart struct {
	CollectionStatus string `json:"collection_status"`
	Truncated        bool   `json:"truncated"`
	PackageCount     int    `json:"package_count"`
	LocationCount    int    `json:"location_count"`
}

type packageLocationPart struct {
	Source           string `json:"source"`
	CollectionStatus string `json:"collection_status"`
	PackageCount     int    `json:"package_count"`
}

type packagePart struct {
	Source         string  `json:"source"`
	Manager        string  `json:"manager"`
	Scope          string  `json:"scope"`
	User           *string `json:"user"`
	UserID         *string `json:"user_id"`
	Name           *string `json:"name"`
	Version        *string `json:"version"`
	Prefix         *string `json:"prefix"`
	RuntimeVersion *string `json:"runtime_version"`
	Interpreter    *string `json:"interpreter"`
	Directory      *string `json:"directory"`
	MetadataStatus *string `json:"metadata_status"`
	PipxApp        *string `json:"pipx_app"`
	PipxMain       *bool   `json:"pipx_main"`
}

// local_models ----------------------------------------------------------------

type localModelsPart struct {
	CollectionStatus string                         `json:"collection_status"`
	Truncated        bool                           `json:"truncated"`
	TruncationReason *string                        `json:"truncation_reason"`
	Runtimes         map[string]localRuntimeSummary `json:"runtimes"`
	Totals           *localModelTotalsPart          `json:"totals"`
	Users            []toolingUserPart              `json:"users"`
	Installations    []localRuntimeInstallationPart `json:"installations"`
	Stores           []localModelStorePart          `json:"stores"`
	Issues           []toolingIssuePart             `json:"issues"`
	Models           []localModelPart               `json:"models"`
}

type localRuntimeSummary struct {
	CollectionStatus  string `json:"collection_status"`
	InstallationCount int    `json:"installation_count"`
	StoreCount        int    `json:"store_count"`
	ModelCount        int    `json:"model_count"`
	TotalBytes        int64  `json:"total_bytes"`
}

type localModelTotalsPart struct {
	ModelCount int   `json:"model_count"`
	TotalBytes int64 `json:"total_bytes"`
}

type localRuntimeInstallationPart struct {
	Runtime       string  `json:"runtime"`
	Scope         string  `json:"scope"`
	User          *string `json:"user"`
	UserID        *string `json:"user_id"`
	Kind          string  `json:"kind"`
	Path          string  `json:"path"`
	Version       *string `json:"version"`
	VersionSource string  `json:"version_source"`
	Identifier    *string `json:"identifier"`
}

type localModelStorePart struct {
	Runtime          string `json:"runtime"`
	CollectionStatus string `json:"collection_status"`
	ModelCount       int    `json:"model_count"`
	TotalBytes       int64  `json:"total_bytes"`
}

type localModelPart struct {
	Runtime        string  `json:"runtime"`
	User           *string `json:"user"`
	UserID         *string `json:"user_id"`
	StorePath      string  `json:"store_path"`
	Name           *string `json:"name"`
	Tag            *string `json:"tag"`
	Format         *string `json:"format"`
	SizeBytes      *int64  `json:"size_bytes"`
	FileCount      *int    `json:"file_count"`
	SizeSource     *string `json:"size_source"`
	MissingBlobs   *int    `json:"missing_blobs"`
	MetadataStatus *string `json:"metadata_status"`
}

// mcp_servers -----------------------------------------------------------------

type mcpServersPart struct {
	CollectionStatus string                   `json:"collection_status"`
	Truncated        bool                     `json:"truncated"`
	TruncationReason *string                  `json:"truncation_reason"`
	Clients          map[string]mcpClientPart `json:"clients"`
	Totals           *mcpTotalsPart           `json:"totals"`
	Users            []toolingUserPart        `json:"users"`
	Configs          []mcpConfigPart          `json:"configs"`
	Issues           []toolingIssuePart       `json:"issues"`
	Servers          []mcpServerPart          `json:"servers"`
}

type mcpClientPart struct {
	CollectionStatus string `json:"collection_status"`
	ConfigCount      int    `json:"config_count"`
	ServerCount      int    `json:"server_count"`
}

type mcpTotalsPart struct {
	ConfigCount int `json:"config_count"`
	ServerCount int `json:"server_count"`
}

type mcpConfigPart struct {
	Client           string `json:"client"`
	CollectionStatus string `json:"collection_status"`
	ServerCount      int    `json:"server_count"`
}

// mcpServerPart is the whole of what Patched keeps for an MCP server: the
// PAT-2020 allowlist. There is deliberately no field for arguments, env,
// headers, a URL path or query; the validator rejects a payload carrying one
// (the PAT-2021 privacy guard), and the extractor stores this struct, never
// the raw object, so an unknown key could not reach storage even if it got
// past the validator.
type mcpServerPart struct {
	Client          string  `json:"client"`
	User            *string `json:"user"`
	UserID          *string `json:"user_id"`
	ConfigPath      string  `json:"config_path"`
	Scope           string  `json:"scope"`
	Name            *string `json:"name"`
	Transport       string  `json:"transport"`
	TransportSource string  `json:"transport_source"`
	Executable      *string `json:"executable"`
	Runner          *string `json:"runner"`
	Package         *string `json:"package"`
	PackageStatus   string  `json:"package_status"`
	Host            *string `json:"host"`
}
