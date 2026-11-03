using System.Text.Json.Serialization;
using Patched.Shared.InstallationEvidence;

namespace Patched.Shared.Contract;

// Observations only. Completeness is not a product identity, compliance or absence verdict.
internal sealed record AppInstallationEvidence
{
    [JsonPropertyName("catalogue_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CatalogueVersion { get; init; }
    [JsonPropertyName("delivery_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? DeliveryVersion { get; init; }
    [JsonPropertyName("content_hash")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ContentHash { get; init; }
    [JsonPropertyName("collection_status")]
    public string CollectionStatus { get; init; } = "unavailable";
    [JsonPropertyName("collected_at")]
    public string CollectedAt { get; init; } = DateTimeOffset.UtcNow.ToString("O");
    [JsonPropertyName("source")]
    public string Source { get; init; } = "windows_authenticode_offline";
    [JsonPropertyName("install_path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? InstallPath { get; init; }
    [JsonPropertyName("executable_path")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExecutablePath { get; init; }
    [JsonPropertyName("executable_sha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExecutableSha256 { get; init; }
    [JsonPropertyName("signature_state")]
    public string SignatureState { get; init; } = "unknown";
    [JsonPropertyName("signer")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Signer { get; init; }
    // PAT-2116: the pinnable publisher, sent only beside "valid" (see SignatureObservation).
    // signer_thumbprint and root_thumbprint are lowercase SHA-256 over the DER certificate;
    // issuer is the leaf's Issuer DN; root_kind is microsoft, public or enterprise.
    [JsonPropertyName("signer_thumbprint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SignerThumbprint { get; init; }
    [JsonPropertyName("issuer")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Issuer { get; init; }
    [JsonPropertyName("root_thumbprint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RootThumbprint { get; init; }
    [JsonPropertyName("root_kind")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RootKind { get; init; }
    // PAT-2116: how the executable was tied to the app row: reviewed_target (the signed
    // curated delivery), display_icon or install_location_single_exe (ExecutableResolver).
    // Absent on a row from an older agent, which only ever had reviewed targets.
    [JsonPropertyName("executable_resolution")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExecutableResolution { get; init; }
    [JsonPropertyName("errors")]
    public IReadOnlyList<string> Errors { get; init; } = [];

    public static AppInstallationEvidence Unavailable(string error) => new() { Errors = [error] };

    internal static AppInstallationEvidence PerUserUnverified() =>
        Unavailable("per_user_scope_unverified") with { ExecutableResolution = ExecutableResolutions.NotAttempted };

    // Copies a signature observation onto the row. Publisher fields travel only with
    // "valid"; every other state carries none, whatever the observation held.
    public AppInstallationEvidence WithSignature(SignatureObservation observation)
    {
        var valid = observation.State == SignatureStates.Valid;
        return this with
        {
            SignatureState = observation.State,
            Signer = valid ? observation.Signer : null,
            SignerThumbprint = valid ? observation.SignerThumbprint : null,
            Issuer = valid ? observation.Issuer : null,
            RootThumbprint = valid ? observation.RootThumbprint : null,
            RootKind = valid ? observation.RootKind : null,
        };
    }
}

internal sealed record InstallationEvidenceSummary
{
    [JsonPropertyName("catalogue_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CatalogueVersion { get; init; }
    [JsonPropertyName("delivery_version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? DeliveryVersion { get; init; }
    [JsonPropertyName("content_hash")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ContentHash { get; init; }
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }
    [JsonPropertyName("errors")]
    public IReadOnlyList<string> Errors { get; init; } = [];
    // PAT-2116: the all-apps Authenticode coverage (AppSignatureCoverage), reported apart
    // from the reviewed-target status above so neither can be read as the other.
    [JsonPropertyName("coverage")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InstallationEvidenceCoverageSummary? Coverage { get; init; }
}

internal sealed record InstallationEvidenceCoverageSummary
{
    [JsonPropertyName("collection_status")]
    public required string CollectionStatus { get; init; }
    [JsonPropertyName("attempted")]
    public int Attempted { get; init; }
    [JsonPropertyName("resolved")]
    public int Resolved { get; init; }
    [JsonPropertyName("errors")]
    public IReadOnlyList<string> Errors { get; init; } = [];
}
