using System.Text.Json;
using Patched.Shared.Config;
using Patched.Shared.InstallationEvidence;
using Patched.Shared.Paths;
using Patched.Shared.Security;

namespace Patched.Service;

// Fixed SYSTEM/Administrators-owned state, separate from tenant config and enrolment resets.
// Store the original signature envelope so every process/restart verifies the exact bytes.
internal static class InstallationEvidenceStore
{
    private static readonly string DirectoryPath = Path.Combine(PathConstants.StateDir, "installation-evidence");
    private static readonly string EnvelopePath = Path.Combine(DirectoryPath, "signed-envelope.json");
    private static readonly string FloorPath = Path.Combine(DirectoryPath, "delivery-floor.json");
    private static readonly object Gate = new();
    private const int MaximumBytes = 4 * 1024 * 1024;

    internal sealed record Floor(long DeliveryVersion, string ContentHash, DateTimeOffset PublishedAt, DateTimeOffset ExpiresAt)
    {
        internal static Floor From(InstallationEvidenceCatalogue catalogue) =>
            new(catalogue.DeliveryVersion, catalogue.ContentHash, catalogue.PublishedAt, catalogue.ExpiresAt);
    }

    internal static bool Accepts(Floor? floor, InstallationEvidenceCatalogue catalogue) => floor is null ||
        catalogue.DeliveryVersion > floor.DeliveryVersion ||
        (catalogue.DeliveryVersion == floor.DeliveryVersion && catalogue.ContentHash == floor.ContentHash &&
            catalogue.PublishedAt == floor.PublishedAt && catalogue.ExpiresAt == floor.ExpiresAt);

    internal static bool AcceptVerifiedEnvelope(byte[] envelope, byte[] verifiedPayload) =>
        AcceptVerifiedEnvelope(() =>
        {
            SecureStagingDirectory.EnsureHardenedChain(DirectoryPath, PathConstants.StateDir);
            PersistVerifiedEnvelope(envelope, verifiedPayload, DateTimeOffset.UtcNow, ReadFloor,
                floor => WriteAtomic(FloorPath, JsonSerializer.SerializeToUtf8Bytes(floor)),
                bytes => WriteAtomic(EnvelopePath, bytes));
        });

    // Exercise the same guarded failure boundary with test IO, without redirecting
    // production paths or weakening directory/signature verification.
    internal static bool AcceptVerifiedEnvelope(Action persist)
    {
        lock (Gate)
        {
            try
            {
                persist();
                return true;
            }
            catch
            {
                // A write failure must not make a prior snapshot current. Parent collection
                // additionally binds the cache to the exact current config bytes on disk.
                return false;
            }
        }
    }

    // IO seams exercise crash/write-failure ordering without redirecting any production
    // path or relaxing its trust checks. Only the signature-verified network path calls it.
    internal static void PersistVerifiedEnvelope(byte[] envelope, byte[] verifiedPayload, DateTimeOffset now,
        Func<Floor?> readFloor, Action<Floor> writeFloor, Action<byte[]> writeEnvelope)
    {
        var catalogue = InstallationEvidenceCatalogue.ParseVerifiedPayload(verifiedPayload, now);
        // Missing, empty and rejected catalogues replace the active envelope too.
        // The floor is retained, so none can reactivate the previous target set.
        if (catalogue is not null && Accepts(readFloor(), catalogue))
        {
            // Floor first: any crash before the new envelope is durable leaves
            // old cache bytes below the floor, hence zero probes.
            writeFloor(Floor.From(catalogue));
        }
        writeEnvelope(envelope);
    }

    internal static InstallationEvidenceCatalogue? LoadForInventory(AgentConfig current) =>
        current is null ? null : Load(current);

    // The helper has no typed manager instance, but verifies the same signed bytes,
    // exact active payload cache and durable delivery floor as the parent.
    internal static InstallationEvidenceCatalogue? LoadForHelper() => Load(null);

    private static InstallationEvidenceCatalogue? Load(AgentConfig? current)
    {
        lock (Gate)
        {
            try
            {
                SecureStagingDirectory.VerifyTrusted(PathConstants.StateDir);
                SecureStagingDirectory.VerifyTrusted(DirectoryPath);
                if (!Ed25519Verifier.TryVerifyEnvelope(ReadProtected(EnvelopePath), out var payload)) return null;
                // Parent and helper must both observe the exact currently accepted config.
                // This denies stale evidence when a signed config removes/malforms the field,
                // when cache writes fail, and when a same-version config changes content.
                return MatchVerifiedPayload(payload, ReadProtected(PathConstants.AgentConfigFile), ReadFloor(), current, DateTimeOffset.UtcNow);
            }
            catch { return null; }
        }
    }

    internal static InstallationEvidenceCatalogue? MatchVerifiedPayload(byte[] payload, byte[] currentPayload,
        Floor? floor, AgentConfig? current, DateTimeOffset now)
    {
        if (!payload.AsSpan().SequenceEqual(currentPayload)) return null;
        using var document = JsonDocument.Parse(payload);
        if (current is not null && (document.RootElement.GetProperty("tenant_id").GetString() != current.TenantId ||
            document.RootElement.GetProperty("config_version").GetInt32() != current.ConfigVersion)) return null;
        var catalogue = InstallationEvidenceCatalogue.ParseVerifiedPayload(payload, now);
        return catalogue is not null && floor is not null && catalogue.DeliveryVersion == floor.DeliveryVersion &&
            Accepts(floor, catalogue) ? catalogue : null;
    }

    private static Floor? ReadFloor()
    {
        byte[] bytes;
        try
        {
            // OpenLocalFile deliberately normalises native open failures. Distinguish
            // true absence before calling it, never convert an unreadable file to no floor.
            _ = File.GetAttributes(FloorPath);
            bytes = ReadProtected(FloorPath);
        }
        catch (FileNotFoundException) { return null; }
        return ParseFloor(bytes);
    }

    internal static Floor ParseFloor(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 4 ||
            !root.TryGetProperty("DeliveryVersion", out var version) || !version.TryGetInt64(out var number) || number < 1 ||
            !root.TryGetProperty("ContentHash", out var hash) || !InstallationEvidenceCatalogue.IsHash(hash.GetString()) ||
            !root.TryGetProperty("PublishedAt", out var published) || !published.TryGetDateTimeOffset(out var publishedAt) ||
            !root.TryGetProperty("ExpiresAt", out var expires) || !expires.TryGetDateTimeOffset(out var expiresAt) || expiresAt <= publishedAt)
            throw new InvalidDataException("evidence_floor_invalid");
        return new(number, hash.GetString()!, publishedAt, expiresAt);
    }

    private static byte[] ReadProtected(string path)
    {
        // Retain the file/ancestor locks while reading, and verify owner and DACL.
        using var file = WindowsInstallationEvidence.OpenLocalFile(path);
        WindowsInstallationEvidence.VerifyExecutableAcl(path);
        if (file.Stream.Length > MaximumBytes) throw new InvalidDataException("evidence_cache_limit");
        using var buffer = new MemoryStream();
        file.Stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static void WriteAtomic(string path, byte[] bytes)
    {
        if (bytes.Length > MaximumBytes) throw new InvalidDataException("evidence_cache_limit");
        // CreateNew avoids following a planted temporary file. Its containing directory
        // is already trusted and grants no non-admin write access.
        var temporary = Path.Combine(DirectoryPath, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
