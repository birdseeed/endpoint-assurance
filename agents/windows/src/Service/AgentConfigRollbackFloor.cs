using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Patched.Service;

/// <summary>
/// PAT-1756: the agent-config anti-rollback floor, keyed by tenant.
///
/// <c>config_version</c> is monotonic per tenant on the server, not globally.
/// Before PAT-1756 the agent stored one bare last-accepted version and compared
/// every tenant's config against it, so a device that re-enrolled into a tenant
/// whose sequence was behind the old one rejected every config and could stay
/// suspended indefinitely (WIN-STAGING, 2026-09-14: floor 12 from one tenant,
/// new tenant at version 3).
///
/// On-disk format of <c>agent-config.version</c> (UTF-8, single line, no BOM):
///
///   {"tenant_id":"&lt;tenant id&gt;","config_version":&lt;non-negative integer&gt;}
///
/// Exactly those two members, each once. <c>tenant_id</c> is always the
/// tenant bound in the signature-verified payload that set the floor. The
/// macOS agent reads and writes the same format (parsed by
/// endpoint/agent_config_floor.py since PAT-1763, written by
/// endpoint/patched-fetch-config.sh).
///
/// How a stored floor is read:
///   - No file: there is no floor yet (fresh install, or reset by enrolment).
///   - A bare non-negative decimal integer (the pre-PAT-1756 format): a legacy
///     floor that applies to the device's CURRENTLY enrolled tenant only. The
///     signed payload's tenant must already equal that enrolled tenant (tenant
///     binding runs first), so a legacy floor is only ever compared against a
///     config for the enrolled tenant. A signed config for any other tenant is
///     rejected by tenant binding and never reaches the floor. The file is
///     rewritten in the keyed format on the next accepted config, and no
///     If-None-Match is sent from it (it may have been left by another tenant
///     on a device that never enrolled through /v1/enrol, and a matching
///     version would draw a 304 that keeps that tenant's cached config). A bare
///     integer left by a previous tenant is cleared by the enrolment reset
///     (<see cref="ResetForEnrolment"/>), which is how the WIN-STAGING shape
///     recovers.
///   - The keyed format: compared only when its tenant equals the verified
///     payload's tenant. A different tenant starts a fresh floor: the config
///     is accepted and the floor is re-keyed to the new tenant and version.
///   - A file that exists but could not be opened or read (for example a
///     sharing violation): unreadable. Treated like a corrupt floor when a
///     config arrives, but never removed by the enrolment reset, because the
///     service cannot see what it would be deleting.
///   - Anything else whose bytes were read (empty, oversized, malformed, a
///     negative or out-of-range version, extra or duplicate members): corrupt.
///     A corrupt or unreadable floor rejects every config and suppresses
///     If-None-Match. It is never
///     read as "no floor", because that would silently disable anti-rollback
///     for the same tenant. Writes are atomic, so corruption means disk damage
///     or tampering, and recovery is an admin act: a successful enrolment
///     resets the floor, or the file is removed by hand.
/// </summary>
internal static class AgentConfigRollbackFloor
{
    /// <summary>Upper bound on the floor file. A valid floor is well under 300 bytes.</summary>
    internal const int MaxFileBytes = 4096;

    internal const string TenantIdMember      = "tenant_id";
    internal const string ConfigVersionMember = "config_version";

    /// <summary>
    /// <see cref="FloorState.Corrupt"/>: the bytes were read and failed to parse.
    /// <see cref="FloorState.Unreadable"/>: the file exists but could not be
    /// opened or read, so its content is unknown.
    /// </summary>
    internal enum FloorState { Absent, Present, Corrupt, Unreadable }

    /// <summary>
    /// A parsed floor file. <see cref="TenantId"/> is null for a legacy bare
    /// integer. <see cref="Problem"/> is set only when <see cref="State"/> is
    /// <see cref="FloorState.Corrupt"/> or <see cref="FloorState.Unreadable"/>.
    /// </summary>
    internal readonly record struct StoredFloor(FloorState State, string? TenantId, int Version, string? Problem)
    {
        public bool IsLegacy => State == FloorState.Present && TenantId is null;

        public static StoredFloor Absent() => new(FloorState.Absent, null, 0, null);
        public static StoredFloor Legacy(int version) => new(FloorState.Present, null, version, null);
        public static StoredFloor Keyed(string tenantId, int version) => new(FloorState.Present, tenantId, version, null);
        public static StoredFloor Corrupt(string problem) => new(FloorState.Corrupt, null, 0, problem);
        public static StoredFloor Unreadable(string problem) => new(FloorState.Unreadable, null, 0, problem);
    }

    /// <summary>Outcome of comparing a verified config against the stored floor.</summary>
    internal readonly record struct Decision(bool Accept, string Message);

    /// <summary>Reads and parses the floor file. Never throws.</summary>
    internal static StoredFloor Read(string path)
    {
        byte[] raw;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buffer = new byte[MaxFileBytes + 1];
            int total = 0;
            int read;
            while (total < buffer.Length && (read = stream.Read(buffer, total, buffer.Length - total)) > 0)
                total += read;
            if (total > MaxFileBytes)
                return StoredFloor.Corrupt($"file is larger than {MaxFileBytes} bytes");
            raw = buffer.AsSpan(0, total).ToArray();
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return StoredFloor.Absent();
        }
        catch (Exception ex)
        {
            return StoredFloor.Unreadable($"file could not be opened or read ({ex.GetType().Name})");
        }

        return Parse(raw);
    }

    /// <summary>Parses floor file bytes. Never throws.</summary>
    internal static StoredFloor Parse(byte[] raw)
    {
        string text;
        try
        {
            text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                .GetString(raw).Trim();
        }
        catch (DecoderFallbackException)
        {
            return StoredFloor.Corrupt("file is not valid UTF-8");
        }

        if (text.Length == 0)
            return StoredFloor.Corrupt("file is empty");

        if (text.All(c => c is >= '0' and <= '9'))
        {
            return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int legacy)
                ? StoredFloor.Legacy(legacy)
                : StoredFloor.Corrupt("legacy version is out of range");
        }

        if (text[0] != '{')
            return StoredFloor.Corrupt("file is neither a keyed floor nor a legacy integer");

        try
        {
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return StoredFloor.Corrupt("floor is not a JSON object");

            string? tenantId = null;
            int? version = null;
            int members = 0;
            foreach (var member in root.EnumerateObject())
            {
                members++;
                if (member.NameEquals(TenantIdMember) && tenantId is null)
                {
                    if (member.Value.ValueKind != JsonValueKind.String)
                        return StoredFloor.Corrupt("tenant_id is not a string");
                    tenantId = member.Value.GetString();
                }
                else if (member.NameEquals(ConfigVersionMember) && version is null)
                {
                    if (member.Value.ValueKind != JsonValueKind.Number ||
                        !member.Value.TryGetInt32(out int v) || v < 0)
                        return StoredFloor.Corrupt("config_version is not a non-negative integer");
                    version = v;
                }
                else
                {
                    return StoredFloor.Corrupt("floor has an unexpected or repeated member");
                }
            }

            if (members != 2 || version is null || string.IsNullOrWhiteSpace(tenantId))
                return StoredFloor.Corrupt("floor must hold exactly a non-empty tenant_id and a config_version");

            return StoredFloor.Keyed(tenantId, version.Value);
        }
        catch (JsonException)
        {
            return StoredFloor.Corrupt("floor is not valid JSON");
        }
    }

    /// <summary>The exact bytes written for a keyed floor.</summary>
    internal static string Serialize(string tenantId, int version)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException("tenant id must be non-empty", nameof(tenantId));
        if (version < 0)
            throw new ArgumentOutOfRangeException(nameof(version));

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString(TenantIdMember, tenantId);
            writer.WriteNumber(ConfigVersionMember, version);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Writes a keyed floor atomically (temp file in the same directory, then
    /// rename over the old file), so a crash leaves either the old floor or the
    /// new one, never an empty or partial file. Throws on failure.
    /// </summary>
    internal static void Write(string path, string tenantId, int version)
    {
        string content = Serialize(tenantId, version);
        string? dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(tmp, path, overwrite: true);
    }

    // PAT-1773: why Windows has no execution-denial marker.
    //
    // macOS keeps a tenant-keyed agent-config.execution-denied marker because
    // its verifier can REJECT a newer, signed, tenant-bound payload that
    // revokes legacy execution or App Control authority (unique top-level
    // members, but a nested duplicate key fails its strict parse). The
    // revoking version never becomes the macOS floor and the last-good config
    // still grants, so the marker is the only record that keeps actuation
    // paused and refuses a same-version grant across restarts.
    //
    // Windows never reaches that state, so this floor is enough on its own:
    //   - AgentConfig.Deserialize does not reject such a payload. Any
    //     duplicate property name, at any depth, resolves AppControlAuthority
    //     to Report and LegacyAppExecutionEnabled to false (Canonicalize), and
    //     a typed field that fails to bind yields a config carrying only the
    //     verified tenant_id and config_version, every authority at its deny
    //     default.
    //   - AgentConfigFetcher.CommitSignatureVerifiedPayload therefore writes
    //     the revoking bytes to agent-config.json and advances this floor to
    //     the revoking version, and AgentConfigManager applies the deny values
    //     at once.
    //   - After a restart the manager deserializes the same cached bytes to
    //     the same deny values. If the cache is wiped it starts from
    //     AgentConfig.Defaults, which also denies, and this floor still refuses
    //     every older, granting config for the tenant.
    //   - The payloads Windows does reject after signature verification
    //     (invalid JSON, a missing or non-integer config_version or tenant_id,
    //     another tenant, an unusable floor, or a typed config whose tenant or
    //     version differs from the payload's) are the same shapes for which
    //     the macOS verifier cannot establish an authenticated revocation
    //     either, so neither agent records a denial for them.
    // The only Windows gate that consumes an authority denial in the shipping
    // Service is App Control (AppControlAuthorityGate on the current config);
    // LegacyAppExecutionGate's callers are excluded from the build (PAT-1531).
    // AgentConfigTenantSwitchTests covers this end to end.
    /// <summary>
    /// Compares a verified config for <paramref name="verifiedTenantId"/> at
    /// <paramref name="newVersion"/> against <paramref name="floor"/>.
    /// <paramref name="verifiedTenantId"/> must be the tenant bound in the
    /// signature-verified payload, already checked equal to the device's
    /// enrolled tenant.
    /// </summary>
    internal static Decision Evaluate(StoredFloor floor, string verifiedTenantId, int newVersion)
    {
        switch (floor.State)
        {
            case FloorState.Absent:
                return new Decision(true,
                    $"anti-rollback: no stored floor, version {newVersion} becomes the floor for tenant {verifiedTenantId}");

            case FloorState.Corrupt:
            case FloorState.Unreadable:
                return new Decision(false,
                    $"anti-rollback: the stored floor is unusable ({floor.Problem}), so no version can be checked for tenant {verifiedTenantId}. " +
                    "Every config is refused until the device re-enrols or the floor file is removed");
        }

        if (floor.TenantId is not null && !string.Equals(floor.TenantId, verifiedTenantId, StringComparison.Ordinal))
        {
            return new Decision(true,
                $"anti-rollback: stored floor belongs to tenant {floor.TenantId} (version {floor.Version}), " +
                $"so tenant {verifiedTenantId} starts a fresh floor at version {newVersion}");
        }

        string kind = floor.IsLegacy ? "legacy floor, applied to the enrolled tenant" : "floor";
        if (newVersion < floor.Version)
        {
            return new Decision(false,
                $"anti-rollback: new version {newVersion} < last accepted {floor.Version} for tenant {verifiedTenantId} ({kind})");
        }

        return new Decision(true,
            $"anti-rollback: version {newVersion} >= last accepted {floor.Version} for tenant {verifiedTenantId} ({kind})");
    }

    /// <summary>
    /// The version to send as If-None-Match, or null to send none. Only a floor
    /// keyed to <paramref name="enrolledTenantId"/> may be used: another
    /// tenant's version could collide with this tenant's current version and
    /// draw a 304 that keeps a stale config. A legacy floor carries no tenant,
    /// so it may be another tenant's (for example on a device re-provisioned
    /// with raw credentials, which never runs the enrolment reset). It sends
    /// none: one full fetch, after which the floor is re-keyed.
    /// </summary>
    internal static int? ConditionalGetVersion(StoredFloor floor, string? enrolledTenantId)
    {
        if (floor.State != FloorState.Present || floor.IsLegacy)
            return null;
        return !string.IsNullOrEmpty(enrolledTenantId) &&
               string.Equals(floor.TenantId, enrolledTenantId, StringComparison.Ordinal)
            ? floor.Version
            : null;
    }

    internal enum EnrolmentResetOutcome { NoFloor, KeptSameTenant, KeptUnreadable, KeptUnstable, Removed, RemoveFailed }

    /// <summary>Most reads the enrolment reset makes while waiting for two consecutive reads to agree.</summary>
    internal const int EnrolmentResetMaxReads = 4;

    /// <summary>
    /// Called after a successful enrolment into <paramref name="enrolledTenantId"/>
    /// has stored its credentials. Removes the floor only when its bytes were read
    /// and show it cannot be this tenant's own keyed floor: a legacy bare integer,
    /// a malformed (corrupt) file, or a floor keyed to another tenant.
    ///
    /// Kept, never removed:
    ///   - a floor keyed to the enrolled tenant, so re-enrolling into the same
    ///     tenant (a documented recovery step) never reopens a replay of an older
    ///     signed config for that tenant;
    ///   - an unreadable floor. A standard user can read StateDir and can hold the
    ///     file open with a share mode that makes the service's reads fail while a
    ///     delete still succeeds; deleting what could not be read would let that
    ///     user strip a same-tenant floor. It stays and keeps failing closed.
    ///   - a floor whose reads never settle (see below).
    ///
    /// Removal needs two consecutive reads that agree, within
    /// <see cref="EnrolmentResetMaxReads"/> reads, and every read is checked
    /// first, so a config accepted for the enrolled tenant after the credentials
    /// were stored (AgentConfigManager runs concurrently) keeps the floor it just
    /// wrote. If the reads never agree, the latest one is checked again and the
    /// file is kept. A write landing in the instant between the last read and the
    /// delete is not excluded; it costs one poll without a floor for this tenant,
    /// never a rejected config.
    ///
    /// <paramref name="readFloor"/> is a test seam; production uses <see cref="Read"/>.
    /// </summary>
    internal static EnrolmentResetOutcome ResetForEnrolment(
        string path, string enrolledTenantId, out StoredFloor removedOrKept, out Exception? error,
        Func<string, StoredFloor>? readFloor = null)
    {
        error = null;
        readFloor ??= Read;

        removedOrKept = readFloor(path);
        bool settled = false;
        for (int reads = 1; reads < EnrolmentResetMaxReads; reads++)
        {
            if (KeepOutcome(removedOrKept, enrolledTenantId) is EnrolmentResetOutcome early)
                return early;

            StoredFloor next = readFloor(path);
            if (next == removedOrKept)
            {
                settled = true;
                break;
            }
            removedOrKept = next;
        }

        if (KeepOutcome(removedOrKept, enrolledTenantId) is EnrolmentResetOutcome kept)
            return kept;
        if (!settled)
            return EnrolmentResetOutcome.KeptUnstable;

        try
        {
            File.Delete(path);
            return File.Exists(path) ? EnrolmentResetOutcome.RemoveFailed : EnrolmentResetOutcome.Removed;
        }
        catch (Exception ex)
        {
            error = ex;
            return EnrolmentResetOutcome.RemoveFailed;
        }
    }

    /// <summary>
    /// The reason to leave the floor alone, or null when <paramref name="floor"/>
    /// is removable (legacy, corrupt, or keyed to another tenant).
    /// </summary>
    private static EnrolmentResetOutcome? KeepOutcome(StoredFloor floor, string enrolledTenantId) => floor.State switch
    {
        FloorState.Absent => EnrolmentResetOutcome.NoFloor,
        FloorState.Unreadable => EnrolmentResetOutcome.KeptUnreadable,
        FloorState.Present when floor.TenantId is not null &&
                               string.Equals(floor.TenantId, enrolledTenantId, StringComparison.Ordinal)
            => EnrolmentResetOutcome.KeptSameTenant,
        _ => null,
    };
}
