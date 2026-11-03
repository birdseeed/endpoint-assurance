using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Patched.Shared.InstallationEvidence;

// This parser accepts only bytes already authenticated by the agent-config verifier.
// Neither deserialising AgentConfig nor loading its legacy unsigned cache grants targets.
internal sealed record InstallationEvidenceCatalogue(string CatalogueVersion, long DeliveryVersion,
    string ContentHash, DateTimeOffset PublishedAt, DateTimeOffset ExpiresAt,
    IReadOnlyList<ReviewedInstallationTarget> Targets)
{
    internal const string Member = "windows_installation_evidence";
    internal const string SupportedIdentity = "windows_msi_product_code";

    internal bool IsCurrent(DateTimeOffset now) => PublishedAt <= now && now < ExpiresAt;

    internal static InstallationEvidenceCatalogue? ParseVerifiedPayload(byte[] payload, DateTimeOffset now)
    {
        try
        {
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;
            if (!UniqueNames(root) || !root.TryGetProperty(Member, out var value) ||
                !HasFields(value, "catalogue_version", "content_hash", "delivery_version", "expires_at",
                    "published_at", "schema_version", "targets") ||
                value.GetProperty("schema_version").GetInt32() != 1)
                return null;
            var version = value.GetProperty("catalogue_version").GetString()!;
            var hash = value.GetProperty("content_hash").GetString()!;
            var delivery = value.GetProperty("delivery_version").GetInt64();
            if (!Text(version, 128) || delivery < 1 || !IsHash(hash) ||
                !Timestamp(value.GetProperty("published_at"), out var published) ||
                !Timestamp(value.GetProperty("expires_at"), out var expires) ||
                published > now || expires <= now || expires <= published)
                return null;
            var array = value.GetProperty("targets");
            if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > InstallationEvidenceCollector.MaximumTargets)
                return null;
            var targets = new List<ReviewedInstallationTarget>();
            foreach (var entry in array.EnumerateArray())
            {
                if (!HasFields(entry, "authenticode_subject", "executable_path", "identity_kind", "identity_value", "install_path"))
                    return null;
                var target = new ReviewedInstallationTarget(entry.GetProperty("identity_kind").GetString()!,
                    entry.GetProperty("identity_value").GetString()!, entry.GetProperty("authenticode_subject").GetString()!,
                    entry.GetProperty("install_path").GetString()!, entry.GetProperty("executable_path").GetString()!);
                if (!ValidTarget(target) || targets.Any(t => string.Equals(t.IdentityValue, target.IdentityValue, StringComparison.OrdinalIgnoreCase)))
                    return null;
                targets.Add(target);
            }
            var ordered = targets.OrderBy(t => t.IdentityKind, StringComparer.Ordinal)
                .ThenBy(t => t.IdentityValue, StringComparer.Ordinal).ToArray();
            if (!targets.SequenceEqual(ordered) || ContentDigest(version, ordered) != hash)
                return null;
            return new(version, delivery, hash, published, expires, Array.AsReadOnly(ordered));
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException or OverflowException or ArgumentException)
        {
            return null;
        }
    }

    internal static bool ValidTarget(ReviewedInstallationTarget t) =>
        t.IdentityKind == SupportedIdentity && t.IdentityValue is { Length: 38 } &&
        Guid.TryParseExact(t.IdentityValue, "B", out var productCode) &&
        string.Equals(t.IdentityValue, productCode.ToString("B").ToUpperInvariant(), StringComparison.Ordinal) && Text(t.AuthenticodeSubject, 512) &&
        SafePath(t.InstallPath) && SafePath(t.ExecutablePath) &&
        t.ExecutablePath.StartsWith(t.InstallPath + "\\", StringComparison.OrdinalIgnoreCase) &&
        t.ExecutablePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

    internal static bool SafePath(string? path) => path is { Length: >= 4 and <= 512 } &&
        char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\' &&
        !path[2..].Contains(':') && !path.Contains('/') && !path.Any(char.IsControl) && WellFormedUnicode(path) &&
        path[3..].Split('\\').All(p => p.Length > 0 && p is not "." and not ".." && !IsDeviceName(p) &&
            !p.EndsWith(' ') && !p.EndsWith('.') && p.IndexOfAny(['*', '?', '"', '<', '>', '|']) < 0);

    private static bool IsDeviceName(string part)
    {
        var name = part.Split('.')[0].ToUpperInvariant();
        return name is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
            (name.Length == 4 && (name.StartsWith("COM") || name.StartsWith("LPT")) && "123456789¹²³".Contains(name[3]));
    }

    internal static bool IsHash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Text(string? value, int maximum) => !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximum && !value.Any(char.IsControl) && WellFormedUnicode(value);

    private static bool WellFormedUnicode(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (char.IsLowSurrogate(value[i])) return false;
            if (!char.IsHighSurrogate(value[i])) continue;
            if (i + 1 == value.Length || !char.IsLowSurrogate(value[i + 1])) return false;
            i++;
        }
        return true;
    }
    private static bool Timestamp(JsonElement value, out DateTimeOffset time)
    {
        time = default;
        return value.ValueKind == JsonValueKind.String &&
            Regex.IsMatch(value.GetString()!, @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$") &&
            DateTimeOffset.TryParse(value.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out time);
    }

    private static bool HasFields(JsonElement value, params string[] fields) => value.ValueKind == JsonValueKind.Object &&
        value.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).SequenceEqual(fields);

    private static bool UniqueNames(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            return value.EnumerateObject().All(p => names.Add(p.Name) && UniqueNames(p.Value));
        }
        return value.ValueKind != JsonValueKind.Array || value.EnumerateArray().All(UniqueNames);
    }

    // Go encoding/json: alphabetic keys, UTF-8, compact, HTML and line-separator escapes.
    internal static string ContentDigest(string version, IReadOnlyList<ReviewedInstallationTarget> targets)
    {
        static string Quote(string value)
        {
            // Never let UTF-8 replacement fallback turn an invalid scalar into a
            // different canonical string. The Go compatibility tests cover valid Unicode.
            if (!WellFormedUnicode(value)) throw new ArgumentException("invalid_unicode");
            var result = new StringBuilder("\"");
            foreach (var character in value)
                result.Append(character switch
                {
                    '"' => "\\\"",
                    '\\' => "\\\\",
                    '\b' => "\\b",
                    '\f' => "\\f",
                    '\n' => "\\n",
                    '\r' => "\\r",
                    '\t' => "\\t",
                    '<' => "\\u003c",
                    '>' => "\\u003e",
                    '&' => "\\u0026",
                    '\u2028' => "\\u2028",
                    '\u2029' => "\\u2029",
                    < ' ' => "\\u" + ((int)character).ToString("x4", CultureInfo.InvariantCulture),
                    _ => character.ToString(),
                });
            return result.Append('"').ToString();
        }
        var rows = targets.Select(t => "{\"authenticode_subject\":" + Quote(t.AuthenticodeSubject) +
            ",\"executable_path\":" + Quote(t.ExecutablePath) + ",\"identity_kind\":" + Quote(t.IdentityKind) +
            ",\"identity_value\":" + Quote(t.IdentityValue) + ",\"install_path\":" + Quote(t.InstallPath) + "}");
        var canonical = "{\"catalogue_version\":" + Quote(version) + ",\"schema_version\":1,\"targets\":[" + string.Join(",", rows) + "]}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }
}
