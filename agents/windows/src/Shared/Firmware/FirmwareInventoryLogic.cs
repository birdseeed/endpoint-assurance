using System.Globalization;
using System.Text.RegularExpressions;
using Patched.Shared.Contract;
using Patched.Shared.DeviceClassification;

namespace Patched.Shared.Firmware;

/// <summary>
/// PAT-2262: the raw property reads the firmware block is built from, one
/// <see cref="SourceRead"/> per WMI property. The Service does the Windows-only WMI reading
/// (<c>DeviceCollector.CollectFirmware</c>) and hands the snapshot here, so every rule is
/// testable off-box.
/// </summary>
internal readonly record struct FirmwareSources(
    SourceRead BiosManufacturer,
    SourceRead BiosVersion,
    SourceRead SmbiosMajorVersion,
    SourceRead SmbiosMinorVersion,
    SourceRead BiosReleaseDate,
    SourceRead SystemManufacturer,
    SourceRead SystemModel,
    SourceRead BaseboardManufacturer,
    SourceRead BaseboardProduct);

/// <summary>
/// PAT-2262: pure decision for the <c>firmware</c> block (<see cref="InventoryFirmware"/>).
///
/// The rules, each of which exists so a gap cannot read as a fact:
/// <list type="bullet">
/// <item>A failed read is never a value. Absent (the read succeeded, nothing is set) is a
///   null field and keeps the section complete; failed is a null field and makes it
///   partial, or unavailable when every read of the section failed.</item>
/// <item>Every string is trimmed and bounded. A value longer than
///   <see cref="MaxValueLength"/>, containing a control character or of the wrong type is
///   dropped rather than truncated (a truncated version string still reads as a real
///   reading, the same rule as DeviceClassResolver's caption) and makes the section
///   partial.</item>
/// <item>ReleaseDate must be a CIM datetime naming a real calendar date. Anything else is
///   partial, with the raw string kept (bounded to <see cref="MaxRawDateLength"/>) so the
///   evidence is not lost.</item>
/// <item>A block with no usable value at all is unavailable, even when every query
///   succeeded, and carries no sections, so an empty or failed collection can never be
///   stored as a complete, empty reading.</item>
/// </list>
/// Error codes are fixed tokens (<see cref="FirmwareErrorCode"/>), never exception text or
/// a firmware string.
/// </summary>
internal static class FirmwareInventoryLogic
{
    /// <summary>
    /// Longest identity value accepted. SMBIOS strings are short in practice (vendor names,
    /// model numbers, version strings well under 64 characters); the platform enforces the
    /// same bound.
    /// </summary>
    public const int MaxValueLength = 128;

    /// <summary>Longest raw ReleaseDate kept. A CIM datetime is 25 characters.</summary>
    public const int MaxRawDateLength = 64;

    // yyyymmddHHMMSS.mmmmmmsUUU. The date part must be digits; the time, microseconds and
    // offset may carry CIM's '*' wildcards. [0-9] rather than \d, which in .NET matches every
    // Unicode decimal digit (fullwidth digits included).
    private static readonly Regex CimDateTime = new(
        "^([0-9]{4})([0-9]{2})([0-9]{2})[0-9*]{6}\\.[0-9*]{6}[+-][0-9*]{3}$",
        RegexOptions.CultureInvariant);

    private const int MinYear = 1970;
    private const int MaxYear = 2099;

    public static InventoryFirmware Build(FirmwareSources s)
    {
        // BIOS (SMBIOS type 0).
        var bios = new SectionReads();
        var biosManufacturer = bios.String(s.BiosManufacturer);
        var biosVersion      = bios.String(s.BiosVersion);
        var smbiosVersion    = bios.SmbiosVersion(s.SmbiosMajorVersion, s.SmbiosMinorVersion);
        var (releaseDate, releaseDateRaw) = bios.ReleaseDate(s.BiosReleaseDate);

        // System (SMBIOS type 1).
        var system = new SectionReads();
        var systemManufacturer = system.String(s.SystemManufacturer);
        var systemModel        = system.String(s.SystemModel);

        // Baseboard (SMBIOS type 2).
        var baseboard = new SectionReads();
        var baseboardManufacturer = baseboard.String(s.BaseboardManufacturer);
        var baseboardProduct      = baseboard.String(s.BaseboardProduct);

        var errors = new List<string>();
        var biosStatus = bios.Resolve(errors,
            FirmwareErrorCode.BiosQueryFailed, FirmwareErrorCode.BiosPropertyFailed, FirmwareErrorCode.BiosValueUnusable);
        if (bios.DateUnparseable)
            errors.Add(FirmwareErrorCode.BiosReleaseDateUnparseable);
        var systemStatus = system.Resolve(errors,
            FirmwareErrorCode.SystemQueryFailed, FirmwareErrorCode.SystemPropertyFailed, FirmwareErrorCode.SystemValueUnusable);
        var baseboardStatus = baseboard.Resolve(errors,
            FirmwareErrorCode.BaseboardQueryFailed, FirmwareErrorCode.BaseboardPropertyFailed, FirmwareErrorCode.BaseboardValueUnusable);

        var statuses = new[] { biosStatus, systemStatus, baseboardStatus };
        if (!bios.AnyValue && !system.AnyValue && !baseboard.AnyValue)
        {
            // Nothing usable. When every class failed outright the query codes already say
            // so; otherwise say plainly that the reads that worked yielded nothing.
            if (statuses.Any(st => st != FirmwareCollectionStatus.Unavailable))
                errors.Add(FirmwareErrorCode.NoFirmwareValues);
            return new InventoryFirmware
            {
                CollectionStatus = FirmwareCollectionStatus.Unavailable,
                Errors           = Bound(errors),
            };
        }

        var blockStatus = statuses.All(st => st == FirmwareCollectionStatus.Complete)
            ? FirmwareCollectionStatus.Complete
            : FirmwareCollectionStatus.Partial;

        return new InventoryFirmware
        {
            CollectionStatus = blockStatus,
            Errors           = Bound(errors),
            Bios = new InventoryFirmwareBios
            {
                CollectionStatus = biosStatus,
                Manufacturer     = biosManufacturer,
                Version          = biosVersion,
                SmbiosVersion    = smbiosVersion,
                ReleaseDate      = releaseDate,
                ReleaseDateRaw   = releaseDateRaw,
            },
            System = new InventoryFirmwareSystem
            {
                CollectionStatus = systemStatus,
                Manufacturer     = systemManufacturer,
                Model            = systemModel,
            },
            Baseboard = new InventoryFirmwareBaseboard
            {
                CollectionStatus = baseboardStatus,
                Manufacturer     = baseboardManufacturer,
                Product          = baseboardProduct,
            },
        };
    }

    /// <summary>
    /// A WMI ReleaseDate as <c>YYYY-MM-DD</c>, or null when it is not a CIM datetime naming a
    /// real calendar date between 1970 and 2099. Only the date part is used, exactly as the
    /// firmware states it: the UTC offset is not applied, because this is a release date,
    /// not an instant, and shifting it could move it to a different day. A
    /// <see cref="DateTime"/> or <see cref="DateTimeOffset"/> (another reader may convert
    /// the CIM string itself) contributes its date part the same way.
    /// </summary>
    public static string? ParseCimDate(object? value)
    {
        int year, month, day;
        switch (value)
        {
            case DateTime dt:
                (year, month, day) = (dt.Year, dt.Month, dt.Day);
                break;
            case DateTimeOffset dto:
                (year, month, day) = (dto.Year, dto.Month, dto.Day);
                break;
            case string text:
            {
                var m = CimDateTime.Match(text.Trim());
                if (!m.Success)
                    return null;
                year  = int.Parse(m.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture);
                month = int.Parse(m.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture);
                day   = int.Parse(m.Groups[3].Value, NumberStyles.None, CultureInfo.InvariantCulture);
                break;
            }
            default:
                return null;
        }

        if (year is < MinYear or > MaxYear || month is < 1 or > 12)
            return null;
        if (day < 1 || day > DateTime.DaysInMonth(year, month))
            return null;
        return string.Create(CultureInfo.InvariantCulture, $"{year:D4}-{month:D2}-{day:D2}");
    }

    private static IReadOnlyList<string> Bound(List<string> errors) =>
        errors.Distinct(StringComparer.Ordinal).Take(FirmwareErrorCode.MaxErrors).ToArray();

    /// <summary>A usable identity string: trimmed, non-empty, bounded, printable.</summary>
    private static bool TryUsableString(object? value, int maxLength, out string? text)
    {
        text = null;
        if (value is not string raw)
            return false;
        var trimmed = raw.Trim();
        if (trimmed.Length == 0)
            return true; // present but blank: the firmware does not populate it
        if (trimmed.Length > maxLength)
            return false;
        foreach (var c in trimmed)
        {
            if (char.IsControl(c))
                return false;
        }
        text = trimmed;
        return true;
    }

    /// <summary>
    /// A WMI integer property (SMBIOSMajorVersion and SMBIOSMinorVersion are uint16) as an
    /// int in 0..65535, or null when it is not an integral value in that range. Text is not
    /// accepted: the property is typed, and a string here means something else answered.
    /// </summary>
    private static int? ToUInt16Range(object? value) => value switch
    {
        byte b                                => b,
        sbyte sb when sb >= 0                 => sb,
        short sh when sh >= 0                 => sh,
        ushort us                             => us,
        int i when i is >= 0 and <= ushort.MaxValue    => i,
        uint u when u <= ushort.MaxValue      => (int)u,
        long l when l is >= 0 and <= ushort.MaxValue   => (int)l,
        ulong ul when ul <= ushort.MaxValue   => (int)ul,
        _                                     => null,
    };

    /// <summary>What happened to the reads of one section, accumulated as they are made.</summary>
    private sealed class SectionReads
    {
        private int _reads;
        private int _failed;

        public bool Unusable { get; private set; }
        public bool DateUnparseable { get; private set; }
        public bool AnyValue { get; private set; }

        public string? String(SourceRead read)
        {
            _reads++;
            switch (read.State)
            {
                case SourceReadState.Failed:
                    _failed++;
                    return null;
                case SourceReadState.Absent:
                    return null;
            }
            if (!TryUsableString(read.Value, MaxValueLength, out var text))
            {
                Unusable = true;
                return null;
            }
            if (text is not null)
                AnyValue = true;
            return text;
        }

        public string? SmbiosVersion(SourceRead major, SourceRead minor)
        {
            _reads += 2;
            var failed = 0;
            if (major.State == SourceReadState.Failed) failed++;
            if (minor.State == SourceReadState.Failed) failed++;
            _failed += failed;

            int? maj = null, min = null;
            if (major.State == SourceReadState.Present)
            {
                maj = ToUInt16Range(major.Value);
                if (maj is null) Unusable = true;
            }
            if (minor.State == SourceReadState.Present)
            {
                min = ToUInt16Range(minor.Value);
                if (min is null) Unusable = true;
            }
            if (maj is null || min is null)
                return null;

            AnyValue = true;
            return string.Create(CultureInfo.InvariantCulture, $"{maj}.{min}");
        }

        public (string? Date, string? Raw) ReleaseDate(SourceRead read)
        {
            _reads++;
            switch (read.State)
            {
                case SourceReadState.Failed:
                    _failed++;
                    return (null, null);
                case SourceReadState.Absent:
                    return (null, null);
            }
            if (read.Value is string blank && blank.Trim().Length == 0)
                return (null, null);

            var date = ParseCimDate(read.Value);
            if (date is not null)
            {
                AnyValue = true;
                return (date, null);
            }

            DateUnparseable = true;
            // The raw string is evidence worth keeping, but only bounded and printable.
            if (TryUsableString(read.Value, MaxRawDateLength, out var raw) && raw is not null)
            {
                AnyValue = true;
                return (null, raw);
            }
            return (null, null);
        }

        /// <summary>The section's status, appending its error codes.</summary>
        public string Resolve(List<string> errors, string queryFailed, string propertyFailed, string valueUnusable)
        {
            if (_reads > 0 && _failed == _reads)
            {
                errors.Add(queryFailed);
                return FirmwareCollectionStatus.Unavailable;
            }
            if (_failed > 0)
                errors.Add(propertyFailed);
            if (Unusable)
                errors.Add(valueUnusable);
            return _failed > 0 || Unusable || DateUnparseable
                ? FirmwareCollectionStatus.Partial
                : FirmwareCollectionStatus.Complete;
        }
    }
}
