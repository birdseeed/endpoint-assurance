namespace Patched.Shared.Metering;

/// <summary>One loaded hive. Failed reads and disabled tracking cannot prove absence.</summary>
public sealed record UserAssistHive(IReadOnlyList<UserAssistUsage> Usages,
    bool TrackingDisabled = false, bool ReadFailed = false);

public sealed record UserAssistCollection(string Status, IReadOnlyList<UserAssistUsage> Usages,
    int? UserHiveCount, int? RecordCount)
{
    // The delegates form the read-only registry boundary, also exercised on non-Windows hosts.
    public static UserAssistCollection Read(Func<IEnumerable<string>> listHives,
        Func<string, UserAssistHive> readHive)
    {
        var usages = new List<UserAssistUsage>();
        int hives = 0;
        bool complete = true;
        try
        {
            foreach (string sid in listHives())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) ||
                    sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                hives++;
                try
                {
                    var hive = readHive(sid);
                    if (hive.TrackingDisabled || hive.ReadFailed) complete = false;
                    if (!hive.TrackingDisabled)
                        usages.AddRange(hive.Usages.Where(u => !string.IsNullOrWhiteSpace(u.Path) &&
                                (u.RunCount > 0 || u.LastUsed is not null))
                            .Select(u => u with { UserHive = hives }));
                }
                catch { complete = false; }
            }
        }
        catch { return new(MeteringStatus.Unavailable, usages, null, null); }
        return new(hives == 0 ? MeteringStatus.NoUserSession :
                complete && usages.Count > 0 ? MeteringStatus.Ok : MeteringStatus.Unavailable,
            usages, hives, usages.Count);
    }
}
