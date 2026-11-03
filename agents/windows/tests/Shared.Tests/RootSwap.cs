namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2050: swaps a scan root for a junction just after the scan registers it. Wrap a scan's
/// root resolver with <see cref="Wrap"/>: the first time <c>root</c> is resolved, the real
/// resolver answers first (so the root is registered with its genuine final path, as AddRoot
/// accepts it), and then the root is moved aside and a junction to <c>target</c> planted in its
/// place, before anything under it is looked at. <see cref="Restore"/> puts the real root back.
/// </summary>
internal sealed class RootSwap(string root, string target)
{
    private readonly string _root = Path.TrimEndingDirectorySeparator(root);
    private string Parked => _root + "-registered";

    public bool Swapped { get; private set; }

    public Func<string, string?> Wrap(Func<string, string?>? real) => candidate =>
    {
        var trimmed = Path.TrimEndingDirectorySeparator(candidate);
        var final = real is null ? trimmed : real(candidate);
        if (!Swapped && final is not null && string.Equals(trimmed, _root, StringComparison.OrdinalIgnoreCase))
        {
            Swapped = true;
            Directory.Move(_root, Parked);
            DirectoryLinks.Plant(_root, target);
        }
        return final;
    };

    public void Restore()
    {
        if (!Swapped) return;
        Directory.Delete(_root);
        Directory.Move(Parked, _root);
        Swapped = false;
    }
}
