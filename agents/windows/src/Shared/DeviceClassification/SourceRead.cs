namespace Patched.Shared.DeviceClassification;

/// <summary>How one device-class source read ended.</summary>
public enum SourceReadState
{
    /// <summary>The source returned a value. It may still be of an unusable type.</summary>
    Present,

    /// <summary>The read succeeded and found nothing: no such key, value, instance or property.</summary>
    Absent,

    /// <summary>The read itself threw. Nothing is known about the source.</summary>
    Failed,
}

/// <summary>
/// PAT-1959: the outcome of one device-class source read, kept as a tri-state so absent
/// and failed cannot collapse into a single null.
///
/// Deliberately its own type rather than a reuse of
/// <see cref="Patched.Shared.Compliance.RegistryRead"/>: the device-class snapshot mixes
/// WMI properties and a registry value, and RegistryRead's contract is registry-specific
/// down to its doc comments. The tri-state shape is intentionally identical so the two
/// read the same way.
///
/// Both <see cref="SourceReadState.Absent"/> and <see cref="SourceReadState.Failed"/>
/// resolve to an honest "unknown" or an omitted field. They are kept apart because the
/// two mean different things in a log and in any later diagnosis: absent is a fact about
/// the machine, failed is a fact about the agent's access to it.
/// </summary>
public readonly record struct SourceRead(SourceReadState State, object? Value = null)
{
    public static SourceRead Absent => new(SourceReadState.Absent);

    public static SourceRead Failed => new(SourceReadState.Failed);

    public static SourceRead Present(object value) => new(SourceReadState.Present, value);

    /// <summary>
    /// Runs a read. A null result (no key, no value, no instance, no property) is
    /// <see cref="SourceReadState.Absent"/>; any exception is
    /// <see cref="SourceReadState.Failed"/> and is passed to <paramref name="onFailure"/>
    /// for logging. Never throws, so no device-class read can abort an inventory cycle.
    /// </summary>
    public static SourceRead Capture(Func<object?> read, Action<Exception>? onFailure = null)
    {
        try
        {
            var value = read();
            return value is null ? Absent : Present(value);
        }
        catch (Exception ex)
        {
            onFailure?.Invoke(ex);
            return Failed;
        }
    }
}
