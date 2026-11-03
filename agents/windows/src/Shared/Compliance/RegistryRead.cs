namespace Patched.Shared.Compliance;

/// <summary>
/// PAT-1767: the three compliance signal states every agent sends. A real value means
/// the read succeeded and the setting is present; <see cref="NotConfigured"/> means the
/// read succeeded and the setting is absent, so the server rule decides what the OS
/// default means; <see cref="Unknown"/> means the read itself failed (the Windows
/// agent's spelling of the contract's null). Absent and failed must never share a
/// branch: a failed read never becomes NotConfigured.
/// </summary>
public static class ComplianceSignalValue
{
    public const string NotConfigured = "NotConfigured";
    public const string Unknown = "Unknown";
}

/// <summary>How one registry value read ended.</summary>
public enum RegistryReadState
{
    /// <summary>The value exists and was read. It may still be of an unusable type.</summary>
    Present,
    /// <summary>The read succeeded and found nothing: the key or the value does not exist.</summary>
    Absent,
    /// <summary>Opening the key or reading the value threw.</summary>
    Failed,
}

/// <summary>
/// The outcome of one registry value read, kept as a tri-state so absent and failed
/// cannot collapse into one null. The Service does the Windows-only read and hands the
/// result to the pure mappers here.
/// </summary>
public readonly record struct RegistryRead(RegistryReadState State, object? Value = null)
{
    public static RegistryRead Absent => new(RegistryReadState.Absent);
    public static RegistryRead Failed => new(RegistryReadState.Failed);
    public static RegistryRead Present(object value) => new(RegistryReadState.Present, value);

    /// <summary>
    /// Runs a read. A null result (missing key or missing value) is
    /// <see cref="RegistryReadState.Absent"/>; any exception (for example
    /// SecurityException, UnauthorizedAccessException or IOException) is
    /// <see cref="RegistryReadState.Failed"/> and is passed to
    /// <paramref name="onFailure"/> for logging.
    /// </summary>
    public static RegistryRead Capture(Func<object?> read, Action<Exception>? onFailure = null)
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

    /// <summary>True when the value was read and is a REG_DWORD (an int).</summary>
    public bool TryGetInt(out int value)
    {
        if (State == RegistryReadState.Present && Value is int i)
        {
            value = i;
            return true;
        }
        value = 0;
        return false;
    }
}
