namespace Patched.Shared.Auth;

/// <summary>
/// PAT-1763: every write <see cref="CredentialStore"/> makes to host credential
/// storage after an enrolment: Windows Credential Manager, the plaintext file
/// store under %ProgramData%\Patched\creds and the installer's registry
/// provisioning key. Production stores use the host implementation inside
/// <see cref="CredentialStore"/>; every test factory
/// (<see cref="CredentialStore.CreateForTests"/>, <see cref="CredentialStore.ForTesting"/>)
/// uses <see cref="InMemoryAgentCredentialWriter"/>, so no test that enrols a
/// device can reach the running user's Credential Manager or %ProgramData%.
/// </summary>
internal interface IAgentCredentialWriter
{
    /// <summary>Stores one credential. Throws when it cannot be stored.</summary>
    void WriteCredential(string target, string value);

    /// <summary>
    /// Removes the consumed enrolment token from every place the installer can
    /// leave it. Best effort: the token is single-use on the server.
    /// </summary>
    void DiscardConsumedEnrollmentToken();
}

/// <summary>
/// PAT-1763: the test double for <see cref="IAgentCredentialWriter"/>. Records
/// what an enrolment stored and never touches the host. Internal, visible only to
/// the test assemblies through InternalsVisibleTo; production never constructs it.
/// </summary>
internal sealed class InMemoryAgentCredentialWriter : IAgentCredentialWriter
{
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _written = new(StringComparer.Ordinal);
    private int _discards;

    /// <summary>When set, every <see cref="WriteCredential"/> throws this, modelling a failed CredWrite.</summary>
    public Exception? FailWith { get; init; }

    /// <summary>Runs after each successful write, for tests that model something happening mid-enrolment.</summary>
    public Action<string, string>? OnWrite { get; init; }

    /// <summary>Snapshot of every credential written, by target.</summary>
    public IReadOnlyDictionary<string, string> Written
    {
        get { lock (_gate) return new Dictionary<string, string>(_written, StringComparer.Ordinal); }
    }

    /// <summary>Tenant IDs written, in order, one per completed enrolment write.</summary>
    public List<string> PersistedTenants { get; } = new();

    public int EnrollmentTokenDiscards
    {
        get { lock (_gate) return _discards; }
    }

    public void WriteCredential(string target, string value)
    {
        if (FailWith is not null)
            throw FailWith;
        lock (_gate)
        {
            _written[target] = value;
            if (target == CredentialStore.TargetTenantId)
                PersistedTenants.Add(value);
        }
        OnWrite?.Invoke(target, value);
    }

    public void DiscardConsumedEnrollmentToken()
    {
        lock (_gate) _discards++;
    }
}
