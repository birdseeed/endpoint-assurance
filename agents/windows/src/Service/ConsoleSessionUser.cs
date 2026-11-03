using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace Patched.Service;

/// <summary>Outcome of resolving the user logged on at the physical console.</summary>
internal enum ConsoleUserLookupStatus
{
    /// <summary>A console user was found; <see cref="ConsoleUserLookup.Sid"/> is set.</summary>
    Resolved,
    /// <summary>No session is attached to the console, or nobody is logged on in it.</summary>
    NoConsoleUser,
    /// <summary>A Windows API call failed for another reason.</summary>
    Failed,
}

internal sealed record ConsoleUserLookup(ConsoleUserLookupStatus Status, string? Sid = null);

/// <summary>
/// PAT-1747: resolves the SID of the user logged on at the physical console, so a
/// LocalSystem service can read that user's hive under HKEY_USERS.
/// <c>Registry.CurrentUser</c> is LocalSystem's own hive in a service, and
/// enumerating HKEY_USERS returns every loaded hive (service logons, RDP and SSH
/// sessions, profiles held open by other processes) with no way to tell which one
/// is the person at the device.
///
/// Read-only. <c>WTSQueryUserToken</c> needs SeTcbPrivilege, which LocalSystem
/// already holds; nothing here enables or adjusts a privilege. The token is used
/// only for <c>GetTokenInformation(TokenUser)</c> and is closed straight away. It is
/// never impersonated, duplicated or used to start a process.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ConsoleSessionUser
{
    private const uint NoConsoleSession = 0xFFFFFFFF;
    private const int ErrorNoToken = 1008;
    private const int ErrorInsufficientBuffer = 122;
    private const int TokenUserClass = 1;

    public static ConsoleUserLookup Resolve()
    {
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == NoConsoleSession)
            return new ConsoleUserLookup(ConsoleUserLookupStatus.NoConsoleUser);

        if (!WTSQueryUserToken(sessionId, out var token))
        {
            // ERROR_NO_TOKEN: the console session exists but nobody is logged on in it
            // (the logon screen).
            return Marshal.GetLastWin32Error() == ErrorNoToken
                ? new ConsoleUserLookup(ConsoleUserLookupStatus.NoConsoleUser)
                : new ConsoleUserLookup(ConsoleUserLookupStatus.Failed);
        }

        IntPtr buffer = IntPtr.Zero;
        try
        {
            GetTokenInformation(token, TokenUserClass, IntPtr.Zero, 0, out var needed);
            if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || needed <= 0)
                return new ConsoleUserLookup(ConsoleUserLookupStatus.Failed);

            buffer = Marshal.AllocHGlobal(needed);
            if (!GetTokenInformation(token, TokenUserClass, buffer, needed, out _))
                return new ConsoleUserLookup(ConsoleUserLookupStatus.Failed);

            // TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first field is the SID pointer.
            var sidPtr = Marshal.ReadIntPtr(buffer);
            var sid = new SecurityIdentifier(sidPtr).Value;
            return new ConsoleUserLookup(ConsoleUserLookupStatus.Resolved, sid);
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
            CloseHandle(token);
        }
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation,
        int tokenInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
