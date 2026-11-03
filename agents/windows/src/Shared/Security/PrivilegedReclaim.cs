using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Patched.Shared.Security;

/// <summary>
/// PAT-2400: takes one file-system object back from a hostile owner and DACL, using
/// privileges LocalSystem holds. Found necessary on an installed agent: a planted
/// <c>updates\</c> owned by a standard user with a protected DACL denying SYSTEM could
/// be neither read nor renamed by the service, so self-update stayed dead.
///
/// Scope is deliberately narrow:
///  - The privileges are enabled on an impersonation token of this thread only
///    (ImpersonateSelf), never on the process token, and are gone again at
///    RevertToSelf before this returns.
///  - Exactly one object is touched. It is opened without following a reparse point,
///    checked through that handle to be a real file or directory, and its security is
///    set through the same handle, so the object re-ACLed is the object checked.
///  - SetKernelObjectSecurity sets that one descriptor and does not propagate, unlike
///    SetSecurityInfo/SetNamedSecurityInfo, whose inheritance pass walks the children.
///    Nothing below the object is enumerated, read or changed.
/// Off Windows every entry point does nothing and returns false.
/// </summary>
internal static class PrivilegedReclaim
{
    internal const string TakeOwnership = "SeTakeOwnershipPrivilege";
    internal const string Backup        = "SeBackupPrivilege";
    internal const string Restore       = "SeRestorePrivilege";

    /// <summary>
    /// Runs <paramref name="action"/> on this thread with every named privilege
    /// enabled, then drops them. False, without running it, when any privilege is not
    /// held or cannot be enabled. An exception from the action propagates after the
    /// privileges are dropped.
    /// </summary>
    internal static bool TryWithPrivileges(IReadOnlyList<string> privileges, Action action)
    {
        if (!OperatingSystem.IsWindows()) return false;
        if (!ImpersonateSelf(SecurityImpersonation)) return false;
        try
        {
            if (!OpenThreadToken(GetCurrentThread(), TokenAdjustPrivileges | TokenQuery, openAsSelf: true, out IntPtr token))
                return false;
            try
            {
                foreach (string name in privileges)
                {
                    if (!LookupPrivilegeValueW(null, name, out Luid luid)) return false;
                    var state = new TokenPrivileges { Count = 1, Luid = luid, Attributes = SePrivilegeEnabled };
                    // Succeeds even when the token lacks the privilege; the last error says so.
                    if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero) ||
                        Marshal.GetLastPInvokeError() == ErrorNotAllAssigned)
                        return false;
                }
            }
            finally
            {
                CloseHandle(token);
            }

            action();
            return true;
        }
        finally
        {
            RevertToSelf();
        }
    }

    /// <summary>
    /// Makes SYSTEM the owner of the object at <paramref name="path"/> and replaces its
    /// DACL with a protected one granting SYSTEM and Administrators full control. The
    /// object only: no child is touched. Refuses a reparse point and an object of the
    /// wrong type. <paramref name="failure"/> is a short token for the log.
    /// </summary>
    internal static bool TryTakeOwnershipAndProtect(string path, bool isDirectory, out string failure)
    {
        failure = "not_windows";
        if (!OperatingSystem.IsWindows()) return false;

        string result = "privileges_not_held";
        TryWithPrivileges([TakeOwnership, Backup, Restore], () => result = Reset(path, isDirectory));
        failure = result;
        return result.Length == 0;
    }

    private static string Reset(string path, bool isDirectory)
    {
        if (!OperatingSystem.IsWindows()) return "not_windows";

        // BACKUP_SEMANTICS is what lets the backup/restore privileges answer the access
        // check instead of the hostile DACL (and is required to open a directory).
        // OPEN_REPARSE_POINT opens a link itself rather than its target.
        using SafeFileHandle handle = CreateFileW(
            path, WriteOwner | WriteDac | FileReadAttributes, ShareAll, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid) return "open_failed_" + Marshal.GetLastPInvokeError();

        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation info))
            return "query_failed_" + Marshal.GetLastPInvokeError();
        var attributes = (FileAttributes)info.FileAttributes;
        if ((attributes & FileAttributes.ReparsePoint) != 0) return "reparse_point";
        if (((attributes & FileAttributes.Directory) != 0) != isDirectory) return "wrong_type";

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var dacl = new RawAcl(GenericAcl.AclRevision, 2);
        dacl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, FileAllAccess, system, false, null));
        dacl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, FileAllAccess, admins, false, null));
        var descriptor = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected, system, null, null, dacl);
        byte[] binary = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(binary, 0);

        return SetKernelObjectSecurity(handle, OwnerSecurityInformation | DaclSecurityInformation, binary)
            ? ""
            : "set_security_failed_" + Marshal.GetLastPInvokeError();
    }

    private const int  SecurityImpersonation    = 2;
    private const uint TokenAdjustPrivileges    = 0x0020;
    private const uint TokenQuery               = 0x0008;
    private const uint SePrivilegeEnabled       = 0x0002;
    private const int  ErrorNotAllAssigned      = 1300;
    private const uint WriteDac                 = 0x00040000;
    private const uint WriteOwner               = 0x00080000;
    private const uint FileReadAttributes       = 0x0080;
    private const uint ShareAll                 = 0x7; // read | write | delete
    private const uint OpenExisting             = 3;
    private const uint FileFlagBackupSemantics  = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int  FileAllAccess            = 0x001F01FF;
    private const uint OwnerSecurityInformation = 0x1;
    private const uint DaclSecurityInformation  = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int  HighPart;
    }

    /// <summary>TOKEN_PRIVILEGES with its one-element array inline.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint Count;
        public Luid Luid;
        public uint Attributes;
    }

    /// <summary>BY_HANDLE_FILE_INFORMATION; only the first field is read.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        // Three FILETIMEs as DWORD pairs: a 64-bit field here would be padded to 8.
        public uint CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateSelf(int impersonationLevel);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(
        IntPtr thread, uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValueW(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges, ref TokenPrivileges newState,
        int bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint securityInformation, byte[] securityDescriptor);
}
