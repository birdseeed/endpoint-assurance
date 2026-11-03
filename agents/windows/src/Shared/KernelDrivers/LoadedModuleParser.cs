using System.Buffers.Binary;
using System.Text;

namespace Patched.Shared.KernelDrivers;

/// <summary>
/// PAT-2263: reads the kernel's loaded-module names out of the RTL_PROCESS_MODULES buffer
/// that NtQuerySystemInformation(SystemModuleInformation) fills. Only the names are used
/// (FullPathName): the image base addresses, which Windows 11 24H2 zeroes for callers without
/// SeDebugPrivilege, are never read, so the list does not depend on them.
///
/// Layout on a 64-bit process (the only kind the service ships as, win-x64 and win-arm64):
/// a ULONG module count, padding to 8, then one 296-byte RTL_PROCESS_MODULE_INFORMATION per
/// module, whose FullPathName is a 256-byte NUL-terminated ANSI string at offset 40. Every
/// offset is bounds-checked. A name with a byte outside printable ASCII is not guessed at
/// through a code page: it is reported as unusable, and the caller counts it.
/// </summary>
internal static class LoadedModuleParser
{
    internal const int HeaderBytes = 8;
    internal const int EntryBytes = 296;
    internal const int NameOffset = 40;
    internal const int NameBytes = 256;
    internal const int MaxModules = 8192;

    /// <summary>
    /// The names in <paramref name="buffer"/>, or <see cref="LoadedModuleList.Unreadable"/>
    /// when the buffer does not hold together. An empty string in the list is a module whose
    /// name was empty or unusable; the inventory logic counts it as unresolved.
    /// </summary>
    public static LoadedModuleList Parse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < HeaderBytes) return LoadedModuleList.Unreadable;
        var count = BinaryPrimitives.ReadUInt32LittleEndian(buffer);
        if (count == 0 || count > MaxModules || HeaderBytes + (long)count * EntryBytes > buffer.Length)
            return LoadedModuleList.Unreadable;
        var names = new List<string>((int)count);
        for (var i = 0; i < count; i++)
        {
            var name = buffer.Slice(HeaderBytes + i * EntryBytes + NameOffset, NameBytes);
            var end = name.IndexOf((byte)0);
            if (end <= 0)
            {
                names.Add(string.Empty);
                continue;
            }
            var raw = name[..end];
            var printable = true;
            foreach (var b in raw)
            {
                if (b < 0x20 || b > 0x7E)
                {
                    printable = false;
                    break;
                }
            }
            names.Add(printable ? Encoding.ASCII.GetString(raw) : string.Empty);
        }
        return new LoadedModuleList(false, names);
    }
}
