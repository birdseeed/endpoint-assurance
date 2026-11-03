using System.Buffers.Binary;
using System.Text;
using Patched.Shared.UserTrees;

namespace Patched.Shared.LocalModels;

/// <summary>
/// PAT-2019: the product version of a Windows executable, read from its VS_VERSIONINFO
/// resource as bytes. The file is never loaded, mapped as an image or run: this walks the PE
/// headers (DOS header, COFF header, optional header's resource data directory, section table)
/// to the RT_VERSION resource and reads VS_FIXEDFILEINFO out of it, a few small ranges of the
/// file in all. Every offset and count comes from a user-writable file, so each one is bounds
/// checked before it is used, and the walk is bounded (sections, directory entries, block size).
///
/// Status: "read" with a version; "none" when the file is a well-formed PE with no version
/// resource (a Go or plain CMake build commonly has none, and that is an answer, not a gap);
/// "unparseable" when the headers do not hold together.
/// </summary>
internal static class PeVersionReader
{
    private const int RtVersion = 16;
    private const int MaxSections = 96;
    private const int MaxEntries = 256;
    private const int MaxVersionBlock = 64 * 1024;
    private const uint FixedSignature = 0xFEEF04BD;
    private static readonly byte[] VersionKey = Encoding.Unicode.GetBytes("VS_VERSION_INFO\0");

    private sealed class Malformed : Exception;

    /// <summary>
    /// Parses through <paramref name="read"/>; never throws. The product version by default;
    /// PAT-2263: the file version (VS_FIXEDFILEINFO dwFileVersionMS/LS) when
    /// <paramref name="fileVersion"/> is set, which is the version driver block rules name.
    /// </summary>
    public static (string Status, string? Version) Read(RangeReader read, bool fileVersion = false)
    {
        try
        {
            var version = Parse(read, fileVersion);
            return version is null ? ("none", null) : ("read", version);
        }
        catch (Exception)
        {
            return ("unparseable", null);
        }
    }

    private static byte[] At(RangeReader read, long offset, int count)
    {
        if (offset < 0 || count < 0) throw new Malformed();
        var buffer = new byte[count];
        var total = 0;
        while (total < count)
        {
            var n = read(offset + total, buffer.AsSpan(total));
            if (n <= 0) throw new Malformed();
            total += n;
        }
        return buffer;
    }

    private static ushort U16(byte[] b, int at) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at, 2));
    private static uint U32(byte[] b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at, 4));

    private static string? Parse(RangeReader read, bool fileVersion)
    {
        var dos = At(read, 0, 64);
        if (dos[0] != (byte)'M' || dos[1] != (byte)'Z') throw new Malformed();
        var peOffset = U32(dos, 0x3C);
        if (peOffset < 64 || peOffset > 0x1000_0000) throw new Malformed();

        var coff = At(read, peOffset, 24);
        if (coff[0] != (byte)'P' || coff[1] != (byte)'E' || coff[2] != 0 || coff[3] != 0) throw new Malformed();
        int sections = U16(coff, 6);
        int optionalSize = U16(coff, 20);
        if (sections == 0 || sections > MaxSections || optionalSize < 96 || optionalSize > 4096) throw new Malformed();

        var optional = At(read, peOffset + 24, optionalSize);
        var magic = U16(optional, 0);
        int dirCountAt, dirsAt;
        if (magic == 0x10B) { dirCountAt = 92; dirsAt = 96; }
        else if (magic == 0x20B) { dirCountAt = 108; dirsAt = 112; }
        else throw new Malformed();
        if (dirsAt + 3 * 8 > optionalSize) return null;
        if (U32(optional, dirCountAt) < 3) return null;
        var rsrcRva = U32(optional, dirsAt + 2 * 8);
        var rsrcSize = U32(optional, dirsAt + 2 * 8 + 4);
        if (rsrcRva == 0 || rsrcSize == 0) return null;

        var table = At(read, peOffset + 24 + optionalSize, sections * 40);
        long ToOffset(uint rva, uint length)
        {
            for (var i = 0; i < sections; i++)
            {
                var s = i * 40;
                long virtualSize = U32(table, s + 8), va = U32(table, s + 12), rawSize = U32(table, s + 16), raw = U32(table, s + 20);
                var span = Math.Max(virtualSize, rawSize);
                if (rva >= va && (long)rva + length <= va + span && (long)rva - va + length <= rawSize)
                    return raw + (rva - va);
            }
            throw new Malformed();
        }

        var root = ToOffset(rsrcRva, 16);
        // Offsets inside the resource tree are relative to its root.
        (uint Id, uint Offset)? Find(long dirOffset, int? wantedId)
        {
            var header = At(read, dirOffset, 16);
            int named = U16(header, 12), ids = U16(header, 14);
            var total = named + ids;
            if (total > MaxEntries) throw new Malformed();
            if (total == 0) return null;
            var entries = At(read, dirOffset + 16, total * 8);
            for (var i = 0; i < total; i++)
            {
                var name = U32(entries, i * 8);
                var offset = U32(entries, i * 8 + 4);
                if (wantedId is null) return (name, offset);
                if ((name & 0x8000_0000) == 0 && name == wantedId) return (name, offset);
            }
            return null;
        }
        long Child(uint offset)
        {
            var rel = offset & 0x7FFF_FFFF;
            if (rel >= rsrcSize) throw new Malformed();
            return root + rel;
        }

        var type = Find(root, RtVersion);
        if (type is null) return null;
        if ((type.Value.Offset & 0x8000_0000) == 0) throw new Malformed();
        var name = Find(Child(type.Value.Offset), null);
        if (name is null || (name.Value.Offset & 0x8000_0000) == 0) throw new Malformed();
        var lang = Find(Child(name.Value.Offset), null);
        if (lang is null || (lang.Value.Offset & 0x8000_0000) != 0) throw new Malformed();

        var dataEntry = At(read, Child(lang.Value.Offset), 16);
        var dataRva = U32(dataEntry, 0);
        var dataSize = U32(dataEntry, 4);
        if (dataSize < 92 || dataSize > MaxVersionBlock) throw new Malformed();
        var block = At(read, ToOffset(dataRva, dataSize), (int)dataSize);

        // VS_VERSIONINFO: wLength, wValueLength, wType, szKey "VS_VERSION_INFO\0", padding to
        // a 4-byte boundary, then VS_FIXEDFILEINFO.
        int length = U16(block, 0), valueLength = U16(block, 2);
        if (length > block.Length || valueLength < 52) throw new Malformed();
        if (!block.AsSpan(6, VersionKey.Length).SequenceEqual(VersionKey)) throw new Malformed();
        var fixedAt = (6 + VersionKey.Length + 3) & ~3;
        if (fixedAt + 52 > block.Length || U32(block, fixedAt) != FixedSignature) throw new Malformed();
        // VS_FIXEDFILEINFO: signature, struct version, file version MS/LS, product version MS/LS.
        var versionAt = fixedAt + (fileVersion ? 8 : 16);
        var ms = U32(block, versionAt);
        var ls = U32(block, versionAt + 4);
        if (ms == 0 && ls == 0) return null;
        return $"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}";
    }
}
