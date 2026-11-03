using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Patched.Shared.KernelDrivers;

/// <summary>PAT-2263: the hashes of one driver file.</summary>
internal sealed record DriverHashes(
    long Length,
    string Sha256,
    string Sha1,
    string? AuthenticodeSha256,
    string? AuthenticodeSha1);

/// <summary>
/// PAT-2263: hashes a driver file in one bounded pass, as bytes. The file is never loaded,
/// mapped as an image or run. Four digests come out of the one read: the flat SHA-256 and
/// SHA-1 of the whole file, and the Authenticode SHA-256 and SHA-1 of the PE image, which is
/// what both Microsoft's recommended driver block rules (the SiPolicy <c>Hash</c> attribute)
/// and loldrivers.io (<c>Authentihash</c>) list.
///
/// The Authenticode digest follows the Authenticode PE specification's linear form: every
/// byte of the file except the optional header's CheckSum field, the certificate table's data
/// directory entry, and the certificate table itself. For a signed driver (every driver
/// Windows will load is signed) the certificate table is the last thing in the file and 8-byte
/// aligned, and this equals the spec's section-by-section form. A file whose headers do not
/// hold together as a PE, or whose certificate directory points outside the file, gets no
/// Authenticode digest (null), never a guessed one; its flat hashes are still returned.
///
/// Every offset comes from the file, so each is bounds-checked before use. Page hashes (the
/// SiPolicy "Hash Page" rules) are not computed.
/// </summary>
internal static class DriverFileHasher
{
    /// <summary>Headers are parsed from at most this much of the start of the file.</summary>
    internal const int MaxHeaderBytes = 64 * 1024;

    private const int ChunkBytes = 128 * 1024;

    /// <summary>Byte ranges (offset, length) the Authenticode digest leaves out, in file order.</summary>
    internal readonly record struct Exclusions(long CheckSumAt, long CertDirectoryAt, long CertTableAt, long CertTableLength);

    /// <summary>
    /// Hashes <paramref name="stream"/> from its start. Throws on a read failure or when
    /// <paramref name="cancellation"/> fires; the caller maps either to an unhashed row.
    /// </summary>
    public static DriverHashes Hash(Stream stream, CancellationToken cancellation)
    {
        var length = stream.Length;
        stream.Position = 0;
        var head = new byte[(int)Math.Min(length, MaxHeaderBytes)];
        ReadExactly(stream, head);
        var exclusions = AuthenticodeExclusions(head, length);

        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        using var authSha256 = exclusions is null ? null : IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var authSha1 = exclusions is null ? null : IncrementalHash.CreateHash(HashAlgorithmName.SHA1);

        stream.Position = 0;
        var buffer = new byte[ChunkBytes];
        long offset = 0;
        while (offset < length)
        {
            cancellation.ThrowIfCancellationRequested();
            var want = (int)Math.Min(buffer.Length, length - offset);
            var read = stream.Read(buffer, 0, want);
            if (read <= 0) throw new EndOfStreamException("driver file shorter than its length");
            var chunk = buffer.AsSpan(0, read);
            sha256.AppendData(chunk);
            sha1.AppendData(chunk);
            if (exclusions is { } ex)
            {
                foreach (var (start, count) in Included(offset, read, ex))
                {
                    var part = chunk.Slice((int)(start - offset), count);
                    authSha256!.AppendData(part);
                    authSha1!.AppendData(part);
                }
            }
            offset += read;
        }
        if (stream.ReadByte() != -1) throw new IOException("driver file grew while it was hashed");

        return new DriverHashes(
            length,
            Hex(sha256.GetHashAndReset()),
            Hex(sha1.GetHashAndReset()),
            authSha256 is null ? null : Hex(authSha256.GetHashAndReset()),
            authSha1 is null ? null : Hex(authSha1.GetHashAndReset()));
    }

    /// <summary>
    /// The ranges to leave out of the Authenticode digest, or null when <paramref name="head"/>
    /// (the first bytes of a file of <paramref name="fileLength"/> bytes) is not a PE whose
    /// headers and certificate directory hold together.
    /// </summary>
    internal static Exclusions? AuthenticodeExclusions(ReadOnlySpan<byte> head, long fileLength)
    {
        if (head.Length < 64 || head[0] != (byte)'M' || head[1] != (byte)'Z') return null;
        var peAt = BinaryPrimitives.ReadUInt32LittleEndian(head.Slice(0x3C, 4));
        if (peAt < 64 || peAt > head.Length - 24) return null;
        var pe = (int)peAt;
        if (head[pe] != (byte)'P' || head[pe + 1] != (byte)'E' || head[pe + 2] != 0 || head[pe + 3] != 0) return null;
        int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(head.Slice(pe + 20, 2));
        var optionalAt = pe + 24;
        if (optionalAt + optionalSize > head.Length || optionalSize < 2) return null;
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(head.Slice(optionalAt, 2));
        int rvaCountAt, directoriesAt;
        if (magic == 0x10B) { rvaCountAt = 92; directoriesAt = 96; }
        else if (magic == 0x20B) { rvaCountAt = 108; directoriesAt = 112; }
        else return null;
        // The security directory is data directory 4. Without it there is no certificate
        // table and no directory entry to leave out, which Authenticode cannot describe.
        var certDirectoryRel = directoriesAt + 4 * 8;
        if (certDirectoryRel + 8 > optionalSize) return null;
        if (BinaryPrimitives.ReadUInt32LittleEndian(head.Slice(optionalAt + rvaCountAt, 4)) < 5) return null;

        long checkSumAt = optionalAt + 64;
        long certDirectoryAt = optionalAt + certDirectoryRel;
        long certTableAt = BinaryPrimitives.ReadUInt32LittleEndian(head.Slice((int)certDirectoryAt, 4));
        long certTableLength = BinaryPrimitives.ReadUInt32LittleEndian(head.Slice((int)certDirectoryAt + 4, 4));
        if (certTableLength == 0)
        {
            certTableAt = fileLength;
        }
        else if (certTableAt < optionalAt + optionalSize || certTableAt + certTableLength > fileLength)
        {
            return null;
        }
        return new Exclusions(checkSumAt, certDirectoryAt, certTableAt, certTableLength);
    }

    /// <summary>The parts of the chunk [offset, offset+count) that the digest includes.</summary>
    internal static IEnumerable<(long Start, int Count)> Included(long offset, int count, Exclusions ex)
    {
        var cuts = new (long Start, long End)[]
        {
            (ex.CheckSumAt, ex.CheckSumAt + 4),
            (ex.CertDirectoryAt, ex.CertDirectoryAt + 8),
            (ex.CertTableAt, ex.CertTableAt + ex.CertTableLength),
        };
        var position = offset;
        var end = offset + count;
        foreach (var (cutStart, cutEnd) in cuts)
        {
            if (cutEnd <= position || cutStart >= end) continue;
            if (cutStart > position) yield return (position, (int)(cutStart - position));
            position = Math.Max(position, Math.Min(cutEnd, end));
        }
        if (position < end) yield return (position, (int)(end - position));
    }

    private static void ReadExactly(Stream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = stream.Read(buffer, total, buffer.Length - total);
            if (n <= 0) throw new EndOfStreamException("driver file shorter than its length");
            total += n;
        }
    }

    private static string Hex(byte[] digest) => Convert.ToHexString(digest).ToLowerInvariant();
}
