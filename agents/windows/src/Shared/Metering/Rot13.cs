using System.Text;

namespace Patched.Shared.Metering;

/// <summary>
/// ROT13 codec. UserAssist Count value names are ROT13-obfuscated executable paths;
/// decoding rotates ASCII letters by 13 and leaves digits / punctuation untouched.
/// </summary>
public static class Rot13
{
    public static string Decode(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c is >= 'a' and <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c is >= 'A' and <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
