using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// The static guard for a read-only collector's source, shared by the Windows scanners
/// (PAT-2018 package managers, PAT-2019 local models, PAT-2020 MCP servers, PAT-2033 IDE
/// extensions; any new one should add its files here
/// rather than grow its own copy). It reads the source files as text from the checkout, strips
/// comments so the check is on code, and fails on anything that could start a process, load
/// code, call native code or open a network connection, and on any using directive outside the
/// caller's allowlist, so a new namespace has to be reviewed before it can be used.
/// </summary>
internal static class CollectorSourceGuard
{
    /// <summary>
    /// Process launch, code loading, native calls, network clients, loopback addresses, and any
    /// URL at all (a scheme followed by ://, PAT-2033): a scanner that reads files has no
    /// address to name.
    /// </summary>
    public static readonly Regex ExecOrNetwork = new(
        @"\bProcess\b|ProcessStartInfo|ShellExecute|CreateProcess|Win32_Process|\bManagementClass\b|" +
        @"Assembly\.Load|\bActivator\b|DllImport|LibraryImport|\bMarshal\b|HttpClient|WebClient|WebRequest|" +
        @"\bSocket\b|TcpClient|UdpClient|Dns\.|NamedPipe|\.(cmd|bat|ps1)""|" +
        @"localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|\b11434\b|:1234\b|/api/|" +
        @"\b[A-Za-z][A-Za-z0-9+.-]*://",
        RegexOptions.CultureInvariant);

    /// <summary>The absolute path of a file under windows/src, from this test file's own location.</summary>
    public static string SourceFile(string relative, [CallerFilePath] string thisFile = "")
    {
        var path = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(thisFile)!, "..", "..", "src", relative));
        Assert.True(File.Exists(path), $"source not found at {path}; this test must run from a source checkout");
        return path;
    }

    /// <summary>
    /// The source with // and /* */ comments removed and every string and char literal kept
    /// whole. PAT-2033: the old line-comment pattern also cut a string at its "//", so a URL in
    /// code lost its "://" before any rule could see it. Regular, verbatim (@"", $@""),
    /// interpolated and raw (""" """) strings are recognised. PAT-2040: an interpolation hole
    /// ({...} in $"", $@"", @$"" and $"""...""", with {{ }} escapes and $$ raw delimiters) is
    /// code, not string text: it is scanned as code, so a string inside a hole cannot end the
    /// outer string early and turn the rest of the line, or everything up to the next */, into
    /// a comment that hides code.
    /// </summary>
    public static string Code(string text)
    {
        var sb = new StringBuilder(text.Length);
        var i = 0;
        ScanCode(text, ref i, sb, inHole: false);
        return sb.ToString();
    }

    /// <summary>
    /// Appends code from <paramref name="i"/> with comments stripped and literals kept whole.
    /// In a hole it stops, without consuming it, at the '}' that closes the hole or at the ':'
    /// that starts its format clause, both at nesting depth 0.
    /// </summary>
    private static void ScanCode(string text, ref int i, StringBuilder sb, bool inHole)
    {
        var depth = 0;
        while (i < text.Length)
        {
            var c = text[i];
            var next = i + 1 < text.Length ? text[i + 1] : '\0';
            if (c == '/' && next == '/')
            {
                while (i < text.Length && text[i] != '\n') i++;
                continue;
            }
            if (c == '/' && next == '*')
            {
                var end = text.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? text.Length : end + 2;
                sb.Append(' ');
                continue;
            }
            if (c == '"')
            {
                StringLiteral(text, ref i, sb);
                continue;
            }
            if (c == '\'')
            {
                // A char literal: '"' or '\'' must not open a string. Anything longer is
                // not a char literal and is copied as it is.
                var close = text.IndexOf('\'', i + (next == '\\' ? 3 : 2));
                if (close > i && close - i <= 8)
                {
                    sb.Append(text, i, close + 1 - i);
                    i = close + 1;
                    continue;
                }
            }
            if (c == '\\' && next is 'u' or 'U')
            {
                // PAT-2040: C# lets an identifier spell any letter as \uXXXX, so Pro\u0063ess
                // is Process to the compiler and invisible to every pattern here. Outside a
                // literal (literals and comments were consumed above) the only other use of a
                // backslash is an error anyway, so any \u or \U in code fails the guard.
                throw new InvalidOperationException(
                    $"a \\{next} escape outside a string or char literal at offset {i}; spell the identifier out");
            }
            if (inHole)
            {
                if (c is '(' or '[' or '{') depth++;
                else if (c is ')' or ']') depth = Math.Max(0, depth - 1);
                else if (c == '}')
                {
                    if (depth == 0) return;
                    depth--;
                }
                else if (c == ':' && depth == 0)
                {
                    if (next == ':')
                    {
                        sb.Append("::");
                        i += 2;
                        continue;
                    }
                    return;
                }
            }
            sb.Append(c);
            i++;
        }
    }

    /// <summary>
    /// Appends the string literal whose first quote is at <paramref name="i"/> and moves past
    /// it. Its $ and @ prefix has already been copied as code; it is read back from the text.
    /// </summary>
    private static void StringLiteral(string text, ref int i, StringBuilder sb)
    {
        var start = i;
        var dollars = 0;
        var verbatim = false;
        for (var p = start - 1; p >= 0 && (text[p] == '$' || text[p] == '@'); p--)
        {
            if (text[p] == '$') dollars++;
            else verbatim = true;
        }
        var quotes = 0;
        while (i < text.Length && text[i] == '"')
        {
            quotes++;
            i++;
        }
        sb.Append('"', quotes);
        if (quotes == 2) return;
        if (quotes >= 3)
        {
            RawBody(text, ref i, sb, quotes, dollars);
            return;
        }
        while (i < text.Length)
        {
            var c = text[i];
            var next = i + 1 < text.Length ? text[i + 1] : '\0';
            if (dollars > 0 && (c == '{' || c == '}'))
            {
                if (next == c)
                {
                    sb.Append(c).Append(c);
                    i += 2;
                    continue;
                }
                if (c == '{')
                {
                    sb.Append(c);
                    i++;
                    Hole(text, ref i, sb, 1);
                    continue;
                }
            }
            if (verbatim)
            {
                if (c == '"')
                {
                    if (next == '"')
                    {
                        sb.Append("\"\"");
                        i += 2;
                        continue;
                    }
                    sb.Append(c);
                    i++;
                    return;
                }
            }
            else
            {
                if (c == '\\')
                {
                    sb.Append(text, i, Math.Min(2, text.Length - i));
                    i += 2;
                    continue;
                }
                if (c == '"' || c == '\n')
                {
                    sb.Append(c);
                    i++;
                    return;
                }
            }
            sb.Append(c);
            i++;
        }
    }

    /// <summary>The body and closing delimiter of a raw string opened by <paramref name="quotes"/> quotes.</summary>
    private static void RawBody(string text, ref int i, StringBuilder sb, int quotes, int dollars)
    {
        var delimiter = new string('"', quotes);
        while (i < text.Length)
        {
            if (string.CompareOrdinal(text, i, delimiter, 0, quotes) == 0)
            {
                sb.Append(delimiter);
                i += quotes;
                return;
            }
            if (dollars > 0 && text[i] == '{')
            {
                var run = 0;
                while (i + run < text.Length && text[i + run] == '{') run++;
                sb.Append('{', run);
                i += run;
                // Fewer braces than dollars are content; the last `dollars` of a longer run open a hole.
                if (run >= dollars) Hole(text, ref i, sb, dollars);
                continue;
            }
            sb.Append(text[i]);
            i++;
        }
    }

    /// <summary>
    /// A hole's code, its format clause if any, and its <paramref name="closers"/> closing
    /// braces, starting just past the opening brace.
    /// </summary>
    private static void Hole(string text, ref int i, StringBuilder sb, int closers)
    {
        ScanCode(text, ref i, sb, inHole: true);
        if (i < text.Length && text[i] == ':')
        {
            // The format clause is text up to the closing brace.
            while (i < text.Length && text[i] != '}' && text[i] != '\n')
            {
                sb.Append(text[i]);
                i++;
            }
        }
        for (var n = 0; n < closers && i < text.Length && text[i] == '}'; n++)
        {
            sb.Append('}');
            i++;
        }
    }

    /// <summary>Every forbidden match in <paramref name="code"/>.</summary>
    public static string[] Hits(string code, Regex forbidden) =>
        forbidden.Matches(code).Select(m => m.Value).ToArray();

    /// <summary>
    /// Fails when the file at <paramref name="relative"/> (under windows/src) executes, loads
    /// or connects anything, uses a namespace outside <paramref name="allowedUsings"/>, or uses
    /// System.Diagnostics for anything but Stopwatch.
    /// </summary>
    public static void AssertExecutesNothing(string relative, IReadOnlySet<string> allowedUsings)
    {
        var code = Code(File.ReadAllText(SourceFile(relative)));
        var hits = Hits(code, ExecOrNetwork);
        Assert.True(hits.Length == 0, $"{relative} must not execute or connect: {string.Join(", ", hits)}");

        var usings = Regex.Matches(code, @"^using\s+([A-Za-z0-9_.]+)\s*;", RegexOptions.Multiline).Select(m => m.Groups[1].Value);
        Assert.All(usings, u => Assert.True(allowedUsings.Contains(u), $"{relative}: using {u} is not on the reviewed list"));
        // System.Diagnostics is allowed for Stopwatch only.
        Assert.DoesNotMatch(new Regex(@"Diagnostics\.(?!Stopwatch)"), code);
    }
}
