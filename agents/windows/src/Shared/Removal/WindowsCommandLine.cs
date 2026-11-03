namespace Patched.Shared.Removal;

/// <summary>
/// Splits a Windows command line (e.g. a registry <c>UninstallString</c>) into an
/// executable path plus an argument list, following the same tokenisation rules as
/// <c>CommandLineToArgvW</c> / the C runtime argv parser.
///
/// PAT-687: the executor previously handed the raw <c>UninstallString</c> to
/// <c>cmd.exe /c &lt;string&gt;</c>, which lets any shell metacharacters (&amp;, |,
/// &amp;&amp;, %VAR%, &gt;) in a vendor-controlled registry value run under the
/// SYSTEM service account. Parsing here lets the caller launch the uninstaller
/// executable directly with a discrete argument list and no shell.
/// </summary>
public static class WindowsCommandLine
{
    /// <summary>The parsed result: the executable and its arguments.</summary>
    public readonly record struct Parsed(string Executable, IReadOnlyList<string> Arguments);

    /// <summary>
    /// Parse <paramref name="commandLine"/> into an executable + arguments.
    /// Returns null when the command line is empty / whitespace-only.
    /// </summary>
    public static Parsed? Parse(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
            return null;

        var tokens = Tokenize(commandLine);
        if (tokens.Count == 0)
            return null;

        var exe  = tokens[0];
        var args = tokens.Count > 1 ? tokens.GetRange(1, tokens.Count - 1) : new List<string>();
        return new Parsed(exe, args);
    }

    /// <summary>
    /// Tokenise a command line. The first token (the program name) uses the special
    /// CommandLineToArgvW rule: backslashes are literal, and a leading quote runs to
    /// the next quote. Every subsequent token uses the backslash/quote escaping rules.
    /// </summary>
    private static List<string> Tokenize(string s)
    {
        var result = new List<string>();
        int i = 0;
        int n = s.Length;

        // Skip leading whitespace.
        while (i < n && IsWhitespace(s[i])) i++;
        if (i >= n) return result;

        // --- argv[0] (program name): backslashes literal; quote runs to next quote. ---
        var first = new System.Text.StringBuilder();
        if (s[i] == '"')
        {
            i++; // consume opening quote
            while (i < n && s[i] != '"') first.Append(s[i++]);
            if (i < n) i++; // consume closing quote
        }
        else
        {
            while (i < n && !IsWhitespace(s[i])) first.Append(s[i++]);
        }
        result.Add(first.ToString());

        // --- remaining arguments: standard msvcrt argv rules ---
        while (true)
        {
            while (i < n && IsWhitespace(s[i])) i++;
            if (i >= n) break;

            var arg = new System.Text.StringBuilder();
            bool inQuotes = false;

            while (i < n)
            {
                char c = s[i];

                if (c == '\\')
                {
                    // Count the run of backslashes.
                    int backslashes = 0;
                    while (i < n && s[i] == '\\') { backslashes++; i++; }

                    if (i < n && s[i] == '"')
                    {
                        // 2n backslashes + " -> n backslashes then toggle quote.
                        // 2n+1 backslashes + " -> n backslashes then a literal ".
                        arg.Append('\\', backslashes / 2);
                        if (backslashes % 2 == 0)
                        {
                            inQuotes = !inQuotes;
                        }
                        else
                        {
                            arg.Append('"');
                        }
                        i++; // consume the quote
                    }
                    else
                    {
                        // Backslashes not followed by a quote are literal.
                        arg.Append('\\', backslashes);
                    }
                    continue;
                }

                if (c == '"')
                {
                    // A quote inside a quoted section, immediately followed by another
                    // quote, is a literal quote ("" -> "). Otherwise it toggles quoting.
                    if (inQuotes && i + 1 < n && s[i + 1] == '"')
                    {
                        arg.Append('"');
                        i += 2;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                        i++;
                    }
                    continue;
                }

                if (!inQuotes && IsWhitespace(c))
                    break;

                arg.Append(c);
                i++;
            }

            result.Add(arg.ToString());
        }

        return result;
    }

    private static bool IsWhitespace(char c) => c == ' ' || c == '\t';
}
