using System.Text.RegularExpressions;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-2040: <see cref="CollectorSourceGuard.Code"/> reads an interpolation hole as code. A
/// string inside a hole used to end the outer string early, so its "//" or "/*" was taken as a
/// comment and the rest of the line, or everything up to the next "*/", vanished from the
/// guard's view, taking a forbidden call with it.
/// </summary>
public sealed class CollectorSourceGuardTests
{
    private static string[] Hits(string source) =>
        CollectorSourceGuard.Hits(CollectorSourceGuard.Code(source), CollectorSourceGuard.ExecOrNetwork);

    [Theory]
    // A "//" in a string inside a hole: the old stripper dropped the rest of the line.
    [InlineData("var s = $\"{(a ? \"//\" : \"\")}\"; Process.Start(x);")]
    [InlineData("var s = $@\"{(a ? \"//\" : \"\")}\"; Process.Start(x);")]
    [InlineData("var s = @$\"{(a ? \"//\" : \"\")}\"; Process.Start(x);")]
    [InlineData("var s = $\"\"\"{(a ? \"//\" : \"\")}\"\"\"; Process.Start(x);")]
    [InlineData("var s = $$\"\"\"{{{(a ? \"//\" : \"\")}}}\"\"\"; Process.Start(x);")]
    // A "/*" in a string inside a hole: the old stripper hid everything up to the next "*/".
    [InlineData("var s = $\"{M(\"/*\")}\";\nProcess.Start(x);\nvar t = \"*/\";")]
    [InlineData("var s = $@\"{M(\"/*\")}\";\nProcess.Start(x);\nvar t = \"*/\";")]
    [InlineData("var s = @$\"{M(\"/*\")}\";\nProcess.Start(x);\nvar t = \"*/\";")]
    // Escaped braces, a format clause with slashes, a nested hole and a global:: alias are not
    // mistaken for the end of the string either.
    [InlineData("var s = $\"{{\\\"//\\\"}}\"; Process.Start(x);")]
    [InlineData("var s = $\"{d:dd//MM}\"; Process.Start(x);")]
    [InlineData("var s = $\"{$\"{\"//\"}\"}\"; Process.Start(x);")]
    [InlineData("var s = $\"{global::System.Math.PI}\"; Process.Start(x);")]
    [InlineData("var s = $\"{new[] { \"//\" }[0]}\"; Process.Start(x);")]
    public void CodeAfterAnInterpolatedString_IsStillSeen(string source) =>
        Assert.Contains("Process", Hits(source));

    [Fact]
    public void AStringInsideAHole_IsKeptWhole() =>
        Assert.NotEmpty(Hits("var s = $\"{(a ? \"https://x.example/\" : \"\")}\";"));

    [Fact]
    public void ACommentInsideAHole_IsStillStripped()
    {
        Assert.Empty(Hits("var s = $\"{x /* https://x.example/ */}\";"));
        Assert.Empty(Hits("var s = $@\"{x /* Process.Start */}\";"));
    }

    [Fact]
    public void EscapedBracesAreText_NotAHole()
    {
        // {{ opens no hole, so the "/*" is string text and nothing after it is hidden.
        Assert.Contains("Process", Hits("var s = $\"{{/*}}\"; Process.Start(x); var t = \"*/\";"));
        Assert.Equal("var s = $\"{{a}}\";", CollectorSourceGuard.Code("var s = $\"{{a}}\";"));
    }

    /// <summary>
    /// PAT-2040: Pro\u0063ess compiles as Process, so a unicode escape in code, where no
    /// pattern could see through it, fails the guard outright. In a string, a char literal or
    /// a comment it is text and is left alone.
    /// </summary>
    [Theory]
    [InlineData("Pro\\u0063ess.Start(x);")]
    [InlineData("Pro\\U00000063ess.Start(x);")]
    [InlineData("var s = $\"{Pro\\u0063ess.Start(x)}\";")]
    [InlineData("var c = 'a'; \\u0048ttpClient h;")]
    public void AUnicodeEscapeInCode_FailsTheGuard(string source) =>
        Assert.Throws<InvalidOperationException>(() => CollectorSourceGuard.Code(source));

    [Theory]
    [InlineData("var s = \"Pro\\u0063ess\";")]
    [InlineData("var s = @\"C:\\users\\u\";")]
    [InlineData("var c = '\\u0063';")]
    [InlineData("// Pro\\u0063ess\nvar a = 1; /* \\U00000063 */")]
    public void AUnicodeEscapeInALiteralOrComment_IsText(string source) =>
        Assert.Empty(Hits(source));
}

/// <summary>
/// PAT-2040: the collectors' native surface is pinned. WindowsFileIdentity is the one file that
/// may import native code, and only these kernel32 entry points; every other collector file
/// (the scan logics, the reader, the PE parser and the four Service scanners) imports none.
/// A new import, a new DLL or an import anywhere else turns this red and has to be reviewed.
/// </summary>
public sealed class CollectorNativeSurfaceTests
{
    private static readonly Regex Import = new(
        @"\[(?:DllImport|LibraryImport)\(\s*""(?<dll>[^""]+)""[^\]]*\][\s\S]*?\bextern\s+[\w.<>\[\]?]+\s+(?<name>\w+)\s*\(",
        RegexOptions.CultureInvariant);

    private static readonly Regex AnyNative = new(
        @"DllImport|LibraryImport|\bextern\b|NativeLibrary|\bdelegate\s+\*\s*unmanaged|UnmanagedCallersOnly",
        RegexOptions.CultureInvariant);

    public static IEnumerable<object[]> OtherCollectorFiles() =>
    [
        [Path.Combine("Shared", "IdeExtensions", "IdeExtensionScanLogic.cs")],
        [Path.Combine("Shared", "LocalModels", "LocalModelScanLogic.cs")],
        [Path.Combine("Shared", "LocalModels", "PeVersionReader.cs")],
        [Path.Combine("Shared", "McpServers", "McpServerScanLogic.cs")],
        [Path.Combine("Shared", "PackageManagers", "PackageManagerScanLogic.cs")],
        [Path.Combine("Shared", "UserTrees", "UserTreeReader.cs")],
        [Path.Combine("Shared", "BrowserExtensions", "BrowserExtensionScanLogic.cs")],
        [Path.Combine("Service", "BrowserExtensionScanner.cs")],
        [Path.Combine("Service", "IdeExtensionScanner.cs")],
        [Path.Combine("Service", "LocalModelScanner.cs")],
        [Path.Combine("Service", "McpServerScanner.cs")],
        [Path.Combine("Service", "PackageManagerScanner.cs")],
    ];

    private static string CodeOf(string relative) =>
        CollectorSourceGuard.Code(File.ReadAllText(CollectorSourceGuard.SourceFile(relative)));

    [Fact]
    public void WindowsFileIdentity_ImportsExactlyTheReviewedKernel32EntryPoints()
    {
        var code = CodeOf(Path.Combine("Shared", "IdeExtensions", "WindowsFileIdentity.cs"));
        var imports = Import.Matches(code).Select(m => m.Groups["dll"].Value + "!" + m.Groups["name"].Value)
            .OrderBy(x => x, StringComparer.Ordinal).ToArray();
        Assert.Equal(
            new[]
            {
                "kernel32.dll!CreateFileW",
                // PAT-2052: FSCTL_GET_REPARSE_POINT on a handle opened on a link itself, so a
                // link's target is read only after the link's own final path is verified.
                "kernel32.dll!DeviceIoControl",
                "kernel32.dll!GetFileInformationByHandle",
                "kernel32.dll!GetFileInformationByHandleEx",
                "kernel32.dll!GetFinalPathNameByHandleW",
                "kernel32.dll!GetLongPathNameW",
            },
            imports);
        // Every import attribute and every extern is one of those six: none escapes the pattern.
        Assert.Equal(6, Regex.Matches(code, @"DllImport|LibraryImport").Count);
        Assert.Equal(6, Regex.Matches(code, @"\bextern\b").Count);
        Assert.DoesNotMatch(new Regex(@"NativeLibrary|\bdelegate\s+\*\s*unmanaged|UnmanagedCallersOnly"), code);
    }

    [Theory]
    [MemberData(nameof(OtherCollectorFiles))]
    public void OtherCollectorFiles_ImportNoNativeCode(string relative) =>
        Assert.Empty(CollectorSourceGuard.Hits(CodeOf(relative), AnyNative));

    [Fact]
    public void TheNativeGuards_CatchWhatTheyAreFor()
    {
        const string Extra = "[DllImport(\"kernel32.dll\")] private static extern bool DeleteFileW(string p);";
        Assert.Equal("kernel32.dll!DeleteFileW",
            Import.Matches(Extra).Select(m => m.Groups["dll"].Value + "!" + m.Groups["name"].Value).Single());
        Assert.NotEmpty(CollectorSourceGuard.Hits("[LibraryImport(\"ntdll.dll\")] static partial int NtQueryDirectoryFile();", AnyNative));
        Assert.NotEmpty(CollectorSourceGuard.Hits("var h = NativeLibrary.Load(\"x.dll\");", AnyNative));
    }
}
