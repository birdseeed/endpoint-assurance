using Patched.Shared.Removal;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// PAT-687: tests for the UninstallString -> executable + argv parser that
/// replaced `cmd.exe /c &lt;UninstallString&gt;` in UninstallExecutor.
/// </summary>
public sealed class WindowsCommandLineTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_EmptyOrWhitespace_ReturnsNull(string? input)
    {
        Assert.Null(WindowsCommandLine.Parse(input));
    }

    [Fact]
    public void Parse_QuotedExeWithArg()
    {
        var p = WindowsCommandLine.Parse("\"C:\\Program Files\\App\\unins000.exe\" /SILENT");
        Assert.NotNull(p);
        Assert.Equal("C:\\Program Files\\App\\unins000.exe", p!.Value.Executable);
        Assert.Equal(new[] { "/SILENT" }, p.Value.Arguments);
    }

    [Fact]
    public void Parse_UnquotedExeWithMultipleArgs()
    {
        var p = WindowsCommandLine.Parse("MsiExec.exe /X{2C1B-GUID} /qn /norestart");
        Assert.NotNull(p);
        Assert.Equal("MsiExec.exe", p!.Value.Executable);
        Assert.Equal(new[] { "/X{2C1B-GUID}", "/qn", "/norestart" }, p.Value.Arguments);
    }

    [Fact]
    public void Parse_ShellMetacharacters_AreLiteralArgvNotOperators()
    {
        // The whole point: `& calc.exe` etc. must be inert argv, not shell operators.
        var p = WindowsCommandLine.Parse("\"C:\\App\\uninst.exe\" /S & calc.exe");
        Assert.NotNull(p);
        Assert.Equal("C:\\App\\uninst.exe", p!.Value.Executable);
        Assert.Equal(new[] { "/S", "&", "calc.exe" }, p.Value.Arguments);
    }

    [Fact]
    public void Parse_QuotedArgWithSpaces()
    {
        var p = WindowsCommandLine.Parse("\"C:\\App\\uninst.exe\" \"/log=C:\\Temp\\my log.txt\"");
        Assert.NotNull(p);
        Assert.Equal("C:\\App\\uninst.exe", p!.Value.Executable);
        Assert.Equal(new[] { "/log=C:\\Temp\\my log.txt" }, p.Value.Arguments);
    }

    [Fact]
    public void Parse_BackslashQuoteEscaping()
    {
        // 2n backslashes + " -> n backslashes + quote toggle; here \\" -> one backslash then quote.
        var p = WindowsCommandLine.Parse("app.exe \"a\\\\\" b");
        Assert.NotNull(p);
        Assert.Equal("app.exe", p!.Value.Executable);
        Assert.Equal(new[] { "a\\", "b" }, p.Value.Arguments);
    }

    [Fact]
    public void Parse_NoArgs()
    {
        var p = WindowsCommandLine.Parse("\"C:\\Program Files\\App\\unins000.exe\"");
        Assert.NotNull(p);
        Assert.Equal("C:\\Program Files\\App\\unins000.exe", p!.Value.Executable);
        Assert.Empty(p.Value.Arguments);
    }
}
