using Patched.Shared.Contract;
using Xunit;

namespace Patched.Shared.Tests;

/// <summary>
/// Tests for TriggerRequestValidator — the privilege-boundary input validator (PAT-307).
/// These run on any OS.
/// </summary>
public sealed class TriggerValidatorTests
{
    [Fact]
    public void ValidDeployTrigger_Passes()
    {
        var json = """{"labels":["googlechrome"],"requested_by":"user","source":"tray"}""";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out var req, out var err);
        Assert.True(ok);
        Assert.Null(err);
        Assert.NotNull(req);
        Assert.True(req!.IsDeployRequest);
        Assert.Equal(["googlechrome"], req.Labels);
    }

    [Fact]
    public void WildcardDeployTrigger_Passes()
    {
        var json = """{"labels":["*"],"requested_by":"user"}""";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out var req, out _);
        Assert.True(ok);
        Assert.Equal(["*"], req!.Labels);
    }

    [Fact]
    public void OsDeferTrigger_Passes()
    {
        var json = """{"type":"os_defer","requested_by":"user","deferred_at":"2026-12-11T09:00:00Z"}""";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out var req, out _);
        Assert.True(ok);
        Assert.True(req!.IsOsDefer);
    }

    [Fact]
    public void OversizedFile_Rejected()
    {
        var json = """{"labels":["googlechrome"]}""";
        var ok = TriggerRequestValidator.TryValidate(json, 5000, out _, out var err);
        Assert.False(ok);
        Assert.Contains("byte limit", err);
    }

    [Fact]
    public void MalformedJson_Rejected()
    {
        var json = "{ not valid json {{";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.Contains("Malformed", err);
    }

    [Fact]
    public void EmptyPayload_Rejected()
    {
        var json = "null";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.Contains("Empty", err);
    }

    [Fact]
    public void TriggerWithNoLabelsNoType_Rejected()
    {
        var json = """{"requested_by":"user"}""";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.NotNull(err);
    }

    [Fact]
    public void LabelWithPathTraversal_Rejected()
    {
        var json = """{"labels":["../etc/passwd"]}""";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.Contains("invalid", err);
    }

    [Fact]
    public void LabelWithNullByte_Rejected()
    {
        var json = "{\"labels\":[\"chro\0me\"]}";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.Contains("invalid", err);
    }

    [Fact]
    public void TooManyLabels_Rejected()
    {
        var labels = string.Join(",", Enumerable.Range(0, 51).Select(i => $"\"pkg{i}\""));
        var json = $"{{\"labels\":[{labels}]}}";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.Contains("exceeds", err);
    }

    [Fact]
    public void RequestedByTooLong_Rejected()
    {
        var longName = new string('x', 257);
        var json = $"{{\"labels\":[\"pkg\"],\"requested_by\":\"{longName}\"}}";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.Contains("requested_by", err);
    }

    // MARK: - removal_defer (PAT-1623)

    [Fact]
    public void RemovalDeferTrigger_Passes()
    {
        var json = """{"type":"removal_defer","entry_id":42,"name":"Slack","requested_by":"user","deferred_at":"2026-09-12T09:00:00Z"}""";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out var req, out var err);
        Assert.True(ok);
        Assert.Null(err);
        Assert.True(req!.IsRemovalDeferRequest);
        Assert.Equal(42, req.EntryId);
        Assert.Equal("Slack", req.Name);
        // The two deferral budgets (OS-update deferrals_remaining vs. removal's
        // own tally) must never be conflated: a removal_defer trigger is never
        // also an os_defer trigger, or vice versa.
        Assert.False(req.IsOsDefer);
    }

    [Fact]
    public void RemovalDeferTriggerWithoutEntryId_Rejected()
    {
        var json = """{"type":"removal_defer","requested_by":"user"}""";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.Contains("entry_id", err);
    }

    [Fact]
    public void RemovalDeferTriggerNameTooLong_Rejected()
    {
        var longName = new string('x', 257);
        var json = $$"""{"type":"removal_defer","entry_id":1,"name":"{{longName}}"}""";
        var ok = TriggerRequestValidator.TryValidate(json, json.Length, out _, out var err);
        Assert.False(ok);
        Assert.Contains("name", err);
    }

    [Fact]
    public void OsDeferAndRemovalDeferAreMutuallyExclusive()
    {
        var osDefer = """{"type":"os_defer","requested_by":"user"}""";
        var ok = TriggerRequestValidator.TryValidate(osDefer, osDefer.Length, out var req, out _);
        Assert.True(ok);
        Assert.True(req!.IsOsDefer);
        Assert.False(req.IsRemovalDeferRequest);
    }
}
