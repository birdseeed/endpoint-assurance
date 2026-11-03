using Patched.Shared.Posture;
using Xunit;
// The namespace and the root type share the name "Posture"; alias the type so
// static calls (PostureDoc.Deserialize) resolve to the type, not the namespace.
using PostureDoc = Patched.Shared.Posture.Posture;

namespace Patched.Shared.Tests;

/// <summary>
/// Desktop chain U0: the platform-neutral posture model + the single honest-gating
/// seam (<see cref="PostureGating"/>). Covers deserialization, the "X of N" coverage
/// rule, tier gating, per-app uninstall gating, and crash-safety on unknown
/// vocabulary / malformed JSON.
/// </summary>
public class PostureModelsTests
{
    // Minimal-but-representative posture, assurance tier (gated surfaces). PAT-1599
    // collapsed the tier vocabulary to assurance/managed; assurance is the new
    // observe-only default (formerly "report_deploy").
    private const string AssuranceTierJson = """
    {
      "schema_version": 1,
      "generated_at": "2026-12-17T08:14:02Z",
      "device": { "id": "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "os": "Windows", "os_version": "11 24H2" },
      "tier": "assurance",
      "app_count": 61,
      "compliance": {
        "platform": "Windows",
        "benchmarks": [
          {
            "benchmark": "CIS Microsoft Windows 11 Enterprise",
            "benchmark_version": "v3.0.0",
            "implemented": 87, "benchmark_total": 134,
            "passed": 74, "failed": 10, "not_applicable": 3, "errors": 0,
            "compliance_pct": 88.1,
            "sections": [
              { "section": "18", "passed": 31, "total": 38, "controls": [
                { "rule_key": "18.9.45.1", "title": "BitLocker on OS drive", "severity": "critical", "status": "pass", "observed_value": "On", "evaluated_at": "2026-12-17T08:13:42Z" }
              ] }
            ]
          }
        ]
      },
      "evidence": { "coverage_window_days": 30, "scans_logged": 27, "last_signed_report_digest": null, "recent_scan_times": ["2026-12-17T08:13:58Z"] },
      "app_policy": {
        "apps": [
          { "app_name": "CrowdStrike Falcon Sensor", "identifier": "{A1}", "policy": "mandatory", "user_removable": false, "enforcement_tier": "app_management" },
          { "app_name": "Microsoft Edge", "identifier": "{56}", "policy": "approved", "user_removable": true, "enforcement_tier": "app_management" }
        ],
        "drift": [
          { "drift_type": "unapproved_present", "app_name": "qBittorrent", "identifier": "qBittorrent", "policy": "unapproved", "enforcement_tier": "app_management" }
        ]
      }
    }
    """;

    [Fact]
    public void Deserialize_AssuranceTier_PopulatesModelAndCoverageText()
    {
        var p = PostureDoc.Deserialize(AssuranceTierJson);

        Assert.NotNull(p);
        Assert.Equal(1, p!.SchemaVersion);
        Assert.Equal("Windows", p.Device.Os);
        Assert.Equal(61, p.AppCount);

        var bench = p.Compliance.Primary;
        Assert.NotNull(bench);
        // The "X of N" rule — coverage from the payload, never a hardcoded total.
        Assert.Equal("87 of 134", bench!.CoverageText);
        Assert.Equal(88.1, bench.CompliancePct, 3);
    }

    [Fact]
    public void AssuranceTier_GatesPatchDeployAndUninstall()
    {
        var p = PostureDoc.Deserialize(AssuranceTierJson)!;

        Assert.False(p.CanPatchDeploy);                       // assurance is gated
        Assert.False(PostureGating.GrantsPatchDeploy(p.Tier));
        Assert.False(PostureGating.GrantsAppManagement(p.Tier));

        var falcon = p.AppPolicy!.Apps[0]; // mandatory, not user_removable
        var edge   = p.AppPolicy!.Apps[1]; // approved, user_removable

        Assert.True(falcon.IsRequired);
        Assert.False(PostureGating.CanUninstall(p.Tier, falcon));  // gated + mandatory
        Assert.False(PostureGating.CanUninstall(p.Tier, edge));    // tier gates it
    }

    [Fact]
    public void EnforcementReportTier_NeverActuatesEvenOnManagedDevice()
    {
        // PAT-1599: device tier is now "managed" (the only actuating device tier);
        // this still proves the per-app enforcement_tier is a distinct, separately
        // gated vocabulary — a managed device does not override an app whose own
        // enforcement_tier is advisory-only ("report").
        var json = AssuranceTierJson
            .Replace("\"assurance\"", "\"managed\"")
            .Replace("\"approved\", \"user_removable\": true, \"enforcement_tier\": \"app_management\"",
                     "\"approved\", \"user_removable\": true, \"enforcement_tier\": \"report\"");
        var p = PostureDoc.Deserialize(json)!;

        var edge = p.AppPolicy!.Apps[1];
        Assert.False(PostureGating.CanUninstall(p.Tier, edge)); // report enforcement is advisory only
    }

    [Fact]
    public void ManagedTier_EnablesPatchDeployAndUninstallExceptMandatory()
    {
        // PAT-1416: "managed" is the agent tier the "full_endpoint" subscription tier
        // maps to (PAT-1048/PAT-1121). PAT-1599 retired the former "patch" rung
        // entirely, so "managed" is now the sole actuating device tier — the
        // top-paying tier must not see its own paid-for affordances presented as
        // gated.
        var json = AssuranceTierJson.Replace("\"assurance\"", "\"managed\"");
        var p = PostureDoc.Deserialize(json)!;

        Assert.True(p.CanPatchDeploy);
        Assert.True(PostureGating.GrantsAppManagement(p.Tier));

        var falcon = p.AppPolicy!.Apps[0]; // mandatory → never removable
        var edge   = p.AppPolicy!.Apps[1]; // approved + app_management + user_removable

        Assert.False(PostureGating.CanUninstall(p.Tier, falcon)); // user_removable=false
        Assert.True(PostureGating.CanUninstall(p.Tier, edge));    // all three gates pass
    }

    [Theory]
    // PAT-1599: only "managed" grants — the former "patch" rung is retired.
    [InlineData("managed", true)]
    [InlineData("MANAGED", true)]
    // Everything else — the canonical observe-only tier, retired values, and
    // anything unrecognized — is advisory-only and fails closed.
    [InlineData("assurance", false)]
    [InlineData("ASSURANCE", false)]
    [InlineData("patch", false)]
    [InlineData("PATCH", false)]
    [InlineData("report", false)]
    [InlineData("report_deploy", false)]
    [InlineData("app_management", false)]
    [InlineData("", false)]
    [InlineData("bogus", false)]
    public void GatingPredicates_MatchExpectedVocabulary(string tier, bool expected)
    {
        Assert.Equal(expected, PostureGating.GrantsPatchDeploy(tier));
        Assert.Equal(expected, PostureGating.GrantsAppManagement(tier));
    }

    [Theory]
    // Canonical + legacy actuating values — PAT-1121 dual-accept, case-insensitive.
    [InlineData("patch", true)]
    [InlineData("PATCH", true)]
    [InlineData("app_management", true)]
    [InlineData("APP_MANAGEMENT", true)]
    [InlineData("managed", true)]
    [InlineData("MANAGED", true)]
    // Advisory-only / unrecognized — fail-closed.
    [InlineData("report", false)]
    [InlineData("report_deploy", false)]
    // PAT-1505 phase 1: "assurance" is newly accepted alongside "report_deploy"
    // but must gate identically to it — phase 1 is accept-both, not a grant of
    // new capability.
    [InlineData("assurance", false)]
    [InlineData("ASSURANCE", false)]
    [InlineData("", false)]
    [InlineData("bogus", false)]
    public void EnforcementActuates_MatchesExpectedVocabulary(string enforcementTier, bool expected)
    {
        Assert.Equal(expected, PostureGating.EnforcementActuates(enforcementTier));
    }

    [Fact]
    public void UnknownVocabulary_DoesNotThrow()
    {
        // A future server severity/policy/tier value must not break the reader.
        var json = AssuranceTierJson
            .Replace("\"critical\"", "\"catastrophic\"")
            .Replace("\"assurance\"", "\"some_future_tier\"");
        var p = PostureDoc.Deserialize(json);

        Assert.NotNull(p);
        Assert.False(p!.CanPatchDeploy);                                   // unknown tier → gated (conservative)
        Assert.Equal("catastrophic", p.Compliance.Primary!.Sections[0].Controls[0].Severity);
    }

    [Fact]
    public void MalformedJson_ReturnsNull()
    {
        Assert.Null(PostureDoc.Deserialize("{ not json"));
        Assert.Null(PostureDoc.Deserialize("null"));
    }

    [Fact]
    public void ShippedFixtures_Deserialize()
    {
        // Guards the contracts/ sample fixtures the desktop apps build against.
        foreach (var name in new[] { "posture.sample.macos.json", "posture.sample.windows.json" })
        {
            var path = LocateContractsFile(name);
            if (path is null) continue; // contracts/ not reachable in this build context
            var p = PostureDoc.Deserialize(File.ReadAllText(path));
            Assert.NotNull(p);
            Assert.Equal(1, p!.SchemaVersion);
            Assert.NotNull(p.Compliance.Primary);
        }
    }

    private static string? LocateContractsFile(string fileName)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "contracts", fileName);
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return null;
    }
}
