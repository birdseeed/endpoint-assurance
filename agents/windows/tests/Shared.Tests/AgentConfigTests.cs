using Patched.Shared.Config;
using Xunit;

namespace Patched.Shared.Tests;

public class AgentConfigTests
{
    private const string FullJson = """
    {
      "catalog_scope": "security-only",
      "config_version": 12,
      "issued_at": "2026-12-11T09:30:00Z",
      "os_update_policy": {
        "target_os": "14.5",
        "minimum_age_days": 10,
        "grace_days": 21,
        "deadline": "2026-07-01",
        "deferral_budget": 3,
        "defer_interval_hours": 48,
        "blocking_window_days": 5,
        "exploited_overrides_age": false
      },
      "per_app_patch": {
        "fleet_default_enabled": false,
        "overrides": [
          { "platform": "windows", "identifier": "Google.Chrome", "enabled": true },
          { "platform": "windows", "identifier": "Mozilla.Firefox", "enabled": false },
          { "platform": "macos", "identifier": "com.google.Chrome", "enabled": false }
        ]
      },
      "proxy": {
        "mode": "manual",
        "type": "socks5",
        "host": "proxy.corp.example",
        "port": 1080,
        "auth_ref": "PatchedAgent/ProxyCreds",
        "bypass_when_off_corp": true,
        "pac_url": "http://wpad/wpad.dat",
        "probe_url": "http://probe.corp.example",
        "no_proxy": ["localhost", "127.0.0.1"]
      },
      "scan_cadence": "hourly",
      "tenant_id": "tenant-xyz",
      "tier": "managed"
    }
    """;

    [Fact]
    public void Deserialize_FromSnakeCaseJson_MapsAllFields()
    {
        AgentConfig? cfg = AgentConfig.Deserialize(FullJson);

        Assert.NotNull(cfg);
        Assert.Equal("security-only", cfg!.CatalogScope);
        Assert.Equal(12, cfg.ConfigVersion);
        Assert.Equal("2026-12-11T09:30:00Z", cfg.IssuedAt);

        // PAT-381: per_app_patch is the policy object (estate default + overrides).
        Assert.NotNull(cfg.PerAppPatch);
        Assert.False(cfg!.PerAppPatch!.FleetDefaultEnabled);
        Assert.Equal(3, cfg.PerAppPatch.Overrides.Count);
        Assert.True(cfg.PerAppPatch.Allows("windows", "Google.Chrome"));    // explicit on
        Assert.False(cfg.PerAppPatch.Allows("windows", "Mozilla.Firefox")); // explicit off
        Assert.False(cfg.PerAppPatch.Allows("windows", "Some.Unlisted"));   // estate default off
        Assert.Equal(PerAppPatchPolicy.SourceOverride,
            cfg.PerAppPatch.SourceFor("windows", "Google.Chrome"));
        Assert.Equal(PerAppPatchPolicy.SourceFleetDefault,
            cfg.PerAppPatch.SourceFor("windows", "Some.Unlisted"));

        Assert.Equal("hourly", cfg.ScanCadence);
        Assert.Equal("tenant-xyz", cfg.TenantId);
        Assert.Equal("managed", cfg.Tier);

        // Nested OS update policy.
        Assert.Equal("14.5", cfg.OsUpdatePolicy.TargetOs);
        Assert.Equal(10, cfg.OsUpdatePolicy.MinimumAgeDays);
        Assert.Equal(21, cfg.OsUpdatePolicy.GraceDays);
        Assert.Equal("2026-07-01", cfg.OsUpdatePolicy.Deadline);
        Assert.Equal(3, cfg.OsUpdatePolicy.DeferralBudget);
        Assert.Equal(48, cfg.OsUpdatePolicy.DeferIntervalHours);
        Assert.Equal(5, cfg.OsUpdatePolicy.BlockingWindowDays);
        Assert.False(cfg.OsUpdatePolicy.ExploitedOverridesAge);

        // Nested proxy.
        Assert.Equal("manual", cfg.Proxy.Mode);
        Assert.Equal("socks5", cfg.Proxy.Type);
        Assert.Equal("proxy.corp.example", cfg.Proxy.Host);
        Assert.Equal(1080, cfg.Proxy.Port);
        Assert.Equal("PatchedAgent/ProxyCreds", cfg.Proxy.AuthRef);
        Assert.True(cfg.Proxy.BypassWhenOffCorp);
        Assert.Equal("http://wpad/wpad.dat", cfg.Proxy.PacUrl);
        Assert.Equal("http://probe.corp.example", cfg.Proxy.ProbeUrl);
        Assert.Equal(new[] { "localhost", "127.0.0.1" }, cfg.Proxy.NoProxy);
    }

    [Fact]
    public void Deserialize_IsCaseInsensitive()
    {
        const string json = """
        { "Tier": "managed", "Config_Version": 3, "Catalog_Scope": "all" }
        """;
        AgentConfig? cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.Equal("managed", cfg!.Tier);
        Assert.Equal(3, cfg.ConfigVersion);
    }

    [Fact]
    public void Defaults_AreConservative()
    {
        AgentConfig d = AgentConfig.Defaults;

        Assert.Equal("assurance", d.Tier);   // never actuates until explicitly granted managed
        Assert.False(d.LegacyAppExecutionEnabled);
        Assert.False(LegacyAppExecutionGate.Allows(d));
        Assert.Equal("all", d.CatalogScope);
        Assert.Equal("daily", d.ScanCadence);
        Assert.Null(d.PerAppPatch);   // no policy by default → all managed apps enabled
        Assert.Equal(0, d.ConfigVersion);

        // Default OS update policy values.
        Assert.Equal(7, d.OsUpdatePolicy.MinimumAgeDays);
        Assert.Equal(14, d.OsUpdatePolicy.GraceDays);
        Assert.Equal(5, d.OsUpdatePolicy.DeferralBudget);
        Assert.Equal(24, d.OsUpdatePolicy.DeferIntervalHours);
        Assert.Equal(3, d.OsUpdatePolicy.BlockingWindowDays);
        Assert.True(d.OsUpdatePolicy.ExploitedOverridesAge);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{ \"legacy_app_execution_enabled\": false }")]
    [InlineData("{ \"legacy_app_execution_enabled\": null }")]
    [InlineData("{ \"legacy_app_execution_enabled\": \"true\" }")]
    [InlineData("{ \"legacy_app_execution_enabled\": 1 }")]
    [InlineData("{ \"legacy_app_execution_enabled\": {} }")]
    [InlineData("{ \"legacy_app_execution_enabled\": { \"nested\": true } }")]
    [InlineData("{ \"legacy_app_execution_enabled\": [true] }")]
    public void LegacyAppExecutionEnabled_OnlyExactBooleanTruePermits(string json)
    {
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.False(cfg!.LegacyAppExecutionEnabled);
        Assert.False(LegacyAppExecutionGate.Allows(cfg));
    }

    [Fact]
    public void LegacyAppExecutionEnabled_TrueIsNecessaryButNotASubstituteForOtherGates()
    {
        var cfg = AgentConfig.Deserialize("{ \"legacy_app_execution_enabled\": true, \"tier\": \"assurance\" }");

        Assert.NotNull(cfg);
        Assert.True(cfg!.LegacyAppExecutionEnabled);
        Assert.True(LegacyAppExecutionGate.Allows(cfg));
        Assert.Equal("assurance", cfg.Tier); // callers must still apply their tier gate.
    }

    [Fact]
    public void LegacyAppExecutionGate_NullConfigDenies()
    {
        Assert.False(LegacyAppExecutionGate.Allows(null));
    }

    [Theory]
    [InlineData("\"not-a-port\"")]
    [InlineData("{}")]
    public void Deserialize_VerifiedNewerRevocationSurvivesUnrelatedTypedFailure(
        string malformedPort)
    {
        string json = $$"""
        {
          "tenant_id": "tenant-xyz",
          "config_version": 13,
          "legacy_app_execution_enabled": false,
          "app_control_authority": "report",
          "proxy": { "port": {{malformedPort}} }
        }
        """;

        AgentConfig? cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.Equal(13, cfg!.ConfigVersion);
        Assert.Equal("tenant-xyz", cfg.TenantId);
        Assert.False(cfg.LegacyAppExecutionEnabled);
        Assert.Equal(AppControlAuthority.Report, cfg.AppControlAuthority);
        Assert.False(LegacyAppExecutionGate.Allows(cfg));
        Assert.False(AppControlAuthorityGate.AllowsBlocklist(cfg.AppControlAuthority));
        Assert.False(AppControlAuthorityGate.AllowsDestructiveAction(cfg.AppControlAuthority));
    }

    [Fact]
    public void Deserialize_VerifiedNewerRevocationSurvivesUnrelatedDuplicateAndBadTypedField()
    {
        const string json = """
        {
          "tenant_id": "tenant-xyz",
          "config_version": 14,
          "legacy_app_execution_enabled": false,
          "app_control_authority": "report",
          "proxy": { "port": 8080, "PORT": "not-a-port" }
        }
        """;

        AgentConfig? cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.Equal(14, cfg!.ConfigVersion);
        Assert.False(cfg.LegacyAppExecutionEnabled);
        Assert.Equal(AppControlAuthority.Report, cfg.AppControlAuthority);
    }

    [Theory]
    [InlineData("{ \"legacy_app_execution_enabled\": false, \"legacy_app_execution_enabled\": true }")]
    [InlineData("{ \"legacy_app_execution_enabled\": true, \"legacy_app_execution_enabled\": false }")]
    [InlineData("{ \"legacy_app_execution_enabled\": false, \"LEGACY_APP_EXECUTION_ENABLED\": true }")]
    [InlineData("{ \"LEGACY_APP_EXECUTION_ENABLED\": true, \"legacy_app_execution_enabled\": false }")]
    public void LegacyAppExecutionEnabled_DuplicateOrCaseVariantKeyDenies(string json)
    {
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.False(cfg!.LegacyAppExecutionEnabled);
        Assert.False(LegacyAppExecutionGate.Allows(cfg));
    }

    [Theory]
    [InlineData("{ \"LEGACY_APP_EXECUTION_ENABLED\": true }")]
    [InlineData("{ \"Legacy_App_Execution_Enabled\": true }")]
    [InlineData("{ \"legacy_app_execution_enabled\": false, \"LEGACY_APP_EXECUTION_ENABLED\": true }")]
    [InlineData("{ \"LEGACY_APP_EXECUTION_ENABLED\": true, \"legacy_app_execution_enabled\": false }")]
    public void LegacyAppExecutionEnabled_NonCanonicalOrAmbiguousKeyDenies(string json)
    {
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.False(cfg!.LegacyAppExecutionEnabled);
        Assert.False(LegacyAppExecutionGate.Allows(cfg));
    }

    [Theory]
    [InlineData("report", AppControlAuthority.Report)]
    [InlineData("block", AppControlAuthority.Block)]
    [InlineData("enforce", AppControlAuthority.Enforce)]
    public void AppControlAuthority_RecognisesCanonicalWireValues(
        string rawAuthority, AppControlAuthority expected)
    {
        var cfg = AgentConfig.Deserialize($"{{ \"app_control_authority\": \"{rawAuthority}\" }}");

        Assert.NotNull(cfg);
        Assert.Equal(expected, cfg!.AppControlAuthority);
        Assert.Equal(expected is AppControlAuthority.Block or AppControlAuthority.Enforce,
            AppControlAuthorityGate.AllowsBlocklist(cfg.AppControlAuthority));
        Assert.Equal(expected == AppControlAuthority.Enforce,
            AppControlAuthorityGate.AllowsDestructiveAction(cfg.AppControlAuthority));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{ \"app_control_authority\": null }")]
    [InlineData("{ \"app_control_authority\": 1 }")]
    [InlineData("{ \"app_control_authority\": \"unknown\" }")]
    [InlineData("{ \"app_control_authority\": \"BLOCK\" }")]
    [InlineData("{ \"app_control_authority\": \" enforce \" }")]
    [InlineData("{ \"app_control_authority\": \"report\", \"APP_CONTROL_AUTHORITY\": \"enforce\" }")]
    [InlineData("{ \"app_control_authority\": \"enforce\", \"nested\": { \"a\": 1, \"A\": 2 } }")]
    public void AppControlAuthority_AmbiguousOrInvalidValueResolvesToReport(string json)
    {
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.Equal(AppControlAuthority.Report, cfg!.AppControlAuthority);
        Assert.False(AppControlAuthorityGate.AllowsBlocklist(cfg.AppControlAuthority));
        Assert.False(AppControlAuthorityGate.AllowsDestructiveAction(cfg.AppControlAuthority));
    }

    [Theory]
    [InlineData("{ \"APP_CONTROL_AUTHORITY\": \"enforce\" }")]
    [InlineData("{ \"App_Control_Authority\": \"enforce\" }")]
    [InlineData("{ \"app_control_authority\": \"report\", \"APP_CONTROL_AUTHORITY\": \"enforce\" }")]
    [InlineData("{ \"APP_CONTROL_AUTHORITY\": \"enforce\", \"app_control_authority\": \"report\" }")]
    public void AppControlAuthority_NonCanonicalOrAmbiguousKeyResolvesToReport(string json)
    {
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.Equal(AppControlAuthority.Report, cfg!.AppControlAuthority);
        Assert.False(AppControlAuthorityGate.AllowsBlocklist(cfg.AppControlAuthority));
        Assert.False(AppControlAuthorityGate.AllowsDestructiveAction(cfg.AppControlAuthority));
    }

    [Fact]
    public void AppControlAuthority_EnforceDoesNotEnableLegacyExecution()
    {
        var cfg = AgentConfig.Deserialize("{ \"app_control_authority\": \"enforce\" }");

        Assert.NotNull(cfg);
        Assert.Equal(AppControlAuthority.Enforce, cfg!.AppControlAuthority);
        Assert.False(LegacyAppExecutionGate.Allows(cfg));
    }

    [Fact]
    public void RingPromotionsScoped_ExplicitNobody_DeniesEvenRingZero()
    {
        const string json = """
        { "ring_promotions_scoped": {
          "windows": { "firefox": { "version": "130.0", "approval": "nobody" } }
        }}
        """;

        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg!.RingPromotionsScoped);
        Assert.False(RingPromotionGate.Allows("firefox", "windows", 0,
            cfg.RingPromotionsScoped, cfg.RingPromotions));
    }

    [Fact]
    public void RingPromotionsScoped_IsAuthoritativeOverLegacyAndPlatformAware()
    {
        const string json = """
        {
          "ring_promotions": { "firefox": { "version": "legacy", "approved_ring": 0 } },
          "ring_promotions_scoped": {
            "windows": { "firefox": { "version": "130.0", "approval": "up_to_ring", "approved_ring": 2 } }
          }
        }
        """;

        var cfg = AgentConfig.Deserialize(json);

        Assert.True(RingPromotionGate.Allows("firefox", "windows", 2,
            cfg!.RingPromotionsScoped, cfg.RingPromotions));
        Assert.True(RingPromotionGate.Allows("firefox", "macos", 3,
            cfg.RingPromotionsScoped, cfg.RingPromotions));
    }

    [Fact]
    public void RingPromotionsScoped_MissingLabelInPresentPlatformMap_DoesNotConsultLegacy()
    {
        const string json = """
        {
          "ring_promotions": { "firefox": { "version": "legacy", "approved_ring": 0 } },
          "ring_promotions_scoped": {
            "windows": { "googlechrome": { "version": "130.0", "approval": "nobody" } }
          }
        }
        """;

        var cfg = AgentConfig.Deserialize(json);

        Assert.True(RingPromotionGate.Allows("firefox", "windows", 3,
            cfg!.RingPromotionsScoped, cfg.RingPromotions));
    }

    [Fact]
    public void RingPromotionsScoped_NullPlatformSection_Denies()
    {
        const string json = """
        { "ring_promotions_scoped": { "windows": null } }
        """;

        var cfg = AgentConfig.Deserialize(json);

        Assert.False(RingPromotionGate.Allows("firefox", "windows", 0,
            cfg!.RingPromotionsScoped, cfg.RingPromotions));
    }

    [Theory]
    [InlineData("unknown", "3")]
    [InlineData("up_to_ring", "null")]
    public void RingPromotionsScoped_MalformedPositiveEntry_Denies(string approval, string approvedRing)
    {
        var json = $$$"""
        { "ring_promotions_scoped": {
          "windows": { "firefox": { "version": "130.0", "approval": "{{{approval}}}", "approved_ring": {{{approvedRing}}} } }
        }}
        """;

        var cfg = AgentConfig.Deserialize(json);

        Assert.False(RingPromotionGate.Allows("firefox", "windows", 0,
            cfg!.RingPromotionsScoped, cfg.RingPromotions));
    }

    [Fact]
    public void ProxyConfig_Defaults_ModeIsSystem()
    {
        var p = new ProxyConfig();

        Assert.Equal("system", p.Mode);
        Assert.Equal("http", p.Type);
        Assert.Equal("", p.Host);
        Assert.Null(p.Port); // PAT-737: null until a manual proxy sets it
        Assert.Null(p.AuthRef);
        Assert.False(p.BypassWhenOffCorp);
        Assert.Null(p.PacUrl);
        Assert.Null(p.ProbeUrl);
        Assert.Null(p.NoProxy);
    }

    // PAT-605: app_control block deserialization.
    [Fact]
    public void AppControl_Deserializes_FromJson()
    {
        const string json = """
        {
          "tenant_id": "t",
          "app_control": {
            "enabled": true,
            "approved_admins": ["alice", "DOMAIN\\bob"],
            "app_allowlist": []
          }
        }
        """;

        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.True(cfg!.AppControl.Enabled);
        Assert.Equal(2, cfg.AppControl.ApprovedAdmins.Count);
        Assert.Equal("alice",        cfg.AppControl.ApprovedAdmins[0]);
        Assert.Equal("DOMAIN\\bob",  cfg.AppControl.ApprovedAdmins[1]);
        Assert.Empty(cfg.AppControl.AppAllowlist);
    }

    [Fact]
    public void AppControl_Defaults_Disabled()
    {
        var cfg = AgentConfig.Defaults;

        Assert.False(cfg.AppControl.Enabled);
        Assert.Empty(cfg.AppControl.ApprovedAdmins);
        Assert.Empty(cfg.AppControl.AppAllowlist);
    }

    [Fact]
    public void AppControl_AbsentBlock_UsesDefaults()
    {
        // When app_control is absent from the JSON, the default (disabled) is used.
        const string json = """{ "tenant_id": "t" }""";
        var cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.False(cfg!.AppControl.Enabled);
        Assert.Empty(cfg.AppControl.ApprovedAdmins);
    }

    // PAT-737 regression: the platform sends "port": null when no manual proxy is
    // configured. A non-nullable int made the entire config document throw
    // JsonException, so the agent silently rejected every config update
    // (including blocked_versions kill-switch entries) and ran on defaults.
    [Fact]
    public void Deserialize_ProxyPortNull_ParsesAndKeepsOtherFields()
    {
        const string json = """
        {
          "config_version": 7,
          "tier": "managed",
          "tenant_id": "tenant-xyz",
          "proxy": { "mode": "system", "type": "http", "host": "", "port": null }
        }
        """;

        AgentConfig? cfg = AgentConfig.Deserialize(json);

        Assert.NotNull(cfg);
        Assert.Equal(7, cfg!.ConfigVersion);
        Assert.Equal("managed", cfg.Tier);
        Assert.Equal("system", cfg.Proxy.Mode);
        Assert.Null(cfg.Proxy.Port);
    }
}
