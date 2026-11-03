// Posture.cs — platform-neutral System.Text.Json model for GET /v1/posture.
//
// Source of truth: contracts/posture.schema.json (schema_version 1).
// No WinForms, WPF, or platform-specific references — pure .NET Standard types.
// Used by both the Windows tray agent and the Windows Self Service app.
//
// PAT-471 · U0 · Posture read-client + vendored contract.

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Patched.Contracts
{
    // -------------------------------------------------------------------------
    // Top-level response
    // -------------------------------------------------------------------------

    /// <summary>Decoded response from GET /v1/posture (schema_version 1).</summary>
    public sealed class Posture
    {
        [JsonPropertyName("schema_version")]
        public int SchemaVersion { get; init; }

        [JsonPropertyName("generated_at")]
        public DateTimeOffset GeneratedAt { get; init; }

        [JsonPropertyName("device")]
        public Device Device { get; init; } = null!;

        [JsonPropertyName("tier")]
        public string Tier { get; init; } = null!;

        [JsonPropertyName("app_count")]
        public int AppCount { get; init; }

        [JsonPropertyName("compliance")]
        public Compliance Compliance { get; init; } = null!;

        [JsonPropertyName("evidence")]
        public Evidence Evidence { get; init; } = null!;

        [JsonPropertyName("findings")]
        public IReadOnlyList<Finding>? Findings { get; init; }

        [JsonPropertyName("updates")]
        public IReadOnlyList<Update>? Updates { get; init; }

        [JsonPropertyName("app_policy")]
        public AppPolicy? AppPolicy { get; init; }
    }

    // -------------------------------------------------------------------------
    // Device
    // -------------------------------------------------------------------------

    public sealed class Device
    {
        [JsonPropertyName("id")]
        public string Id { get; init; } = null!;

        [JsonPropertyName("serial")]
        public string? Serial { get; init; }

        [JsonPropertyName("hw_uuid")]
        public string? HwUuid { get; init; }

        [JsonPropertyName("hostname")]
        public string? Hostname { get; init; }

        [JsonPropertyName("computer_name")]
        public string? ComputerName { get; init; }

        [JsonPropertyName("hw_model")]
        public string? HwModel { get; init; }

        [JsonPropertyName("arch")]
        public string? Arch { get; init; }

        [JsonPropertyName("os")]
        public string Os { get; init; } = null!;

        [JsonPropertyName("os_version")]
        public string? OsVersion { get; init; }

        [JsonPropertyName("os_build")]
        public string? OsBuild { get; init; }

        [JsonPropertyName("agent_version")]
        public string? AgentVersion { get; init; }

        [JsonPropertyName("first_seen")]
        public DateTimeOffset? FirstSeen { get; init; }

        [JsonPropertyName("last_seen")]
        public DateTimeOffset? LastSeen { get; init; }
    }

    // -------------------------------------------------------------------------
    // Compliance
    // -------------------------------------------------------------------------

    public sealed class Compliance
    {
        [JsonPropertyName("platform")]
        public string Platform { get; init; } = null!;

        [JsonPropertyName("benchmarks")]
        public IReadOnlyList<Benchmark> Benchmarks { get; init; } = null!;
    }

    public sealed class Benchmark
    {
        [JsonPropertyName("benchmark")]
        public string BenchmarkName { get; init; } = null!;

        [JsonPropertyName("benchmark_version")]
        public string BenchmarkVersion { get; init; } = null!;

        [JsonPropertyName("implemented")]
        public int Implemented { get; init; }

        [JsonPropertyName("benchmark_total")]
        public int BenchmarkTotal { get; init; }

        [JsonPropertyName("passed")]
        public int Passed { get; init; }

        [JsonPropertyName("failed")]
        public int Failed { get; init; }

        [JsonPropertyName("not_applicable")]
        public int NotApplicable { get; init; }

        [JsonPropertyName("errors")]
        public int Errors { get; init; }

        [JsonPropertyName("compliance_pct")]
        public double CompliancePct { get; init; }

        [JsonPropertyName("sections")]
        public IReadOnlyList<Section> Sections { get; init; } = null!;
    }

    public sealed class Section
    {
        [JsonPropertyName("section")]
        public string SectionNumber { get; init; } = null!;

        [JsonPropertyName("passed")]
        public int Passed { get; init; }

        [JsonPropertyName("total")]
        public int Total { get; init; }

        [JsonPropertyName("controls")]
        public IReadOnlyList<Control> Controls { get; init; } = null!;
    }

    public sealed class Control
    {
        [JsonPropertyName("rule_key")]
        public string RuleKey { get; init; } = null!;

        [JsonPropertyName("title")]
        public string Title { get; init; } = null!;

        [JsonPropertyName("severity")]
        public string Severity { get; init; } = null!;

        [JsonPropertyName("status")]
        public string Status { get; init; } = null!;

        [JsonPropertyName("observed_value")]
        public string? ObservedValue { get; init; }

        [JsonPropertyName("evaluated_at")]
        public DateTimeOffset EvaluatedAt { get; init; }
    }

    // -------------------------------------------------------------------------
    // Evidence
    // -------------------------------------------------------------------------

    public sealed class Evidence
    {
        [JsonPropertyName("coverage_window_days")]
        public int CoverageWindowDays { get; init; }

        [JsonPropertyName("scans_logged")]
        public int ScansLogged { get; init; }

        [JsonPropertyName("last_signed_report_digest")]
        public string? LastSignedReportDigest { get; init; }

        [JsonPropertyName("recent_scan_times")]
        public IReadOnlyList<DateTimeOffset> RecentScanTimes { get; init; } = null!;
    }

    // -------------------------------------------------------------------------
    // Findings (CVE)
    // -------------------------------------------------------------------------

    public sealed class Finding
    {
        [JsonPropertyName("cve_id")]
        public string CveId { get; init; } = null!;

        [JsonPropertyName("description")]
        public string Description { get; init; } = null!;

        [JsonPropertyName("cvss_v3_score")]
        public double? CvssV3Score { get; init; }

        [JsonPropertyName("severity")]
        public string Severity { get; init; } = null!;

        [JsonPropertyName("published_at")]
        public DateTimeOffset? PublishedAt { get; init; }

        [JsonPropertyName("app_name")]
        public string AppName { get; init; } = null!;

        [JsonPropertyName("app_version")]
        public string AppVersion { get; init; } = null!;

        [JsonPropertyName("match_confidence")]
        public string MatchConfidence { get; init; } = null!;

        [JsonPropertyName("last_seen_at")]
        public DateTimeOffset LastSeenAt { get; init; }
    }

    // -------------------------------------------------------------------------
    // Updates
    // -------------------------------------------------------------------------

    public sealed class Update
    {
        [JsonPropertyName("app_name")]
        public string AppName { get; init; } = null!;

        [JsonPropertyName("identifier")]
        public string Identifier { get; init; } = null!;

        [JsonPropertyName("current_version")]
        public string CurrentVersion { get; init; } = null!;

        [JsonPropertyName("target_version")]
        public string TargetVersion { get; init; } = null!;

        [JsonPropertyName("source")]
        public string Source { get; init; } = null!;

        [JsonPropertyName("linked_cve_ids")]
        public IReadOnlyList<string> LinkedCveIds { get; init; } = null!;
    }

    // -------------------------------------------------------------------------
    // App Policy
    // -------------------------------------------------------------------------

    public sealed class AppPolicy
    {
        [JsonPropertyName("apps")]
        public IReadOnlyList<AppPolicyEntry> Apps { get; init; } = null!;

        [JsonPropertyName("drift")]
        public IReadOnlyList<DriftEntry> Drift { get; init; } = null!;
    }

    public sealed class AppPolicyEntry
    {
        [JsonPropertyName("app_name")]
        public string AppName { get; init; } = null!;

        [JsonPropertyName("identifier")]
        public string Identifier { get; init; } = null!;

        [JsonPropertyName("policy")]
        public string Policy { get; init; } = null!;

        [JsonPropertyName("user_removable")]
        public bool UserRemovable { get; init; }

        [JsonPropertyName("enforcement_tier")]
        public string EnforcementTier { get; init; } = null!;
    }

    public sealed class DriftEntry
    {
        [JsonPropertyName("drift_type")]
        public string DriftType { get; init; } = null!;

        [JsonPropertyName("app_name")]
        public string AppName { get; init; } = null!;

        [JsonPropertyName("identifier")]
        public string Identifier { get; init; } = null!;

        [JsonPropertyName("policy")]
        public string Policy { get; init; } = null!;

        [JsonPropertyName("enforcement_tier")]
        public string EnforcementTier { get; init; } = null!;
    }
}
