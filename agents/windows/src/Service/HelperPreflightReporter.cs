namespace Patched.Service;

// PAT-2116: a refused evidence-helper preflight must be loud. 0.14.2 refused every spawn on a
// real install (the install directory's inherited DACL) and nothing said so: no log line, no
// agent-health entry, only helper_failed on every row. One reporter per helper per inventory
// cycle: the first refusal logs one WARN line (with the offending principal and rights for an
// ACL refusal) and records helper_preflight/<subject>/<reason> in agent-health; a preflight
// that passed clears it. Repeats within a cycle are dropped so a helper retried up to six
// times per scan still logs once.
internal sealed class HelperPreflightReporter(ILogger log, AgentHealthStore health, string subject)
{
    internal const string HealthKind = "helper_preflight";
    internal const string AppSignaturesSubject = "app_signatures";
    internal const string InstallationEvidenceSubject = "installation_evidence";

    private bool _passed;
    private bool _refused;

    internal void Observe(InstallationEvidenceProbe.HelperPreflightRefusal? refusal)
    {
        try
        {
            if (refusal is null)
            {
                if (_passed || _refused) return;
                _passed = true;
                health.RecordSuccess(HealthKind, subject);
                return;
            }
            if (_refused) return;
            _refused = true;
            log.LogWarning(
                "evidence helper preflight refused ({Subject}): {Reason} {Detail}; rows report {Error}",
                subject, refusal.Reason, refusal.Detail ?? "", InstallationEvidenceProbe.PreflightRefused);
            health.RecordFailure(HealthKind, subject, refusal.Reason);
        }
        catch
        {
            // Reporting must never change the evidence result; the row still says why.
        }
    }
}
