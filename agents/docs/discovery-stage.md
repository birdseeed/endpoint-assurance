# Discovery stage (PAT-848 S2): retired

**Retired 2026-09-30 (PAT-2299).** The discovery stage no longer exists.
`ci/discovery_common.py`, `ci/discovery_macos.py`, `ci/discovery_windows.py`
and their three test files were deleted, and
`ci/test_legacy_workflow_quarantine.py` fails if any of them comes back or a
workflow starts calling them.

Why it went:

- Its only runner was the `discovery-report` job in `daily-vendor-verify.yml`,
  which PAT-2247 deleted on 2026-09-29.
- It read its baseline from, and reported jobs and runs to, the platform's
  `/admin/discovery/*` routes, which PAT-2249 removed.
- Andy ruled on 2026-09-28 that patching is not coming back, so there are no
  package versions left for it to discover.

There is nothing to run and no flag to set. `DISCOVERY_REPORT_ENABLED`,
`DISCOVERY_BASELINE_FILE` and `DISCOVERY_SPOOL` are read by nothing.

For the design as it last stood, read this file at the commit before
retirement:

```bash
git show a2646a86:docs/discovery-stage.md
```

The wider design it belonged to is `nightly-discovery-unification.md`, also
retired.
