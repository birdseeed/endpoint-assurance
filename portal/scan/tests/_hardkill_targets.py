"""Module-level PAT-1177 test targets for the killable report-generation
subprocess (scan/shared.py run_report_job).

These stand in for the real report generators (generate_devices_report /
generate_apps_cve_report) in tests. They MUST be plain, module-level
functions -- never closures or lambdas defined inside a test -- because
run_report_job hands `target` to multiprocessing.Process, and the default
start method on the macOS test runner is 'spawn': the child re-imports
whatever module `target` came from and looks the function up by name, which
only works for a real top-level function. A closure captured over local test
state has no such import path and fails to pickle at all (a plain
`AttributeError`/`PicklingError` well before the function would ever run) --
that failure mode is itself proof the contract is being respected.
"""

import time


def sleep_then_touch_sentinel(devices, output_path, logo_path, sleep_seconds=3.0):
    """Stands in for generate_devices_report. Genuinely blocks in the CHILD
    process via a real time.sleep() -- there is no event/flag a test could
    use to fake this the way it could with an in-process thread, because the
    only thing crossing the process boundary is picklable data. If (and only
    if) this call is allowed to run to completion, it writes a sentinel file
    next to `output_path`. A test that hard-kills the process before the
    sleep completes and later finds no sentinel has proven the child was
    genuinely terminated, not merely abandoned: an abandoned/orphaned child
    would eventually wake up and write it regardless."""
    time.sleep(sleep_seconds)
    with open(output_path + ".sentinel", "w") as f:
        f.write("reached")
    return {"total": len(devices)}


def raise_synthetic_failure(devices, output_path, logo_path):
    """Stands in for generate_devices_report to exercise the ERROR outcome:
    an exception raised inside the child must come back to the parent as
    ReportJobOutcome(status="error", error=...), not crash the parent or get
    silently swallowed."""
    raise RuntimeError("synthetic failure for PAT-1177/PAT-1173 coverage")


def wait_for_release_then_write(output_path, started_path, release_path, deadline_seconds=10):
    """Synthetic orphan-writer target; no network or application records."""
    import os
    from pathlib import Path

    Path(started_path).write_text(str(os.getpid()))
    deadline = time.monotonic() + deadline_seconds
    while not Path(release_path).exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("synthetic orphan writer release deadline")
        time.sleep(0.02)
    Path(output_path).write_text("synthetic orphan report")
    return {"synthetic": True}
