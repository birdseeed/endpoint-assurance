"""PAT-1441: a dispatched deploy must still reconcile box-side config when the
push moves no ref.

The incident: PAT-1439 shipped a hardened patched-maintenance-facts.service,
the deploy reported success, and prod-01 kept running the old 9.6-UNSAFE unit.
Two timing properties compounded:

  1. deploy/post-receive execs scripts/deploy.sh and the `git reset` to the new
     commit happens INSIDE that script, so the running version is always the
     one that was on the box beforehand -- a deploy.sh change lands one deploy
     late.

  2. Re-dispatching the workflow to pick that up did nothing at all. With no
     new commits `git push` prints "Everything up-to-date" and sends nothing,
     so the hook never fires and deploy.sh never executes. This was originally
     mis-diagnosed as "the script ran and exited at the no-op guard"; it did
     not run.

Property (2) is the dangerous one, because dispatching the deploy workflow is
exactly the reflex when someone suspects the box has drifted -- and in that
precise case it was inert while reporting success.

scripts/deploy.sh now reconciles box config before its own no-op guard (pinned
by Test 10 in scripts/test-post-receive-rollback.sh, which drives the real
script). This file pins the other half: the workflow must notice the no-op
push and invoke the script directly, so drift is recoverable without inventing
a commit purely to make the deploy do something.

Static assertions against the real workflow YAML, in the same spirit as
patched.im's deploy/api-01 wiring tests -- no runner, no box.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO / "ci-archive" / "workflows" / "deploy.yml"


def _deploy_steps() -> list[dict]:
    doc = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    jobs = doc["jobs"]
    # Single-job workflow today; take whichever job carries the push step
    # rather than hardcoding a job name that may be renamed.
    for job in jobs.values():
        steps = job.get("steps") or []
        if any("bare mirror" in (s.get("name") or "") for s in steps):
            return steps
    raise AssertionError("no job in deploy.yml contains the bare-mirror push step")


def _step_named(fragment: str) -> dict:
    for step in _deploy_steps():
        if fragment.lower() in (step.get("name") or "").lower():
            return step
    raise AssertionError(f"no step whose name contains {fragment!r}")


def test_push_step_records_whether_it_moved_the_ref():
    """The workflow cannot react to a no-op push unless it detects one.

    `git push` exits 0 whether or not it sent anything, so the exit code is
    not the signal -- the "Everything up-to-date" line is.
    """
    step = _step_named("bare mirror")
    assert step.get("id"), "the push step needs an id so a later step can read its output"
    run = step.get("run") or ""
    assert "Everything up-to-date" in run, (
        "the push step must detect the no-op case; git push exits 0 either way, "
        "so the printed 'Everything up-to-date' line is the only signal"
    )
    assert "GITHUB_OUTPUT" in run, "the detection has to be exported for a later step to gate on"


def test_a_step_reconciles_box_config_when_the_push_was_a_no_op():
    step = _step_named("Reconcile box-side config")
    condition = str(step.get("if", ""))
    assert "pushed" in condition and "false" in condition, (
        f"the reconcile step must be gated on the push having moved nothing, got {condition!r}"
    )
    script = str((step.get("with") or {}).get("script", ""))
    assert "scripts/deploy.sh" in script, (
        "reconciling means running the real deploy script on the box -- it is what "
        "holds the sync_box_config logic; a bespoke copy here would drift from it"
    )


def test_reconcile_runs_after_the_push_it_depends_on():
    names = [(s.get("name") or "") for s in _deploy_steps()]
    push_idx = next(i for i, n in enumerate(names) if "bare mirror" in n)
    reconcile_idx = next(i for i, n in enumerate(names) if "Reconcile box-side config" in n)
    assert push_idx < reconcile_idx, (
        "the reconcile step reads the push step's output, so it must come after it"
    )


def test_post_receive_documents_both_timing_properties():
    """The hook is where someone lands when a deploy 'did nothing'.

    Both properties are counter-intuitive enough that the next person will
    otherwise conclude their change is broken, so they are documented rather
    than left to be rediscovered from an empty log.
    """
    text = (REPO / "deploy" / "post-receive").read_text(encoding="utf-8")
    assert "one deploy LATE" in text or "one deploy late" in text.lower()
    assert "Everything up-to-date" in text
    assert "PAT-1441" in text
