#!/usr/bin/env python3
"""Fail when a Go main command lacks a complete deployment classification."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


MANAGED = "deploy-api-01"
SEPARATE = "separate"
VALID_CLASSES = {MANAGED, SEPARATE}
FORWARD_MIGRATION = re.compile(r"^[0-9]{4}_[a-z0-9_]+\.sql$")
ROLLBACK_MIGRATION = re.compile(r"^[0-9]{4}_[a-z0-9_]+_rollback\.sql$")


def workflow_step(workflow: str, name: str) -> str:
    """Return one named top-level step, without accepting text elsewhere."""
    match = re.search(
        rf"(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - (?:name:|uses:)|^  [a-z]|\Z)",
        workflow,
    )
    return match.group(1) if match else ""


def exact_path_line(block: str, path: str) -> bool:
    return re.search(rf"(?m)^\s+{re.escape(path)}(?:\s*\\)?\s*$", block) is not None


def check(root: Path) -> list[str]:
    errors: list[str] = []
    inventory_path = root / "deploy/api-01/production-binaries.tsv"
    # PAT-1970 split the api-01 pipeline across two workflow files. The build,
    # manifest and artifact-upload steps moved to api-build.yml (which runs on
    # push and is also called by the deploy workflow); everything that touches
    # the box stayed in deploy-api-01.yml. Both halves are still one contract,
    # so this guard reads both rather than one, and each assertion below is
    # asked of the file that now owns that step.
    build_workflow_path = root / ".github/workflows/api-build.yml"
    workflow_path = root / ".github/workflows/deploy-api-01.yml"
    deploy_path = root / "deploy/api-01/deploy.sh"

    records: dict[str, tuple[str, str, str]] = {}
    for line_number, raw_line in enumerate(
        inventory_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = raw_line.split("\t", 3)
        if len(parts) != 4:
            errors.append(f"{inventory_path}:{line_number}: expected four tab-separated fields")
            continue
        name, deployment_class, deploy_symbol, reason = (part.strip() for part in parts)
        if name in records:
            errors.append(f"{inventory_path}:{line_number}: duplicate command {name}")
            continue
        if deployment_class not in VALID_CLASSES:
            errors.append(
                f"{inventory_path}:{line_number}: {name} has invalid class {deployment_class!r}"
            )
        if not reason:
            errors.append(f"{inventory_path}:{line_number}: {name} needs a classification reason")
        if deployment_class == MANAGED and not re.fullmatch(r"[A-Z][A-Z0-9_]*", deploy_symbol):
            errors.append(f"{inventory_path}:{line_number}: {name} needs a deploy symbol")
        if deployment_class == SEPARATE and deploy_symbol != "-":
            errors.append(f"{inventory_path}:{line_number}: separate command symbol must be '-'")
        records[name] = (deployment_class, deploy_symbol, reason)

    commands: set[str] = set()
    command_root = root / "go-service/cmd"
    main_directories = {
        source.parent
        for source in command_root.rglob("*.go")
        if re.search(
            r"(?m)^\s*package\s+main(?:\s*//[^\r\n]*)?\s*$",
            source.read_text(encoding="utf-8"),
        )
    }
    for path in main_directories:
        commands.add(path.relative_to(command_root).as_posix())

    migrations = root / "go-service/migrations"
    for migration in sorted(migrations.glob("*.sql")):
        if not (FORWARD_MIGRATION.fullmatch(migration.name) or ROLLBACK_MIGRATION.fullmatch(migration.name)):
            errors.append(f"migration filename violates deploy contract: {migration.name}")
    inventoried = set(records)
    for name in sorted(commands - inventoried):
        errors.append(f"unclassified Go main command: go-service/cmd/{name}")
    for name in sorted(inventoried - commands):
        errors.append(f"inventory names missing command directory: {name}")

    workflow = workflow_path.read_text(encoding="utf-8")
    build_workflow = build_workflow_path.read_text(encoding="utf-8")
    normalized_workflow = build_workflow.replace("\\\n", " ")
    upload_step = workflow_step(build_workflow, "Upload built binaries")
    rsync_step = workflow_step(workflow, "Stage binaries, migrations and deploy script on api-01")
    manifest_step = workflow_step(build_workflow, "Create commit-bound binary manifest")
    readback_step = workflow_step(workflow, "Read back three-binary provenance and timer state")
    deploy = deploy_path.read_text(encoding="utf-8")
    if "if: always()" not in readback_step:
        errors.append("provenance readback step must use if: always()")

    service_unit = root / "api-vps-artefacts/patched-cve-sync.service"
    timer_unit = root / "api-vps-artefacts/patched-cve-sync.timer"
    if not service_unit.is_file():
        errors.append("missing bootstrap unit api-vps-artefacts/patched-cve-sync.service")
    else:
        exec_starts = re.findall(r"(?m)^ExecStart=([^\r\n]+)$", service_unit.read_text(encoding="utf-8"))
        if exec_starts != ["/opt/patched-api/bin/patched-cve-sync --mode=scheduled"]:
            errors.append("patched-cve-sync.service ExecStart must exactly run the deployed CVE binary in scheduled mode")
    if not timer_unit.is_file():
        errors.append("missing bootstrap unit api-vps-artefacts/patched-cve-sync.timer")

    for name, (deployment_class, deploy_symbol, _) in sorted(records.items()):
        build_pattern = re.compile(
            rf"(?m)\bgo build\s+[^\n]*"
            rf"-o\s+dist/{re.escape(name)}\s+\./cmd/{re.escape(name)}\s*$"
        )
        built = build_pattern.search(normalized_workflow) is not None
        # A managed binary must be built in api-build.yml specifically, so the
        # positive check above is deliberately narrow. The negative check below
        # must not be: a `separate` command smuggled into a go build step in
        # deploy-api-01.yml is exactly the thing it exists to catch, and looking
        # only at api-build.yml would have quietly stopped catching it when
        # PAT-1970 split the files.
        built_anywhere = built or build_pattern.search(
            workflow.replace("\\\n", " ")
        ) is not None
        artifact_contract = f"go-service/dist/{name}"
        uploaded = exact_path_line(upload_step, artifact_contract)
        transferred = exact_path_line(rsync_step, artifact_contract)
        manifested = exact_path_line(manifest_step, f"dist/{name}")
        deploy_wired = re.search(
            rf'(?m)^NEW_{re.escape(deploy_symbol)}_BIN="\$STAGING_DIR/{re.escape(name)}"$', deploy
        ) is not None
        deploy_occurrence = re.search(
            rf'(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])', deploy
        ) is not None

        if deployment_class == MANAGED:
            if not built:
                errors.append(f"{name}: workflow lacks an exact go build output/command pair")
            if not uploaded:
                errors.append(f"{name}: upload-artifact step lacks exact path {artifact_contract}")
            if not transferred:
                errors.append(f"{name}: rsync step lacks exact path {artifact_contract}")
            if not manifested:
                errors.append(f"{name}: binary manifest step lacks exact input dist/{name}")
            if not deploy_wired:
                errors.append(f"{name}: box-side deploy script lacks a staged binary assignment")
            required_deploy_fragments = (
                f'{deploy_symbol}_BACKUP="$BACKUP_DIR/{name}.bak-',
                f'cp -a "${deploy_symbol}_BIN" "${deploy_symbol}_BACKUP"',
                f'{deploy_symbol}_BACKUP_SHA256="$(sha256_file "${deploy_symbol}_BACKUP")"',
                f'atomic_restore "${deploy_symbol}_BACKUP" "${deploy_symbol}_BIN" "${deploy_symbol}_BACKUP_SHA256"',
                f'[[ "$(sha256_file "$NEW_{deploy_symbol}_BIN")" == "$EXPECTED_{deploy_symbol}_SHA256" ]]',
                f'cp "$NEW_{deploy_symbol}_BIN" "${{{deploy_symbol}_BIN}}.new"',
                f'mv -f "${{{deploy_symbol}_BIN}}.new" "${deploy_symbol}_BIN"',
                f'INSTALLED_{deploy_symbol}_SHA256="$(sha256_file "${deploy_symbol}_BIN")"',
                f'[[ "$INSTALLED_{deploy_symbol}_SHA256" == "$EXPECTED_{deploy_symbol}_SHA256" ]]',
                f"printf '{name}=%s\\n' \"$INSTALLED_{deploy_symbol}_SHA256\"",
            )
            for fragment in required_deploy_fragments:
                if fragment not in deploy:
                    errors.append(f"{name}: deploy script lacks required wiring {fragment!r}")
        elif built_anywhere or uploaded or transferred or deploy_wired or deploy_occurrence:
            errors.append(f"{name}: separate command appears in api-01 build/deploy wiring")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to the checkout containing this script)",
    )
    args = parser.parse_args()
    errors = check(args.root.resolve())
    if errors:
        print("production binary inventory check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("production binary inventory check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
