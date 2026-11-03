from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("check_binary_inventory.py")
SPEC = importlib.util.spec_from_file_location("check_binary_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BinaryInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "go-service/cmd/patched-api").mkdir(parents=True)
        (self.root / "go-service/cmd/patched-api/main.go").write_text(
            "package main\n", encoding="utf-8"
        )
        (self.root / "go-service/migrations").mkdir(parents=True)
        (self.root / "go-service/migrations/0056_valid_name.sql").write_text(
            "SELECT 1;\n", encoding="utf-8"
        )
        (self.root / "deploy/api-01").mkdir(parents=True)
        (self.root / "api-vps-artefacts").mkdir(parents=True)
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / "deploy/api-01/production-binaries.tsv").write_text(
            "patched-api\tdeploy-api-01\tAPI\tproduction API\n", encoding="utf-8"
        )
        (self.root / "api-vps-artefacts/patched-cve-sync.service").write_text(
            "[Service]\nExecStart=/opt/patched-api/bin/patched-cve-sync --mode=scheduled\n", encoding="utf-8"
        )
        (self.root / "api-vps-artefacts/patched-cve-sync.timer").write_text(
            "[Timer]\nOnCalendar=daily\n", encoding="utf-8"
        )
        # PAT-1970 split the pipeline in two: api-build.yml builds, manifests
        # and uploads; deploy-api-01.yml is the only file that touches the box.
        # The fixture mirrors that split so the guard is exercised against the
        # shape it actually has to police.
        (self.root / ".github/workflows/api-build.yml").write_text(
            "jobs:\n"
            "  build-test:\n"
            "    steps:\n"
            "      - name: Build patched-api\n"
            "        run: go build -o dist/patched-api ./cmd/patched-api\n"
            "      - name: Create commit-bound binary manifest\n"
            "        run: |\n"
            "          sha256sum \\\n"
            "            dist/patched-api \\\n"
            "            > dist/BINARY_MANIFEST\n"
            "      - name: Upload built binaries\n"
            "        with:\n"
            "          path: |\n"
            "            go-service/dist/patched-api\n",
            encoding="utf-8",
        )
        (self.root / ".github/workflows/deploy-api-01.yml").write_text(
            "jobs:\n"
            "  deploy:\n"
            "    steps:\n"
            "      - name: Stage binaries, migrations and deploy script on api-01\n"
            "        run: |\n"
            "          rsync -av \\\n"
            "            go-service/dist/patched-api \\\n"
            "            root@patched-api-01:/tmp/\n"
            "      - name: Read back three-binary provenance and timer state\n"
            "        if: always()\n"
            "        run: cat receipt\n",
            encoding="utf-8",
        )
        (self.root / "deploy/api-01/deploy.sh").write_text(
            'NEW_API_BIN="$STAGING_DIR/patched-api"\n'
            'API_BACKUP="$BACKUP_DIR/patched-api.bak-$TS"\n'
            'cp -a "$API_BIN" "$API_BACKUP"\n'
            'API_BACKUP_SHA256="$(sha256_file "$API_BACKUP")"\n'
            'atomic_restore "$API_BACKUP" "$API_BIN" "$API_BACKUP_SHA256"\n'
            '[[ "$(sha256_file "$NEW_API_BIN")" == "$EXPECTED_API_SHA256" ]]\n'
            'cp "$NEW_API_BIN" "${API_BIN}.new"\n'
            'mv -f "${API_BIN}.new" "$API_BIN"\n'
            'INSTALLED_API_SHA256="$(sha256_file "$API_BIN")"\n'
            '[[ "$INSTALLED_API_SHA256" == "$EXPECTED_API_SHA256" ]]\n'
            'printf \'patched-api=%s\\n\' "$INSTALLED_API_SHA256"\n',
            encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_complete_inventory_passes(self) -> None:
        self.assertEqual(MODULE.check(self.root), [])

    def test_new_patched_command_fails_until_classified(self) -> None:
        command = self.root / "go-service/cmd/patched-new-daemon"
        command.mkdir()
        (command / "main.go").write_text("package main\n", encoding="utf-8")
        errors = MODULE.check(self.root)
        self.assertTrue(any("unclassified" in error for error in errors), errors)

    def test_managed_binary_requires_workflow_build_and_transfer(self) -> None:
        for name in ("api-build.yml", "deploy-api-01.yml"):
            (self.root / ".github/workflows" / name).write_text(
                "jobs:\n  build:\n    steps: []\n", encoding="utf-8"
            )
        errors = MODULE.check(self.root)
        self.assertTrue(any("exact go build" in error for error in errors), errors)
        self.assertTrue(any("upload-artifact" in error for error in errors), errors)
        self.assertTrue(any("rsync" in error for error in errors), errors)

    def test_managed_binary_build_must_live_in_the_build_workflow(self) -> None:
        # Moving the build back into deploy-api-01.yml would restore the exact
        # defect PAT-1970 removed: a push-triggered green run under a name that
        # promises a deploy. The guard has to reject it, not shrug because the
        # step still exists somewhere.
        build = self.root / ".github/workflows/api-build.yml"
        deploy = self.root / ".github/workflows/deploy-api-01.yml"
        deploy.write_text(
            deploy.read_text(encoding="utf-8")
            + "      - name: Build patched-api\n"
            + "        run: go build -o dist/patched-api ./cmd/patched-api\n",
            encoding="utf-8",
        )
        build.write_text(
            build.read_text(encoding="utf-8").replace(
                "        run: go build -o dist/patched-api ./cmd/patched-api\n",
                "        run: echo skipped\n",
            ),
            encoding="utf-8",
        )
        errors = MODULE.check(self.root)
        self.assertTrue(any("exact go build" in error for error in errors), errors)

    def test_separate_binary_requires_reason_but_not_workflow_wiring(self) -> None:
        tool = self.root / "go-service/cmd/patched-tool"
        tool.mkdir()
        (tool / "main.go").write_text("package main\n", encoding="utf-8")
        inventory = self.root / "deploy/api-01/production-binaries.tsv"
        inventory.write_text(
            inventory.read_text(encoding="utf-8") + "patched-tool\tseparate\t-\toperator-only\n",
            encoding="utf-8",
        )
        self.assertEqual(MODULE.check(self.root), [])

    def test_separate_binary_is_rejected_when_hidden_in_workflow(self) -> None:
        tool = self.root / "go-service/cmd/patched-tool"
        tool.mkdir()
        (tool / "main.go").write_text("package main\n", encoding="utf-8")
        inventory = self.root / "deploy/api-01/production-binaries.tsv"
        inventory.write_text(
            inventory.read_text(encoding="utf-8") + "patched-tool\tseparate\t-\toperator-only\n",
            encoding="utf-8",
        )
        # Check both halves of the split pipeline. Looking only at
        # api-build.yml after PAT-1970 would have silently stopped catching a
        # separate command smuggled into the deploy workflow.
        for name in ("api-build.yml", "deploy-api-01.yml"):
            workflow = self.root / ".github/workflows" / name
            original = workflow.read_text(encoding="utf-8")
            workflow.write_text(
                original
                + "      - name: Build hidden tool\n"
                + "        run: go build -o dist/patched-tool ./cmd/patched-tool\n",
                encoding="utf-8",
            )
            errors = MODULE.check(self.root)
            self.assertTrue(
                any("separate command appears" in error for error in errors), (name, errors)
            )
            workflow.write_text(original, encoding="utf-8")

    def test_separate_binary_is_rejected_on_any_deploy_script_occurrence(self) -> None:
        tool = self.root / "go-service/cmd/patched-tool"
        tool.mkdir()
        (tool / "main.go").write_text("package main\n", encoding="utf-8")
        inventory = self.root / "deploy/api-01/production-binaries.tsv"
        inventory.write_text(
            inventory.read_text(encoding="utf-8") + "patched-tool\tseparate\t-\toperator-only\n",
            encoding="utf-8",
        )
        deploy = self.root / "deploy/api-01/deploy.sh"
        deploy.write_text(deploy.read_text(encoding="utf-8") + "# patched-tool must stay separate\n", encoding="utf-8")
        errors = MODULE.check(self.root)
        self.assertTrue(any("separate command appears" in error for error in errors), errors)

    def test_non_prefixed_main_package_must_be_classified(self) -> None:
        command = self.root / "go-service/cmd/internal-tool"
        command.mkdir()
        (command / "main.go").write_text("package main\n", encoding="utf-8")
        errors = MODULE.check(self.root)
        self.assertTrue(any("internal-tool" in error and "unclassified" in error for error in errors), errors)

    def test_main_package_with_trailing_comment_is_classified(self) -> None:
        command = self.root / "go-service/cmd/commented-main"
        command.mkdir()
        (command / "main.go").write_text("package main // executable command\n", encoding="utf-8")
        errors = MODULE.check(self.root)
        self.assertTrue(any("commented-main" in error and "unclassified" in error for error in errors), errors)

    def test_nested_main_packages_are_discovered_by_relative_path(self) -> None:
        for relative in ("tools/alpha", "internal/alpha"):
            command = self.root / "go-service/cmd" / relative
            command.mkdir(parents=True)
            (command / "main.go").write_text("package main\n", encoding="utf-8")
        errors = MODULE.check(self.root)
        self.assertTrue(any("cmd/tools/alpha" in error for error in errors), errors)
        self.assertTrue(any("cmd/internal/alpha" in error for error in errors), errors)

    def test_nested_commands_with_duplicate_basenames_need_distinct_inventory_rows(self) -> None:
        for relative in ("one/tool", "two/tool"):
            command = self.root / "go-service/cmd" / relative
            command.mkdir(parents=True)
            (command / "main.go").write_text("package main\n", encoding="utf-8")
        inventory = self.root / "deploy/api-01/production-binaries.tsv"
        inventory.write_text(
            inventory.read_text(encoding="utf-8")
            + "one/tool\tseparate\t-\tfirst nested tool\n"
            + "two/tool\tseparate\t-\tsecond nested tool\n",
            encoding="utf-8",
        )
        self.assertEqual(MODULE.check(self.root), [])

    def test_duplicate_inventory_path_is_rejected(self) -> None:
        inventory = self.root / "deploy/api-01/production-binaries.tsv"
        inventory.write_text(
            inventory.read_text(encoding="utf-8")
            + "patched-api\tseparate\t-\tduplicate row\n",
            encoding="utf-8",
        )
        errors = MODULE.check(self.root)
        self.assertTrue(any("duplicate command patched-api" in error for error in errors), errors)

    def test_migration_filename_contract_rejects_unmanifestable_sql(self) -> None:
        bad = self.root / "go-service/migrations/0106_bad-name.sql"
        bad.write_text("SELECT 1;\n", encoding="utf-8")
        errors = MODULE.check(self.root)
        self.assertTrue(any("migration filename violates deploy contract" in error for error in errors), errors)

    def test_repository_migration_catalogue_matches_deploy_contract(self) -> None:
        repository_root = MODULE_PATH.parents[2]
        errors = MODULE.check(repository_root)
        self.assertFalse([error for error in errors if "migration" in error], errors)
        # Both steps moved to api-build.yml together under PAT-1970; the
        # ordering contract between them is unchanged.
        workflow = (repository_root / ".github/workflows/api-build.yml").read_text(encoding="utf-8")
        self.assertLess(
            workflow.index("Verify migration and command deployment contracts"),
            workflow.index("Create commit-bound binary manifest"),
        )

    def test_managed_command_requires_full_backup_hash_and_receipt_wiring(self) -> None:
        deploy = self.root / "deploy/api-01/deploy.sh"
        deploy.write_text('NEW_API_BIN="$STAGING_DIR/patched-api"\n', encoding="utf-8")
        errors = MODULE.check(self.root)
        self.assertTrue(any("required wiring" in error for error in errors), errors)

    def test_bootstrap_units_and_exact_execstart_are_pinned(self) -> None:
        service = self.root / "api-vps-artefacts/patched-cve-sync.service"
        service.write_text("[Service]\nExecStart=/wrong/path\n", encoding="utf-8")
        errors = MODULE.check(self.root)
        self.assertTrue(any("ExecStart must exactly run" in error for error in errors), errors)
        (self.root / "api-vps-artefacts/patched-cve-sync.timer").unlink()
        errors = MODULE.check(self.root)
        self.assertTrue(any("missing bootstrap unit" in error for error in errors), errors)

    def test_bootstrap_execstart_rejects_non_scheduled_arguments(self) -> None:
        service = self.root / "api-vps-artefacts/patched-cve-sync.service"
        service.write_text(
            "[Service]\nExecStart=/opt/patched-api/bin/patched-cve-sync --batch-size=100\n",
            encoding="utf-8",
        )
        self.assertTrue(any("scheduled mode" in error for error in MODULE.check(self.root)))

    def test_root_scripts_do_not_require_proc_or_dev_fd(self) -> None:
        for name in ("deploy.sh", "emergency-api-only.sh", "bootstrap-cve-sync.sh"):
            script = (Path(__file__).with_name(name)).read_text(encoding="utf-8")
            self.assertNotIn("<<<", script, name)
            self.assertNotIn("<(", script, name)
            self.assertNotIn(">(", script, name)
            self.assertNotIn("/proc/", script, name)

        harness = Path(__file__).with_name("test_root_production_integration.sh").read_text(encoding="utf-8")
        self.assertIn('[[ -c /dev/null', harness)
        self.assertIn("PATCHED_ROOT_HARNESS_CONTAINER", harness)
        self.assertNotIn("mknod", harness)
        self.assertNotIn("chroot", harness)
        self.assertNotIn("mount -t proc", harness)
        self.assertNotIn("--rbind", harness)


if __name__ == "__main__":
    unittest.main()
