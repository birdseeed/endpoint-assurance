# OS update card state fixtures

Each file below is a self-contained `os_update` block you can splice into
`dev-fixtures/update-status.json` to render a specific card state without a
real behind-OS machine.

Set `PATCHED_UPDATER_DIR` to point at a writable copy of `dev-fixtures/` and
the app reads from it instead of `/Library/Application Support/Patched`.

| File | State | Notes |
|---|---|---|
| `up-to-date.json` | `up_to_date` | No card rendered |
| `recommended.json` | `update_recommended` | Amber passive card |
| `required.json` | `update_required` severity=medium | Deadline-bearing card |
| `required-blocking.json` | `update_required` severity=high | Triggers blocking window |
| `deadline-passed.json` | `deadline_passed` | Red overdue card |
| `unsupported.json` | `unsupported_hardware` | Quiet notice |
