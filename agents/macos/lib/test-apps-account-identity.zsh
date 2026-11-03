#!/bin/zsh
# DirectoryService boundary guard. Only synthetic plist data is read.
set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3=/usr/bin/python3
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/apps.sh"
PATCHED_TMPDIR=$(mktemp -d) || exit 2
trap 'rm -rf "$PATCHED_TMPDIR"' EXIT
FIXTURE_HOME=/Users/pat2075-synthetic-alias
DS_CASE=one
/usr/bin/dscl() {
    [[ "$*" == '-plist . -readall /Users RecordName NFSHomeDirectory' ]] || return 2
    [[ "$DS_CASE" == failed ]] && return 1
    "$PYTHON3" - "$DS_CASE" "$FIXTURE_HOME" <<'PY'
import plistlib, sys
case, home = sys.argv[1:]
record = {'dsAttrTypeStandard:RecordName': ['actual_synthetic_account'], 'dsAttrTypeStandard:NFSHomeDirectory': [home]}
if case == 'wrong_home': record['dsAttrTypeStandard:NFSHomeDirectory'] = ['/Users/another-synthetic-home']
if case == 'overlong': record['dsAttrTypeStandard:RecordName'] = ['a'*129]
if case == 'bad_homes': record['dsAttrTypeStandard:NFSHomeDirectory'] = home
if case == 'missing_name': record.pop('dsAttrTypeStandard:RecordName')
plistlib.dump([record, record] if case == 'ambiguous' else [record], sys.stdout.buffer)
PY
}
value=$(_apps_user_account_for_root "$FIXTURE_HOME/Applications") || exit 1
[[ "$value" == actual_synthetic_account ]] || exit 1
for DS_CASE in failed wrong_home overlong bad_homes missing_name ambiguous; do
    if _apps_user_account_for_root "$FIXTURE_HOME/Applications" > "$PATCHED_TMPDIR/result"; then
        print -r -- "FAIL: $DS_CASE was accepted"; exit 1
    fi
    [[ ! -s "$PATCHED_TMPDIR/result" ]] || { print -r -- "FAIL: $DS_CASE emitted an identity"; exit 1; }
done
DS_CASE=failed
value=$(_apps_user_account_for_root /Applications) || exit 1
[[ -z "$value" ]] || exit 1
print -r -- 'PASS: resolved metadata identity, six refusals, machine scope independent of DirectoryService'
