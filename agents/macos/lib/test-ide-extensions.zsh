#!/bin/zsh
##############################################################################
# test-ide-extensions.zsh — PAT-2017 IDE extension collector contract tests.
#
# Sources macos/lib/ide_extensions.sh and runs the real collect_ide_extensions
# against home directories built in a scratch directory: several users, each
# with a different mix of VS Code, VS Code Insiders, Cursor, Windsurf and
# JetBrains profiles. No root, no editor and no network are needed, so it runs
# the same on a Mac and on the Linux CI runner.
#
# Also carries two guards that must stay red-capable:
#   [static]  the collector launches no process and opens no network client
#   [wire]    the ide_extensions block is on the wire (PAT-2225, 2026-09-28);
#             setting _IDE_EXTENSIONS_PAYLOAD_ON_WIRE back to 0 turns this
#             red, and that change must update this test in the same change.
#             The off path is still exercised with the flag set locally.
#   [budget]  a block over _IDE_MAX_BYTES is sent as failed, never cut down
#
# Run: zsh macos/lib/test-ide-extensions.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
MODULE="$SCRIPT_DIR/ide_extensions.sh"
COLLECT_SH="$SCRIPT_DIR/../patched-collect.sh"
PYTHON3="${PATCHED_TEST_PYTHON3:-$(command -v python3)}"
REAL_PYTHON3="$PYTHON3"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.ide-ext-test.XXXXXX")
trap 'chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT
WORK=${WORK:A}

source "$SCRIPT_DIR/common.sh"
source "$MODULE"

pass=0; fail=0
# ok is one or more 1/0 flags run together ("11", "10"); every one must be 1.
chk() {
    local desc="$1" ok="$2"
    if [[ -n "$ok" && "$ok" != *[^1]* ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# jq_py <python expression over `obj`> — against the block the last run wrote.
jq_py() {
    "$REAL_PYTHON3" -c 'import json,sys; obj=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' \
        "$IDE_EXTENSIONS_JSON_TMP" "$1" 2>/dev/null
}
is_true() { [[ "$(jq_py "$1")" == "True" ]] && echo 1 || echo 0; }
status_is() { [[ "$(ide_extensions_collection_status)" == "$1" ]] && echo 1 || echo 0; }

write_file() { mkdir -p "${1:h}"; print -r -- "$2" > "$1"; }

# vsx_entry <id> <version> <installedTimestamp-ms> <publisherDisplayName>
vsx_entry() {
    print -r -- "{\"identifier\":{\"id\":\"$1\",\"uuid\":\"00000000-0000-0000-0000-000000000000\"},\"version\":\"$2\",\"location\":{\"\$mid\":1,\"path\":\"/x/$1-$2\",\"scheme\":\"file\"},\"relativeLocation\":\"$1-$2\",\"metadata\":{\"installedTimestamp\":$3,\"source\":\"gallery\",\"publisherDisplayName\":\"$4\",\"targetPlatform\":\"undefined\",\"isPreReleaseVersion\":false}}"
}

# package_json <dir> <publisher> <name> <version>
package_json() {
    write_file "$1/package.json" "{\"name\":\"$3\",\"publisher\":\"$2\",\"version\":\"$4\",\"engines\":{\"vscode\":\"^1.80.0\"}}"
}

# make_jar <jar-path> <plugin.xml-content or ''> — a zip with META-INF/plugin.xml
make_jar() {
    mkdir -p "${1:h}"
    "$REAL_PYTHON3" - "$1" "$2" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe")
    if sys.argv[2]:
        z.writestr("META-INF/plugin.xml", sys.argv[2])
PY
}

plugin_xml() {  # plugin_xml <id> <name> <vendor> <version>
    print -r -- "<idea-plugin><id>$1</id><name>$2</name><vendor url=\"https://example.invalid\">$3</vendor><version>$4</version><depends>com.intellij.modules.platform</depends></idea-plugin>"
}

build_tree() {
    rm -rf "$WORK/Users"
    U="$WORK/Users"
    mkdir -p "$U/Shared/.vscode/extensions" "$U/carol/Documents"

    # alice: VS Code from extensions.json, Cursor from manifests with an
    # obsolete folder, Windsurf from extensions.json.
    local vs="$U/alice/.vscode/extensions"
    mkdir -p "$vs/github.copilot-1.250.0" "$vs/ms-python.python-2026.1.0"
    write_file "$vs/extensions.json" "[$(vsx_entry github.copilot 1.250.0 1767225600000 GitHub),$(vsx_entry ms-python.python 2026.1.0 1767225700000 Microsoft)]"
    local cu="$U/alice/.cursor/extensions"
    package_json "$cu/continue.continue-1.2.22" Continue continue 1.2.22
    package_json "$cu/anysphere.remote-ssh-1.1.13" anysphere remote-ssh 1.1.13
    package_json "$cu/anysphere.remote-ssh-1.1.7" anysphere remote-ssh 1.1.7
    write_file "$cu/.obsolete" '{"anysphere.remote-ssh-1.1.7":true}'
    local ws="$U/alice/.windsurf/extensions"
    write_file "$ws/extensions.json" "[$(vsx_entry codeium.windsurf-pyright 1.0.0 1767225800000 Codeium)]"

    # bob: VS Code Insiders, and two JetBrains product versions.
    write_file "$U/bob/.vscode-insiders/extensions/extensions.json" "[$(vsx_entry rooveterinaryinc.roo-cline 3.0.0 1767225900000 RooCode)]"
    JB="$U/bob/Library/Application Support/JetBrains"
    local idea="$JB/IntelliJIdea2025.2"
    # A folder plugin whose plugin.xml is inside a jar in lib/ (not the first jar by name).
    make_jar "$idea/plugins/github-copilot-intellij/lib/aaa-deps.jar" ""
    make_jar "$idea/plugins/github-copilot-intellij/lib/github-copilot-intellij.jar" "$(plugin_xml com.github.copilot 'GitHub Copilot' GitHub 1.5.40-243)"
    # A single-jar plugin.
    make_jar "$idea/plugins/tabnine.jar" "$(plugin_xml com.tabnine.TabNine Tabnine Tabnine 1.200.0)"
    # A folder plugin with plugin.xml unpacked, and no <id> (JetBrains uses <name>).
    write_file "$idea/plugins/unpacked/META-INF/plugin.xml" "<idea-plugin><name>Unpacked Tool</name><vendor>Acme</vendor><version>0.9</version></idea-plugin>"
    write_file "$idea/disabled_plugins.txt" "com.tabnine.TabNine"
    # An older product version with no plugins directory, and a non-product dir.
    mkdir -p "$JB/PyCharm2024.3/options" "$JB/consentOptions"
}

run() {
    PATCHED_TMPDIR=$(mktemp -d "$WORK/run.XXXXXX")
    collect_ide_extensions > "$WORK/last.log" 2>&1
}

##############################################################################
echo "[1] several users, every editor family, everything readable"
build_tree
_IDE_USERS_ROOT="$U"
run
chk "status complete" "$(status_is complete)"
chk "counts: 9 extensions, 6 profiles, 3 users" "$([[ "$IDE_EXTENSIONS_COUNT/$IDE_EXTENSIONS_PROFILE_COUNT/$IDE_EXTENSIONS_USER_COUNT" == 9/6/3 ]] && echo 1 || echo 0)"
chk "Shared is skipped" "$(is_true 'not any(u["user"]=="Shared" for u in obj["users"])')"
chk "users: alice and bob complete, carol not_present" "$(is_true '[(u["user"],u["collection_status"]) for u in obj["users"]] == [("alice","complete"),("bob","complete"),("carol","not_present")]')"
chk "user_id is the home owner's uid" "$(is_true 'all(u["user_id"] == str(__import__("os").getuid()) for u in obj["users"])')"
chk "profiles: every editor with its source" "$(is_true 'sorted((p["user"],p["editor"],p["editor_version"],p["manifest_source"],p["extension_count"]) for p in obj["profiles"]) == [("alice","cursor",None,"package_json",2),("alice","vscode",None,"extensions_json",2),("alice","windsurf",None,"extensions_json",1),("bob","IntelliJIdea","2025.2","plugin_xml",3),("bob","PyCharm","2024.3","plugin_xml",0),("bob","vscode_insiders",None,"extensions_json",1)]')"
C='[e for e in obj["extensions"] if e["id"]=="github.copilot"][0]'
chk "extensions.json entry: id, publisher, version, install time, source" "$(is_true "($C)['publisher']=='github' and ($C)['name']=='copilot' and ($C)['version']=='1.250.0' and ($C)['installed_at']=='2026-07-01T00:00:00Z' and ($C)['source']=='gallery' and ($C)['publisher_display_name']=='GitHub' and ($C)['family']=='vscode' and ($C)['editor']=='vscode' and ($C)['user']=='alice'")"
chk "targetPlatform undefined is null, pre_release false" "$(is_true "($C)['target_platform'] is None and ($C)['pre_release'] is False")"
chk "manifest fallback: obsolete folder skipped, current one read" "$(is_true '[e["version"] for e in obj["extensions"] if e["id"]=="anysphere.remote-ssh"] == ["1.1.13"]')"
chk "manifest fallback: id is lowercased publisher.name" "$(is_true 'any(e["id"]=="continue.continue" and e["publisher"]=="Continue" and e["manifest_source"]=="package_json" for e in obj["extensions"])')"
chk "Windsurf and Insiders read" "$(is_true '{e["editor"] for e in obj["extensions"]} >= {"windsurf","vscode_insiders","cursor","vscode"}')"
G='[e for e in obj["extensions"] if e["id"]=="com.github.copilot"][0]'
chk "JetBrains folder plugin: plugin.xml found in the right jar" "$(is_true "($G)['name']=='GitHub Copilot' and ($G)['publisher']=='GitHub' and ($G)['version']=='1.5.40-243' and ($G)['manifest_source']=='plugin_xml_jar' and ($G)['editor_version']=='2025.2' and ($G)['family']=='jetbrains'")"
chk "JetBrains enabled plugin: disabled false" "$(is_true "($G)['disabled'] is False")"
chk "JetBrains single-jar plugin, listed in disabled_plugins.txt: disabled true" "$(is_true '[e["disabled"] for e in obj["extensions"] if e["id"]=="com.tabnine.TabNine"] == [True]')"
chk "JetBrains unpacked plugin.xml with no <id>: name used as id" "$(is_true 'any(e["id"]=="Unpacked Tool" and e["manifest_source"]=="plugin_xml_unpacked" and e["publisher"]=="Acme" for e in obj["extensions"])')"
chk "not truncated, no issues" "$(is_true 'obj["truncated"] is False and obj["issues"] == []')"
chk "no location or home path leaks into extension rows" "$(is_true '"/x/" not in json.dumps(obj["extensions"])' 2>/dev/null || echo 0)"
chk "collect log line summarises and says sent" "$(grep -q 'ide_extensions: status=complete extensions=9 profiles=6 users=3 (sent)' "$WORK/last.log" && echo 1 || echo 0)"

##############################################################################
echo "[2] a corrupt manifest makes the block partial, never empty"
build_tree
print -r -- '[{"identifier":' > "$U/alice/.vscode/extensions/extensions.json"
package_json "$U/alice/.vscode/extensions/github.copilot-1.250.0" GitHub copilot 1.250.0
print -r -- '{not json' > "$U/alice/.vscode/extensions/ms-python.python-2026.1.0/package.json"
run
chk "status partial" "$(status_is partial)"
chk "corrupt extensions.json: folders read instead, profile partial" "$(is_true '[(p["manifest_source"],p["collection_status"],p["extension_count"]) for p in obj["profiles"] if p["user"]=="alice" and p["editor"]=="vscode"] == [("package_json","partial",2)]')"
chk "corrupt package.json: extension still listed by folder, fields null" "$(is_true '[(e["id"],e["manifest_status"],e["directory"]) for e in obj["extensions"] if e["directory"]=="ms-python.python-2026.1.0"] == [(None,"unparseable","ms-python.python-2026.1.0")]')"
chk "the readable manifest in the same profile is kept" "$(is_true 'any(e["id"]=="github.copilot" and e["manifest_source"]=="package_json" for e in obj["extensions"])')"
chk "other users unaffected" "$(is_true '[(u["user"],u["collection_status"]) for u in obj["users"]] == [("alice","partial"),("bob","complete"),("carol","not_present")]')"
chk "issues name both" "$(is_true 'sorted(i["code"] for i in obj["issues"]) == ["extensions_json_unparseable","manifest_unparseable"]')"

build_tree
write_file "$U/alice/.windsurf/extensions/extensions.json" '{"not":"a list"}'
run
chk "extensions.json of the wrong shape is partial too" "$(is_true '[p["collection_status"] for p in obj["profiles"] if p["editor"]=="windsurf"] == ["partial"]')"

build_tree
"$REAL_PYTHON3" -c 'import sys; open(sys.argv[1], "w").write("[" * 100000 + "]" * 100000)' "$U/alice/.windsurf/extensions/extensions.json"
run
chk "deeply nested extensions.json: that profile partial, not the whole block failed" "$(status_is partial)$(is_true '[p["collection_status"] for p in obj["profiles"] if p["editor"]=="windsurf"] == ["partial"] and len(obj["extensions"]) == 8')"

build_tree
write_file "$U/bob/Library/Application Support/JetBrains/IntelliJIdea2025.2/plugins/unpacked/META-INF/plugin.xml" "<idea-plugin><name>broken"
make_jar "$U/bob/Library/Application Support/JetBrains/IntelliJIdea2025.2/plugins/nometa.jar" ""
print -r -- "PK not a zip" > "$U/bob/Library/Application Support/JetBrains/IntelliJIdea2025.2/plugins/garbage.jar"
run
chk "JetBrains: corrupt plugin.xml, jar without one, non-zip jar all partial" "$(is_true '[p["collection_status"] for p in obj["profiles"] if p["editor"]=="IntelliJIdea"] == ["partial"]')"
chk "JetBrains: each is still listed by its directory" "$(is_true 'sorted((e["directory"],e["manifest_status"]) for e in obj["extensions"] if e["editor"]=="IntelliJIdea" and e["id"] is None) == [("garbage.jar","unparseable"),("nometa.jar","missing"),("unpacked","unparseable")]')"

##############################################################################
echo "[3] symlinks, hard links and FIFOs planted by the user are never followed"
build_tree
SECRET_DIR="$WORK/root-only"
mkdir -p "$SECRET_DIR/leaked.secret-9.9.9"
write_file "$SECRET_DIR/extensions.json" "[$(vsx_entry leaked.secret 9.9.9 1 Leaked)]"
rm -rf "$U/alice/.vscode/extensions"
ln -s "$SECRET_DIR" "$U/alice/.vscode/extensions"
run
chk "symlinked extensions dir: not followed, nothing read through it" "$(is_true '"leaked" not in json.dumps(obj).lower()')"
chk "symlinked extensions dir: profile failed with symlink_not_followed" "$(is_true '[p["collection_status"] for p in obj["profiles"] if p["user"]=="alice" and p["editor"]=="vscode"] == ["failed"] and any(i["code"]=="symlink_not_followed" and i["path"].endswith("alice/.vscode/extensions") for i in obj["issues"])')"
chk "symlinked extensions dir: user and block partial, other profiles kept" "$(status_is partial)$(is_true 'len([e for e in obj["extensions"] if e["user"]=="alice"]) == 3')"

build_tree
rm -rf "$U/alice/.cursor"
ln -s "$SECRET_DIR" "$U/alice/.cursor"
run
chk "symlinked editor dir (.cursor itself): not followed, failed profile" "$(is_true '"leaked" not in json.dumps(obj).lower() and [p["collection_status"] for p in obj["profiles"] if p["editor"]=="cursor"] == ["failed"]')"

build_tree
rm -f "$U/alice/.vscode/extensions/extensions.json"
ln -s "$SECRET_DIR/extensions.json" "$U/alice/.vscode/extensions/extensions.json"
run
chk "symlinked extensions.json: refused, folders read instead" "$(is_true '"leaked" not in json.dumps(obj).lower() and any(i["code"]=="extensions_json_unreadable" for i in obj["issues"])')"

build_tree
rm -f "$U/alice/.vscode/extensions/extensions.json"
ln "$SECRET_DIR/extensions.json" "$U/alice/.vscode/extensions/extensions.json"
run
chk "hard-linked extensions.json: refused like a symlink" "$(is_true '"leaked" not in json.dumps(obj).lower() and any(i["code"]=="extensions_json_unreadable" for i in obj["issues"])')"
chk "hard-linked extensions.json: partial" "$(status_is partial)"

build_tree
rm -f "$U/alice/.cursor/extensions/.obsolete"
ln -s "$SECRET_DIR/leaked.secret-9.9.9" "$U/alice/.cursor/extensions/planted-1.0.0"
run
chk "symlinked extension folder: skipped and recorded" "$(is_true '"leaked" not in json.dumps(obj).lower() and any(i["code"]=="symlink_not_followed" and i["path"].endswith("planted-1.0.0") for i in obj["issues"])')"

build_tree
IDEA="$U/bob/Library/Application Support/JetBrains/IntelliJIdea2025.2"
make_jar "$SECRET_DIR/secret.jar" "$(plugin_xml leaked.secret Leaked Leaked 9)"
ln -s "$SECRET_DIR/secret.jar" "$IDEA/plugins/planted.jar"
rm -rf "$IDEA/plugins/unpacked"
mkdir -p "$IDEA/plugins/unpacked"
ln -s "$SECRET_DIR" "$IDEA/plugins/unpacked/META-INF"
run
chk "symlinked jar and symlinked META-INF: never read" "$(is_true '"leaked" not in json.dumps(obj).lower()')"
chk "symlinked jar and META-INF: recorded, profile partial" "$(is_true '[p["collection_status"] for p in obj["profiles"] if p["editor"]=="IntelliJIdea"] == ["partial"] and sum(1 for i in obj["issues"] if i["code"]=="symlink_not_followed") == 2')"

build_tree
rm -rf "$U/carol"
ln -s "$U/alice" "$U/carol"
run
chk "symlinked home: not followed, user failed, alice not read twice" "$(is_true '[u["collection_status"] for u in obj["users"] if u["user"]=="carol"] == ["failed"] and not any(e["user"]=="carol" for e in obj["extensions"])')"

build_tree
rm -f "$U/alice/.vscode/extensions/extensions.json"
mkfifo "$U/alice/.vscode/extensions/extensions.json"
_ie_t0=$SECONDS
run
chk "FIFO extensions.json: refused without hanging ($(( SECONDS - _ie_t0 ))s)" "$(( SECONDS - _ie_t0 <= 5 ))$(is_true 'any(i["code"]=="extensions_json_unreadable" for i in obj["issues"])')"

##############################################################################
echo "[4] plugin.xml is parsed safely"
build_tree
IDEA="$U/bob/Library/Application Support/JetBrains/IntelliJIdea2025.2"
make_jar "$IDEA/plugins/entity.jar" '<?xml version="1.0"?>
<!DOCTYPE idea-plugin [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<idea-plugin><id>entity</id><name>&b;</name></idea-plugin>'
run
chk "a DTD is refused: unparseable, no entity expanded" "$(is_true '[e["manifest_status"] for e in obj["extensions"] if e["directory"]=="entity.jar"] == ["unparseable"] and "aaaa" not in json.dumps(obj)')"
build_tree
"$REAL_PYTHON3" - "$IDEA/plugins/bomb.jar" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("META-INF/plugin.xml", "<idea-plugin><id>x</id><name>" + "a" * (3 * 1024 * 1024) + "</name></idea-plugin>")
PY
run
chk "an oversized plugin.xml inside a jar is refused unread" "$(is_true '[e["manifest_status"] for e in obj["extensions"] if e["directory"]=="bomb.jar"] == ["unreadable"]')"

##############################################################################
echo "[4b] corrupt jars: every file descriptor is closed, and none can crash the parser"
build_tree
IDEA="$U/bob/Library/Application Support/JetBrains/IntelliJIdea2025.2"
CORRUPT="$IDEA/plugins/corrupt-jars/lib"
mkdir -p "$CORRUPT"
for n in {1..40}; do print -r -- "PK not a zip $n" > "$CORRUPT/garbage-$n.jar"; done
make_jar "$CORRUPT/truncated.jar" "$(plugin_xml t T T 1)"
"$REAL_PYTHON3" -c 'import sys; d=open(sys.argv[1],"rb").read(); open(sys.argv[1],"wb").write(d[:len(d)//2])' "$CORRUPT/truncated.jar"
# A valid zip directory whose deflated plugin.xml bytes are corrupt: zlib raises
# its own error type, not BadZipFile.
"$REAL_PYTHON3" - "$CORRUPT/zz-baddeflate.jar" <<'PY'
import sys, zipfile
p = sys.argv[1]
with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("META-INF/plugin.xml", "<idea-plugin><id>x</id>" + "<name>n</name>" * 200 + "</idea-plugin>")
data = bytearray(open(p, "rb").read())
start = data.index(b"META-INF/plugin.xml") + len("META-INF/plugin.xml")
for i in range(start + 2, start + 40):
    data[i] ^= 0xFF
open(p, "wb").write(bytes(data))
PY
# Run the real parser under a wrapper that counts this process's open file
# descriptors before the program starts and after it finishes.
FD_LOG="$WORK/fd-count"
print -r -- '#!/bin/zsh
[[ "${1:-}" == "-" ]] || exec "'"$REAL_PYTHON3"'" "$@"
exec "'"$REAL_PYTHON3"'" -c "
import os, sys
before = len(os.listdir(\"/dev/fd\"))
program = sys.stdin.read()
sys.argv = sys.argv[1:]
exec(compile(program, \"<collector>\", \"exec\"), {\"__name__\": \"__main__\"})
after = len(os.listdir(\"/dev/fd\"))
open(os.environ[\"FD_LOG\"], \"w\").write(\"%d %d\" % (before, after))
" "$@"' > "$WORK/fdpy"; chmod +x "$WORK/fdpy"
rm -f "$FD_LOG"
PYTHON3="$WORK/fdpy" FD_LOG="$FD_LOG" run
PYTHON3="$REAL_PYTHON3"
fd_counts=($(cat "$FD_LOG" 2>/dev/null))
chk "the parser completed under the fd-counting wrapper" "$(( ${#fd_counts} == 2 ))"
chk "open fds unchanged across 42 corrupt jars (${fd_counts[1]:-?} before, ${fd_counts[2]:-?} after)" "$(( ${#fd_counts} == 2 && fd_counts[1] == fd_counts[2] ))"
chk "corrupt jars leave the block partial, not failed" "$(status_is partial)"
chk "the corrupt-jar plugin is listed, unparseable" "$(is_true '[e["manifest_status"] for e in obj["extensions"] if e["directory"]=="corrupt-jars"] == ["unparseable"]')"

##############################################################################
echo "[5] credential-shaped text never leaves the device"
build_tree
write_file "$U/alice/.windsurf/extensions/extensions.json" "[$(vsx_entry acme.tool 1.0.0 1767225800000 'https://placeholder:placeholder@gallery.example.invalid/acme')]"
run
chk "userinfo stripped from a URL-shaped field" "$(is_true '[e["publisher_display_name"] for e in obj["extensions"] if e["id"]=="acme.tool"] == ["https://gallery.example.invalid/acme"]')"
chk "no credential text anywhere in the block (raw)" "$(grep -q placeholder "$IDE_EXTENSIONS_JSON_TMP" && echo 0 || echo 1)"
write_file "$U/alice/.windsurf/extensions/extensions.json" '[{"identifier":{"id":"acme.tool"},"version":"1.0\u001b[31m","metadata":{}}]'
run
chk "a value with control characters is dropped, not sent" "$(is_true '[e["version"] for e in obj["extensions"] if e["id"]=="acme.tool"] == [None]')"

##############################################################################
echo "[6] no editor anywhere is not_present, with an empty list"
rm -rf "$WORK/empty"; mkdir -p "$WORK/empty/Users/dave/Documents" "$WORK/empty/Users/erin/.vscode"
_IDE_USERS_ROOT="$WORK/empty/Users"
run
chk "status not_present" "$(status_is not_present)"
chk "extensions present and empty (a genuine reading)" "$(is_true 'obj["extensions"] == [] and obj["profiles"] == [] and [u["collection_status"] for u in obj["users"]] == ["not_present","not_present"]')"
_IDE_USERS_ROOT="$U"

##############################################################################
echo "[7] nothing readable is failed, with the list omitted"
_IDE_USERS_ROOT="$WORK/does-not-exist"
run
chk "missing users root: failed" "$(status_is failed)"
chk "failed block omits extensions, never []" "$(is_true 'obj["collection_status"] == "failed" and "extensions" not in obj')"
ln -s "$U" "$WORK/linked-users"
_IDE_USERS_ROOT="$WORK/linked-users"
run
chk "symlinked users root: failed, not followed" "$(status_is failed)$(is_true '"extensions" not in obj and obj["issues"][0]["code"] == "symlink_not_followed"')"
build_tree
rm -rf "$U/bob" "$U/carol"
rm -rf "$U/alice/.cursor" "$U/alice/.windsurf"
rm -rf "$U/alice/.vscode/extensions"
ln -s "$SECRET_DIR" "$U/alice/.vscode/extensions"
_IDE_USERS_ROOT="$U"
run
chk "the only profile unreadable: failed, not not_present" "$(status_is failed)"
if (( EUID != 0 )); then
    build_tree
    chmod 000 "$U/alice/.cursor/extensions"
    rm -f "$U/alice/.cursor/extensions/extensions.json" 2>/dev/null
    run
    chmod 755 "$U/alice/.cursor/extensions"
    chk "unlistable extensions dir: profile failed, block partial" "$(is_true '[p["collection_status"] for p in obj["profiles"] if p["editor"]=="cursor"] == ["failed"]')$(status_is partial)"
else
    echo "  SKIP: running as root, chmod 000 does not deny a listing"
fi

##############################################################################
echo "[8] bounds: extension count and time budget stop collection as partial"
build_tree
_IDE_MAX_EXTENSIONS=2
run
chk "past the extension limit: partial, extension_limit, exactly 2" "$(status_is partial)$(is_true 'obj["truncated"] is True and obj["truncation_reason"] == "extension_limit" and len(obj["extensions"]) == 2')"
_IDE_MAX_EXTENSIONS=5000
_IDE_TIME_BUDGET_SECONDS=0
run
chk "past the time budget: partial, time_limit" "$(status_is partial)$(is_true 'obj["truncation_reason"] == "time_limit"')"
_IDE_TIME_BUDGET_SECONDS=30

##############################################################################
echo "[9] a hung or crashed parser is failed, and the hang is bounded"
print -r -- '#!/bin/zsh
sleep 30' > "$WORK/slowpy"; chmod +x "$WORK/slowpy"
print -r -- '#!/bin/zsh
exit 3' > "$WORK/crashpy"; chmod +x "$WORK/crashpy"
PYTHON3="$WORK/slowpy"; _IDE_HARD_TIMEOUT_SECONDS=1
_ie_t0=$SECONDS
run
_ie_elapsed=$(( SECONDS - _ie_t0 ))
PYTHON3="$REAL_PYTHON3"; _IDE_HARD_TIMEOUT_SECONDS=45
chk "hung parser: failed" "$(status_is failed)"
chk "hung parser: killed within the hard limit (${_ie_elapsed}s)" "$(( _ie_elapsed <= 4 ))"
chk "hung parser: stub block says failed" "$(is_true 'obj == {"collection_status": "failed"}')"
PYTHON3="$WORK/crashpy"
run
PYTHON3="$REAL_PYTHON3"
chk "crashed parser: failed" "$(status_is failed)"
# A parser the loop gave up on is failed even when wait then reports a clean
# exit (PAT-2033). kill -9 is made a no-op, as when the parser finishes in the
# moment between the last check and the kill, and the parser exits 0 with good
# output after the limit.
print -r -- "#!/bin/zsh
\"$REAL_PYTHON3\" \"\$@\"; _rc=\$?; sleep 2; exit \$_rc" > "$WORK/latepy"; chmod +x "$WORK/latepy"
kill() { [[ "$1" == -9 ]] && return 0; builtin kill "$@"; }
PYTHON3="$WORK/latepy"; _IDE_HARD_TIMEOUT_SECONDS=1
run
unfunction kill
PYTHON3="$REAL_PYTHON3"; _IDE_HARD_TIMEOUT_SECONDS=45
chk "killed parser that still exits 0 with good output: failed" "$(status_is failed)"

##############################################################################
echo "[wire] the block is on the wire (PAT-2225)"
build_tree
_IDE_USERS_ROOT="$U"
run
chk "the wire flag is 1" "$(( _IDE_EXTENSIONS_PAYLOAD_ON_WIRE == 1 ))"
chk "collect log line says the block is sent" "$(grep -q '^ide_extensions: status=complete extensions=9 profiles=6 users=3 (sent)$' "$WORK/last.log" && echo 1 || echo 0)"
frag="{$(ide_extensions_payload_member) \"next\": 1}"
chk "the member is a valid payload fragment carrying the collected block" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); b=json.load(open(sys.argv[1])); print(1 if d["ide_extensions"]==b and d["ide_extensions"]["collection_status"]=="complete" and len(d["ide_extensions"]["extensions"])==9 and d["next"]==1 else 0)' "$IDE_EXTENSIONS_JSON_TMP" 2>/dev/null || echo 0)"
IDE_EXTENSIONS_COLLECTION_STATUS="failed"
frag="{$(ide_extensions_payload_member) \"next\": 1}"
chk "a failed block is only its status" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["ide_extensions"]=={"collection_status":"failed"} else 0)' 2>/dev/null || echo 0)"
# The off path stays covered: with the flag at 0 nothing is emitted and the
# log line says so.
_IDE_EXTENSIONS_PAYLOAD_ON_WIRE=0
run
chk "flag 0: a complete collection emits no payload member" "$([[ -z "$(ide_extensions_payload_member)" ]] && echo 1 || echo 0)"
chk "flag 0: collect log line says held off the wire" "$(grep -q '^ide_extensions: status=complete extensions=9 profiles=6 users=3 (held off the wire)$' "$WORK/last.log" && echo 1 || echo 0)"
_IDE_EXTENSIONS_PAYLOAD_ON_WIRE=1
chk "patched-collect.sh calls the member exactly once in the payload heredoc" \
    "$([[ "$(grep -c '^  \$(ide_extensions_payload_member)$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"
chk "patched-collect.sh names no \"ide_extensions\" key of its own" \
    "$(grep -q '"ide_extensions"' "$COLLECT_SH" && echo 0 || echo 1)"
chk "patched-collect.sh runs collect_ide_extensions in the daily collection" \
    "$([[ "$(grep -c '^collect_ide_extensions$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"

##############################################################################
echo "[budget] a block over _IDE_MAX_BYTES is sent as failed (PAT-2225)"
chk "the shipped budget is 512 KiB" "$(( _IDE_MAX_BYTES == 524288 ))"
build_tree
_IDE_USERS_ROOT="$U"
run
_ie_size=$(wc -c < "$IDE_EXTENSIONS_JSON_TMP" | tr -d ' ')
# Exactly at the budget is within it.
_IDE_MAX_BYTES=$_ie_size
run
chk "a block exactly at the budget is sent complete" "$(status_is complete)$(is_true 'len(obj["extensions"]) == 9')"
_IDE_MAX_BYTES=$(( _ie_size - 1 ))
run
chk "one byte over: status failed" "$(status_is failed)"
chk "one byte over: the block file is only its status" "$(is_true 'obj == {"collection_status": "failed"}')"
frag="{$(ide_extensions_payload_member) \"next\": 1}"
chk "one byte over: the member sends only the failed status" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["ide_extensions"]=={"collection_status":"failed"} else 0)' 2>/dev/null || echo 0)"
chk "one byte over: WARN names the size and the budget" "$(grep -q "^WARN: ide_extensions: block is $_ie_size bytes, over the $(( _ie_size - 1 ))-byte budget; sent as failed$" "$WORK/last.log" && echo 1 || echo 0)"
chk "one byte over: the log line says failed" "$(grep -q '^ide_extensions: status=failed extensions=9 profiles=6 users=3 (sent)$' "$WORK/last.log" && echo 1 || echo 0)"
_IDE_MAX_BYTES=junk
run
chk "an unusable budget fails closed" "$(status_is failed)"
_IDE_MAX_BYTES=$(( 512 * 1024 ))

##############################################################################
echo "[race] a directory swapped for a symlink between its check and the read is not read through (PAT-2033)"
# A test-only sitecustomize.py swaps one directory for a symlink to a decoy the
# moment the collector's lstat has reported it a directory: the window between
# a check and the open that follows it. Every leaked marker lives in the decoy.
# The first check proves the swap happened, so this cannot pass by never
# reaching the race.
mkdir -p "$WORK/race-hook"
cat > "$WORK/race-hook/sitecustomize.py" <<'HOOKEOF'
import os
import stat

_dir = os.environ.get("PATCHED_RACE_DIR")
_decoy = os.environ.get("PATCHED_RACE_DECOY")
_lstat = os.lstat
_fired = []


def _is_target(path, dir_fd):
    if not isinstance(path, str):
        return False
    if dir_fd is None:
        return os.path.normpath(path) == _dir
    if path != os.path.basename(_dir):
        return False
    try:
        return os.fstat(dir_fd).st_ino == _lstat(os.path.dirname(_dir)).st_ino
    except OSError:
        return False


def _hooked_lstat(path, *, dir_fd=None):
    st = _lstat(path, dir_fd=dir_fd)
    if not _fired and stat.S_ISDIR(st.st_mode) and _is_target(path, dir_fd):
        _fired.append(True)
        os.rename(_dir, _dir + ".checked")
        os.symlink(_decoy, _dir)
    return st


if _dir and _decoy:
    os.lstat = _hooked_lstat
HOOKEOF
# race_run <directory to swap> <decoy directory>
race_run() {
    export PYTHONPATH="$WORK/race-hook" PATCHED_RACE_DIR="$1" PATCHED_RACE_DECOY="$2"
    run
    unset PYTHONPATH PATCHED_RACE_DIR PATCHED_RACE_DECOY
}
swapped() { [[ -L "$1" && -d "$1.checked" ]] && echo 1 || echo 0; }

build_tree
RACE_DECOY="$WORK/race-decoy"; rm -rf "$RACE_DECOY"; mkdir -p "$RACE_DECOY"
write_file "$RACE_DECOY/extensions.json" "[$(vsx_entry leaked.secret 9.9.9 1767225600000 Leaked)]"
RACE_DIR="$U/alice/.vscode/extensions"
race_run "$RACE_DIR" "$RACE_DECOY"
chk "the extensions directory was swapped between its check and the read" "$(swapped "$RACE_DIR")"
chk "extensions.json was not read through the swapped-in link" "$(is_true '"leaked" not in json.dumps(obj).lower()')"
chk "the refusal is recorded and the block is partial, never complete" "$(status_is partial)"

##############################################################################
echo "[static] the collector launches no process and opens no network client"
SHELL_PART="$WORK/shell-part"; PY_PART="$WORK/py-part"
awk '/<<.PYEOF.( &)?$/{print; inpy=1; next} /^PYEOF$/{inpy=0} !inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$SHELL_PART"
awk '/<<.PYEOF.( &)?$/{inpy=1; next} /^PYEOF$/{inpy=0} inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$PY_PART"
chk "extracted a non-trivial python part" "$(( $(wc -l < "$PY_PART") > 200 ))"
chk "extracted a non-trivial shell part" "$(( $(wc -l < "$SHELL_PART") > 30 ))"
hits=$(grep -nE '(^|[;&|(`[:space:]]|\$\()(curl|wget|nc|ncat|ssh|scp|sftp|rsync|git|open|osascript|nscurl|code|cursor|windsurf|idea|launchctl|sudo)([[:space:]]|$)|/dev/(tcp|udp)' "$SHELL_PART")
chk "shell part runs no network client, editor or opener" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE '^[[:space:]]*(import|from)[[:space:]]' "$PY_PART" \
    | grep -vE '^[0-9]+:import (datetime|errno|json|os|re|stat|sys|time|zipfile|xml\.etree\.ElementTree as ElementTree)$')
chk "python imports only the reviewed modules" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE '__import__|importlib|subprocess|socket|urllib|http\.client|requests|ftplib|os\.(system|popen|exec|spawn|fork|posix_spawn|kill)|(^|[^.A-Za-z_])(eval|exec|compile)\(|https?://' "$PY_PART")
chk "python launches no process, opens no socket, names no URL" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE 'O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)|\b(unlink|remove|rename|replace|rmdir|mkdir|makedirs|chmod|chown|symlink|utime|extract|extractall)\(' "$PY_PART")
chk "python writes nothing but its own output file, extracts nothing" "$([[ -z "$hits" && "$(grep -cE '(^|[^.A-Za-z_])open\(' "$PY_PART")" == 1 ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
# Every open, lstat, readlink and listing is relative to a directory the
# walk opened itself (PAT-2033). The only call given a whole path is the open
# of / that each walk starts from, so no path is left to swap for a symlink.
chk "every os.open is O_NOFOLLOW: / itself, or relative to a walked directory" \
    "$([[ "$(grep -c 'os\.open(' "$PY_PART")" == 4 \
        && "$(grep -c '^DIR_FLAGS = os\.O_RDONLY | os\.O_NOFOLLOW | os\.O_DIRECTORY | os\.O_CLOEXEC$' "$PY_PART")" == 1 \
        && "$(grep -c '^FILE_FLAGS = os\.O_RDONLY | os\.O_NOFOLLOW | os\.O_NONBLOCK | os\.O_CLOEXEC$' "$PY_PART")" == 1 \
        && -z "$(grep 'os\.open(' "$PY_PART" | grep -vE 'os\.open\("/", DIR_FLAGS\)|os\.open\((part|name), (DIR|FILE)_FLAGS, dir_fd=')" ]] && echo 1 || echo 0)"
hits=$(grep -nE 'os\.(lstat|readlink|scandir|listdir|stat|access|chdir|walk)\(|os\.path\.(exists|lexists|isdir|isfile|islink|getsize)\(' "$PY_PART" \
    | grep -vE 'os\.(lstat|readlink)\((part|name), dir_fd=[a-z_]+(\[-1\])?\)|os\.scandir\(fd\)')
chk "no stat, readlink or listing is given a whole path" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"

##############################################################################
echo "[tcc] a folder macOS privacy protection denies is tcc_denied, never complete, and an agent_health entry (PAT-2100)"
source "$SCRIPT_DIR/tcc-deny-hook.zsh"
export PATCHED_AGENT_HEALTH_STORE="$AH_STORE"
TCC_KEY='"tcc_denied|ide_extensions"'
TCC_WARN='WARN: ide_extensions: macOS privacy protection denied access to'
has_issue() { is_true "any(i[\"code\"]==\"$1\" and i[\"path\"].endswith(\"$2\") for i in obj[\"issues\"])"; }
ustatus() { is_true "[u[\"collection_status\"] for u in obj[\"users\"] if u[\"user\"]==\"$1\"] == [\"$2\"]"; }

build_tree
_IDE_USERS_ROOT="$U"
rm -rf "$WORK/agent-health"
deny_run "$EPERM" "$JB"
chk "EPERM: the hook really denied the open (so the test can fail)" "$(hook_fired)"
chk "bob's JetBrains folder is tcc_denied, not unreadable" \
    "$(has_issue tcc_denied "Application Support/JetBrains")$(is_true 'not any(i["code"]=="unreadable" for i in obj["issues"])')"
chk "bob is partial, never not_present or complete; his other editor is still read" \
    "$(ustatus bob partial)$(is_true 'any(e["editor"]=="vscode_insiders" for e in obj["extensions"]) and not any(e["family"]=="jetbrains" for e in obj["extensions"])')"
chk "the block is partial, never complete" "$(status_is partial)"
chk "the collect log says so, with a count and why" \
    "$(grep -qF "$TCC_WARN 1 folder(s) or file(s) (Full Disk Access is not granted to the Patched collector)" "$WORK/last.log" && echo 1 || echo 0)"
chk "without agent_health.sh loaded the collector writes no store" "$(store_absent)"

build_tree
deny_run "$EPERM" "$JB/IntelliJIdea2025.2"
chk "a denied product folder: its plugins are tcc_denied and the profile failed, never empty-complete" \
    "$(hook_fired)$(has_issue tcc_denied "IntelliJIdea2025.2/plugins")$(is_true '[p["collection_status"] for p in obj["profiles"] if p["editor"]=="IntelliJIdea"] == ["failed"]')$(ustatus bob partial)$(status_is partial)"

source "$SCRIPT_DIR/agent_health.sh"
# The entry is the LaunchDaemon run's alone (parent PID 1); these tests run
# under another parent, so they stand in for launchd until the manual case.
_PATCHED_TCC_HEALTH_PPID=1
build_tree
deny_run "$EPERM" "$JB"
chk "the daemon run records tcc_denied / ide_extensions / full_disk_access_missing" \
    "$(hook_fired)$(ah_true "active[$TCC_KEY][\"reason\"] == \"full_disk_access_missing\" and active[$TCC_KEY][\"count\"] == 1")"
deny_run "$EACCES" "$JB"
chk "EACCES is unreadable, no privacy wording, and no opinion on the entry" \
    "$(hook_fired)$(has_issue unreadable "Application Support/JetBrains")$(is_true 'not any(i["code"]=="tcc_denied" for i in obj["issues"])')$(grep -qF "$TCC_WARN" "$WORK/last.log" && echo 0 || echo 1)$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
_PATCHED_TCC_HEALTH_PPID=4242
run
chk "a clean manual run leaves the daemon's entry, and says why" \
    "$(ah_true "active[$TCC_KEY][\"count\"] == 1")$(grep -q 'ide_extensions: not the LaunchDaemon run (parent 4242)' "$WORK/last.log" && echo 1 || echo 0)"
_PATCHED_TCC_HEALTH_PPID=1
_IDE_MAX_EXTENSIONS=2
run
_IDE_MAX_EXTENSIONS=5000
chk "a truncated walk is no opinion" "$(is_true 'obj["truncated"] is True')$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
run
chk "a full clean daemon run clears it, and the ledger says it once worked" \
    "$(status_is complete)$(ah_true "$TCC_KEY not in active and ever.get($TCC_KEY) is True")"
unset _PATCHED_TCC_HEALTH_PPID PATCHED_AGENT_HEALTH_STORE

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
