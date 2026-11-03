#!/bin/zsh
##############################################################################
# test-homebrew.zsh — PAT-2012 Homebrew collector contract tests.
#
# Sources macos/lib/homebrew.sh and runs the real collect_homebrew against
# Cellar, Caskroom and Taps trees built in a scratch directory, one shaped
# like an Apple silicon /opt/homebrew and one like an Intel /usr/local. No
# root, no Homebrew install and no network are needed, so it runs the same on
# a Mac and on the Linux CI runner.
#
# Also carries two guards that must stay red-capable:
#   [static]  the collector contains no Homebrew invocation, network client or
# process launch (Homebrew is read from disk only rule)
#   [wire]    the homebrew block is on the wire (PAT-2032, 2026-09-28);
#             setting _HOMEBREW_PAYLOAD_ON_WIRE back to 0 turns this red, and
#             that change must update this test in the same change. The off
#             path is still exercised with the flag set locally.
#
# Run: zsh macos/lib/test-homebrew.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
MODULE="$SCRIPT_DIR/homebrew.sh"
COLLECT_SH="$SCRIPT_DIR/../patched-collect.sh"
PYTHON3="${PATCHED_TEST_PYTHON3:-$(command -v python3)}"
REAL_PYTHON3="$PYTHON3"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.homebrew-test.XXXXXX")
trap 'chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT
WORK=${WORK:A}  # one canonical spelling, so paths compare as the collector reports them

source "$SCRIPT_DIR/common.sh"
source "$MODULE"

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# jq_py <python expression over `obj`> — evaluated against the block the
# last collect_homebrew wrote.
jq_py() {
    "$REAL_PYTHON3" -c 'import json,sys; obj=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' \
        "$HOMEBREW_JSON_TMP" "$1" 2>/dev/null
}
is_true() { [[ "$(jq_py "$1")" == "True" ]] && echo 1 || echo 0; }

# write_receipt <path> <json>
write_file() { mkdir -p "${1:h}"; print -r -- "$2" > "$1"; }

# formula <prefix> <name> <version> <receipt-json> [<rb-body>]
formula() {
    local keg="$1/Cellar/$2/$3"
    mkdir -p "$keg/.brew"
    write_file "$keg/INSTALL_RECEIPT.json" "$4"
    [[ -n "${5:-}" ]] && write_file "$keg/.brew/$2.rb" "$5"
    return 0
}

receipt() {  # receipt <tap> <on_request> <as_dep> <time> [<deps-json>]
    print -r -- "{\"installed_on_request\":$2,\"installed_as_dependency\":$3,\"time\":$4,\"runtime_dependencies\":${5:-[]},\"source\":{\"tap\":\"$1\",\"spec\":\"stable\"}}"
}

build_tree() {
    rm -rf "$WORK/t"
    A="$WORK/t/opt/homebrew"
    B="$WORK/t/usr/local"
    APPS="$WORK/t/Applications"
    mkdir -p "$A/Library/Homebrew" "$A/opt" "$B/Homebrew/Library/Homebrew" "$APPS/Firefox.app"

    # A requested formula with a dependency, and its formula file: homepage,
    # a one-line head (not a block), the main url, then a resource url that
    # must not be taken.
    formula "$A" wget 1.24.5 "$(receipt homebrew/core true false 1767225600 '[{"full_name":"libidn2","version":"2.3.7"}]')" \
'class Wget < Formula
  desc "Internet file retriever"
  homepage "https://www.gnu.org/software/wget/"
  head "https://git.savannah.gnu.org/git/wget.git", branch: "master"
  url "https://ftpmirror.gnu.org/gnu/wget/wget-1.24.5.tar.gz"
  sha256 "0000"
  resource "extra" do
    url "https://example.invalid/not-the-source.tar.gz"
  end
end'
    ln -s ../Cellar/wget/1.24.5 "$A/opt/wget"
    # The dependency formula.
    formula "$A" libidn2 2.3.7 "$(receipt homebrew/core false true 1767225500)" \
'class Libidn2 < Formula
  homepage "https://www.gnu.org/software/libidn/"
  stable do
    url "https://ftpmirror.gnu.org/gnu/libidn/libidn2-2.3.7.tar.gz"
  end
end'
    ln -s ../Cellar/libidn2/2.3.7 "$A/opt/libidn2"
    # Two kegs of one formula; opt points at the newer.
    formula "$A" sqlite 3.50.0 "$(receipt homebrew/core false true 1767225000)"
    formula "$A" sqlite 3.51.0 "$(receipt homebrew/core false true 1767225100)"
    ln -s ../Cellar/sqlite/3.51.0 "$A/opt/sqlite"
    # A formula from a third-party tap.
    formula "$A" widget 2.0.1 "$(receipt acme/tools true false 1767225200)" \
'class Widget < Formula
  homepage "https://widget.example.invalid"
  url "https://placeholder:placeholder@downloads.example.invalid/widget-2.0.1.tgz?token=placeholder&arch=arm64"
end'
    ln -s ../Cellar/widget/2.0.1 "$A/opt/widget"

    # A cask that installed an app (symlink in the version dir, as Homebrew
    # leaves it), and one with no app.
    mkdir -p "$A/Caskroom/firefox/140.0/" "$A/Caskroom/firefox/.metadata"
    ln -s "$APPS/Firefox.app" "$A/Caskroom/firefox/140.0/Firefox.app"
    write_file "$A/Caskroom/firefox/.metadata/INSTALL_RECEIPT.json" \
        '{"installed_on_request":true,"time":1767226000,"source":{"tap":"homebrew/cask","version":"140.0"},"uninstall_artifacts":[{"app":["Firefox.app"]},{"zap":[{"trash":["~/Library/Caches/Firefox"]}]}]}'
    mkdir -p "$A/Caskroom/font-archivo/latest" "$A/Caskroom/font-archivo/.metadata"
    write_file "$A/Caskroom/font-archivo/.metadata/INSTALL_RECEIPT.json" \
        '{"installed_on_request":true,"time":1767226100,"source":{"tap":"homebrew/cask","version":"latest"},"uninstall_artifacts":[{"font":["Archivo.ttf"]}]}'

    # A third-party tap whose remote carries credentials, and a tap on B's
    # repository-under-prefix layout.
    mkdir -p "$A/Library/Taps/acme/homebrew-tools/.git"
    write_file "$A/Library/Taps/acme/homebrew-tools/.git/config" \
'[core]
	bare = false
[remote "upstream"]
	url = https://example.invalid/wrong.git
[remote "origin"]
	url = https://placeholder:placeholder@git.example.invalid/acme/homebrew-tools.git
	fetch = +refs/heads/*:refs/remotes/origin/*'

    formula "$B" telnet 294 "$(receipt homebrew/core true false 1698181191)" \
'class Telnet < Formula
  homepage "https://opensource.apple.com/"
  url "https://github.com/apple-oss-distributions/remote_cmds/archive/refs/tags/remote_cmds-294.tar.gz"
end'
    mkdir -p "$B/Homebrew/Library/Taps/homebrew/homebrew-core/.git"
    write_file "$B/Homebrew/Library/Taps/homebrew/homebrew-core/.git/config" \
'[remote "origin"]
	url = https://github.com/Homebrew/homebrew-core'
}

run() {
    PATCHED_TMPDIR=$(mktemp -d "$WORK/run.XXXXXX")
    collect_homebrew > "$WORK/last.log" 2>&1
}

##############################################################################
echo "[1] both prefixes, every entry readable"
build_tree
_HOMEBREW_PREFIXES=("$A" "$B")
run
chk "status complete" "$([[ "$(homebrew_collection_status)" == complete ]] && echo 1 || echo 0)"
chk "counts: 6 formulae, 2 casks, 2 taps" "$([[ "$HOMEBREW_FORMULA_COUNT/$HOMEBREW_CASK_COUNT/$HOMEBREW_TAP_COUNT" == 6/2/2 ]] && echo 1 || echo 0)"
chk "both prefixes reported, each complete" "$(is_true '[(p["path"].endswith("opt/homebrew"), p["collection_status"]) for p in obj["prefixes"]] == [(True,"complete"),(False,"complete")]')"
chk "prefix owner recorded" "$(is_true 'all(p["owner_uid"] == __import__("os").getuid() and p["owner"] for p in obj["prefixes"])')"
chk "not truncated" "$(is_true 'obj["truncated"] is False and obj["truncation_reason"] is None')"
W='[f for f in obj["formulae"] if f["name"]=="wget"][0]'
chk "requested formula: tap, request flags, install time" "$(is_true "($W)['tap']=='homebrew/core' and ($W)['installed_on_request'] is True and ($W)['installed_as_dependency'] is False and ($W)['installed_at']=='2026-07-01T00:00:00Z'")"
chk "requested formula: runtime dependency recorded" "$(is_true "($W)['runtime_dependencies']==['libidn2']")"
chk "formula file: homepage and main url, not the resource url or head" "$(is_true "($W)['homepage']=='https://www.gnu.org/software/wget/' and ($W)['source_url']=='https://ftpmirror.gnu.org/gnu/wget/wget-1.24.5.tar.gz'")"
L='[f for f in obj["formulae"] if f["name"]=="libidn2"][0]'
chk "dependency formula: installed_as_dependency true, not on request" "$(is_true "($L)['installed_as_dependency'] is True and ($L)['installed_on_request'] is False")"
chk "url inside a stable block is read" "$(is_true "($L)['source_url']=='https://ftpmirror.gnu.org/gnu/libidn/libidn2-2.3.7.tar.gz'")"
chk "two kegs of one formula both reported, only the newer opt-linked" "$(is_true '[(f["version"], f["opt_linked"]) for f in obj["formulae"] if f["name"]=="sqlite"] == [("3.50.0", False), ("3.51.0", True)]')"
chk "keg with no formula file: file missing, not partial" "$(is_true '[f["formula_file_status"] for f in obj["formulae"] if f["name"]=="sqlite"] == ["missing","missing"]')"
X='[f for f in obj["formulae"] if f["name"]=="widget"][0]'
chk "third-party tap formula keeps its tap" "$(is_true "($X)['tap']=='acme/tools'")"
chk "credentials stripped from a source url, secret query redacted" "$(is_true "($X)['source_url']=='https://downloads.example.invalid/widget-2.0.1.tgz?token=REDACTED&arch=arm64'")"
F='[c for c in obj["casks"] if c["token"]=="firefox"][0]'
chk "cask with app: version, tap, time" "$(is_true "($F)['version']=='140.0' and ($F)['tap']=='homebrew/cask' and ($F)['installed_at']=='2026-07-01T00:06:40Z'")"
chk "cask with app: .app path resolved from the Caskroom symlink" "$(is_true "($F)['apps']==[{'name':'Firefox.app','path':'$APPS/Firefox.app','exists':True}]")"
chk "cask without app: empty apps, version latest" "$(is_true '[(c["version"], c["apps"]) for c in obj["casks"] if c["token"]=="font-archivo"] == [("latest", [])]')"
T='[t for t in obj["taps"] if t["directory"]=="acme/homebrew-tools"][0]'
chk "third-party tap: name, origin remote chosen over another remote" "$(is_true "($T)['name']=='acme/tools' and ($T)['remote_url']=='https://git.example.invalid/acme/homebrew-tools.git'")"
chk "no credential text anywhere in the block" "$(is_true '"placeholder" not in json.dumps(obj)' 2>/dev/null || echo 0)"
chk "no credential text anywhere in the block (raw)" "$(grep -q placeholder "$HOMEBREW_JSON_TMP" && echo 0 || echo 1)"
chk "Intel layout: taps under Homebrew/Library/Taps, formula read" "$(is_true '[(t["prefix"].endswith("usr/local"), t["name"]) for t in obj["taps"] if t["name"]=="homebrew/core"] == [(True, "homebrew/core")] and any(f["name"]=="telnet" and f["prefix"].endswith("usr/local") for f in obj["formulae"])')"
chk "no issues recorded" "$(is_true 'obj["issues"] == []')"

##############################################################################
echo "[2] unreadable receipts make the block partial, never empty"
build_tree
# Unreadable as root too: the receipt is a directory.
formula "$A" brokenpkg 1.0 "{}"
rm -f "$A/Cellar/brokenpkg/1.0/INSTALL_RECEIPT.json"; mkdir "$A/Cellar/brokenpkg/1.0/INSTALL_RECEIPT.json"
# A receipt that does not parse.
formula "$A" garbled 1.0 "{not json"
_HOMEBREW_PREFIXES=("$A" "$B")
run
chk "status partial" "$([[ "$(homebrew_collection_status)" == partial ]] && echo 1 || echo 0)"
chk "unreadable receipt still listed, marked unreadable, fields null" "$(is_true '[(f["receipt_status"], f["tap"], f["installed_on_request"]) for f in obj["formulae"] if f["name"]=="brokenpkg"] == [("unreadable", None, None)]')"
chk "unparseable receipt listed and marked" "$(is_true '[f["receipt_status"] for f in obj["formulae"] if f["name"]=="garbled"] == ["unparseable"]')"
chk "the readable entries are still all there" "$(is_true 'len(obj["formulae"]) == 8 and len(obj["casks"]) == 2 and len(obj["taps"]) == 2')"
chk "only the affected prefix is partial" "$(is_true '[p["collection_status"] for p in obj["prefixes"]] == ["partial","complete"]')"
chk "issues name the receipt codes" "$(is_true 'sorted(i["code"] for i in obj["issues"]) == ["receipt_unparseable","receipt_unreadable"]')"
if (( EUID != 0 )); then
    build_tree
    chmod 000 "$A/Cellar/wget/1.24.5/INSTALL_RECEIPT.json"
    run
    chk "permission-denied receipt is partial" "$([[ "$(homebrew_collection_status)" == partial ]] && echo 1 || echo 0)"
    chk "permission-denied receipt keeps the formula listed" "$(is_true '[f["receipt_status"] for f in obj["formulae"] if f["name"]=="wget"] == ["unreadable"]')"
else
    echo "  SKIP: running as root, chmod 000 does not deny a read (the directory case above covers it)"
fi

##############################################################################
echo "[3] symlinks planted in the user-owned tree are never followed"
build_tree
SECRET="$WORK/root-only-secret"
print -r -- '{"installed_on_request":true,"source":{"tap":"leaked/secret"}}' > "$SECRET"
rm -f "$A/Cellar/wget/1.24.5/INSTALL_RECEIPT.json"
ln -s "$SECRET" "$A/Cellar/wget/1.24.5/INSTALL_RECEIPT.json"
mkdir -p "$WORK/elsewhere/9.9"
ln -s "$WORK/elsewhere" "$A/Cellar/planted"
run
chk "symlinked receipt is unreadable, its target never parsed" "$(is_true '[f["receipt_status"] for f in obj["formulae"] if f["name"]=="wget"] == ["unreadable"] and "leaked" not in json.dumps(obj)')"
chk "symlinked formula directory is skipped" "$(is_true 'not any(f["name"]=="planted" for f in obj["formulae"])')"
chk "status partial" "$([[ "$(homebrew_collection_status)" == partial ]] && echo 1 || echo 0)"

##############################################################################
echo "[4] no Homebrew layout anywhere is not_present, with empty lists"
_HOMEBREW_PREFIXES=("$WORK/nope/opt/homebrew" "$WORK/nope/usr/local")
mkdir -p "$WORK/nope/usr/local/bin"
run
chk "status not_present" "$([[ "$(homebrew_collection_status)" == not_present ]] && echo 1 || echo 0)"
chk "lists present and empty (a genuine reading)" "$(is_true 'obj["formulae"] == [] and obj["casks"] == [] and obj["taps"] == [] and obj["prefixes"] == []')"

##############################################################################
echo "[5] a layout that cannot be read is failed, with the lists omitted"
rm -rf "$WORK/bad"; mkdir -p "$WORK/bad"
print -r -- "not a directory" > "$WORK/bad/Cellar"
_HOMEBREW_PREFIXES=("$WORK/bad")
run
chk "status failed" "$([[ "$(homebrew_collection_status)" == failed ]] && echo 1 || echo 0)"
chk "formulae/casks/taps omitted, not []" "$(is_true 'obj["collection_status"] == "failed" and "formulae" not in obj and "casks" not in obj and "taps" not in obj')"
if (( EUID != 0 )); then
    build_tree
    chmod 000 "$A/Cellar"
    _HOMEBREW_PREFIXES=("$A")
    run
    chmod 755 "$A/Cellar"
    chk "unlistable Cellar with a readable Caskroom is partial, casks kept" "$([[ "$(homebrew_collection_status)" == partial ]] && [[ "$(jq_py 'len(obj["casks"])')" == 2 ]] && echo 1 || echo 0)"
else
    echo "  SKIP: running as root, chmod 000 does not deny a listing"
fi

##############################################################################
echo "[6] bounds: formula count and time budget stop collection as partial"
build_tree
_HOMEBREW_PREFIXES=("$A" "$B")
_HOMEBREW_MAX_FORMULAE=2
run
chk "past the formula limit: partial, formula_limit, exactly 2 formulae" "$([[ "$(homebrew_collection_status)" == partial ]] && echo 1 || echo 0)"
chk "truncation recorded" "$(is_true 'obj["truncated"] is True and obj["truncation_reason"] == "formula_limit" and len(obj["formulae"]) == 2')"
_HOMEBREW_MAX_FORMULAE=5000
_HOMEBREW_TIME_BUDGET_SECONDS=0
run
chk "past the time budget: partial, time_limit" "$([[ "$(homebrew_collection_status)" == partial ]] && [[ "$(jq_py 'obj["truncation_reason"]')" == time_limit ]] && echo 1 || echo 0)"
_HOMEBREW_TIME_BUDGET_SECONDS=30

##############################################################################
echo "[7] a hung or crashed parser is failed, and the hang is bounded"
print -r -- '#!/bin/zsh
sleep 30' > "$WORK/slowpy"; chmod +x "$WORK/slowpy"
print -r -- '#!/bin/zsh
exit 3' > "$WORK/crashpy"; chmod +x "$WORK/crashpy"
PYTHON3="$WORK/slowpy"; _HOMEBREW_HARD_TIMEOUT_SECONDS=1
_hb_t0=$SECONDS
run
_hb_elapsed=$(( SECONDS - _hb_t0 ))
PYTHON3="$REAL_PYTHON3"; _HOMEBREW_HARD_TIMEOUT_SECONDS=45
chk "hung parser: failed" "$([[ "$(homebrew_collection_status)" == failed ]] && echo 1 || echo 0)"
chk "hung parser: killed within the hard limit (${_hb_elapsed}s)" "$(( _hb_elapsed <= 4 ))"
chk "hung parser: stub block says failed" "$(is_true 'obj == {"collection_status": "failed"}')"
PYTHON3="$WORK/crashpy"
run
PYTHON3="$REAL_PYTHON3"
chk "crashed parser: failed" "$([[ "$(homebrew_collection_status)" == failed ]] && echo 1 || echo 0)"
# A parser the loop gave up on is failed even when wait then reports a clean
# exit (PAT-2033). kill -9 is made a no-op, as when the parser finishes in the
# moment between the last check and the kill, and the parser exits 0 with good
# output after the limit.
print -r -- "#!/bin/zsh
\"$REAL_PYTHON3\" \"\$@\"; _rc=\$?; sleep 2; exit \$_rc" > "$WORK/latepy"; chmod +x "$WORK/latepy"
kill() { [[ "$1" == -9 ]] && return 0; builtin kill "$@"; }
PYTHON3="$WORK/latepy"; _HOMEBREW_HARD_TIMEOUT_SECONDS=1
run
unfunction kill
PYTHON3="$REAL_PYTHON3"; _HOMEBREW_HARD_TIMEOUT_SECONDS=45
chk "killed parser that still exits 0 with good output: failed" "$([[ "$(homebrew_collection_status)" == failed ]] && echo 1 || echo 0)"

##############################################################################
echo "[8] special files, unreadable directories and a symlinked prefix"
build_tree
_HOMEBREW_PREFIXES=("$A" "$B")
rm -f "$A/Cellar/wget/1.24.5/INSTALL_RECEIPT.json"
mkfifo "$A/Cellar/wget/1.24.5/INSTALL_RECEIPT.json"
run
chk "FIFO receipt: refused as unreadable, never read" "$(is_true '[f["receipt_status"] for f in obj["formulae"] if f["name"]=="wget"] == ["unreadable"]')"
chk "FIFO receipt: block partial" "$([[ "$(homebrew_collection_status)" == partial ]] && echo 1 || echo 0)"

build_tree
mkfifo "$A/Cellar/fifopkg"
run
chk "FIFO where a formula dir should be: partial, not silently skipped" "$([[ "$(homebrew_collection_status)" == partial ]] && echo 1 || echo 0)"
chk "FIFO entry recorded as not_regular" "$(is_true 'any(i["code"]=="not_regular" and i["path"].endswith("/Cellar/fifopkg") for i in obj["issues"])')"

build_tree
rm -rf "$A/Library/Taps/acme/homebrew-tools/.git"
mkfifo "$A/Library/Taps/acme/homebrew-tools/.git"
run
chk "FIFO where a tap .git should be: partial with not_regular" "$([[ "$(homebrew_collection_status)" == partial ]] && [[ "$(jq_py 'any(i["code"]=="not_regular" for i in obj["issues"])')" == True ]] && echo 1 || echo 0)"

if (( EUID != 0 )); then
    build_tree
    chmod 000 "$A/Cellar/libidn2"
    run
    chmod 755 "$A/Cellar/libidn2"
    chk "unreadable formula directory: partial with an issue, other entries kept" "$([[ "$(homebrew_collection_status)" == partial ]] && [[ "$(jq_py '[i["code"] for i in obj["issues"]] == ["unreadable"] and len(obj["formulae"]) == 5')" == True ]] && echo 1 || echo 0)"
else
    echo "  SKIP: running as root, chmod 000 does not deny a listing"
fi

build_tree
ln -s "$A" "$WORK/t/linked-prefix"
_HOMEBREW_PREFIXES=("$WORK/t/linked-prefix")
run
chk "symlinked prefix: not followed, nothing read through it" "$(is_true 'obj["formulae"] == [] and obj["casks"] == [] and obj["taps"] == []')"
chk "symlinked prefix: recorded partial with symlink_not_followed" "$(is_true '[(p["collection_status"]) for p in obj["prefixes"]] == ["partial"] and obj["issues"][0]["code"] == "symlink_not_followed"')"
chk "symlinked prefix: block partial" "$([[ "$(homebrew_collection_status)" == partial ]] && echo 1 || echo 0)"
_HOMEBREW_PREFIXES=("$A" "$B")

##############################################################################
echo "[9] a deeply nested receipt costs only that formula (PAT-2032)"
build_tree
_HOMEBREW_PREFIXES=("$A" "$B")
# 200,000 levels would exhaust json.loads' recursion limit; 65 is one past the
# 64-level cap. Both sit in the user-owned tree, under the receipt size cap.
formula "$A" deepnest 1.0 "$("$REAL_PYTHON3" -c 'print("{\"a\":" + "[" * 200000 + "]" * 200000 + "}")')"
formula "$A" nest65 1.0 "$("$REAL_PYTHON3" -c 'print("[" * 64 + "{}" + "]" * 64)')"
formula "$A" nest64 1.0 "$("$REAL_PYTHON3" -c 'print("{\"installed_on_request\":true,\"x\":" + "[" * 63 + "]" * 63 + "}")')"
run
chk "block partial, not failed" "$([[ "$(homebrew_collection_status)" == partial ]] && echo 1 || echo 0)"
chk "recursion-deep receipt marked unparseable, formula kept" "$(is_true '[f["receipt_status"] for f in obj["formulae"] if f["name"]=="deepnest"] == ["unparseable"]')"
chk "65-level receipt marked unparseable" "$(is_true '[f["receipt_status"] for f in obj["formulae"] if f["name"]=="nest65"] == ["unparseable"]')"
chk "64-level receipt still parses" "$(is_true '[(f["receipt_status"], f["installed_on_request"]) for f in obj["formulae"] if f["name"]=="nest64"] == [("read", True)]')"
chk "every other entry still read" "$(is_true 'len(obj["formulae"]) == 9 and len(obj["casks"]) == 2 and len(obj["taps"]) == 2 and sum(f["receipt_status"]=="read" for f in obj["formulae"]) == 7')"
chk "only the deep receipts are issues" "$(is_true 'sorted(i["path"].split("/Cellar/")[1] for i in obj["issues"] if i["code"]=="receipt_unparseable") == ["deepnest/1.0","nest65/1.0"] and len(obj["issues"]) == 2')"

##############################################################################
echo "[10] byte budget: an oversized block drops whole entries and ends partial (PAT-2032)"
size_ok() { [[ -s "$HOMEBREW_JSON_TMP" ]] && (( $(wc -c < "$HOMEBREW_JSON_TMP") <= $1 )) && echo 1 || echo 0; }
# Prefix counts equal the entries sent, and a prefix that lost any is partial.
COUNTS_MATCH='all((p["formulae"], p["casks"], p["taps"]) == (sum(f["prefix"]==p["path"] for f in obj["formulae"]), sum(c["prefix"]==p["path"] for c in obj["casks"]), sum(t["prefix"]==p["path"] for t in obj["taps"])) for p in obj["prefixes"])'

# A synthetic tree over the real 2 MB budget: 600 formulae, two kegs each,
# every formula file carrying a long homepage, so about 2.9 MB in full.
build_tree
_HOMEBREW_PREFIXES=("$A" "$B")
"$REAL_PYTHON3" - "$A" <<'PYEOF'
import json, os, sys
root = sys.argv[1]
receipt = json.dumps({"installed_on_request": True, "installed_as_dependency": False, "time": 1767225600,
                      "runtime_dependencies": [], "source": {"tap": "homebrew/core"}})
for i in range(600):
    name = "bulk%04d" % i
    for version in ("1.0", "2.0"):
        keg = os.path.join(root, "Cellar", name, version)
        os.makedirs(os.path.join(keg, ".brew"))
        with open(os.path.join(keg, "INSTALL_RECEIPT.json"), "w") as f:
            f.write(receipt)
        with open(os.path.join(keg, ".brew", name + ".rb"), "w") as f:
            f.write('class X < Formula\n  homepage "https://example.invalid/%s"\nend\n' % ("h" * 2000))
    os.symlink("../Cellar/%s/2.0" % name, os.path.join(root, "opt", name))
PYEOF
_hb_default_budget=$_HOMEBREW_MAX_BYTES
run
chk "default budget is 2 MiB" "$(( _hb_default_budget == 2097152 ))"
chk "oversized tree: partial, truncated, size_limit" "$(is_true 'obj["collection_status"]=="partial" and obj["truncated"] is True and obj["truncation_reason"]=="size_limit"')"
chk "shell status is partial" "$([[ "$(homebrew_collection_status)" == partial ]] && echo 1 || echo 0)"
chk "emitted block is within the budget ($(wc -c < "$HOMEBREW_JSON_TMP" | tr -d ' ') bytes)" "$(size_ok 2097152)"
chk "some formulae were dropped, not all" "$(is_true '0 < len(obj["formulae"]) < 1206')"
chk "no formula is cut mid keg list: every name sent has both kegs" "$(is_true 'all(sorted(f["version"] for f in obj["formulae"] if f["name"]==n) == ["1.0","2.0"] for n in {f["name"] for f in obj["formulae"] if f["name"].startswith("bulk")})')"
chk "drop is deterministic: the tail of the sorted list goes first" "$(is_true '[f["name"] for f in obj["formulae"]] == sorted(f["name"] for f in obj["formulae"]) and obj["formulae"][-1]["prefix"].endswith("opt/homebrew") and not any(f["prefix"].endswith("usr/local") for f in obj["formulae"])')"
chk "casks and taps untouched while formulae remain" "$(is_true 'len(obj["casks"]) == 2 and len(obj["taps"]) == 2')"
chk "prefix counts match what is sent, dropped prefixes partial" "$(is_true "$COUNTS_MATCH and [p['collection_status'] for p in obj['prefixes']] == ['partial','partial']")"
chk "shell counts match the emitted lists" "$([[ "$HOMEBREW_FORMULA_COUNT" == "$(jq_py 'len(obj["formulae"])')" && "$HOMEBREW_CASK_COUNT/$HOMEBREW_TAP_COUNT" == 2/2 ]] && echo 1 || echo 0)"
_hb_first="$(jq_py '[f["name"] for f in obj["formulae"]]')"
run
chk "same tree, same budget: same entries dropped" "$([[ "$(jq_py '[f["name"] for f in obj["formulae"]]')" == "$_hb_first" ]] && echo 1 || echo 0)"

# Small tree, lowered budget: formulae go first, then casks, then taps.
build_tree
_HOMEBREW_PREFIXES=("$A" "$B")
run
_hb_full=$(wc -c < "$HOMEBREW_JSON_TMP" | tr -d ' ')
_hb_noformulae=$(jq_py 'len(json.dumps(dict(obj, formulae=[]), separators=(",",":")))')
_HOMEBREW_MAX_BYTES=$(( _hb_full - 1 ))
run
chk "one byte over: only the last formula (telnet, the only one in usr/local) dropped" "$(is_true '[f["name"] for f in obj["formulae"]] == ["libidn2","sqlite","sqlite","wget","widget"] and len(obj["casks"]) == 2 and len(obj["taps"]) == 2')"
chk "one byte over: within budget" "$(size_ok $_HOMEBREW_MAX_BYTES)"
chk "one byte over: only the prefix that lost an entry is partial" "$(is_true "$COUNTS_MATCH and [p['collection_status'] for p in obj['prefixes']] == ['complete','partial']")"
_HOMEBREW_MAX_BYTES=$(( _hb_noformulae - 50 ))
run
chk "past every formula: all formulae dropped before any tap, casks from the tail" "$(is_true 'obj["formulae"] == [] and [c["token"] for c in obj["casks"]] == ["firefox"] and len(obj["taps"]) == 2')"
chk "past every formula: within budget, partial, size_limit" "$(( $(size_ok $_HOMEBREW_MAX_BYTES) && $(is_true 'obj["collection_status"]=="partial" and obj["truncation_reason"]=="size_limit"') ))"
chk "past every formula: counts match" "$(is_true "$COUNTS_MATCH")"
# An earlier bound's reason wins over size_limit.
_HOMEBREW_MAX_FORMULAE=2
_HOMEBREW_MAX_BYTES=$(( _hb_noformulae - 50 ))
run
chk "earlier truncation reason is kept (formula_limit, not size_limit)" "$(is_true 'obj["truncated"] is True and obj["truncation_reason"]=="formula_limit" and obj["formulae"] == []')"
chk "earlier reason: still within budget" "$(size_ok $_HOMEBREW_MAX_BYTES)"
_HOMEBREW_MAX_FORMULAE=5000
# A budget nothing honest fits in is a failed block, never an oversized one.
_HOMEBREW_MAX_BYTES=40
run
chk "budget below any valid block: failed, lists omitted" "$(( $([[ "$(homebrew_collection_status)" == failed ]] && echo 1 || echo 0) && $(is_true 'obj == {"collection_status": "failed"}') ))"
_HOMEBREW_MAX_BYTES=$_hb_default_budget

##############################################################################
echo "[11] formula fields that need Ruby evaluated are null, never wrong (PAT-2042)"
rm -rf "$WORK/t11"; P="$WORK/t11/opt/homebrew"; mkdir -p "$P/Library/Homebrew"
formula "$P" interphome 1.0 "$(receipt homebrew/core true false 1767225600)" \
'class Interphome < Formula
  homepage "https://example.invalid/#{name}/"
  url "https://downloads.example.invalid/interphome-1.0.tar.gz"
end'
formula "$P" interpurl 2.0 "$(receipt homebrew/core true false 1767225600)" \
'class Interpurl < Formula
  homepage "https://interpurl.example.invalid/"
  url "https://downloads.example.invalid/interpurl-#{version}.tar.gz"
  url "https://downloads.example.invalid/not-the-source-2.0.tar.gz"
end'
formula "$P" escquote 3.0 "$(receipt homebrew/core true false 1767225600)" \
'class Escquote < Formula
  homepage "https://escquote.example.invalid/a\"b"
  url "https://downloads.example.invalid/esc\"quote-3.0.tar.gz", using: :nounzip
end'
formula "$P" concat 4.0 "$(receipt homebrew/core true false 1767225600)" \
'class Concat < Formula
  homepage "https://concat.example.invalid/" + "extra"
  url "https://downloads.example.invalid/concat-" "4.0.tar.gz"
end'
formula "$P" literal 5.0 "$(receipt homebrew/core true false 1767225600)" \
'class Literal < Formula
  homepage "https://literal.example.invalid/" # project site
  url "https://downloads.example.invalid/literal-5.0.tar.gz", using: :homebrew_curl
end'
formula "$P" ivarinterp 7.0 "$(receipt homebrew/core true false 1767225600)" \
'class Ivarinterp < Formula
  homepage "https://ivar.example.invalid/#@project/"
  url "https://downloads.example.invalid/ivar-#$version.tar.gz"
end'
formula "$P" singleq 6.0 "$(receipt homebrew/core true false 1767225600)" \
"class Singleq < Formula
  homepage 'https://singleq.example.invalid/'
  url 'https://downloads.example.invalid/singleq-6.0.tar.gz'
end"
_HOMEBREW_PREFIXES=("$P")
run
fld() { print -r -- "[(f['formula_file_status'], f['homepage'], f['source_url']) for f in obj['formulae'] if f['name']=='$1']"; }
chk "interpolated homepage is null, literal url still read" "$(is_true "$(fld interphome) == [('read', None, 'https://downloads.example.invalid/interphome-1.0.tar.gz')]")"
chk "interpolated url is null, not replaced by a later url; literal homepage read" "$(is_true "$(fld interpurl) == [('read', 'https://interpurl.example.invalid/', None)]")"
chk "escaped quote in either field is null, not truncated" "$(is_true "$(fld escquote) == [('read', None, None)]")"
chk "ivar and gvar interpolation (#@, #\$) is null too" "$(is_true "$(fld ivarinterp) == [('read', None, None)]")"
chk "concatenated or adjacent literals are null" "$(is_true "$(fld concat) == [('read', None, None)]")"
chk "literal homepage and url read, with a comment and url options after them" "$(is_true "$(fld literal) == [('read', 'https://literal.example.invalid/', 'https://downloads.example.invalid/literal-5.0.tar.gz')]")"
chk "single-quoted fields are left null" "$(is_true "$(fld singleq) == [('read', None, None)]")"
chk "no interpolation or backslash text anywhere in the block" "$(is_true '"#{" not in json.dumps(obj) and "\\\\" not in json.dumps(obj)')"

##############################################################################
echo "[wire] the block is on the wire (PAT-2032)"
build_tree
_HOMEBREW_PREFIXES=("$A" "$B")
run
chk "the wire flag is 1" "$(( _HOMEBREW_PAYLOAD_ON_WIRE == 1 ))"
chk "collect log line says the block is sent" "$(grep -q '^homebrew: status=complete formulae=6 casks=2 taps=2 (sent)$' "$WORK/last.log" && echo 1 || echo 0)"
frag="{$(homebrew_payload_member) \"next\": 1}"
chk "the member is a valid payload fragment carrying the collected block" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); b=json.load(open(sys.argv[1])); print(1 if d["homebrew"]==b and d["homebrew"]["collection_status"]=="complete" and len(d["homebrew"]["formulae"])==6 and d["next"]==1 else 0)' "$HOMEBREW_JSON_TMP" 2>/dev/null || echo 0)"
HOMEBREW_COLLECTION_STATUS="failed"
frag="{$(homebrew_payload_member) \"next\": 1}"
chk "a failed block is only its status" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["homebrew"]=={"collection_status":"failed"} else 0)' 2>/dev/null || echo 0)"
# The off path stays covered: with the flag at 0 nothing is emitted and the
# log line says so.
_HOMEBREW_PAYLOAD_ON_WIRE=0
run
chk "flag 0: a complete collection emits no payload member" "$([[ -z "$(homebrew_payload_member)" ]] && echo 1 || echo 0)"
chk "flag 0: collect log line says held off the wire" "$(grep -q '^homebrew: status=complete formulae=6 casks=2 taps=2 (held off the wire)$' "$WORK/last.log" && echo 1 || echo 0)"
_HOMEBREW_PAYLOAD_ON_WIRE=1
chk "patched-collect.sh calls the member exactly once in the payload heredoc" \
    "$([[ "$(grep -c '^  \$(homebrew_payload_member)$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"
chk "patched-collect.sh names no \"homebrew\" key of its own" \
    "$(grep -q '"homebrew"' "$COLLECT_SH" && echo 0 || echo 1)"
chk "patched-collect.sh runs collect_homebrew in the daily collection" \
    "$([[ "$(grep -c '^collect_homebrew$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"

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
write_file "$RACE_DECOY/wget.rb" 'class Wget < Formula
  homepage "https://leaked.example/"
  url "https://leaked.example/wget.tar.gz"
end'
RACE_DIR="$A/Cellar/wget/1.24.5/.brew"
race_run "$RACE_DIR" "$RACE_DECOY"
chk "the .brew directory was swapped between its check and the read" "$(swapped "$RACE_DIR")"
chk "the formula file was not read through the swapped-in link" "$(is_true '"leaked" not in json.dumps(obj)')"
chk "the refusal is recorded: formula file unreadable, block partial" \
    "$(is_true '[f["formula_file_status"] for f in obj["formulae"] if f["name"]=="wget"] == ["unreadable"] and obj["collection_status"]=="partial"')"

##############################################################################
echo "[static] the collector never runs Homebrew, a network client or a process"
SHELL_PART="$WORK/shell-part"; PY_PART="$WORK/py-part"
awk '/<<.PYEOF.( &)?$/{print; inpy=1; next} /^PYEOF$/{inpy=0} !inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$SHELL_PART"
awk '/<<.PYEOF.( &)?$/{inpy=1; next} /^PYEOF$/{inpy=0} inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$PY_PART"
chk "extracted a non-trivial python part" "$(( $(wc -l < "$PY_PART") > 100 ))"
chk "extracted a non-trivial shell part" "$(( $(wc -l < "$SHELL_PART") > 30 ))"

# brew as a word anywhere in code (".brew/" keg paths and "Homebrew" excluded).
hits=$(cat "$SHELL_PART" "$PY_PART" | grep -nE '(^|[^.A-Za-z0-9_-])brew([^A-Za-z0-9_-]|$)')
chk "no brew invocation or bare brew word in code" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(cat "$SHELL_PART" "$PY_PART" | grep -niE 'formulae\.brew\.sh|api\.github|https?://')
chk "no URL literal in code (no API or site is ever named)" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE '(^|[;&|(`[:space:]]|\$\()(curl|wget|nc|ncat|ssh|scp|sftp|rsync|git|open|osascript|nscurl|networksetup|ftp|telnet)([[:space:]]|$)|/dev/(tcp|udp)' "$SHELL_PART")
chk "shell part runs no network client, git or opener" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
# Python: allowlist of imports, then a blocklist of process and network calls.
hits=$(grep -nE '^[[:space:]]*(import|from)[[:space:]]' "$PY_PART" \
    | grep -vE '^[0-9]+:import (datetime|json|os|pwd|re|stat|sys|time)$')
chk "python imports only datetime/json/os/pwd/re/stat/sys/time" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE '__import__|importlib|subprocess|socket|urllib|http\.client|requests|ftplib|os\.(system|popen|exec|spawn|fork|posix_spawn|kill)|(^|[^.A-Za-z_])(eval|exec|compile)\(' "$PY_PART")
chk "python launches no process and opens no socket" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE 'O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)|\b(unlink|remove|rename|replace|rmdir|mkdir|makedirs|chmod|chown|symlink|utime)\(' "$PY_PART")
chk "python writes nothing but its own output file" "$([[ -z "$hits" && "$(grep -cE '(^|[^.A-Za-z_])open\(' "$PY_PART")" == 1 ]] && echo 1 || echo 0)"
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
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
