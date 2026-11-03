#!/bin/zsh
##############################################################################
# test-package-managers.zsh — PAT-2018 npm global, pip user and pipx collector
# contract tests.
#
# Sources macos/lib/package_managers.sh and runs the real
# collect_package_managers against home directories and a machine root built
# in a scratch directory: several users, nvm with two Node versions, fnm,
# volta, scoped npm packages, framework and non-framework user sites, and a
# pipx venv. No root, no Node, no Python package manager and no network are
# needed, so it runs the same on a Mac and on the Linux CI runner.
#
# Also carries guards that must stay red-capable:
#   [static]  the collector executes no package manager, no runtime and no
#             process of any kind, and opens no network client
#   [drift]   the file-safety helpers are byte-identical to their twins in
#             ide_extensions.sh, here, in local_models.sh (PAT-2019) and
#             in mcp_servers.sh (PAT-2020); json_depth_ok is byte-identical
#             across local_models.sh, mcp_servers.sh and homebrew.sh (PAT-2032);
#             the walk helpers are byte-identical in homebrew.sh too (PAT-2033)
#             and in browser_extensions.sh (PAT-2054)
#   [walk]    a user's symlink on the way down is refused and never read as
#             absent; the system's own /var link is still followed (PAT-2033);
#             a link that merely looks root's is refused too, because only the
#             allowlisted /tmp, /var and /etc links are followed (PAT-2040)
#   [wire]    the package_managers block is on the wire (PAT-2225,
#             2026-09-28); setting _PACKAGE_MANAGERS_PAYLOAD_ON_WIRE back to 0
#             turns this red, and that change must update this test in the
#             same change. The off path is still exercised with the flag set
#             locally.
#   [budget]  a block over _PKG_MAX_BYTES is sent as failed, never cut down
#
# Run: zsh macos/lib/test-package-managers.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
MODULE="$SCRIPT_DIR/package_managers.sh"
SIBLING="$SCRIPT_DIR/ide_extensions.sh"
LOCAL_MODELS="$SCRIPT_DIR/local_models.sh"
MCP_SERVERS="$SCRIPT_DIR/mcp_servers.sh"
HOMEBREW="$SCRIPT_DIR/homebrew.sh"
BROWSER_EXTENSIONS="$SCRIPT_DIR/browser_extensions.sh"
COLLECT_SH="$SCRIPT_DIR/../patched-collect.sh"
PYTHON3="${PATCHED_TEST_PYTHON3:-$(command -v python3)}"
REAL_PYTHON3="$PYTHON3"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.pkg-mgr-test.XXXXXX")
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
    "$REAL_PYTHON3" -c 'import json,sys; obj=json.load(open(sys.argv[1])); P=obj.get("packages") or []; S=obj["sources"] if "sources" in obj else {}; print(eval(sys.argv[2]))' \
        "$PACKAGE_MANAGERS_JSON_TMP" "$1" 2>/dev/null
}
is_true() { [[ "$(jq_py "$1")" == "True" ]] && echo 1 || echo 0; }
status_is() { [[ "$(package_managers_collection_status)" == "$1" ]] && echo 1 || echo 0; }
src_is() { is_true "S[\"$1\"][\"collection_status\"] == \"$2\""; }

write_file() { mkdir -p "${1:h}"; print -r -- "$2" > "$1"; }

# npm_pkg <node_modules dir> <name, may be @scope/name> <version>
npm_pkg() { write_file "$1/$2/package.json" "{\"name\":\"$2\",\"version\":\"$3\",\"bin\":{\"x\":\"cli.js\"}}"; }

# dist <site-packages> <Name> <Version> — a dist-info with a long description
dist() {
    local d="$1/${2//-/_}-$3.dist-info"
    mkdir -p "$d"
    print -r -- "Metadata-Version: 2.1
Name: $2
Version: $3
Summary: fixture
Classifier: Programming Language :: Python

Long description. Name: not-a-header
Version: 9.9.9" > "$d/METADATA"
    print -r -- "pip" > "$d/INSTALLER"
}

build_tree() {
    rm -rf "$WORK/Users" "$WORK/sys"
    U="$WORK/Users"; SYS="$WORK/sys"
    mkdir -p "$U/Shared/.nvm/versions/node/v1.0.0/lib/node_modules/npm" "$U/carol/Documents"

    # Machine-wide prefixes.
    npm_pkg "$SYS/usr/local/lib/node_modules" npm 10.2.4
    npm_pkg "$SYS/usr/local/lib/node_modules" corepack 0.24.0
    mkdir -p "$SYS/usr/local/lib/node_modules/.bin"
    npm_pkg "$SYS/opt/homebrew/lib/node_modules" typescript 5.6.2
    mkdir -p "$SYS/Library/Frameworks/Python.framework/Versions/3.12/bin"
    print -r -- "" > "$SYS/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"

    # alice: nvm with two Node versions, a scoped package in each, and the
    # "current" alias pointing somewhere it must never be followed to.
    local nvm="$U/alice/.nvm/versions/node"
    npm_pkg "$nvm/v20.11.0/lib/node_modules" npm 10.2.4
    npm_pkg "$nvm/v20.11.0/lib/node_modules" @anthropic-ai/claude-code 2.0.1
    npm_pkg "$nvm/v22.3.0/lib/node_modules" npm 10.8.1
    npm_pkg "$nvm/v22.3.0/lib/node_modules" @openai/codex 0.40.0
    ln -s "$SECRET_DIR" "$U/alice/.nvm/current"
    write_file "$U/alice/.nvm/alias/default" "22"
    # alice: a framework user site (python.org 3.12) with a dist-info and an egg-info.
    local site="$U/alice/Library/Python/3.12/lib/python/site-packages"
    dist "$site" llm 0.19
    write_file "$site/oldpkg-1.0-py3.12.egg-info/PKG-INFO" "Metadata-Version: 1.1
Name: oldpkg
Version: 1.0
"
    mkdir -p "$site/llm" "$site/__pycache__"
    write_file "$site/distutils-precedence.pth" "import os"

    # bob: fnm (with an alias symlink), volta (a node image and a scoped package
    # image), a pipx venv and a non-framework user site with a pyenv interpreter.
    local fnm="$U/bob/.local/share/fnm"
    npm_pkg "$fnm/node-versions/v20.1.0/installation/lib/node_modules" npm 9.6.4
    mkdir -p "$fnm/aliases"
    ln -s "$SECRET_DIR" "$fnm/aliases/default"
    npm_pkg "$U/bob/.volta/tools/image/node/18.0.0/lib/node_modules" npm 8.6.0
    npm_pkg "$U/bob/.volta/tools/image/packages/@google/gemini-cli/lib/node_modules" @google/gemini-cli 0.5.0
    local venv="$U/bob/.local/pipx/venvs/aider-chat"
    write_file "$venv/pyvenv.cfg" "home = /opt/homebrew/opt/python@3.12/bin
include-system-site-packages = false
version = 3.12.4
executable = /opt/homebrew/Cellar/python@3.12/3.12.4/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
    dist "$venv/lib/python3.12/site-packages" aider-chat 0.80.0
    dist "$venv/lib/python3.12/site-packages" requests 2.32.0
    dist "$U/bob/.local/lib/python3.11/site-packages" httpie 3.2.2
    mkdir -p "$U/bob/.pyenv/versions/3.11.9/bin"
    print -r -- "" > "$U/bob/.pyenv/versions/3.11.9/bin/python3.11"
}

SECRET_DIR="$WORK/root-only"
mkdir -p "$SECRET_DIR/lib/node_modules/leaked-secret"
write_file "$SECRET_DIR/lib/node_modules/leaked-secret/package.json" '{"name":"leaked-secret","version":"9.9.9"}'
write_file "$SECRET_DIR/package.json" '{"name":"leaked-secret","version":"9.9.9"}'
mkdir -p "$SECRET_DIR/leaked_secret-9.9.9.dist-info"
write_file "$SECRET_DIR/leaked_secret-9.9.9.dist-info/METADATA" "Name: leaked-secret
Version: 9.9.9
"
write_file "$SECRET_DIR/METADATA" "Name: leaked-secret
Version: 9.9.9
"

run() {
    PATCHED_TMPDIR=$(mktemp -d "$WORK/run.XXXXXX")
    collect_package_managers > "$WORK/last.log" 2>&1
}

no_leak() { is_true '"leaked" not in json.dumps(obj).lower()'; }

_PKG_USERS_ROOT="$WORK/Users"
_PKG_SYSTEM_ROOT="$WORK/sys"

##############################################################################
echo "[1] every source, several users, everything readable"
build_tree
run
chk "status complete" "$(status_is complete)"
chk "every source complete" "$(src_is npm_global complete)$(src_is pip_user complete)$(src_is pipx complete)"
chk "counts: 10 npm, 3 pip_user, 2 pipx, 3 users" "$([[ "$PACKAGE_MANAGERS_NPM_COUNT/$PACKAGE_MANAGERS_PIP_COUNT/$PACKAGE_MANAGERS_PIPX_COUNT/$PACKAGE_MANAGERS_USER_COUNT" == 10/3/2/3 ]] && echo 1 || echo 0)"
chk "Shared is skipped" "$(is_true 'not any(u["user"]=="Shared" for u in obj["users"]) and "v1.0.0" not in json.dumps(obj)')"
chk "users: alice and bob complete, carol not_present" "$(is_true '[(u["user"],u["collection_status"]) for u in obj["users"]] == [("alice","complete"),("bob","complete"),("carol","not_present")]')"
chk "users: per-source status per user" "$(is_true '[u["sources"] for u in obj["users"]] == [{"npm_global":"complete","pip_user":"complete","pipx":"not_present"},{"npm_global":"complete","pip_user":"complete","pipx":"complete"},{"npm_global":"not_present","pip_user":"not_present","pipx":"not_present"}]')"
chk "user_id is the home owner's uid" "$(is_true 'all(u["user_id"] == str(__import__("os").getuid()) for u in obj["users"])')"
chk "nvm: both Node versions read, one location each" "$(is_true 'sorted((l["runtime_version"],l["package_count"]) for l in obj["locations"] if l["manager"]=="nvm") == [("20.11.0",2),("22.3.0",2)]')"
chk "nvm: scoped packages carry @scope/name, prefix and user" "$(is_true 'any(p["name"]=="@anthropic-ai/claude-code" and p["version"]=="2.0.1" and p["directory"]=="@anthropic-ai/claude-code" and p["user"]=="alice" and p["prefix"].endswith(".nvm/versions/node/v20.11.0") and p["runtime_version"]=="20.11.0" for p in P)')"
chk "nvm current alias and fnm default alias: never followed, nothing leaked, no issue" "$(no_leak)$(is_true 'obj["issues"] == []')"
chk "each nvm version read exactly once (no alias double count)" "$(is_true 'sum(1 for p in P if p["manager"]=="nvm") == 4')"
chk "fnm: installation prefix read" "$(is_true 'any(p["manager"]=="fnm" and p["name"]=="npm" and p["runtime_version"]=="20.1.0" and p["prefix"].endswith("node-versions/v20.1.0/installation") for p in P)')"
chk "volta: node image and scoped package image read" "$(is_true 'sorted(p["name"] for p in P if p["manager"]=="volta") == ["@google/gemini-cli","npm"]')"
chk "machine-wide prefixes: scope system, no user" "$(is_true 'sorted((p["manager"],p["name"]) for p in P if p["scope"]=="system") == [("homebrew","typescript"),("system","corepack"),("system","npm")] and all(p["user"] is None and p["user_id"] is None for p in P if p["scope"]=="system")')"
chk ".bin and dot entries are not packages" "$(is_true 'not any(p["directory"].startswith(".") for p in P if p["directory"])')"
L='[p for p in P if p["name"]=="llm"][0]'
chk "pip_user framework site: name, version, interpreter inferred" "$(is_true "($L)['version']=='0.19' and ($L)['manager']=='library_python' and ($L)['runtime_version']=='3.12' and ($L)['interpreter'].endswith('Python.framework/Versions/3.12/bin/python3.12') and ($L)['metadata_status']=='read' and ($L)['directory']=='llm-0.19.dist-info'")"
chk "pip_user: only the header is read (description lines ignored)" "$(is_true 'not any(p["version"]=="9.9.9" or p["name"]=="not-a-header" for p in P)')"
chk "pip_user: egg-info read from PKG-INFO" "$(is_true 'any(p["name"]=="oldpkg" and p["version"]=="1.0" for p in P)')"
chk "pip_user non-framework site: pyenv interpreter" "$(is_true 'any(p["name"]=="httpie" and p["manager"]=="local_lib" and p["interpreter"].endswith(".pyenv/versions/3.11.9/bin/python3.11") for p in P)')"
chk "pipx: every dist with app, main flag and pyvenv interpreter" "$(is_true 'sorted((p["name"],p["pipx_app"],p["pipx_main"]) for p in P if p["source"]=="pipx") == [("aider-chat","aider-chat",True),("requests","aider-chat",False)] and all(p["interpreter"].endswith("bin/python3.12") and p["runtime_version"]=="3.12.4" for p in P if p["source"]=="pipx")')"
chk "npm and pip_user rows have no pipx fields" "$(is_true 'all(p["pipx_app"] is None and p["pipx_main"] is None for p in P if p["source"]!="pipx")')"
chk "every row carries the same keys" "$(is_true 'all(list(p.keys()) == ["source","manager","scope","user","user_id","name","version","prefix","runtime_version","interpreter","directory","metadata_status","pipx_app","pipx_main"] for p in P)')"
chk "top-level keys in order" "$(is_true 'list(obj.keys()) == ["collection_status","truncated","truncation_reason","sources","users","locations","issues","packages"]')"
chk "per-source counts" "$(is_true '[(s, S[s]["package_count"], S[s]["location_count"]) for s in ("npm_global","pip_user","pipx")] == [("npm_global",10,7),("pip_user",3,2),("pipx",2,1)]')"
chk "collect log line summarises and says sent" "$(grep -q 'package_managers: status=complete npm_global=complete/10 pip_user=complete/3 pipx=complete/2 users=3 (sent)' "$WORK/last.log" && echo 1 || echo 0)"

##############################################################################
echo "[2] an unreadable or corrupt METADATA makes pip_user partial, never empty"
if (( EUID != 0 )); then
    build_tree
    chmod 000 "$U/alice/Library/Python/3.12/lib/python/site-packages/llm-0.19.dist-info/METADATA"
    run
    chmod 644 "$U/alice/Library/Python/3.12/lib/python/site-packages/llm-0.19.dist-info/METADATA"
    chk "unreadable METADATA: pip_user and block partial" "$(status_is partial)$(src_is pip_user partial)"
    chk "unreadable METADATA: still listed by directory, fields null" "$(is_true '[(p["name"],p["version"],p["metadata_status"]) for p in P if p["directory"]=="llm-0.19.dist-info"] == [(None,None,"unreadable")]')"
    chk "unreadable METADATA: issue and partial location" "$(is_true 'any(i["code"]=="metadata_unreadable" for i in obj["issues"]) and [l["collection_status"] for l in obj["locations"] if l["manager"]=="library_python"] == ["partial"]')"
    chk "unreadable METADATA: other sources unaffected" "$(src_is npm_global complete)$(src_is pipx complete)"
else
    echo "  SKIP: running as root, chmod 000 does not deny a read"
fi
build_tree
print -r -- "Metadata-Version: 2.1
Summary: no name header
" > "$U/bob/.local/lib/python3.11/site-packages/httpie-3.2.2.dist-info/METADATA"
run
chk "METADATA without Name: unparseable, partial" "$(src_is pip_user partial)$(is_true '[p["metadata_status"] for p in P if p["directory"]=="httpie-3.2.2.dist-info"] == ["unparseable"]')"
build_tree
rm -f "$U/bob/.local/lib/python3.11/site-packages/httpie-3.2.2.dist-info/METADATA"
run
chk "dist-info with no METADATA: missing, partial" "$(src_is pip_user partial)$(is_true '[p["metadata_status"] for p in P if p["directory"]=="httpie-3.2.2.dist-info"] == ["missing"]')"
build_tree
M="$U/alice/Library/Python/3.12/lib/python/site-packages/llm-0.19.dist-info/METADATA"
"$REAL_PYTHON3" -c 'import sys; open(sys.argv[1],"a").write("x" * (8 * 1024 * 1024))' "$M"
run
chk "8 MiB METADATA: header read, body never needed" "$(src_is pip_user complete)$(is_true '[p["version"] for p in P if p["name"]=="llm"] == ["0.19"]')"

##############################################################################
echo "[3] a corrupt package.json makes npm_global partial, never empty"
build_tree
print -r -- '{not json' > "$U/alice/.nvm/versions/node/v22.3.0/lib/node_modules/@openai/codex/package.json"
run
chk "status partial, npm_global partial" "$(status_is partial)$(src_is npm_global partial)"
chk "corrupt manifest: listed by directory, unparseable" "$(is_true '[(p["name"],p["metadata_status"]) for p in P if p["directory"]=="@openai/codex"] == [(None,"unparseable")]')"
chk "the rest of that prefix is kept" "$(is_true 'any(p["name"]=="npm" and p["runtime_version"]=="22.3.0" for p in P)')"
chk "user alice partial, bob complete" "$(is_true '[(u["user"],u["collection_status"]) for u in obj["users"]] == [("alice","partial"),("bob","complete"),("carol","not_present")]')"
build_tree
rm -f "$U/bob/.local/share/fnm/node-versions/v20.1.0/installation/lib/node_modules/npm/package.json"
run
chk "package directory with no package.json: missing, partial" "$(is_true '[p["metadata_status"] for p in P if p["manager"]=="fnm"] == ["missing"]')$(src_is npm_global partial)"

##############################################################################
echo "[4] symlinks, hard links and FIFOs planted by the user are never followed"
build_tree
ln -s "$SECRET_DIR" "$U/alice/.nvm/versions/node/v99.0.0"
run
chk "symlinked nvm version dir: not followed, nothing leaked" "$(no_leak)"
chk "symlinked nvm version dir: recorded, npm_global partial, real versions kept" "$(is_true 'any(i["code"]=="symlink_not_followed" and i["path"].endswith("v99.0.0") for i in obj["issues"]) and sum(1 for p in P if p["manager"]=="nvm") == 4')$(src_is npm_global partial)"

build_tree
ln -s "$SECRET_DIR/lib/node_modules/leaked-secret" "$U/alice/.nvm/versions/node/v20.11.0/lib/node_modules/linked-dev"
run
chk "npm link symlink in node_modules: recorded, not read, partial" "$(no_leak)$(is_true 'any(i["code"]=="symlink_not_followed" and i["path"].endswith("linked-dev") for i in obj["issues"])')$(src_is npm_global partial)"

build_tree
rm -rf "$U/alice/.nvm/versions/node/v20.11.0/lib/node_modules/@anthropic-ai"
ln -s "$SECRET_DIR/lib/node_modules" "$U/alice/.nvm/versions/node/v20.11.0/lib/node_modules/@anthropic-ai"
run
chk "symlinked @scope directory: not entered" "$(no_leak)$(src_is npm_global partial)"

build_tree
rm -rf "$U/bob/.local/share/fnm"
ln -s "$SECRET_DIR" "$U/bob/.local/share/fnm"
rm -rf "$U/bob/.volta"
run
chk "symlinked fnm dir as bob's only npm tree: bob's npm failed, source partial" "$(no_leak)$(src_is npm_global partial)$(is_true '[u["collection_status"] for u in obj["users"] if u["user"]=="bob"] == ["partial"]')"

build_tree
F="$U/alice/.nvm/versions/node/v20.11.0/lib/node_modules/npm/package.json"
rm -f "$F"; ln -s "$SECRET_DIR/package.json" "$F"
run
chk "symlinked package.json: refused (unreadable), not read" "$(no_leak)$(is_true '[p["metadata_status"] for p in P if p["prefix"].endswith("v20.11.0") and p["directory"]=="npm"] == ["unreadable"]')"
build_tree
rm -f "$F"; ln "$SECRET_DIR/package.json" "$F"
run
chk "hard-linked package.json: refused like a symlink" "$(no_leak)$(src_is npm_global partial)"

build_tree
M="$U/alice/Library/Python/3.12/lib/python/site-packages/llm-0.19.dist-info/METADATA"
rm -f "$M"; ln -s "$SECRET_DIR/METADATA" "$M"
run
chk "symlinked METADATA: refused, partial" "$(no_leak)$(src_is pip_user partial)"
build_tree
rm -f "$M"; ln "$SECRET_DIR/METADATA" "$M"
run
chk "hard-linked METADATA: refused, partial" "$(no_leak)$(src_is pip_user partial)"
build_tree
ln -s "$SECRET_DIR/leaked_secret-9.9.9.dist-info" "$U/alice/Library/Python/3.12/lib/python/site-packages/planted-1.0.dist-info"
run
chk "symlinked dist-info: recorded, not read" "$(no_leak)$(src_is pip_user partial)$(is_true 'any(i["code"]=="symlink_not_followed" and i["path"].endswith("planted-1.0.dist-info") for i in obj["issues"])')"
build_tree
S_DIR="$U/bob/.local/lib/python3.11/site-packages"
rm -rf "$S_DIR"; ln -s "$SECRET_DIR" "$S_DIR"
run
chk "symlinked site-packages: refused, pip_user partial" "$(no_leak)$(src_is pip_user partial)"
build_tree
ln -s "$SECRET_DIR" "$U/bob/.local/pipx/venvs/planted"
run
chk "symlinked pipx venv: recorded, not entered, pipx partial" "$(no_leak)$(src_is pipx partial)$(is_true 'any(i["code"]=="symlink_not_followed" and i["path"].endswith("planted") for i in obj["issues"])')"

build_tree
rm -rf "$U/carol"
ln -s "$U/alice" "$U/carol"
run
chk "symlinked home: user failed, alice not read twice" "$(is_true '[u["collection_status"] for u in obj["users"] if u["user"]=="carol"] == ["failed"] and not any(p["user"]=="carol" for p in P)')"

build_tree
M="$U/alice/Library/Python/3.12/lib/python/site-packages/llm-0.19.dist-info/METADATA"
rm -f "$M"; mkfifo "$M"
_pm_t0=$SECONDS
run
chk "FIFO METADATA: refused without hanging ($(( SECONDS - _pm_t0 ))s)" "$(( SECONDS - _pm_t0 <= 5 ))$(is_true '[p["metadata_status"] for p in P if p["directory"]=="llm-0.19.dist-info"] == ["unreadable"]')"

##############################################################################
echo "[5] a machine-wide prefix that is a link: covered alias costs nothing, anything else is partial"
build_tree
rm -rf "$SYS/usr/local/lib/node_modules"
ln -s "$U/alice/.nvm/versions/node/v22.3.0/lib/node_modules" "$SYS/usr/local/lib/node_modules"
run
chk "link into a version this run read: alias_not_followed, npm_global complete" "$(src_is npm_global complete)$(is_true 'any(i["code"]=="alias_not_followed" for i in obj["issues"]) and not any(p["manager"]=="system" for p in P)')"
build_tree
rm -rf "$SYS/usr/local/lib"
ln -s "$U/alice/.nvm/versions/node/v22.3.0/lib" "$SYS/usr/local/lib"
run
chk "link higher up the prefix into a read version: still covered" "$(src_is npm_global complete)"
build_tree
rm -rf "$SYS/usr/local/lib/node_modules"
ln -s "$SECRET_DIR/lib/node_modules" "$SYS/usr/local/lib/node_modules"
run
chk "link anywhere else: not followed, symlink_not_followed, partial" "$(no_leak)$(src_is npm_global partial)$(is_true 'any(i["code"]=="symlink_not_followed" and i["path"].endswith("usr/local/lib/node_modules") for i in obj["issues"])')"

##############################################################################
echo "[6] credential-shaped and control-character text never leaves the device"
build_tree
write_file "$SYS/opt/homebrew/lib/node_modules/typescript/package.json" '{"name":"typescript","version":"https://placeholder:placeholder@registry.example.invalid/5.6.2"}'
run
chk "userinfo stripped from a URL-shaped value" "$(is_true '[p["version"] for p in P if p["name"]=="typescript"] == ["https://registry.example.invalid/5.6.2"]')"
chk "no credential text anywhere in the block (raw)" "$(grep -q placeholder "$PACKAGE_MANAGERS_JSON_TMP" && echo 0 || echo 1)"
write_file "$SYS/opt/homebrew/lib/node_modules/typescript/package.json" '{"name":"typescript","version":"5.6\u001b[31m"}'
run
chk "a value with control characters is dropped, not sent" "$(is_true '[p["version"] for p in P if p["name"]=="typescript"] == [None]')"

##############################################################################
echo "[7] nothing anywhere is not_present, with an empty list"
rm -rf "$WORK/empty"; mkdir -p "$WORK/empty/Users/dave/Documents" "$WORK/empty/Users/erin/.nvm" "$WORK/empty/sys"
_PKG_USERS_ROOT="$WORK/empty/Users"; _PKG_SYSTEM_ROOT="$WORK/empty/sys"
run
chk "status not_present, every source not_present" "$(status_is not_present)$(src_is npm_global not_present)$(src_is pip_user not_present)$(src_is pipx not_present)"
chk "packages present and empty (a genuine reading)" "$(is_true 'obj["packages"] == [] and obj["locations"] == [] and [u["collection_status"] for u in obj["users"]] == ["not_present","not_present"]')"

##############################################################################
echo "[8] nothing readable is failed, with the list omitted"
build_tree
_PKG_USERS_ROOT="$WORK/does-not-exist"; _PKG_SYSTEM_ROOT="$WORK/sys"
run
chk "missing users root, machine prefixes read: npm partial, pip and pipx failed" "$(status_is partial)$(src_is npm_global partial)$(src_is pip_user failed)$(src_is pipx failed)"
chk "failed sources contribute no rows" "$(is_true 'not any(p["source"]!="npm_global" for p in P)')"
rm -rf "$SYS/usr/local/lib/node_modules" "$SYS/opt"
ln -s "$SECRET_DIR/lib/node_modules" "$SYS/usr/local/lib/node_modules"
run
chk "and a refused machine prefix: every source failed, block failed" "$(status_is failed)$(src_is npm_global failed)"
chk "failed block omits packages, never []" "$(is_true 'obj["collection_status"] == "failed" and "packages" not in obj')$(no_leak)"
build_tree
rm -rf "$U/bob" "$U/carol" "$U/alice/Library" "$SYS/usr" "$SYS/opt"
rm -rf "$U/alice/.nvm"
ln -s "$SECRET_DIR" "$U/alice/.nvm"
_PKG_USERS_ROOT="$U"
run
chk "the only user npm tree refused: that user's npm_global failed, never not_present" "$(is_true '[u["sources"] for u in obj["users"]] == [{"npm_global":"failed","pip_user":"not_present","pipx":"not_present"}]')$(no_leak)"
chk "and the source is partial (the machine-wide half was read and is absent), never not_present" "$(src_is npm_global partial)"
if (( EUID != 0 )); then
    build_tree
    chmod 000 "$U/bob/.local/pipx/venvs"
    run
    chmod 755 "$U/bob/.local/pipx/venvs"
    chk "unlistable pipx venvs dir: bob's pipx failed, source partial" "$(is_true '[u["sources"]["pipx"] for u in obj["users"]] == ["not_present","failed","not_present"]')$(src_is pipx partial)"
    rm -rf "$U/alice" "$U/carol"
    chmod 000 "$U/bob/.local/pipx/venvs"
    run
    chmod 755 "$U/bob/.local/pipx/venvs"
    chk "unlistable pipx venvs dir of the only user: pipx failed" "$(src_is pipx failed)$(status_is partial)"
else
    echo "  SKIP: running as root, chmod 000 does not deny a listing"
fi
_PKG_USERS_ROOT="$WORK/Users"; _PKG_SYSTEM_ROOT="$WORK/sys"

##############################################################################
echo "[9] bounds: packages per source and the time budget stop collection as partial"
build_tree
_PKG_MAX_PACKAGES=2
run
chk "past the package limit: every source over it partial, package_limit" "$(status_is partial)$(is_true 'obj["truncated"] is True and obj["truncation_reason"] == "package_limit" and S["npm_global"]["package_count"] == 2 and S["pip_user"]["package_count"] == 2 and S["npm_global"]["truncated"] is True')"
chk "a source under the limit stays complete" "$(src_is pipx complete)"
_PKG_MAX_PACKAGES=5000
_PKG_TIME_BUDGET_SECONDS=0
run
chk "past the time budget: partial, time_limit, no source claims complete" "$(status_is partial)$(is_true 'obj["truncation_reason"] == "time_limit" and all(S[s]["collection_status"] in ("partial","failed") for s in S)')"
_PKG_TIME_BUDGET_SECONDS=30

##############################################################################
echo "[10] a hung or crashed parser is failed, and the hang is bounded"
print -r -- '#!/bin/zsh
sleep 30' > "$WORK/slowpy"; chmod +x "$WORK/slowpy"
print -r -- '#!/bin/zsh
exit 3' > "$WORK/crashpy"; chmod +x "$WORK/crashpy"
build_tree
PYTHON3="$WORK/slowpy"; _PKG_HARD_TIMEOUT_SECONDS=1
_pm_t0=$SECONDS
run
_pm_elapsed=$(( SECONDS - _pm_t0 ))
PYTHON3="$REAL_PYTHON3"; _PKG_HARD_TIMEOUT_SECONDS=45
chk "hung parser: failed" "$(status_is failed)"
chk "hung parser: killed within the hard limit (${_pm_elapsed}s)" "$(( _pm_elapsed <= 4 ))"
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
PYTHON3="$WORK/latepy"; _PKG_HARD_TIMEOUT_SECONDS=1
run
unfunction kill
PYTHON3="$REAL_PYTHON3"; _PKG_HARD_TIMEOUT_SECONDS=45
chk "killed parser that still exits 0 with good output: failed" "$(status_is failed)"

##############################################################################
echo "[wire] the block is on the wire (PAT-2225)"
build_tree
run
chk "the wire flag is 1" "$(( _PACKAGE_MANAGERS_PAYLOAD_ON_WIRE == 1 ))"
chk "collect log line says the block is sent" "$(grep -q '^package_managers: status=complete npm_global=complete/10 pip_user=complete/3 pipx=complete/2 users=3 (sent)$' "$WORK/last.log" && echo 1 || echo 0)"
frag="{$(package_managers_payload_member) \"next\": 1}"
chk "the member is a valid payload fragment carrying the collected block" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); b=json.load(open(sys.argv[1])); print(1 if d["package_managers"]==b and d["package_managers"]["collection_status"]=="complete" and len(d["package_managers"]["packages"])==15 and d["next"]==1 else 0)' "$PACKAGE_MANAGERS_JSON_TMP" 2>/dev/null || echo 0)"
PACKAGE_MANAGERS_COLLECTION_STATUS="failed"
frag="{$(package_managers_payload_member) \"next\": 1}"
chk "a failed block is only its status" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["package_managers"]=={"collection_status":"failed"} else 0)' 2>/dev/null || echo 0)"
# The off path stays covered: with the flag at 0 nothing is emitted and the
# log line says so.
_PACKAGE_MANAGERS_PAYLOAD_ON_WIRE=0
run
chk "flag 0: a complete collection emits no payload member" "$([[ -z "$(package_managers_payload_member)" ]] && echo 1 || echo 0)"
chk "flag 0: collect log line says held off the wire" "$(grep -q '^package_managers: status=complete npm_global=complete/10 pip_user=complete/3 pipx=complete/2 users=3 (held off the wire)$' "$WORK/last.log" && echo 1 || echo 0)"
_PACKAGE_MANAGERS_PAYLOAD_ON_WIRE=1
chk "patched-collect.sh calls the member exactly once in the payload heredoc" \
    "$([[ "$(grep -c '^  \$(package_managers_payload_member)$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"
chk "patched-collect.sh names no \"package_managers\" key of its own" \
    "$(grep -q '"package_managers"' "$COLLECT_SH" && echo 0 || echo 1)"
chk "patched-collect.sh runs collect_package_managers in the daily collection" \
    "$([[ "$(grep -c '^collect_package_managers$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"

##############################################################################
echo "[budget] a block over _PKG_MAX_BYTES is sent as failed (PAT-2225)"
chk "the shipped budget is 1 MiB" "$(( _PKG_MAX_BYTES == 1048576 ))"
build_tree
run
_pm_size=$(wc -c < "$PACKAGE_MANAGERS_JSON_TMP" | tr -d ' ')
# Exactly at the budget is within it.
_PKG_MAX_BYTES=$_pm_size
run
chk "a block exactly at the budget is sent complete" "$(status_is complete)$(is_true 'len(obj["packages"]) == 15')"
_PKG_MAX_BYTES=$(( _pm_size - 1 ))
run
chk "one byte over: status failed" "$(status_is failed)"
chk "one byte over: the block file is only its status" "$(is_true 'obj == {"collection_status": "failed"}')"
frag="{$(package_managers_payload_member) \"next\": 1}"
chk "one byte over: the member sends only the failed status" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["package_managers"]=={"collection_status":"failed"} else 0)' 2>/dev/null || echo 0)"
chk "one byte over: WARN names the size and the budget" "$(grep -q "^WARN: package_managers: block is $_pm_size bytes, over the $(( _pm_size - 1 ))-byte budget; sent as failed$" "$WORK/last.log" && echo 1 || echo 0)"
chk "one byte over: the log line says failed" "$(grep -q '^package_managers: status=failed npm_global=complete/10 pip_user=complete/3 pipx=complete/2 users=3 (sent)$' "$WORK/last.log" && echo 1 || echo 0)"
_PKG_MAX_BYTES=junk
run
chk "an unusable budget fails closed" "$(status_is failed)"
_PKG_MAX_BYTES=$(( 1024 * 1024 ))

##############################################################################
echo "[volta-names] a Volta package directory is entered only under a name an npm package can have (PAT-2033)"
build_tree
VP="$U/bob/.volta/tools/image/packages"
npm_pkg "$VP/JSONStream/lib/node_modules" JSONStream 1.3.5
npm_pkg "$VP/has space/lib/node_modules" leaked-volta-space 1.0.0
npm_pkg "$VP/semi;colon/lib/node_modules" leaked-volta-semi 1.0.0
npm_pkg "$VP/@bad scope/child/lib/node_modules" leaked-volta-scope 1.0.0
npm_pkg "$VP/@google/bad*child/lib/node_modules" leaked-volta-child 1.0.0
run
chk "valid names still read, a legacy capitalised one included" \
    "$(is_true 'sorted(p["name"] for p in P if p["manager"]=="volta") == ["@google/gemini-cli","JSONStream","npm"]')"
chk "no directory with an impossible name is entered" "$(no_leak)"
chk "each one is recorded as name_unsafe and npm_global is partial" \
    "$(is_true 'sorted(i["path"].split("/packages/")[1] for i in obj["issues"] if i["code"]=="name_unsafe") == ["@bad scope","@google/bad*child","has space","semi;colon"]')$(src_is npm_global partial)"

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
RACE_DIR="$U/alice/Library/Python/3.12/lib/python/site-packages"
race_run "$RACE_DIR" "$SECRET_DIR"
chk "the site-packages directory was swapped between its check and the read" "$(swapped "$RACE_DIR")"
chk "nothing was read through the swapped-in link" "$(no_leak)"
chk "the refusal is recorded: pip_user is partial, never complete" "$(src_is pip_user partial)"

##############################################################################
echo "[framework-link] Homebrew's own Versions/<X.Y> link is read as text, never walked through (PAT-2033)"
build_tree
HBF="$SYS/opt/homebrew/Frameworks/Python.framework/Versions"
KEG="$SYS/opt/homebrew/Cellar/python@3.13/3.13.1/Frameworks/Python.framework/Versions/3.13"
mkdir -p "$KEG/bin" "$HBF"; print -r -- "" > "$KEG/bin/python3.13"
ln -s ../../../Cellar/python@3.13/3.13.1/Frameworks/Python.framework/Versions/3.13 "$HBF/3.13"
dist "$U/alice/Library/Python/3.13/lib/python/site-packages" rich 13.9.4
run
chk "the interpreter behind the link is found and reported at the link's own path" \
    "$(is_true "[p['interpreter'] for p in P if p['name']=='rich'] == ['$HBF/3.13/bin/python3.13']")"

echo "[framework-escape] a Versions/<X.Y> link out of the prefix's Cellar answers nothing about its target (PAT-2040)"
build_tree
HBF="$SYS/opt/homebrew/Frameworks/Python.framework/Versions"
LFW="$SYS/Library/Frameworks/Python.framework/Versions"
mkdir -p "$HBF" "$SECRET_DIR/bin" "$SYS/opt/homebrew/Cellar"
print -r -- "" > "$SECRET_DIR/bin/python3.14"; print -r -- "" > "$SECRET_DIR/bin/python3.15"
print -r -- "" > "$SECRET_DIR/bin/python3.16"
# Absolute out of the Cellar; relative, through the Cellar and back out; and a
# link where Homebrew never makes one (python.org's own framework directory).
ln -s "$SECRET_DIR" "$HBF/3.14"
ln -s "../../../Cellar/../../../../root-only" "$HBF/3.15"
ln -s "$SECRET_DIR" "$LFW/3.16"
dist "$U/alice/Library/Python/3.14/lib/python/site-packages" probe14 1.0
dist "$U/alice/Library/Python/3.15/lib/python/site-packages" probe15 1.0
dist "$U/alice/Library/Python/3.16/lib/python/site-packages" probe16 1.0
run
chk "the escaping links' targets are never reported as interpreters" \
    "$(is_true "sorted((p['name'], p['interpreter']) for p in P if p['name'].startswith('probe')) == [('probe14', None), ('probe15', None), ('probe16', None)]")"
chk "the escape test really points at the secret tree" \
    "$([[ "${$(cd "$HBF/3.15" && pwd -P)}" == "${SECRET_DIR:A}" ]] && echo 1 || echo 0)"

##############################################################################
echo "[static] no package manager, runtime or other process is executed; no network client"
SHELL_PART="$WORK/shell-part"; PY_PART="$WORK/py-part"
awk '/<<.PYEOF.( &)?$/{print; inpy=1; next} /^PYEOF$/{inpy=0} !inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$SHELL_PART"
awk '/<<.PYEOF.( &)?$/{inpy=1; next} /^PYEOF$/{inpy=0} inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$PY_PART"
chk "extracted a non-trivial python part" "$(( $(wc -l < "$PY_PART") > 300 ))"
chk "extracted a non-trivial shell part" "$(( $(wc -l < "$SHELL_PART") > 40 ))"
# Every command word the shell part could run a package manager or runtime
# with, anywhere on a line (so a pipe, $( ), backtick or && cannot hide one).
hits=$(grep -nE '(^|[;&|(`{[:space:]]|\$\()(npm|npx|pnpm|yarn|corepack|node|nodejs|nvm|fnm|volta|pip|pip3|pipx|python|python3|uv|uvx|pyenv|conda|brew|curl|wget|nc|ncat|ssh|scp|sftp|rsync|git|open|osascript|nscurl|launchctl|sudo|su|env|exec|eval|xargs)([[:space:];|&)]|$)|/dev/(tcp|udp)' "$SHELL_PART")
chk "shell part runs no package manager, runtime, network client or opener" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
# The only interpreter the shell part starts is the collector's own parser
# (the reviewed "$PYTHON3" - heredoc) plus the same one-line json.load check
# the sibling collectors use to validate the parser's output.
chk "the only \$PYTHON3 launches are the parser and the output check" \
    "$([[ "$(grep -c '"\$PYTHON3"' "$SHELL_PART")" == 2 && "$(grep -c '"\$PYTHON3" - ' "$SHELL_PART")" == 1 && "$(grep -c "\"\$PYTHON3\" -c 'import json,sys; json.load(open(sys.argv\[1\]))'" "$SHELL_PART")" == 1 ]] && echo 1 || echo 0)"
hits=$(grep -nE '^[[:space:]]*(import|from)[[:space:]]' "$PY_PART" \
    | grep -vE '^[0-9]+:import (errno|json|os|re|stat|sys|time)$')
chk "python imports only the reviewed modules" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE '__import__|importlib|subprocess|multiprocessing|socket|urllib|http\.client|requests|ftplib|ctypes|runpy|os\.(system|popen|exec|spawn|fork|posix_spawn|kill|startfile)|(^|[^.A-Za-z_])(eval|exec|compile)\(|https?://' "$PY_PART")
chk "python launches no process, opens no socket, names no URL" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE 'O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)|\b(unlink|remove|rename|replace|rmdir|mkdir|makedirs|chmod|chown|symlink|utime)\(' "$PY_PART" | grep -v 'CANON_RE.sub\|USERINFO_RE.sub')
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
chk "no path is resolved through links (no realpath, no stat that follows)" "$(grep -qE 'realpath|os\.stat\(|os\.path\.(exists|isdir|isfile)\(|follow_symlinks=True' "$PY_PART" && echo 0 || echo 1)"

##############################################################################
echo "[drift] the file-safety helpers match ide_extensions.sh exactly, here, in local_models.sh, mcp_servers.sh, homebrew.sh and browser_extensions.sh"
# py_def <module> <name>: the named top-level def (or assignment) from the
# module's parser, up to the next top-level statement.
py_def() {
    awk -v name="$2" '
        /<<.PYEOF.( &)?$/ { inpy = 1; next }
        /^PYEOF$/ { inpy = 0 }
        !inpy { next }
        grab && /^[^ \t]/ && $0 !~ /^$/ { grab = 0 }
        $0 ~ ("^def " name "\\(") || $0 ~ ("^class " name "\\(") || $0 ~ ("^" name " = ") { grab = 1 }
        grab { print }
    ' "$1" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
}
# The walk helpers (PAT-2033) are shared with homebrew.sh and
# browser_extensions.sh (PAT-2054) too; their text helpers are their own, so
# clean_path, USERINFO_RE and clean_text are not.
WALK_HELPERS=(DIR_FLAGS FILE_FLAGS MAX_LINK_HOPS SYSTEM_LINKS LinkRefused open_parent lstat_at read_link open_dir
    open_regular_errno open_regular read_file_errno read_file lstat_kind kind list_dir)
for fn in clean_path USERINFO_RE clean_text $WALK_HELPERS; do
    a=$(py_def "$MODULE" "$fn"); b=$(py_def "$SIBLING" "$fn"); c=$(py_def "$LOCAL_MODELS" "$fn")
    d=$(py_def "$MCP_SERVERS" "$fn")
    if (( ${WALK_HELPERS[(Ie)$fn]} )); then
        e=$(py_def "$HOMEBREW" "$fn")
        chk "$fn in homebrew.sh is identical to ide_extensions.sh" \
            "$([[ -n "$e" && "$e" == "$b" ]] && echo 1 || echo 0)"
        f=$(py_def "$BROWSER_EXTENSIONS" "$fn")
        chk "$fn in browser_extensions.sh is identical to ide_extensions.sh" \
            "$([[ -n "$f" && "$f" == "$b" ]] && echo 1 || echo 0)"
    fi
    chk "$fn is identical to ide_extensions.sh ($(print -r -- "$a" | wc -l | tr -d ' ') lines)" \
        "$([[ -n "$a" && "$a" == "$b" ]] && echo 1 || echo 0)"
    chk "$fn in local_models.sh is identical to ide_extensions.sh" \
        "$([[ -n "$c" && "$c" == "$b" ]] && echo 1 || echo 0)"
    chk "$fn in mcp_servers.sh is identical to ide_extensions.sh" \
        "$([[ -n "$d" && "$d" == "$b" ]] && echo 1 || echo 0)"
done
echo "[walk] the shared walk refuses a user's symlink on the way down and never calls it absent (PAT-2033)"
rm -rf "$WORK/walk"
WALK_OUT=$("$REAL_PYTHON3" - "$MODULE" "$WORK/walk" <<'WALKEOF'
import os, stat, sys
src = open(sys.argv[1]).read()
start = src.index("DIR_FLAGS = "); end = src.index("# --- end of the verbatim copy")
class Abort(Exception):
    pass
ns = {"os": os, "stat": stat, "Abort": Abort}
exec(src[start:end], ns)
kind, read_file, list_dir = ns["kind"], ns["read_file"], ns["list_dir"]
base = sys.argv[2]
os.makedirs(base + "/real/sub")
with open(base + "/real/sub/f", "w") as f:
    f.write("x")
os.symlink(base + "/real", base + "/link")
out = [kind(base + "/real/sub/f"), kind(base + "/link/sub/f"), read_file(base + "/link/sub/f", 10)[0],
       kind(base + "/link"), kind(base + "/nope/f"), kind(base + "/real/sub/f/x")]
try:
    list_dir(base + "/link/sub")
    out.append("listed")
except Abort:
    out.append("abort")
# macOS's /var is root's own link in root's own directory, so the walk follows
# it. Elsewhere there is no such link to test and the row says so.
out.append(kind(base[len("/private"):] + "/real/sub/f") if base.startswith("/private/var/") else "file")
# PAT-2040: owner and mode bits are not the rule, because a macOS ACL can let
# a user replace a link that root owns in a directory only root can write. So
# the same user link, made to look root's in a root-only directory, is still
# refused: only /tmp, /var and /etc right under / are ever followed.
real_os = os
def as_root(st, mode):
    return real_os.stat_result((mode, st.st_ino, st.st_dev, st.st_nlink, 0, 0, st.st_size,
                                st.st_atime, st.st_mtime, st.st_ctime))
class RootLooking:
    def __getattr__(self, name):
        return getattr(real_os, name)
    def lstat(self, *args, **kwargs):
        st = real_os.lstat(*args, **kwargs)
        return as_root(st, st.st_mode) if stat.S_ISLNK(st.st_mode) else st
    def fstat(self, fd):
        st = real_os.fstat(fd)
        return as_root(st, st.st_mode & ~0o022) if stat.S_ISDIR(st.st_mode) else st
ns_root = {"os": RootLooking(), "stat": stat, "Abort": Abort}
exec(src[start:end], ns_root)
out.append(ns_root["kind"](base + "/link/sub/f"))
out.append(ns_root["read_file"](base + "/link/sub/f", 10)[0])
print(" ".join(out))
WALKEOF
)
WALK_WANT="file error unreadable symlink absent absent abort file error unreadable"
chk "real path is a file; through a user's symlink it is error (never absent) and unreadable" \
    "$([[ "$WALK_OUT" == "$WALK_WANT" ]] && echo 1 || echo 0)"
[[ "$WALK_OUT" == "$WALK_WANT" ]] || print -r -- "  got: $WALK_OUT"
# The JSON nesting cap has no copy in ide_extensions.sh; local_models.sh is
# the reference for it (PAT-2032).
a=$(py_def "$LOCAL_MODELS" json_depth_ok)
for twin in "$MCP_SERVERS" "$HOMEBREW"; do
    b=$(py_def "$twin" json_depth_ok)
    chk "json_depth_ok in ${twin:t} is identical to local_models.sh ($(print -r -- "$a" | wc -l | tr -d ' ') lines)" \
        "$([[ -n "$a" && "$a" == "$b" ]] && echo 1 || echo 0)"
done

##############################################################################
echo "[tcc] a folder macOS privacy protection denies is tcc_denied, never complete, and an agent_health entry (PAT-2100)"
source "$SCRIPT_DIR/tcc-deny-hook.zsh"
export PATCHED_AGENT_HEALTH_STORE="$AH_STORE"
TCC_KEY='"tcc_denied|package_managers"'
TCC_WARN='WARN: package_managers: macOS privacy protection denied access to'
has_issue() { is_true "any(i[\"code\"]==\"$1\" and i[\"path\"].endswith(\"$2\") for i in obj[\"issues\"])"; }
# carol_tcc_tree: carol gets fnm and pipx under ~/Library/Application Support.
CAROL_FNM="$U/carol/Library/Application Support/fnm"
CAROL_PIPX="$U/carol/Library/Application Support/pipx"
carol_tcc_tree() {
    npm_pkg "$CAROL_FNM/node-versions/v22.0.0/installation/lib/node_modules" npm 10.5.0
    write_file "$CAROL_PIPX/venvs/httpie/pyvenv.cfg" "version = 3.12.4
executable = /usr/bin/python3"
    dist "$CAROL_PIPX/venvs/httpie/lib/python3.12/site-packages" httpie 3.2.2
}

build_tree; carol_tcc_tree
run
chk "set up: carol's fnm and pipx are read when nothing is denied" \
    "$(status_is complete)$(is_true 'any(p["user"]=="carol" and p["manager"]=="fnm" for p in P) and any(p["user"]=="carol" and p["source"]=="pipx" for p in P)')"
rm -rf "$WORK/agent-health"
deny_run "$EPERM" "$CAROL_FNM" "$CAROL_PIPX"
chk "EPERM: the hook really denied the opens (so the test can fail)" "$(hook_fired)"
chk "carol's fnm and pipx folders are tcc_denied, not unreadable" \
    "$(has_issue tcc_denied "Application Support/fnm/node-versions")$(has_issue tcc_denied "Application Support/pipx/venvs")$(is_true 'not any(i["code"]=="unreadable" for i in obj["issues"])')"
chk "carol's npm_global and pipx are failed, never not_present or complete" \
    "$(is_true '[u["sources"] for u in obj["users"] if u["user"]=="carol"] == [{"npm_global":"failed","pip_user":"not_present","pipx":"failed"}]')"
chk "nothing of carol's is listed, everyone else's still is" \
    "$(is_true 'not any(p["user"]=="carol" for p in P) and sum(1 for p in P if p["user"]=="bob" and p["source"]=="pipx") == 2')"
chk "the sources and the block are partial, never complete" "$(src_is npm_global partial)$(src_is pipx partial)$(status_is partial)"
chk "the collect log says so, with a count and why" \
    "$(grep -qF "$TCC_WARN 2 folder(s) or file(s) (Full Disk Access is not granted to the Patched collector)" "$WORK/last.log" && echo 1 || echo 0)"
chk "without agent_health.sh loaded the collector writes no store" "$(store_absent)"

build_tree; carol_tcc_tree
deny_run "$EPERM" "$U/carol/Library/Application Support"
chk "one denied folder above fnm and pipx counts once" \
    "$(hook_fired)$(is_true 'sum(1 for i in obj["issues"] if i["code"]=="tcc_denied") == 2')$(grep -qF "$TCC_WARN 1 folder(s) or file(s)" "$WORK/last.log" && echo 1 || echo 0)"

source "$SCRIPT_DIR/agent_health.sh"
# The entry is the LaunchDaemon run's alone (parent PID 1); these tests run
# under another parent, so they stand in for launchd until the manual case.
_PATCHED_TCC_HEALTH_PPID=1
build_tree; carol_tcc_tree
deny_run "$EPERM" "$CAROL_PIPX"
chk "the daemon run records tcc_denied / package_managers / full_disk_access_missing" \
    "$(hook_fired)$(ah_true "active[$TCC_KEY][\"reason\"] == \"full_disk_access_missing\" and active[$TCC_KEY][\"count\"] == 1")"
deny_run "$EACCES" "$CAROL_PIPX"
chk "EACCES is unreadable, no privacy wording, and no opinion on the entry" \
    "$(hook_fired)$(has_issue unreadable "Application Support/pipx/venvs")$(is_true 'not any(i["code"]=="tcc_denied" for i in obj["issues"])')$(grep -qF "$TCC_WARN" "$WORK/last.log" && echo 0 || echo 1)$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
_PATCHED_TCC_HEALTH_PPID=4242
run
chk "a clean manual run leaves the daemon's entry, and says why" \
    "$(ah_true "active[$TCC_KEY][\"count\"] == 1")$(grep -q 'package_managers: not the LaunchDaemon run (parent 4242)' "$WORK/last.log" && echo 1 || echo 0)"
_PATCHED_TCC_HEALTH_PPID=1
_PKG_MAX_PACKAGES=2
run
_PKG_MAX_PACKAGES=5000
chk "a truncated walk is no opinion" "$(is_true 'obj["truncated"] is True')$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
run
chk "a full clean daemon run clears it, and the ledger says it once worked" \
    "$(status_is complete)$(ah_true "$TCC_KEY not in active and ever.get($TCC_KEY) is True")"
unset _PATCHED_TCC_HEALTH_PPID PATCHED_AGENT_HEALTH_STORE

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
