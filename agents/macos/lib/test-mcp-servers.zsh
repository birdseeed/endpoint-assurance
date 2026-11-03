#!/bin/zsh
##############################################################################
# test-mcp-servers.zsh — PAT-2020 MCP server configuration collector
# contract tests.
#
# Sources macos/lib/mcp_servers.sh and runs the real collect_mcp_servers
# against home directories built in a scratch directory, one config file per
# client format: Claude Desktop, Cursor, VS Code mcp.json and settings.json
# (JSONC), Windsurf and Claude Code's ~/.claude.json. No root, no client and
# no network are needed, so it runs the same on a Mac and on the Linux CI
# runner.
#
# Secrets: every value a config may carry that must never leave the device
# (env, arguments, headers, URL userinfo, path and query, other keys in the
# file, files beside it) is planted as a PLACEHOLDER or "leaked" marker, and
# every case checks that neither appears in the block or the collect log. The
# ticket's secret cases each have their own section: [S1] env, [S2] arguments,
# [S3] headers, [S4] URL query and userinfo, [S5] an internal hostname in an
# argument against one in a URL, [S6] an unrecognised package candidate.
#
# Also carries guards that must stay red-capable:
#   [static]   the collector runs no process, opens no network client
#   [privacy]  it opens only the six named config files, and its server model
#              can emit only the allowed keys
#   [wire]     the mcp_servers block is on the wire (PAT-2225, 2026-09-28);
#              setting _MCP_SERVERS_PAYLOAD_ON_WIRE back to 0 turns this red,
#              and that change must update this test in the same change. The
#              off path is still exercised with the flag set locally.
#   [budget]   a block over _MCP_MAX_BYTES is sent as failed, never cut down
#   The helper drift check lives in test-package-managers.zsh [drift].
#
# Run: zsh macos/lib/test-mcp-servers.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
MODULE="$SCRIPT_DIR/mcp_servers.sh"
COLLECT_SH="$SCRIPT_DIR/../patched-collect.sh"
PYTHON3="${PATCHED_TEST_PYTHON3:-$(command -v python3)}"
REAL_PYTHON3="$PYTHON3"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.mcp-servers-test.XXXXXX")
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
# S is the servers list, C the per-client summary, F the config rows.
jq_py() {
    "$REAL_PYTHON3" -c 'import json,sys; obj=json.load(open(sys.argv[1])); S=obj.get("servers") or []; C=obj.get("clients") or {}; F=obj.get("configs") or []; by=lambda n: [s for s in S if s["name"]==n]; one=lambda n: by(n)[0] if len(by(n))==1 else {}; print(eval(sys.argv[2]))' \
        "$MCP_SERVERS_JSON_TMP" "$1" 2>/dev/null
}
is_true() { [[ "$(jq_py "$1")" == "True" ]] && echo 1 || echo 0; }
status_is() { [[ "$(mcp_servers_collection_status)" == "$1" ]] && echo 1 || echo 0; }
cl_is() { is_true "C[\"$1\"][\"collection_status\"] == \"$2\""; }
# ucl <user> <client> <status>: that user's status for that client.
ucl() { is_true "[u[\"clients\"][\"$2\"] for u in obj[\"users\"] if u[\"user\"]==\"$1\"] == [\"$3\"]"; }
has_issue() { is_true "any(i[\"code\"]==\"$1\" and i[\"path\"].endswith(\"$2\") for i in obj[\"issues\"])"; }
# absent <text>: 1 when text appears neither in the block file nor the collect log.
absent() {
    { grep -qiF -- "$1" "$MCP_SERVERS_JSON_TMP" || grep -qiF -- "$1" "$WORK/last.log"; } && echo 0 || echo 1
}
no_leak() { echo "$(absent leaked)$(absent PLACEHOLDER)"; }

write_file() { mkdir -p "${1:h}"; print -r -- "$2" > "$1"; }

APPSUP="Library/Application Support"
CD_REL="$APPSUP/Claude/claude_desktop_config.json"
CUR_REL=".cursor/mcp.json"
VSM_REL="$APPSUP/Code/User/mcp.json"
VSS_REL="$APPSUP/Code/User/settings.json"
WS_REL=".codeium/windsurf/mcp_config.json"
CC_REL=".claude.json"

build_tree() {
    rm -rf "$WORK/Users"
    U="$WORK/Users"
    mkdir -p "$U/Shared" "$U/dave/Documents"

    # alice: Claude Desktop (stdio: npx, docker, a uvx by full path) and Cursor
    # (a remote server whose URL and headers carry credentials).
    write_file "$U/alice/$CD_REL" '{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/leaked-dir"]},
    "github": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server:latest", "--leaked-flag"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "PLACEHOLDER_DESKTOP_ENV"}},
    "git": {"command": "/opt/homebrew/leaked-bin/uvx", "args": ["mcp-server-git@0.6.2", "--repository", "/Users/alice/leaked-repo"]}
  },
  "globalShortcut": "leaked-other-key"
}'
    write_file "$U/alice/$CUR_REL" '{"mcpServers": {"remote": {"url": "https://mcp.example.com/sse", "headers": {"X-Leaked": "PLACEHOLDER_CURSOR_HEADER"}}}}'

    # bob: VS Code mcp.json and settings.json, both JSONC (comments, trailing
    # commas), and Windsurf.
    write_file "$U/bob/$VSM_REL" '// user-level MCP servers, leaked comment
{
  "servers": {
    /* a block comment, leaked */
    "playwright": {"type": "stdio", "command": "npx", "args": ["@playwright/mcp@latest",],},
    "context7": {"type": "http", "url": "https://mcp.context7.com/mcp", "headers": {"leaked": "x"}},
  },
  "inputs": [{"id": "leaked-input", "type": "promptString", "password": true},],
}'
    write_file "$U/bob/$VSS_REL" '{
  // editor settings the collector never keeps
  "editor.fontSize": 14,
  "leaked.setting": "https://leaked.example.org/a//b",
  "mcp": {
    "servers": {
      "legacy-sse": {"type": "sse", "url": "http://legacy.example.org:9000/sse"},
    },
  },
}'
    write_file "$U/bob/$WS_REL" '{"mcpServers": {
  "brave-search": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-brave-search"], "env": {"BRAVE_API_KEY": "PLACEHOLDER_WINDSURF_ENV"}},
  "remote-w": {"serverUrl": "https://windsurf.example.net/mcp/leaked-path"}
}}'

    # carol: Claude Code's ~/.claude.json, user scope and a project's local
    # scope, beside the account, history and other keys it must never keep,
    # and ~/.claude/settings.json, which it must never open.
    write_file "$U/carol/$CC_REL" '{
  "numStartups": 12,
  "oauthAccount": {"emailAddress": "leaked@example.com"},
  "mcpServers": {"sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"}},
  "projects": {
    "/Users/carol/leaked-project": {
      "history": [{"display": "leaked prompt"}],
      "mcpServers": {"time": {"type": "stdio", "command": "pipx", "args": ["run", "--spec", "mcp-server-time", "mcp-server-time"], "env": {}}}
    },
    "/Users/carol/leaked-empty-project": {"allowedTools": []}
  }
}'
    write_file "$U/carol/.claude/settings.json" '{"mcpServers": {"leaked-never-read": {"command": "npx", "args": ["leaked"]}}}'
}

run() {
    PATCHED_TMPDIR=$(mktemp -d "$WORK/run.XXXXXX")
    collect_mcp_servers > "$WORK/last.log" 2>&1
}

# plant <user> <relative config path> <json>: replace one config file.
plant() { write_file "$U/$1/$2" "$3"; }

_MCP_USERS_ROOT="$WORK/Users"

ROW_KEYS='["client","user","user_id","config_path","scope","name","transport","transport_source","executable","runner","package","package_status","host"]'

##############################################################################
echo "[1] one config per client format, every user"
build_tree
run
chk "status complete" "$(status_is complete)"
chk "every client complete" "$(cl_is claude_desktop complete)$(cl_is cursor complete)$(cl_is vscode complete)$(cl_is windsurf complete)$(cl_is claude_code complete)"
chk "nothing it must not keep left the parser (env, args, headers, paths, other keys, other files)" "$(no_leak)"
chk "counts: 11 servers, 6 configs, 4 users" "$([[ "$MCP_SERVERS_SERVER_COUNT/$MCP_SERVERS_CONFIG_COUNT/$MCP_SERVERS_USER_COUNT" == 11/6/4 ]] && echo 1 || echo 0)"
chk "Shared is skipped; dave has nothing and is not_present" "$(is_true '[u["user"] for u in obj["users"]] == ["alice","bob","carol","dave"] and obj["users"][3]["collection_status"] == "not_present"')"
chk "every server row carries exactly the allowed keys" "$(is_true "all(list(s.keys()) == $ROW_KEYS for s in S)")"
chk "config rows and top-level keys" "$(is_true 'all(list(f.keys()) == ["client","user","user_id","path","collection_status","server_count"] for f in F) and list(obj.keys()) == ["collection_status","truncated","truncation_reason","clients","totals","users","configs","issues","servers"]')"
chk "no issues on a clean estate" "$(is_true 'obj["issues"] == []')"
chk "claude_desktop: npx package, stdio inferred" "$(is_true '(one("filesystem")["client"],one("filesystem")["transport"],one("filesystem")["transport_source"],one("filesystem")["executable"],one("filesystem")["runner"],one("filesystem")["package"],one("filesystem")["package_status"],one("filesystem")["host"]) == ("claude_desktop","stdio","inferred","npx","npx","@modelcontextprotocol/server-filesystem","extracted",None)')"
chk "claude_desktop: docker image after its flags and -e value, tag dropped" "$(is_true '(one("github")["runner"],one("github")["package"]) == ("docker","ghcr.io/github/github-mcp-server")')"
chk "claude_desktop: executable is the basename, uvx version stripped" "$(is_true '(one("git")["executable"],one("git")["package"]) == ("uvx","mcp-server-git")')"
chk "cursor: url with no type is http inferred, host only" "$(is_true '(one("remote")["client"],one("remote")["transport"],one("remote")["transport_source"],one("remote")["host"],one("remote")["executable"],one("remote")["package_status"]) == ("cursor","http","inferred","mcp.example.com",None,"not_applicable")')"
chk "vscode mcp.json (JSONC): stdio declared, npx package with @latest stripped" "$(is_true '(one("playwright")["client"],one("playwright")["transport_source"],one("playwright")["package"]) == ("vscode","declared","@playwright/mcp")')"
chk "vscode mcp.json: http declared, host" "$(is_true '(one("context7")["transport"],one("context7")["host"]) == ("http","mcp.context7.com")')"
chk "vscode settings.json (JSONC) mcp.servers: sse declared, host without port" "$(is_true '(one("legacy-sse")["client"],one("legacy-sse")["transport"],one("legacy-sse")["host"]) == ("vscode","sse","legacy.example.org")')"
chk "windsurf: npx package, and serverUrl host with the path dropped" "$(is_true '(one("brave-search")["package"],one("remote-w")["client"],one("remote-w")["host"]) == ("@modelcontextprotocol/server-brave-search","windsurf","windsurf.example.net")')"
chk "claude_code: user scope from the top level" "$(is_true '(one("sentry")["client"],one("sentry")["scope"],one("sentry")["host"]) == ("claude_code","user","mcp.sentry.dev")')"
chk "claude_code: project scope, pipx --spec package, no project directory" "$(is_true '(one("time")["scope"],one("time")["runner"],one("time")["package"]) == ("project","pipx","mcp-server-time")')"
chk "~/.claude/settings.json is never read" "$(is_true 'by("leaked-never-read") == [] and not any("settings.json" in f["path"] and "/.claude/" in f["path"] for f in F)')"
chk "per-client summary" "$(is_true '[(c, C[c]["config_count"], C[c]["server_count"]) for c in ("claude_desktop","cursor","vscode","windsurf","claude_code")] == [("claude_desktop",1,3),("cursor",1,1),("vscode",2,3),("windsurf",1,2),("claude_code",1,2)]')"
chk "user_id is the home owner's uid" "$(is_true 'all(u["user_id"] == str(__import__("os").getuid()) for u in obj["users"])')"
chk "collect log line: counts and statuses only, says sent" "$(grep -q 'mcp_servers: status=complete claude_desktop=complete cursor=complete vscode=complete windsurf=complete claude_code=complete configs=6 servers=11 users=4 (sent)' "$WORK/last.log" && echo 1 || echo 0)"
chk "collect log names no server" "$(grep -qE 'filesystem|github|playwright|sentry' "$WORK/last.log" && echo 0 || echo 1)"

##############################################################################
echo "[S1] a token in env never leaves the device"
build_tree
plant alice "$CUR_REL" '{"mcpServers": {"envcase": {"command": "npx", "args": ["-y", "@acme/mcp"], "env": {"API_KEY": "PLACEHOLDER_ENV_SECRET", "OTHER": "PLACEHOLDER_ENV_SECRET_2"}}}}'
run
chk "env token absent from block and log" "$(absent PLACEHOLDER_ENV_SECRET)$(no_leak)"
chk "the server is still reported" "$(is_true '(one("envcase")["package"],one("envcase")["package_status"]) == ("@acme/mcp","extracted")')$(cl_is cursor complete)"

##############################################################################
echo "[S2] a token in an argument never leaves the device"
build_tree
plant alice "$CUR_REL" '{"mcpServers": {
  "argeq": {"command": "npx", "args": ["-y", "@acme/mcp", "--api-key=PLACEHOLDER_ARG_EQ"]},
  "argsp": {"command": "npx", "args": ["-y", "@acme/mcp", "--token", "PLACEHOLDER_ARG_SPACE"]},
  "argfirst": {"command": "npx", "args": ["--token", "PLACEHOLDER_ARG_FIRST", "@acme/mcp"]},
  "argeqfirst": {"command": "npx", "args": ["--api-key=PLACEHOLDER_ARG_EQ_FIRST", "@acme/mcp"]},
  "pyword": {"command": "uvx", "args": ["--api-key", "placeholder-token-value", "mcp-x"]},
  "oneline": {"command": "npx -y @acme/mcp --token PLACEHOLDER_IN_COMMAND"}
}}'
run
chk "--api-key=SECRET after the package: absent, package kept" "$(absent PLACEHOLDER_ARG_EQ)$(is_true 'one("argeq")["package"] == "@acme/mcp"')"
chk "--token SECRET after the package: absent, package kept" "$(absent PLACEHOLDER_ARG_SPACE)$(is_true 'one("argsp")["package"] == "@acme/mcp"')"
chk "--token SECRET before the package: the value is the candidate, fails the pattern, dropped" "$(absent PLACEHOLDER_ARG_FIRST)$(is_true '(one("argfirst")["package"],one("argfirst")["package_status"]) == (None,"unrecognised")')"
chk "--api-key=SECRET before the package: self-contained flag skipped, package kept" "$(absent PLACEHOLDER_ARG_EQ_FIRST)$(is_true 'one("argeqfirst")["package"] == "@acme/mcp"')"
chk "a lowercase secret that fits the PyPI pattern is dropped by the credential-word check" "$(absent placeholder-token-value)$(is_true 'one("pyword")["package_status"] == "unrecognised"')"
chk "a whole command line in command: executable unrecognised, nothing kept" "$(absent PLACEHOLDER_IN_COMMAND)$(is_true '(one("oneline")["executable"],one("oneline")["package"]) == (None,None)')$(has_issue executable_unrecognised .cursor/mcp.json)"
chk "no argument text anywhere" "$(no_leak)"

##############################################################################
echo "[S3] a token in http headers never leaves the device"
build_tree
plant alice "$CUR_REL" '{"mcpServers": {"hdr": {"type": "http", "url": "https://api.example.com/mcp", "headers": {"Authorization": "Bearer PLACEHOLDER_HEADER_SECRET", "X-Api-Key": "PLACEHOLDER_HEADER_SECRET_2"}}}}'
run
chk "header token absent from block and log" "$(absent PLACEHOLDER_HEADER_SECRET)$(absent Authorization)$(no_leak)"
chk "host kept" "$(is_true 'one("hdr")["host"] == "api.example.com"')"

##############################################################################
echo "[S4] a token in the URL query or userinfo never leaves the device"
build_tree
plant alice "$CUR_REL" '{"mcpServers": {
  "query": {"url": "https://q.example.com/sse?token=PLACEHOLDER_QUERY_SECRET&x=1#PLACEHOLDER_FRAGMENT"},
  "userinfo": {"url": "https://PLACEHOLDER_USER:PLACEHOLDER_PASS@u.example.com:8443/leaked-path"},
  "atinpath": {"url": "https://p.example.com/PLACEHOLDER_PATH@q"},
  "atinpass": {"url": "https://user:PLACEHOLDER@SECRET@host.example/path?x=PLACEHOLDER_TOKEN_VALUE"}
}}'
run
chk "query and fragment absent, host kept" "$(absent PLACEHOLDER_QUERY_SECRET)$(absent PLACEHOLDER_FRAGMENT)$(is_true 'one("query")["host"] == "q.example.com"')"
chk "userinfo and port absent, host kept" "$(absent PLACEHOLDER_USER)$(absent PLACEHOLDER_PASS)$(absent 8443)$(is_true 'one("userinfo")["host"] == "u.example.com"')"
chk "an @ in the path is not taken for userinfo" "$(is_true 'one("atinpath")["host"] == "p.example.com"')$(no_leak)"
chk "an @ inside the password: host only, userinfo cut at the last @" "$(is_true 'one("atinpass")["host"] == "host.example"')$(absent SECRET@)$(absent PLACEHOLDER_TOKEN_VALUE)$(no_leak)"
# clean_text (the drift-guarded helper every collector shares) cuts userinfo at
# the last @ before the host, so a password containing @ leaves nothing behind.
CT_OUT=$("$REAL_PYTHON3" -c '
import re, sys
src = open(sys.argv[1]).read()
start = src.index("def clean_path"); end = src.index("DIR_FLAGS = ")
ns = {"re": re, "TEXT_CAP": 512}
exec(src[start:end], ns)
print(ns["clean_text"]("see https://user:PLACEHOLDER@SECRET@host.example/p and ftp://a@b@c.example"))' "$MODULE")
chk "clean_text strips userinfo up to the last @" "$([[ "$CT_OUT" == "see https://host.example/p and ftp://c.example" ]] && echo 1 || echo 0)"

##############################################################################
echo "[S5] an internal hostname in an argument is dropped; a URL's host is kept"
build_tree
plant alice "$CUR_REL" '{"mcpServers": {
  "bridge": {"command": "npx", "args": ["-y", "mcp-remote", "https://argonly.corp.example/sse", "--header", "Authorization: Bearer PLACEHOLDER_BRIDGE"]},
  "direct": {"url": "https://urlhost.corp.example/sse"},
  "private-image": {"command": "docker", "args": ["run", "-i", "--rm", "registry.argimage.corp.example/team/mcp:1.0"]}
}}'
run
chk "argument hostname absent; the runner package is kept" "$(absent argonly.corp.example)$(absent PLACEHOLDER_BRIDGE)$(is_true 'one("bridge")["package"] == "mcp-remote" and one("bridge")["host"] is None')"
chk "URL host kept" "$(is_true 'one("direct")["host"] == "urlhost.corp.example"')"
chk "an image from a private registry is dropped, its hostname absent" "$(absent argimage.corp.example)$(is_true 'one("private-image")["package_status"] == "unrecognised"')"

##############################################################################
echo "[S6] an unrecognised package candidate is dropped and recorded, never sent"
build_tree
plant alice "$CUR_REL" '{"mcpServers": {
  "path": {"command": "npx", "args": ["-y", "./leaked-local-dir/server"]},
  "url": {"command": "npx", "args": ["https://leaked.example.com/pkg.tgz"]},
  "upper": {"command": "npx", "args": ["-y", "LEAKED_UPPER"]},
  "eq": {"command": "uvx", "args": ["leaked-pkg==1.0"]},
  "shape": {"command": "npx", "args": ["sk-abcdefghijklmnopqrstuvwxyz0123456789"]},
  "jwt": {"command": "npx", "args": ["eyjhbg-x"]},
  "jwtshort": {"command": "npx", "args": ["eyJhbGc"]},
  "newline": {"command": "npx", "args": ["acme-pkg\n"]},
  "noarg": {"command": "npx", "args": ["-y"]},
  "notrunner": {"command": "node", "args": ["/Users/alice/leaked-server.js"]},
  "compose": {"command": "docker", "args": ["compose", "up"]}
}}'
run
chk "a path, a URL, uppercase, ==, a key-shaped value and a trailing newline: unrecognised, not sent" "$(no_leak)$(absent sk-abc)$(is_true 'all((one(n)["package"],one(n)["package_status"]) == (None,"unrecognised") for n in ("path","url","upper","eq","shape","newline","jwtshort"))')"
chk "recorded as package_unrecognised against the config file, value-free" "$(has_issue package_unrecognised .cursor/mcp.json)$(is_true 'sum(1 for i in obj["issues"] if i["code"]=="package_unrecognised") == 7')"
chk "a lowercase eyj name is not a JWT and is kept" "$(is_true 'one("jwt")["package"] == "eyjhbg-x"')"
chk "a runner with no candidate is missing; a plain executable is not_applicable" "$(is_true 'one("noarg")["package_status"] == "missing" and (one("notrunner")["executable"],one("notrunner")["runner"],one("notrunner")["package_status"]) == ("node",None,"not_applicable")')"
chk "docker without run is not a package invocation" "$(is_true 'one("compose")["package_status"] == "not_applicable"')"
chk "the client is still complete: dropping a value is not a failed read" "$(cl_is cursor complete)"

##############################################################################
echo "[7] runner forms"
build_tree
plant alice "$CUR_REL" '{"mcpServers": {
  "npmx": {"command": "npm", "args": ["exec", "--yes", "--package=@acme/tool", "--", "tool"]},
  "npmx2": {"command": "npm", "args": ["x", "--", "@acme/other@2"]},
  "bun": {"command": "bunx", "args": ["@acme/bun-mcp"]},
  "pnpm": {"command": "pnpm", "args": ["dlx", "acme-mcp"]},
  "uvtool": {"command": "uv", "args": ["tool", "run", "--python", "3.12", "acme-py"]},
  "uvfrom": {"command": "uvx", "args": ["--from", "acme-pkg", "acme-cmd"]},
  "uvrun": {"command": "uv", "args": ["run", "leaked-script.py"]},
  "win": {"command": "C:\\Program Files\\nodejs\\npx.cmd", "args": ["-y", "@acme/win"]},
  "wrapped": {"command": "cmd", "args": ["/c", "npx", "-y", "@acme/wrapped"]},
  "dock": {"command": "docker", "args": ["run", "-it", "--rm", "--name", "leaked-name", "-v", "/Users/alice/leaked:/data", "--env=A=PLACEHOLDER_D", "mcp/fetch@sha256:0000000000000000000000000000000000000000000000000000000000000000"]},
  "weird": {"type": "ws", "url": "wss://ws.example.com/x"},
  "notobj": "leaked-string-entry"
}}'
run
chk "npm exec --package= and npm x --" "$(is_true '(one("npmx")["package"],one("npmx2")["package"]) == ("@acme/tool","@acme/other")')"
chk "bunx, pnpm dlx" "$(is_true '(one("bun")["package"],one("pnpm")["package"]) == ("@acme/bun-mcp","acme-mcp")')"
chk "uv tool run skips --python's value; uvx --from names the package" "$(is_true '(one("uvtool")["package"],one("uvfrom")["package"]) == ("acme-py","acme-pkg")')"
chk "uv run is not a package runner invocation" "$(is_true 'one("uvrun")["package_status"] == "not_applicable"')"
chk "a Windows path: basename kept, .cmd runner recognised" "$(is_true '(one("win")["executable"],one("win")["runner"],one("win")["package"]) == ("npx.cmd","npx","@acme/win")')"
chk "cmd /c npx: the wrapped runner and package" "$(is_true '(one("wrapped")["executable"],one("wrapped")["runner"],one("wrapped")["package"]) == ("cmd","npx","@acme/wrapped")')"
chk "docker: -it, --name and -v values, --env= skipped; digest dropped" "$(is_true 'one("dock")["package"] == "mcp/fetch"')$(no_leak)"
chk "an unknown declared type is unknown; a wss host is kept" "$(is_true '(one("weird")["transport"],one("weird")["transport_source"],one("weird")["host"]) == ("unknown","declared","ws.example.com")')"
chk "an entry that is not an object: reported without a transport, config partial" "$(is_true '(one("notobj")["transport"],one("notobj")["executable"]) == ("unknown",None)')$(has_issue server_unparseable .cursor/mcp.json)$(cl_is cursor partial)"

build_tree
plant alice "$CUR_REL" '{"mcpServers": {"sk-abcdefghijklmnopqrstuvwxyz0123456789": {"command": "npx"}, "https://leaked.example.com": {"command": "npx"}}}'
run
chk "a secret-shaped or URL server name is dropped, the server still counted" "$(absent sk-abc)$(no_leak)$(is_true 'len(S) == 12 and sum(1 for s in S if s["name"] is None) == 2')$(has_issue name_unsafe .cursor/mcp.json)"

build_tree
"$REAL_PYTHON3" -c 'import json,sys; p={"/leaked/p%d" % i: {} for i in range(1000)}; p["/leaked/last"]={"mcpServers":{"beyond":{"command":"npx"}}}; json.dump({"mcpServers":{"top":{"command":"npx"}},"projects":p}, open(sys.argv[1],"w"))' "$U/carol/$CC_REL"
run
chk "past 1,000 Claude Code projects: the rest not read, project_limit, claude_code partial" "$(is_true 'by("beyond") == [] and len(by("top")) == 1')$(has_issue project_limit .claude.json)$(cl_is claude_code partial)$(no_leak)"

##############################################################################
echo "[8] an unparseable or unreadable config is partial or failed, never empty"
build_tree
print -r -- '{"mcpServers": {"x": {"command": "npx", "env": {"K": "PLACEHOLDER_BROKEN"}}' > "$U/alice/$CUR_REL"
run
chk "truncated JSON: unparseable, alice's cursor failed (its only file), value absent" "$(has_issue unparseable .cursor/mcp.json)$(ucl alice cursor failed)$(cl_is cursor partial)$(absent PLACEHOLDER_BROKEN)$(is_true '[f["collection_status"] for f in F if f["client"]=="cursor"] == ["failed"]')"
chk "the block is partial, not failed; alice's cursor failed" "$(status_is partial)$(is_true '[u["clients"]["cursor"] for u in obj["users"] if u["user"]=="alice"] == ["failed"]')"
build_tree
print -r -- '/* unterminated' > "$U/bob/$VSS_REL"
run
chk "an unterminated JSONC comment: settings.json unparseable, vscode partial (mcp.json read)" "$(has_issue unparseable Code/User/settings.json)$(cl_is vscode partial)"
build_tree
print -r -- '{"mcpServers": ["leaked"]}' > "$U/alice/$CUR_REL"
run
chk "mcpServers that is not an object: unparseable" "$(has_issue unparseable .cursor/mcp.json)$(ucl alice cursor failed)"
build_tree
print -r -- '{"mcp": "leaked"}' > "$U/bob/$VSS_REL"
run
chk "settings.json mcp that is not an object: unparseable" "$(has_issue unparseable Code/User/settings.json)"
build_tree
print -r -- '{"editor.fontSize": 12}' > "$U/bob/$VSS_REL"
run
chk "settings.json with no mcp key: complete, zero servers from it" "$(cl_is vscode complete)$(is_true '[(f["collection_status"],f["server_count"]) for f in F if f["path"].endswith("settings.json")] == [("complete",0)]')"
for _mcp_depth in 65 200000; do
    build_tree
    "$REAL_PYTHON3" -c 'import sys; d=int(sys.argv[2]); open(sys.argv[1],"w").write("{\"mcpServers\":{},\"x\":" + "["*d + "]"*d + "}")' "$U/alice/$CUR_REL" "$(( _mcp_depth - 1 ))"
    run
    chk "a config nested $_mcp_depth deep: unparseable, the rest read, block partial" "$(has_issue unparseable .cursor/mcp.json)$(cl_is claude_desktop complete)$(status_is partial)"
done
build_tree
print -r -- '{"mcpServers": {"x": {"command": "npx", "args": ["// not a comment", "/* nor this */"]}}, "u": "http://a.example/b//c",}' > "$U/alice/$CUR_REL"
run
chk "comment markers inside strings are text, not comments" "$(cl_is cursor complete)$(is_true 'one("x")["package_status"] == "unrecognised"')"
if (( EUID != 0 )); then
    build_tree
    chmod 000 "$U/alice/$CUR_REL"
    run
    chmod 644 "$U/alice/$CUR_REL"
    chk "unreadable config: alice's cursor failed, recorded" "$(ucl alice cursor failed)$(has_issue unreadable .cursor/mcp.json)"
else
    echo "  SKIP: running as root, chmod 000 does not deny a read"
fi

##############################################################################
echo "[9] links are not followed; oversize, hard-linked and FIFO files are refused"
SECRET_DIR="$WORK/root-only"
write_file "$SECRET_DIR/mcp.json" '{"mcpServers": {"leaked-through-link": {"command": "npx", "env": {"K": "PLACEHOLDER_LINKED"}}}}'
mkdir -p "$SECRET_DIR/cursor-dir"; cp "$SECRET_DIR/mcp.json" "$SECRET_DIR/cursor-dir/mcp.json"
build_tree
rm -f "$U/alice/$CUR_REL"; ln -s "$SECRET_DIR/mcp.json" "$U/alice/$CUR_REL"
run
chk "symlinked config file: not read, recorded, alice's cursor partial" "$(no_leak)$(has_issue symlink_not_followed .cursor/mcp.json)$(cl_is cursor partial)$(is_true 'not any(f["client"]=="cursor" for f in F)')"
build_tree
rm -rf "$U/alice/.cursor"; ln -s "$SECRET_DIR/cursor-dir" "$U/alice/.cursor"
run
chk "symlinked config directory: not entered" "$(no_leak)$(has_issue symlink_not_followed alice/.cursor)$(cl_is cursor partial)"
build_tree
rm -f "$U/alice/$CUR_REL"; ln "$SECRET_DIR/mcp.json" "$U/alice/$CUR_REL"
run
chk "hard-linked config: refused like a symlink" "$(no_leak)$(has_issue unreadable .cursor/mcp.json)$(ucl alice cursor failed)"
build_tree
rm -rf "$U/carol"; ln -s "$U/alice" "$U/carol"
run
chk "symlinked home: user failed, alice not read twice" "$(is_true '[u["collection_status"] for u in obj["users"] if u["user"]=="carol"] == ["failed"] and not any(s["user"]=="carol" for s in S)')"
build_tree
"$REAL_PYTHON3" -c 'import sys; open(sys.argv[1],"w").write("{\"mcpServers\":{}, \"pad\":\"" + "x"*(1024*1024) + "\"}")' "$U/alice/$CUR_REL"
run
chk "a config over its size cap is refused, alice's cursor failed" "$(has_issue unreadable .cursor/mcp.json)$(ucl alice cursor failed)"
build_tree
rm -f "$U/alice/$CUR_REL"; mkfifo "$U/alice/$CUR_REL"
_mcp_t0=$SECONDS
run
chk "FIFO config: refused without hanging ($(( SECONDS - _mcp_t0 ))s)" "$(( SECONDS - _mcp_t0 <= 5 ))$(has_issue not_regular .cursor/mcp.json)$(ucl alice cursor failed)"

##############################################################################
echo "[10] nothing present is not_present; nothing readable is failed, with servers omitted"
rm -rf "$WORK/empty"; mkdir -p "$WORK/empty/erin/Documents" "$WORK/empty/frank/.cursor"
_MCP_USERS_ROOT="$WORK/empty"
run
chk "no config anywhere: not_present, every client not_present, servers []" "$(status_is not_present)$(cl_is cursor not_present)$(cl_is claude_code not_present)$(is_true 'obj["servers"] == [] and F == []')"
_MCP_USERS_ROOT="$WORK/does-not-exist"
run
chk "missing users root: failed, servers omitted, never []" "$(status_is failed)$(is_true 'obj["collection_status"] == "failed" and "servers" not in obj')"
_MCP_USERS_ROOT="$WORK/Users"

##############################################################################
echo "[11] bounds: servers and the time budget stop collection as partial"
build_tree
_MCP_MAX_SERVERS=2
run
chk "past the server limit: partial, server_limit, exactly 2 servers" "$(status_is partial)$(is_true 'obj["truncated"] is True and obj["truncation_reason"] == "server_limit" and len(S) == 2')"
_MCP_MAX_SERVERS=2000
_MCP_TIME_BUDGET_SECONDS=0
run
chk "past the time budget: partial, time_limit, no client claims complete" "$(status_is partial)$(is_true 'obj["truncation_reason"] == "time_limit" and all(C[c]["collection_status"] in ("partial","failed") for c in C)')"
_MCP_TIME_BUDGET_SECONDS=30

##############################################################################
echo "[12] a hung or crashed parser is failed, bounded, and its stderr is never logged"
print -r -- '#!/bin/zsh
sleep 30' > "$WORK/slowpy"; chmod +x "$WORK/slowpy"
print -r -- '#!/bin/zsh
echo "Traceback: PLACEHOLDER_STDERR_SECRET" >&2
exit 3' > "$WORK/crashpy"; chmod +x "$WORK/crashpy"
build_tree
PYTHON3="$WORK/slowpy"; _MCP_HARD_TIMEOUT_SECONDS=1
_mcp_t0=$SECONDS
run
_mcp_elapsed=$(( SECONDS - _mcp_t0 ))
PYTHON3="$REAL_PYTHON3"; _MCP_HARD_TIMEOUT_SECONDS=45
chk "hung parser: failed, killed within the hard limit (${_mcp_elapsed}s)" "$(status_is failed)$(( _mcp_elapsed <= 4 ))"
chk "hung parser: stub block says failed" "$(is_true 'obj == {"collection_status": "failed"}')"
PYTHON3="$WORK/crashpy"
run
PYTHON3="$REAL_PYTHON3"
chk "crashed parser: failed, and what it printed is not in the log" "$(status_is failed)$(absent PLACEHOLDER_STDERR_SECRET)"
# A parser the loop gave up on is failed even when wait then reports a clean
# exit (PAT-2033). kill -9 is made a no-op, as when the parser finishes in the
# moment between the last check and the kill, and the parser exits 0 with good
# output after the limit.
print -r -- "#!/bin/zsh
\"$REAL_PYTHON3\" \"\$@\"; _rc=\$?; sleep 2; exit \$_rc" > "$WORK/latepy"; chmod +x "$WORK/latepy"
kill() { [[ "$1" == -9 ]] && return 0; builtin kill "$@"; }
PYTHON3="$WORK/latepy"; _MCP_HARD_TIMEOUT_SECONDS=1
run
unfunction kill
PYTHON3="$REAL_PYTHON3"; _MCP_HARD_TIMEOUT_SECONDS=45
chk "killed parser that still exits 0 with good output: failed" "$(status_is failed)"

##############################################################################
echo "[wire] the block is on the wire (PAT-2225)"
build_tree
run
chk "the wire flag is 1" "$(( _MCP_SERVERS_PAYLOAD_ON_WIRE == 1 ))"
chk "collect log line says the block is sent" "$(grep -q '^mcp_servers: status=complete claude_desktop=complete cursor=complete vscode=complete windsurf=complete claude_code=complete configs=6 servers=11 users=4 (sent)$' "$WORK/last.log" && echo 1 || echo 0)"
frag="{$(mcp_servers_payload_member) \"next\": 1}"
chk "the member is a valid payload fragment carrying the collected block, without a secret" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; t=sys.stdin.read(); d=json.loads(t); b=json.load(open(sys.argv[1])); print(1 if d["mcp_servers"]==b and d["mcp_servers"]["collection_status"]=="complete" and len(d["mcp_servers"]["servers"])==11 and d["next"]==1 and "PLACEHOLDER" not in t and "leaked" not in t else 0)' "$MCP_SERVERS_JSON_TMP" 2>/dev/null || echo 0)"
chk "every sent server row has only the contract keys" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); ok={"client","user","user_id","config_path","scope","name","transport","transport_source","executable","runner","package","package_status","host"}; print(1 if d["mcp_servers"]["servers"] and all(set(s)==ok for s in d["mcp_servers"]["servers"]) else 0)' 2>/dev/null || echo 0)"
MCP_SERVERS_COLLECTION_STATUS="failed"
frag="{$(mcp_servers_payload_member) \"next\": 1}"
chk "a failed block is only its status" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["mcp_servers"]=={"collection_status":"failed"} else 0)' 2>/dev/null || echo 0)"
# The off path stays covered: with the flag at 0 nothing is emitted and the
# log line says so.
_MCP_SERVERS_PAYLOAD_ON_WIRE=0
run
chk "flag 0: a complete collection emits no payload member" "$([[ -z "$(mcp_servers_payload_member)" ]] && echo 1 || echo 0)"
chk "flag 0: collect log line says held off the wire" "$(grep -q '^mcp_servers: status=complete claude_desktop=complete cursor=complete vscode=complete windsurf=complete claude_code=complete configs=6 servers=11 users=4 (held off the wire)$' "$WORK/last.log" && echo 1 || echo 0)"
_MCP_SERVERS_PAYLOAD_ON_WIRE=1
chk "patched-collect.sh calls the member exactly once in the payload heredoc" \
    "$([[ "$(grep -c '^  \$(mcp_servers_payload_member)$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"
chk "patched-collect.sh names no \"mcp_servers\" key of its own" \
    "$(grep -q '"mcp_servers"' "$COLLECT_SH" && echo 0 || echo 1)"
chk "patched-collect.sh runs collect_mcp_servers in the daily collection" \
    "$([[ "$(grep -c '^collect_mcp_servers$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"

##############################################################################
echo "[budget] a block over _MCP_MAX_BYTES is sent as failed (PAT-2225)"
chk "the shipped budget is 256 KiB" "$(( _MCP_MAX_BYTES == 262144 ))"
build_tree
run
_mcp_size=$(wc -c < "$MCP_SERVERS_JSON_TMP" | tr -d ' ')
# Exactly at the budget is within it.
_MCP_MAX_BYTES=$_mcp_size
run
chk "a block exactly at the budget is sent complete" "$(status_is complete)$(is_true 'len(S) == 11')"
_MCP_MAX_BYTES=$(( _mcp_size - 1 ))
run
chk "one byte over: status failed" "$(status_is failed)"
chk "one byte over: the block file is only its status" "$(is_true 'obj == {"collection_status": "failed"}')"
frag="{$(mcp_servers_payload_member) \"next\": 1}"
chk "one byte over: the member sends only the failed status" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["mcp_servers"]=={"collection_status":"failed"} else 0)' 2>/dev/null || echo 0)"
chk "one byte over: WARN names the size and the budget" "$(grep -q "^WARN: mcp_servers: block is $_mcp_size bytes, over the $(( _mcp_size - 1 ))-byte budget; sent as failed$" "$WORK/last.log" && echo 1 || echo 0)"
chk "one byte over: the log line says failed" "$(grep -q '^mcp_servers: status=failed claude_desktop=complete cursor=complete vscode=complete windsurf=complete claude_code=complete configs=6 servers=11 users=4 (sent)$' "$WORK/last.log" && echo 1 || echo 0)"
_MCP_MAX_BYTES=junk
run
chk "an unusable budget fails closed" "$(status_is failed)"
_MCP_MAX_BYTES=$(( 256 * 1024 ))

##############################################################################
echo "[ipv6-host] a bracketed host is kept only when it is an IPv6 literal (PAT-2033)"
build_tree
plant alice "$CUR_REL" '{"mcpServers": {
  "hexhost": {"url": "http://[0123456789abcdef0123456789abcdef01234567]/"},
  "v6": {"url": "http://[fe80::1]:8080/mcp"}
}}'
run
chk "a colon-less bracketed host is dropped, never sent as the host" \
    "$(is_true 'one("hexhost") != {} and one("hexhost")["host"] is None')$(absent 0123456789abcdef0123456789abcdef01234567)"
chk "a real IPv6 literal is still kept" "$(is_true 'one("v6")["host"] == "fe80::1"')"
chk "the block is not failed by it" "$(is_true 'obj["collection_status"] != "failed" and C["cursor"]["collection_status"] == "complete"')"

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
write_file "$RACE_DECOY/mcp.json" '{"mcpServers": {"leaked-server": {"command": "npx", "args": ["-y", "leaked-package"]}}}'
RACE_DIR="$U/alice/.cursor"
race_run "$RACE_DIR" "$RACE_DECOY"
chk "the .cursor directory was swapped between its check and the read" "$(swapped "$RACE_DIR")"
chk "mcp.json was not read through the swapped-in link" "$(absent leaked)"
chk "the refusal is recorded: cursor is not complete" "$(is_true 'C["cursor"]["collection_status"] != "complete"')"

##############################################################################
echo "[static] no process is executed; no network client"
SHELL_PART="$WORK/shell-part"; PY_PART="$WORK/py-part"
awk '/<<.PYEOF.( &)?$/{print; inpy=1; next} /^PYEOF$/{inpy=0} !inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$SHELL_PART"
awk '/<<.PYEOF.( &)?$/{inpy=1; next} /^PYEOF$/{inpy=0} inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$PY_PART"
chk "extracted a non-trivial python part" "$(( $(wc -l < "$PY_PART") > 400 ))"
chk "extracted a non-trivial shell part" "$(( $(wc -l < "$SHELL_PART") > 40 ))"
hits=$(grep -nE '(^|[;&|(`{[:space:]]|\$\()(npx|npm|uvx|uv|pipx|bunx|pnpm|yarn|docker|podman|node|claude|cursor|code|windsurf|curl|wget|nc|ncat|ssh|scp|sftp|rsync|git|open|osascript|nscurl|launchctl|sudo|su|env|exec|eval|xargs|python|python3)([[:space:];|&)]|$)|/dev/(tcp|udp)' "$SHELL_PART")
chk "shell part runs no runner, client, network client or opener" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
chk "the only \$PYTHON3 launches are the parser and the output check" \
    "$([[ "$(grep -c '"\$PYTHON3"' "$SHELL_PART")" == 2 && "$(grep -c '"\$PYTHON3" - ' "$SHELL_PART")" == 1 && "$(grep -c "\"\$PYTHON3\" -c 'import json,sys; json.load(open(sys.argv\[1\]))'" "$SHELL_PART")" == 1 ]] && echo 1 || echo 0)"
chk "parser stderr is never logged" "$(grep -qE 'cat[^|]*_mcp_err|head[^|]*_mcp_err|< *"\$_mcp_err"' "$SHELL_PART" && echo 0 || echo 1)"
hits=$(grep -nE '^[[:space:]]*(import|from)[[:space:]]' "$PY_PART" \
    | grep -vE '^[0-9]+:import (errno|json|os|re|stat|sys|time)$')
chk "python imports only the reviewed modules" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE '__import__|importlib|subprocess|multiprocessing|socket|urllib|http\.client|requests|ftplib|ctypes|runpy|os\.(system|popen|exec|spawn|fork|posix_spawn|kill|startfile|environ|getenv)|(^|[^.A-Za-z_])(eval|exec|compile)\(|https?://' "$PY_PART")
chk "python launches no process, opens no socket, reads no environment, names no URL" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE 'O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)|\b(unlink|remove|rename|replace|rmdir|mkdir|makedirs|chmod|chown|symlink|utime)\(' "$PY_PART" | grep -v 'USERINFO_RE.sub')
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
chk "no path is resolved through links (no realpath, no stat that follows)" "$(grep -qE 'realpath|os\.stat\(|os\.path\.(exists|isdir|isfile|getsize)\(|follow_symlinks=True' "$PY_PART" && echo 0 || echo 1)"

##############################################################################
echo "[privacy] only the six config files are opened, and a server row holds only the allowed keys"
# PAT-2096: the shared helpers gained errno-carrying twins. open_regular_errno
# is reached only from read_file_errno (and the open_regular wrapper, which
# nothing here calls). PAT-2100: the one read is read_file_errno, for the
# errno that tells a privacy denial apart; the read_file wrapper is unused.
chk "open_regular is called only inside read_file_errno" \
    "$([[ "$(grep -cE '(^|[^_A-Za-z])open_regular\(' "$PY_PART")" == 1 && "$(grep -cE 'open_regular_errno\(' "$PY_PART")" == 3 && "$(grep -cE 'read_file_errno\(' "$PY_PART")" == 3 ]] && echo 1 || echo 0)"
chk "the file read has exactly one call site, over the CONFIGS table" "$([[ "$(grep -cE '(^|[^_A-Za-z])read_file\(' "$PY_PART")" == 1 && "$(grep -c 'status, data, err_no = read_file_errno(path, cap)' "$PY_PART")" == 1 ]] && echo 1 || echo 0)"
chk "the CONFIGS table names exactly the six files" "$([[ "$(grep -cE '^    \("(claude_desktop|cursor|vscode|windsurf|claude_code)", ' "$PY_PART")" == 6 ]] && echo 1 || echo 0)"
chk "~/.claude/settings.json is not named" "$(grep -qE '"\.claude", *"settings' "$PY_PART" && echo 0 || echo 1)"
hits=$(grep -niE 'history|conversation|prompt|oauth|credential[s]?\.json|\.env\b|keychain|\.sqlite|\.db\b' "$PY_PART" | grep -v 'SECRET_WORD_RE')
chk "python names no history, conversation, prompt, account or credential store" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
# The server model reads exactly these keys of an entry, and nothing reads
# "env" or "headers" at all.
chk "summarise_server reads only type, command, args, url and serverUrl" "$([[ "$(grep -oE 'entry\.get\("[A-Za-z]+"\)' "$PY_PART" | sort -u | tr '\n' ' ')" == 'entry.get("args") entry.get("command") entry.get("serverUrl") entry.get("type") entry.get("url") ' ]] && echo 1 || echo 0)"
chk "nothing reads env or headers" "$(grep -qE '"(env|headers|envFile|inputs)"' "$PY_PART" && echo 0 || echo 1)"

# Red-capability of the leak checks: a block that did copy an argument must
# fail them, so the absence checks above can go red.
print -r -- '{"servers": [{"name": "x", "args": ["--token", "PLACEHOLDER_SELF_TEST"]}]}' > "$WORK/leak-selftest.json"
MCP_SERVERS_JSON_TMP_SAVED="$MCP_SERVERS_JSON_TMP"; MCP_SERVERS_JSON_TMP="$WORK/leak-selftest.json"
chk "the absence check catches a planted leak (self-test)" "$([[ "$(absent PLACEHOLDER_SELF_TEST)" == 0 ]] && echo 1 || echo 0)"
MCP_SERVERS_JSON_TMP="$MCP_SERVERS_JSON_TMP_SAVED"

##############################################################################
echo "[tcc] a folder macOS privacy protection denies is tcc_denied, never complete, and an agent_health entry (PAT-2100)"
source "$SCRIPT_DIR/tcc-deny-hook.zsh"
export PATCHED_AGENT_HEALTH_STORE="$AH_STORE"
TCC_KEY='"tcc_denied|mcp_servers"'
TCC_WARN='WARN: mcp_servers: macOS privacy protection denied access to'
ALICE_CLAUDE="$U/alice/$APPSUP/Claude"
BOB_CODE_USER="$U/bob/$APPSUP/Code/User"

build_tree
rm -rf "$WORK/agent-health"
deny_run "$EPERM" "$ALICE_CLAUDE" "$BOB_CODE_USER"
chk "EPERM: the hook really denied the opens (so the test can fail)" "$(hook_fired)"
chk "the denied configs are tcc_denied, not unreadable" \
    "$(has_issue tcc_denied "Claude/claude_desktop_config.json")$(has_issue tcc_denied "Code/User/mcp.json")$(has_issue tcc_denied "Code/User/settings.json")$(is_true 'not any(i["code"]=="unreadable" for i in obj["issues"])')"
chk "a denied client is failed for that user, never not_present or complete" \
    "$(ucl alice claude_desktop failed)$(ucl bob vscode failed)"
chk "the rest is still read, and the block is partial, never complete" \
    "$(ucl alice cursor complete)$(ucl bob windsurf complete)$(status_is partial)$(cl_is claude_desktop partial)$(cl_is vscode partial)"
chk "the collect log says so, counting each denied folder once (Claude, and Code/User for its two files)" \
    "$(grep -qF "$TCC_WARN 2 folder(s) or file(s) (Full Disk Access is not granted to the Patched collector)" "$WORK/last.log" && echo 1 || echo 0)"
chk "nothing leaks from a denied run" "$(no_leak)"
chk "without agent_health.sh loaded the collector writes no store" "$(store_absent)"

build_tree
plant bob "$CD_REL" '{"mcpServers": {"x": {"command": "npx", "args": ["some-pkg"]}}}'
deny_run "$EPERM" "$U/bob/$APPSUP"
chk "one denied folder above several clients' configs counts once" \
    "$(hook_fired)$(ucl bob claude_desktop failed)$(ucl bob vscode failed)$(is_true 'sum(1 for i in obj["issues"] if i["code"]=="tcc_denied") == 3')$(grep -qF "$TCC_WARN 1 folder(s) or file(s)" "$WORK/last.log" && echo 1 || echo 0)"

echo "  -- patched_tcc_summary finds the tcc line by prefix; anything else is no opinion"
ts_is() { print -r -- "$1" > "$WORK/summary"; [[ "$(patched_tcc_summary "$WORK/summary")" == "$2" ]] && echo 1 || echo 0; }
chk "the parser's own two lines" "$(ts_is $'complete 1 2 3\ntcc 2 denied' '2 denied')"
chk "an extra line before it does not shift it" "$(ts_is $'noise line\ncomplete 1 2 3\ntcc 0 reached' '0 reached')"
chk "missing, garbled, a bad verdict or count, or two tcc lines: 0 unknown" \
    "$(ts_is 'complete 1 2 3' '0 unknown')$(ts_is $'complete\ntcc two denied' '0 unknown')$(ts_is $'complete\ntcc 1 cleared' '0 unknown')$(ts_is $'complete\ntcc 1 denied extra' '0 unknown')$(ts_is $'tcc 1 denied\ntcc 0 reached' '0 unknown')$(ts_is '' '0 unknown')"
chk "a missing summary file is 0 unknown" "$([[ "$(patched_tcc_summary "$WORK/no-such-summary")" == "0 unknown" ]] && echo 1 || echo 0)"

source "$SCRIPT_DIR/agent_health.sh"
# The entry is the LaunchDaemon run's alone (parent PID 1); these tests run
# under another parent, so they stand in for launchd until the manual case.
_PATCHED_TCC_HEALTH_PPID=1
build_tree
deny_run "$EPERM" "$ALICE_CLAUDE"
chk "the daemon run records tcc_denied / mcp_servers / full_disk_access_missing" \
    "$(hook_fired)$(ah_true "active[$TCC_KEY][\"reason\"] == \"full_disk_access_missing\" and active[$TCC_KEY][\"count\"] == 1")"
deny_run "$EACCES" "$ALICE_CLAUDE"
chk "EACCES is unreadable, no privacy wording, and no opinion on the entry" \
    "$(hook_fired)$(has_issue unreadable "Claude/claude_desktop_config.json")$(is_true 'not any(i["code"]=="tcc_denied" for i in obj["issues"])')$(grep -qF "$TCC_WARN" "$WORK/last.log" && echo 0 || echo 1)$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
_PATCHED_TCC_HEALTH_PPID=4242
run
chk "a clean manual run leaves the daemon's entry, and says why" \
    "$(ah_true "active[$TCC_KEY][\"count\"] == 1")$(grep -q 'mcp_servers: not the LaunchDaemon run (parent 4242)' "$WORK/last.log" && echo 1 || echo 0)"
_PATCHED_TCC_HEALTH_PPID=1
_MCP_USERS_ROOT="$WORK/no-such-users"
run
_MCP_USERS_ROOT="$WORK/Users"
chk "a failed walk is no opinion" "$(status_is failed)$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
_MCP_MAX_SERVERS=2
run
_MCP_MAX_SERVERS=2000
chk "a truncated walk is no opinion" "$(is_true 'obj["truncated"] is True')$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
run
chk "a full clean daemon run clears it, and the ledger says it once worked" \
    "$(status_is complete)$(ah_true "$TCC_KEY not in active and ever.get($TCC_KEY) is True")"

echo "  -- with either store function missing, nothing is written, and the log says why"
build_tree
rm -rf "$WORK/agent-health"
functions -c patched_agent_health_record_success _saved_record_success
unfunction patched_agent_health_record_success
deny_run "$EPERM" "$ALICE_CLAUDE"
chk "no record_success: a denied daemon run leaves the store alone" \
    "$(hook_fired)$(store_absent)$(grep -q 'mcp_servers: the agent_health store functions are not loaded' "$WORK/last.log" && echo 1 || echo 0)"
functions -c _saved_record_success patched_agent_health_record_success
functions -c patched_agent_health_record_failure _saved_record_failure
unfunction patched_agent_health_record_failure
run
chk "no record_failure: a clean daemon run leaves the store alone" "$(store_absent)"
functions -c _saved_record_failure patched_agent_health_record_failure
unfunction _saved_record_success _saved_record_failure
deny_run "$EPERM" "$ALICE_CLAUDE"
chk "with both restored, the denied run records again" "$(ah_true "active[$TCC_KEY][\"count\"] == 1")"
unset _PATCHED_TCC_HEALTH_PPID PATCHED_AGENT_HEALTH_STORE

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
