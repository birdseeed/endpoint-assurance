#!/bin/zsh
##############################################################################
# test-local-models.zsh — PAT-2019 local model runtime and model store
# collector contract tests.
#
# Sources macos/lib/local_models.sh and runs the real collect_local_models
# against a machine root and home directories built in a scratch directory:
# Ollama.app, a Homebrew llama.cpp keg and their bin links, an Ollama store
# with two models sharing a blob, LM Studio in ~/Applications with a GGUF repo,
# an MLX repo and the older ~/.cache/lm-studio store. No root, no runtime and
# no network are needed, so it runs the same on a Mac and on the Linux CI
# runner.
#
# Every fixture home also carries the files this collector must never read
# (Ollama's prompt history, key pair and logs; LM Studio's conversations and
# settings) and a root-only tree the links point at, each containing the
# marker "leaked", and every case checks that the marker never appears.
#
# Also carries guards that must stay red-capable:
#   [static]   the collector runs no runtime and no process of any kind,
#              opens no network client, names no loopback address or port
#   [privacy]  it opens only a manifest or an Info.plist, and names none of
#              the history, conversation, key, log or settings files
#   [wire]     the local_models block is on the wire (PAT-2225, 2026-09-28);
#              setting _LOCAL_MODELS_PAYLOAD_ON_WIRE back to 0 turns this red,
#              and that change must update this test in the same change. The
#              off path is still exercised with the flag set locally.
#   [budget]   a block over _LM_MAX_BYTES is sent as failed, never cut down
#   The helper drift check lives in test-package-managers.zsh [drift].
#
# Run: zsh macos/lib/test-local-models.zsh
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
MODULE="$SCRIPT_DIR/local_models.sh"
COLLECT_SH="$SCRIPT_DIR/../patched-collect.sh"
PYTHON3="${PATCHED_TEST_PYTHON3:-$(command -v python3)}"
REAL_PYTHON3="$PYTHON3"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.local-models-test.XXXXXX")
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
# M is the models list, R the per-runtime summary, I installations, S stores.
jq_py() {
    "$REAL_PYTHON3" -c 'import json,sys; obj=json.load(open(sys.argv[1])); M=obj.get("models") or []; R=obj.get("runtimes") or {}; I=obj.get("installations") or []; S=obj.get("stores") or []; print(eval(sys.argv[2]))' \
        "$LOCAL_MODELS_JSON_TMP" "$1" 2>/dev/null
}
is_true() { [[ "$(jq_py "$1")" == "True" ]] && echo 1 || echo 0; }
status_is() { [[ "$(local_models_collection_status)" == "$1" ]] && echo 1 || echo 0; }
rt_is() { is_true "R[\"$1\"][\"collection_status\"] == \"$2\""; }
has_issue() { is_true "any(i[\"code\"]==\"$1\" and i[\"path\"].endswith(\"$2\") for i in obj[\"issues\"])"; }

write_file() { mkdir -p "${1:h}"; print -r -- "$2" > "$1"; }
# sized <file> <bytes>: a file of exactly that many bytes.
sized() { mkdir -p "${1:h}"; head -c "$2" /dev/zero > "$1"; }

# info_plist <app dir> <bundle id> <version>
info_plist() {
    write_file "$1/Contents/Info.plist" "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\"><dict>
<key>CFBundleIdentifier</key><string>$2</string>
<key>CFBundleShortVersionString</key><string>$3</string>
<key>CFBundleVersion</key><string>9999</string>
</dict></plist>"
}

hex() { local out="" i; for i in {1..64}; do out+="$1"; done; print -r -- "$out"; }
A=$(hex a); B=$(hex b); L=$(hex c); C1=$(hex d); C2=$(hex e)

# manifest <file> <config digest> <config size> <layer digest> <layer size> ...
manifest() {
    local file="$1" cd="$2" cs="$3" layers="" sep=""
    shift 3
    while (( $# >= 2 )); do
        layers+="$sep{\"mediaType\":\"application/vnd.ollama.image.model\",\"digest\":\"sha256:$1\",\"size\":$2}"
        sep=","
        shift 2
    done
    write_file "$file" "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.docker.distribution.manifest.v2+json\",\"config\":{\"mediaType\":\"application/vnd.docker.container.image.v1+json\",\"digest\":\"sha256:$cd\",\"size\":$cs},\"layers\":[$layers]}"
}

build_tree() {
    rm -rf "$WORK/Users" "$WORK/sys"
    U="$WORK/Users"; SYS="$WORK/sys"
    mkdir -p "$U/Shared/.ollama/models/manifests" "$U/carol/Documents"

    # Machine-wide: Ollama.app with its CLI link, a Homebrew llama.cpp keg with
    # its bin link (relative, as Homebrew writes it).
    info_plist "$SYS/Applications/Ollama.app" com.electron.ollama 0.34.2
    sized "$SYS/Applications/Ollama.app/Contents/Resources/ollama" 10
    mkdir -p "$SYS/usr/local/bin"
    ln -s "$SYS/Applications/Ollama.app/Contents/Resources/ollama" "$SYS/usr/local/bin/ollama"
    sized "$SYS/opt/homebrew/Cellar/llama.cpp/6230/bin/llama-server" 10
    mkdir -p "$SYS/opt/homebrew/bin"
    ln -s ../Cellar/llama.cpp/6230/bin/llama-server "$SYS/opt/homebrew/bin/llama-server"

    # alice: an Ollama store with two models sharing a license blob, and the
    # files around it that must never be read.
    OS="$U/alice/.ollama/models"
    manifest "$OS/manifests/registry.ollama.ai/library/llama3.2/latest" "$C1" 10 "$A" 1000 "$L" 100
    manifest "$OS/manifests/registry.ollama.ai/library/qwen3/14b" "$C2" 20 "$B" 2000 "$L" 100
    sized "$OS/blobs/sha256-$A" 1000; sized "$OS/blobs/sha256-$B" 2000; sized "$OS/blobs/sha256-$L" 100
    sized "$OS/blobs/sha256-$C1" 10; sized "$OS/blobs/sha256-$C2" 20
    write_file "$U/alice/.ollama/history" "leaked prompt: tell me the payroll"
    write_file "$U/alice/.ollama/id_ed25519" "leaked private key"
    write_file "$U/alice/.ollama/logs/server.log" "leaked log line"

    # bob: LM Studio in ~/Applications, a GGUF repo with two quantisations and a
    # README, an MLX repo, the older ~/.cache store, and conversations/settings.
    info_plist "$U/bob/Applications/LM Studio.app" ai.elementlabs.lmstudio 0.3.27
    LS="$U/bob/.lmstudio/models"
    sized "$LS/lmstudio-community/Qwen3-8B-GGUF/Qwen3-8B-Q4_K_M.gguf" 3000
    sized "$LS/lmstudio-community/Qwen3-8B-GGUF/Qwen3-8B-Q8_0.gguf" 5000
    write_file "$LS/lmstudio-community/Qwen3-8B-GGUF/README.md" "leaked readme text"
    sized "$LS/mlx-community/Llama-3.2-3B-Instruct-4bit/model.safetensors" 4000
    sized "$LS/mlx-community/Llama-3.2-3B-Instruct-4bit/config.json" 50
    sized "$LS/mlx-community/Llama-3.2-3B-Instruct-4bit/tokenizer.json" 60
    sized "$U/bob/.cache/lm-studio/models/TheBloke/old-GGUF/old.Q4_0.gguf" 700
    write_file "$U/bob/.lmstudio/conversations/1.conversation.json" "leaked conversation"
    write_file "$U/bob/.lmstudio/settings.json" "leaked settings"
}

SECRET_DIR="$WORK/root-only"
mkdir -p "$SECRET_DIR/leaked-publisher/leaked-repo"
sized "$SECRET_DIR/leaked-publisher/leaked-repo/leaked.gguf" 123
manifest "$SECRET_DIR/manifests/registry.ollama.ai/library/leaked/latest" "$C1" 10 "$A" 1000
write_file "$SECRET_DIR/leaked-manifest" '{"layers":[{"digest":"sha256:'"$A"'","size":1}],"leaked":1}'
write_file "$SECRET_DIR/Info.plist" '<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>leaked</string></dict></plist>'

run() {
    PATCHED_TMPDIR=$(mktemp -d "$WORK/run.XXXXXX")
    collect_local_models > "$WORK/last.log" 2>&1
}

no_leak() { is_true '"leaked" not in json.dumps(obj).lower()'; }

_LM_USERS_ROOT="$WORK/Users"
_LM_SYSTEM_ROOT="$WORK/sys"

##############################################################################
echo "[1] an Ollama store with two models, LM Studio stores, runtimes on the machine and per user"
build_tree
run
chk "status complete" "$(status_is complete)"
chk "every runtime complete" "$(rt_is ollama complete)$(rt_is lm_studio complete)$(rt_is llama_cpp complete)"
chk "nothing it must not read was read (history, key, logs, conversations, settings, README)" "$(no_leak)"
chk "counts: 6 models, 3 installations, 3 users" "$([[ "$LOCAL_MODELS_MODEL_COUNT/$LOCAL_MODELS_INSTALLATION_COUNT/$LOCAL_MODELS_USER_COUNT" == 6/3/3 ]] && echo 1 || echo 0)"
chk "Shared is skipped" "$(is_true 'not any(u["user"]=="Shared" for u in obj["users"])')"
chk "users and their per-runtime status" "$(is_true '[(u["user"],u["collection_status"],u["runtimes"]) for u in obj["users"]] == [("alice","complete",{"ollama":"complete","lm_studio":"not_present","llama_cpp":"not_present"}),("bob","complete",{"ollama":"not_present","lm_studio":"complete","llama_cpp":"not_present"}),("carol","not_present",{"ollama":"not_present","lm_studio":"not_present","llama_cpp":"not_present"})]')"
chk "user_id is the home owner's uid" "$(is_true 'all(u["user_id"] == str(__import__("os").getuid()) for u in obj["users"])')"
chk "Ollama.app: version and identifier from Info.plist, system scope" "$(is_true '[(i["kind"],i["version"],i["version_source"],i["identifier"],i["scope"],i["user"]) for i in I if i["runtime"]=="ollama"] == [("app_bundle","0.34.2","info_plist","com.electron.ollama","system",None)]')"
chk "CFBundleShortVersionString wins over CFBundleVersion" "$(is_true 'not any(i["version"]=="9999" for i in I)')"
chk "llama.cpp: Homebrew keg name is the version" "$(is_true '[(i["kind"],i["version"],i["version_source"]) for i in I if i["runtime"]=="llama_cpp"] == [("homebrew_formula","6230","homebrew_keg")]')"
chk "LM Studio in ~/Applications: user scope" "$(is_true '[(i["kind"],i["version"],i["identifier"],i["scope"],i["user"]) for i in I if i["runtime"]=="lm_studio"] == [("app_bundle","0.3.27","ai.elementlabs.lmstudio","user","bob")]')"
chk "bin links into recorded installations: alias_not_followed, no partial" "$(has_issue alias_not_followed usr/local/bin/ollama)$(has_issue alias_not_followed opt/homebrew/bin/llama-server)$(is_true 'len(obj["issues"]) == 2')"
chk "Ollama: two models, name and tag from the manifest path" "$(is_true 'sorted((m["name"],m["tag"]) for m in M if m["runtime"]=="ollama") == [("llama3.2","latest"),("qwen3","14b")]')"
chk "Ollama: size is config plus layers from the manifest, blobs all present" "$(is_true 'sorted((m["tag"],m["size_bytes"],m["file_count"],m["missing_blobs"],m["size_source"],m["metadata_status"]) for m in M if m["runtime"]=="ollama") == [("14b",2120,3,0,"manifest","read"),("latest",1110,3,0,"manifest","read")]')"
chk "Ollama store total counts the shared blob once, from disk" "$(is_true '[(s["user"],s["model_count"],s["total_bytes"],s["collection_status"]) for s in S if s["runtime"]=="ollama"] == [("alice",2,3130,"complete")]')"
chk "LM Studio: each GGUF is a model, tag is the file name, size from stat" "$(is_true 'sorted((m["name"],m["tag"],m["format"],m["size_bytes"],m["file_count"]) for m in M if m["runtime"]=="lm_studio" and m["format"]=="gguf") == [("TheBloke/old-GGUF","old.Q4_0","gguf",700,1),("lmstudio-community/Qwen3-8B-GGUF","Qwen3-8B-Q4_K_M","gguf",3000,1),("lmstudio-community/Qwen3-8B-GGUF","Qwen3-8B-Q8_0","gguf",5000,1)]')"
chk "LM Studio: an MLX repo is one model sized over every file" "$(is_true '[(m["name"],m["tag"],m["format"],m["size_bytes"],m["file_count"]) for m in M if m["format"]=="safetensors"] == [("mlx-community/Llama-3.2-3B-Instruct-4bit",None,"safetensors",4110,3)]')"
chk "LM Studio: both stores recorded with totals" "$(is_true 'sorted((s["path"].split("/bob/")[1],s["model_count"],s["total_bytes"]) for s in S if s["runtime"]=="lm_studio") == [(".cache/lm-studio/models",1,700),(".lmstudio/models",3,12110)]')"
chk "per-runtime summary" "$(is_true '[(r, R[r]["installation_count"], R[r]["store_count"], R[r]["model_count"], R[r]["total_bytes"]) for r in ("ollama","lm_studio","llama_cpp")] == [("ollama",1,1,2,3130),("lm_studio",1,2,4,12810),("llama_cpp",1,0,0,0)]')"
chk "device totals" "$(is_true 'obj["totals"] == {"model_count": 6, "total_bytes": 15940}')"
chk "every model row carries the same keys" "$(is_true 'all(list(m.keys()) == ["runtime","user","user_id","store_path","name","tag","format","size_bytes","file_count","size_source","missing_blobs","metadata_status"] for m in M)')"
chk "installation and store rows carry the same keys" "$(is_true 'all(list(i.keys()) == ["runtime","scope","user","user_id","kind","path","version","version_source","identifier"] for i in I) and all(list(s.keys()) == ["runtime","scope","user","user_id","path","collection_status","model_count","total_bytes"] for s in S)')"
chk "top-level keys in order" "$(is_true 'list(obj.keys()) == ["collection_status","truncated","truncation_reason","runtimes","totals","users","installations","stores","issues","models"]')"
chk "collect log line summarises and says sent" "$(grep -q 'local_models: status=complete ollama=complete lm_studio=complete llama_cpp=complete installations=3 models=6 bytes=15940 users=3 (sent)' "$WORK/last.log" && echo 1 || echo 0)"

build_tree
manifest "$OS/manifests/hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF/Q4_K_M" "$C1" 10 "$A" 1000
manifest "$OS/manifests/registry.ollama.ai/MFDoom/deepseek-coder-v2-tool-calling/16b" "$C1" 10 "$(hex f)" 5
run
chk "Ollama names: other namespace and other registry keep their prefix" "$(is_true 'sorted(m["name"] for m in M if m["runtime"]=="ollama") == ["MFDoom/deepseek-coder-v2-tool-calling","hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF","llama3.2","qwen3"]')"
chk "a manifest whose blob is gone: missing_blobs counted, size still declared, store complete" "$(is_true '[(m["missing_blobs"],m["size_bytes"]) for m in M if m["tag"]=="16b"] == [(1,15)] and S[0]["total_bytes"] == 3130')$(rt_is ollama complete)"

##############################################################################
echo "[2] an empty store is complete with zero models"
build_tree
rm -rf "$U/alice/.ollama/models/manifests" "$U/alice/.ollama/models/blobs" "$U/bob/.lmstudio/models" "$U/bob/.cache"
mkdir -p "$U/alice/.ollama/models/manifests" "$U/alice/.ollama/models/blobs" "$U/bob/.lmstudio/models"
run
chk "status complete, stores complete with zero models" "$(status_is complete)$(is_true 'M == [] and obj["totals"] == {"model_count": 0, "total_bytes": 0} and sorted((s["runtime"],s["collection_status"],s["model_count"]) for s in S) == [("lm_studio","complete",0),("ollama","complete",0)]')"
chk "models present and empty (a genuine reading)" "$(is_true '"models" in obj and obj["models"] == []')"
build_tree
rm -rf "$U/alice/.ollama/models/manifests"
run
chk "an Ollama models dir with no manifests yet: complete, zero" "$(rt_is ollama complete)$(is_true 'not any(m["runtime"]=="ollama" for m in M)')"

##############################################################################
echo "[3] a missing runtime is not_present"
rm -rf "$WORK/empty"; mkdir -p "$WORK/empty/Users/dave/Documents" "$WORK/empty/Users/erin/.ollama" "$WORK/empty/sys/Applications"
_LM_USERS_ROOT="$WORK/empty/Users"; _LM_SYSTEM_ROOT="$WORK/empty/sys"
run
chk "status not_present, every runtime not_present" "$(status_is not_present)$(rt_is ollama not_present)$(rt_is lm_studio not_present)$(rt_is llama_cpp not_present)"
chk "models, installations and stores present and empty" "$(is_true 'obj["models"] == [] and I == [] and S == [] and [u["collection_status"] for u in obj["users"]] == ["not_present","not_present"]')"
chk "an ~/.ollama with no models dir is not a store" "$(is_true 'S == []')"
_LM_USERS_ROOT="$WORK/Users"; _LM_SYSTEM_ROOT="$WORK/sys"
build_tree
rm -rf "$SYS/opt" "$SYS/usr"
run
chk "llama.cpp removed from the machine: llama_cpp not_present, the others unaffected" "$(rt_is llama_cpp not_present)$(rt_is ollama complete)$(rt_is lm_studio complete)"

##############################################################################
echo "[4] a linked models dir is not followed, and is partial"
build_tree
rm -rf "$U/bob/.lmstudio/models"
ln -s "$SECRET_DIR" "$U/bob/.lmstudio/models"
run
chk "symlinked LM Studio models dir: nothing leaked" "$(no_leak)"
chk "recorded as symlink_not_followed, lm_studio partial, bob partial" "$(has_issue symlink_not_followed .lmstudio/models)$(rt_is lm_studio partial)$(status_is partial)$(is_true '[u["runtimes"]["lm_studio"] for u in obj["users"] if u["user"]=="bob"] == ["partial"]')"
chk "the store is not read and not claimed; the older store still is" "$(is_true '[s["path"].split("/bob/")[1] for s in S if s["runtime"]=="lm_studio"] == [".cache/lm-studio/models"]')"
chk "the other runtimes are unaffected" "$(rt_is ollama complete)$(rt_is llama_cpp complete)"

build_tree
rm -rf "$U/alice/.ollama/models"
ln -s "$SECRET_DIR" "$U/alice/.ollama/models"
run
chk "symlinked Ollama models dir: not followed, ollama partial" "$(no_leak)$(has_issue symlink_not_followed .ollama/models)$(rt_is ollama partial)"
build_tree
rm -rf "$U/alice/.ollama"
ln -s "$U/bob" "$U/alice/.ollama"
run
chk "symlinked ~/.ollama: not followed" "$(has_issue symlink_not_followed alice/.ollama)$(rt_is ollama partial)"

build_tree
rm -rf "$U/alice/.ollama/models/blobs"
ln -s "$SECRET_DIR" "$U/alice/.ollama/models/blobs"
run
chk "symlinked blobs dir: not looked into, sizes from manifests, partial" "$(no_leak)$(has_issue symlink_not_followed models/blobs)$(rt_is ollama partial)$(is_true 'all(m["missing_blobs"] is None for m in M if m["runtime"]=="ollama") and S[0]["total_bytes"] == 3130')"

build_tree
F="$OS/manifests/registry.ollama.ai/library/qwen3/14b"
rm -f "$F"; ln -s "$SECRET_DIR/leaked-manifest" "$F"
run
chk "symlinked manifest: recorded, not read, partial" "$(no_leak)$(has_issue symlink_not_followed qwen3/14b)$(rt_is ollama partial)"
build_tree
rm -f "$F"; ln "$SECRET_DIR/leaked-manifest" "$F"
run
chk "hard-linked manifest: refused like a symlink, row kept unsized" "$(no_leak)$(rt_is ollama partial)$(is_true '[(m["size_bytes"],m["metadata_status"]) for m in M if m["tag"]=="14b"] == [(None,"unreadable")]')"
build_tree
rm -rf "$OS/manifests/registry.ollama.ai/library/qwen3"
ln -s "$SECRET_DIR/manifests/registry.ollama.ai/library/leaked" "$OS/manifests/registry.ollama.ai/library/qwen3"
run
chk "symlinked model dir inside manifests: not entered" "$(no_leak)$(rt_is ollama partial)"
build_tree
rm -f "$OS/blobs/sha256-$A"; ln -s "$SECRET_DIR/leaked-publisher/leaked-repo/leaked.gguf" "$OS/blobs/sha256-$A"
run
# PAT-2040: a refused blob is on disk, so it is unreadable, never missing: not
# in missing_blobs, not in the total, the store partial, a blob_unreadable
# issue at its path. The Windows agent's LocalModelScanLogicTests hold the same.
chk "a blob that is a link is not a blob: unreadable (never missing), never sized through" "$(no_leak)$(is_true '[m["missing_blobs"] for m in M if m["tag"]=="latest"] == [0] and S[0]["total_bytes"] == 2130 and S[0]["collection_status"] == "partial"')$(has_issue blob_unreadable "sha256-$A")$(rt_is ollama partial)"
build_tree
rm -f "$OS/blobs/sha256-$B"; ln "$SECRET_DIR/leaked-publisher/leaked-repo/leaked.gguf" "$OS/blobs/sha256-$B"
run
chk "a hard-linked blob: unreadable (never missing), never sized" "$(is_true '[m["missing_blobs"] for m in M if m["tag"]=="14b"] == [0] and S[0]["total_bytes"] == 1130')$(has_issue blob_unreadable "sha256-$B")$(rt_is ollama partial)"

build_tree
ln -s "$SECRET_DIR/leaked-publisher/leaked-repo/leaked.gguf" "$LS/lmstudio-community/Qwen3-8B-GGUF/planted.gguf"
ln -s "$SECRET_DIR/leaked-publisher" "$LS/planted-publisher"
ln -s "$SECRET_DIR/leaked-publisher/leaked-repo" "$LS/mlx-community/planted-repo"
run
chk "symlinked gguf, publisher and repo: recorded, not stat'd through, partial" "$(no_leak)$(has_issue symlink_not_followed planted.gguf)$(has_issue symlink_not_followed planted-publisher)$(has_issue symlink_not_followed planted-repo)$(rt_is lm_studio partial)$(is_true 'sum(1 for m in M if m["runtime"]=="lm_studio") == 4')"

build_tree
rm -rf "$SYS/Applications/Ollama.app"
ln -s "$SECRET_DIR" "$SYS/Applications/Ollama.app"
run
chk "symlinked app bundle: not followed, partial; the CLI link is then not covered" "$(no_leak)$(has_issue symlink_not_followed Applications/Ollama.app)$(has_issue symlink_not_followed usr/local/bin/ollama)$(rt_is ollama partial)"
build_tree
rm -f "$SYS/Applications/Ollama.app/Contents/Info.plist"; ln -s "$SECRET_DIR/Info.plist" "$SYS/Applications/Ollama.app/Contents/Info.plist"
run
chk "symlinked Info.plist: installation recorded without a version, partial" "$(no_leak)$(is_true '[(i["version"],i["version_source"]) for i in I if i["runtime"]=="ollama"] == [(None,"none")]')$(has_issue info_plist_unreadable Ollama.app)$(rt_is ollama partial)"

build_tree
rm -f "$SYS/usr/local/bin/ollama"; ln -s "$SECRET_DIR/ollama" "$SYS/usr/local/bin/ollama"
sized "$SYS/usr/local/bin/llama-cli" 10
run
chk "a bin link to somewhere unrecorded: not followed, partial" "$(has_issue symlink_not_followed usr/local/bin/ollama)$(rt_is ollama partial)"
chk "a standalone binary: presence only, no version" "$(is_true '[(i["kind"],i["version"],i["version_source"]) for i in I if i["path"].endswith("usr/local/bin/llama-cli")] == [("binary",None,"none")]')$(rt_is llama_cpp complete)"

build_tree
rm -rf "$U/carol"; ln -s "$U/alice" "$U/carol"
run
chk "symlinked home: user failed, alice not read twice" "$(is_true '[u["collection_status"] for u in obj["users"] if u["user"]=="carol"] == ["failed"] and not any(m["user"]=="carol" for m in M)')"

build_tree
rm -f "$F"; mkfifo "$F"
_lm_t0=$SECONDS
run
chk "FIFO manifest: refused without hanging ($(( SECONDS - _lm_t0 ))s)" "$(( SECONDS - _lm_t0 <= 5 ))$(has_issue not_regular qwen3/14b)$(rt_is ollama partial)"

##############################################################################
echo "[5] an unreadable or corrupt manifest makes ollama partial, never empty"
if (( EUID != 0 )); then
    build_tree
    chmod 000 "$F"
    run
    chmod 644 "$F"
    chk "unreadable manifest: ollama and block partial" "$(status_is partial)$(rt_is ollama partial)"
    chk "unreadable manifest: still listed by name and tag, unsized" "$(is_true '[(m["name"],m["tag"],m["size_bytes"],m["metadata_status"]) for m in M if m["tag"]=="14b"] == [("qwen3","14b",None,"unreadable")]')"
    chk "unreadable manifest: issue, store partial, the other model kept" "$(has_issue manifest_unreadable qwen3/14b)$(is_true '[s["collection_status"] for s in S if s["runtime"]=="ollama"] == ["partial"] and any(m["tag"]=="latest" and m["size_bytes"]==1110 for m in M)')"
    chk "unreadable manifest: other runtimes unaffected" "$(rt_is lm_studio complete)$(rt_is llama_cpp complete)"
    build_tree
    chmod 000 "$OS/manifests"
    run
    chmod 755 "$OS/manifests"
    chk "unlistable manifests dir: store failed, alice's ollama failed, runtime partial" "$(is_true '[s["collection_status"] for s in S if s["runtime"]=="ollama"] == ["failed"] and [u["runtimes"]["ollama"] for u in obj["users"] if u["user"]=="alice"] == ["failed"]')$(rt_is ollama partial)"
else
    echo "  SKIP: running as root, chmod 000 does not deny a read"
fi
build_tree
print -r -- '{not json' > "$F"
run
chk "corrupt manifest: unparseable, partial" "$(rt_is ollama partial)$(is_true '[m["metadata_status"] for m in M if m["tag"]=="14b"] == ["unparseable"]')"
build_tree
write_file "$F" '{"layers":[{"digest":"sha256:../../../root-only/leaked-manifest","size":1}]}'
run
chk "a digest that is not sha256 hex is refused before it becomes a path" "$(no_leak)$(is_true '[m["metadata_status"] for m in M if m["tag"]=="14b"] == ["unparseable"]')"
for _lm_depth in 65 200000; do
    build_tree
    "$REAL_PYTHON3" -c 'import sys; d=int(sys.argv[2]); open(sys.argv[1],"w").write("{\"layers\":[{\"digest\":\"sha256:" + "b"*64 + "\",\"size\":1}],\"x\":" + "["*d + "]"*d + "}")' "$F" "$(( _lm_depth - 1 ))"
    run
    chk "a manifest nested $_lm_depth deep: that model unparseable, the rest read, block partial not failed" "$(is_true '[m["metadata_status"] for m in M if m["tag"]=="14b"] == ["unparseable"] and [m["metadata_status"] for m in M if m["tag"]=="latest"] == ["read"]')$(rt_is ollama partial)$(status_is partial)"
done
build_tree
"$REAL_PYTHON3" -c 'import sys; d=63; open(sys.argv[1],"w").write("{\"layers\":[{\"digest\":\"sha256:" + "b"*64 + "\",\"size\":1}],\"x\":" + "["*d + "\"[[[[\"" + "]"*d + "}")' "$F"
run
chk "nesting at the limit, and brackets inside strings, still parse" "$(is_true '[(m["metadata_status"],m["size_bytes"]) for m in M if m["tag"]=="14b"] == [("read",1)]')$(rt_is ollama complete)"
build_tree
write_file "$F" '{"layers":[{"digest":"sha256:'"$B"'","size":true}]}'
run
chk "a size that is not an integer is refused" "$(is_true '[m["metadata_status"] for m in M if m["tag"]=="14b"] == ["unparseable"]')"
build_tree
print -r -- "not a plist" > "$SYS/Applications/Ollama.app/Contents/Info.plist"
run
chk "corrupt Info.plist: installation kept, no version, partial" "$(is_true '[(i["version"],i["identifier"]) for i in I if i["runtime"]=="ollama"] == [(None,None)]')$(has_issue info_plist_unparseable Ollama.app)$(rt_is ollama partial)"
build_tree
write_file "$SYS/Applications/Ollama.app/Contents/Info.plist" '<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY x "leaked">]><plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>&x;</string></dict></plist>'
run
chk "an Info.plist declaring an XML entity is refused" "$(no_leak)$(has_issue info_plist_unparseable Ollama.app)"

##############################################################################
echo "[6] credential-shaped and control-character text never leaves the device"
build_tree
mkdir -p "$LS/lmstudio-community/$(printf 'bad\033[31mname')"
sized "$LS/lmstudio-community/$(printf 'bad\033[31mname')/x.gguf" 5
run
chk "a repo name with control characters is dropped and recorded" "$(has_issue name_unsafe lmstudio-community)$(is_true 'not any("\x1b" in (m["name"] or "") for m in M)')$(rt_is lm_studio partial)"

##############################################################################
echo "[7] nothing readable is failed, with the models list omitted"
build_tree
_LM_USERS_ROOT="$WORK/does-not-exist"
run
chk "missing users root, machine read: runtimes partial, never not_present" "$(status_is partial)$(rt_is ollama partial)$(rt_is lm_studio partial)$(rt_is llama_cpp partial)"
rm -rf "$SYS"
mkdir -p "$SYS/Applications" "$SYS/opt/homebrew/Cellar"
print -r -- "" > "$SYS/Applications/Ollama.app"
print -r -- "" > "$SYS/Applications/LM Studio.app"
print -r -- "" > "$SYS/opt/homebrew/Cellar/llama.cpp"
run
chk "and every machine-wide place unreadable: every runtime failed, block failed" "$(status_is failed)$(rt_is ollama failed)$(rt_is lm_studio failed)$(rt_is llama_cpp failed)"
chk "failed block omits models, never []" "$(is_true 'obj["collection_status"] == "failed" and "models" not in obj')"
_LM_USERS_ROOT="$WORK/Users"

##############################################################################
echo "[8] bounds: models and the time budget stop collection as partial"
build_tree
_LM_MAX_MODELS=2
run
chk "past the model limit: partial, model_limit, exactly 2 models" "$(status_is partial)$(is_true 'obj["truncated"] is True and obj["truncation_reason"] == "model_limit" and len(M) == 2')"
chk "a store skipped at the limit is partial, not complete" "$(rt_is lm_studio partial)"
_LM_MAX_MODELS=5000
_LM_TIME_BUDGET_SECONDS=0
run
chk "past the time budget: partial, time_limit, no runtime claims complete" "$(status_is partial)$(is_true 'obj["truncation_reason"] == "time_limit" and all(R[r]["collection_status"] in ("partial","failed") for r in R)')"
_LM_TIME_BUDGET_SECONDS=30

##############################################################################
echo "[9] a hung or crashed parser is failed, and the hang is bounded"
print -r -- '#!/bin/zsh
sleep 30' > "$WORK/slowpy"; chmod +x "$WORK/slowpy"
print -r -- '#!/bin/zsh
exit 3' > "$WORK/crashpy"; chmod +x "$WORK/crashpy"
build_tree
PYTHON3="$WORK/slowpy"; _LM_HARD_TIMEOUT_SECONDS=1
_lm_t0=$SECONDS
run
_lm_elapsed=$(( SECONDS - _lm_t0 ))
PYTHON3="$REAL_PYTHON3"; _LM_HARD_TIMEOUT_SECONDS=45
chk "hung parser: failed" "$(status_is failed)"
chk "hung parser: killed within the hard limit (${_lm_elapsed}s)" "$(( _lm_elapsed <= 4 ))"
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
PYTHON3="$WORK/latepy"; _LM_HARD_TIMEOUT_SECONDS=1
run
unfunction kill
PYTHON3="$REAL_PYTHON3"; _LM_HARD_TIMEOUT_SECONDS=45
chk "killed parser that still exits 0 with good output: failed" "$(status_is failed)"

##############################################################################
echo "[wire] the block is on the wire (PAT-2225)"
build_tree
run
chk "the wire flag is 1" "$(( _LOCAL_MODELS_PAYLOAD_ON_WIRE == 1 ))"
chk "collect log line says the block is sent" "$(grep -q '^local_models: status=complete ollama=complete lm_studio=complete llama_cpp=complete installations=3 models=6 bytes=15940 users=3 (sent)$' "$WORK/last.log" && echo 1 || echo 0)"
frag="{$(local_models_payload_member) \"next\": 1}"
chk "the member is a valid payload fragment carrying the collected block" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); b=json.load(open(sys.argv[1])); print(1 if d["local_models"]==b and d["local_models"]["collection_status"]=="complete" and len(d["local_models"]["models"])==6 and d["next"]==1 else 0)' "$LOCAL_MODELS_JSON_TMP" 2>/dev/null || echo 0)"
LOCAL_MODELS_COLLECTION_STATUS="failed"
frag="{$(local_models_payload_member) \"next\": 1}"
chk "a failed block is only its status" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["local_models"]=={"collection_status":"failed"} else 0)' 2>/dev/null || echo 0)"
# The off path stays covered: with the flag at 0 nothing is emitted and the
# log line says so.
_LOCAL_MODELS_PAYLOAD_ON_WIRE=0
run
chk "flag 0: a complete collection emits no payload member" "$([[ -z "$(local_models_payload_member)" ]] && echo 1 || echo 0)"
chk "flag 0: collect log line says held off the wire" "$(grep -q '^local_models: status=complete ollama=complete lm_studio=complete llama_cpp=complete installations=3 models=6 bytes=15940 users=3 (held off the wire)$' "$WORK/last.log" && echo 1 || echo 0)"
_LOCAL_MODELS_PAYLOAD_ON_WIRE=1
chk "patched-collect.sh calls the member exactly once in the payload heredoc" \
    "$([[ "$(grep -c '^  \$(local_models_payload_member)$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"
chk "patched-collect.sh names no \"local_models\" key of its own" \
    "$(grep -q '"local_models"' "$COLLECT_SH" && echo 0 || echo 1)"
chk "patched-collect.sh runs collect_local_models in the daily collection" \
    "$([[ "$(grep -c '^collect_local_models$' "$COLLECT_SH")" == 1 ]] && echo 1 || echo 0)"

##############################################################################
echo "[budget] a block over _LM_MAX_BYTES is sent as failed (PAT-2225)"
chk "the shipped budget is 256 KiB" "$(( _LM_MAX_BYTES == 262144 ))"
build_tree
run
_lm_size=$(wc -c < "$LOCAL_MODELS_JSON_TMP" | tr -d ' ')
# Exactly at the budget is within it.
_LM_MAX_BYTES=$_lm_size
run
chk "a block exactly at the budget is sent complete" "$(status_is complete)$(is_true 'len(obj["models"]) == 6')"
_LM_MAX_BYTES=$(( _lm_size - 1 ))
run
chk "one byte over: status failed" "$(status_is failed)"
chk "one byte over: the block file is only its status" "$(is_true 'obj == {"collection_status": "failed"}')"
frag="{$(local_models_payload_member) \"next\": 1}"
chk "one byte over: the member sends only the failed status" \
    "$(print -r -- "$frag" | "$REAL_PYTHON3" -c 'import json,sys; d=json.load(sys.stdin); print(1 if d["local_models"]=={"collection_status":"failed"} else 0)' 2>/dev/null || echo 0)"
chk "one byte over: WARN names the size and the budget" "$(grep -q "^WARN: local_models: block is $_lm_size bytes, over the $(( _lm_size - 1 ))-byte budget; sent as failed$" "$WORK/last.log" && echo 1 || echo 0)"
chk "one byte over: the log line says failed" "$(grep -q '^local_models: status=failed ollama=complete lm_studio=complete llama_cpp=complete installations=3 models=6 bytes=15940 users=3 (sent)$' "$WORK/last.log" && echo 1 || echo 0)"
_LM_MAX_BYTES=junk
run
chk "an unusable budget fails closed" "$(status_is failed)"
_LM_MAX_BYTES=$(( 256 * 1024 ))

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
RACE_DIR="$U/alice/.ollama/models"
race_run "$RACE_DIR" "$SECRET_DIR"
chk "the Ollama store was swapped between its check and the read" "$(swapped "$RACE_DIR")"
chk "nothing was read through the swapped-in link" "$(no_leak)"
chk "the refusal is recorded: ollama is not complete" "$(is_true 'R["ollama"]["collection_status"] != "complete"')"

##############################################################################
echo "[static] no runtime or other process is executed; no network client"
SHELL_PART="$WORK/shell-part"; PY_PART="$WORK/py-part"
awk '/<<.PYEOF.( &)?$/{print; inpy=1; next} /^PYEOF$/{inpy=0} !inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$SHELL_PART"
awk '/<<.PYEOF.( &)?$/{inpy=1; next} /^PYEOF$/{inpy=0} inpy' "$MODULE" \
    | grep -vE '^[[:space:]]*#' > "$PY_PART"
chk "extracted a non-trivial python part" "$(( $(wc -l < "$PY_PART") > 400 ))"
chk "extracted a non-trivial shell part" "$(( $(wc -l < "$SHELL_PART") > 40 ))"
# Every command word the shell part could start a runtime, a network client or
# an opener with, anywhere on a line (so a pipe, $( ), backtick or && cannot
# hide one).
hits=$(grep -nE '(^|[;&|(`{[:space:]]|\$\()(ollama|lms|llama|llama-cli|llama-server|llama-run|lm-studio|curl|wget|nc|ncat|ssh|scp|sftp|rsync|git|open|osascript|nscurl|launchctl|sudo|su|env|exec|eval|xargs|python|python3|node|brew)([[:space:];|&)]|$)|/dev/(tcp|udp)' "$SHELL_PART")
chk "shell part runs no runtime, network client or opener" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
chk "the only \$PYTHON3 launches are the parser and the output check" \
    "$([[ "$(grep -c '"\$PYTHON3"' "$SHELL_PART")" == 2 && "$(grep -c '"\$PYTHON3" - ' "$SHELL_PART")" == 1 && "$(grep -c "\"\$PYTHON3\" -c 'import json,sys; json.load(open(sys.argv\[1\]))'" "$SHELL_PART")" == 1 ]] && echo 1 || echo 0)"
hits=$(grep -nE '^[[:space:]]*(import|from)[[:space:]]' "$PY_PART" \
    | grep -vE '^[0-9]+:import (json|os|plistlib|re|stat|sys|time)$')
chk "python imports only the reviewed modules" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -nE '__import__|importlib|subprocess|multiprocessing|socket|urllib|http\.client|requests|ftplib|ctypes|runpy|os\.(system|popen|exec|spawn|fork|posix_spawn|kill|startfile)|(^|[^.A-Za-z_])(eval|exec|compile)\(|https?://' "$PY_PART")
chk "python launches no process, opens no socket, names no URL" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
hits=$(grep -niE 'localhost|127\.0\.0\.1|::1|0\.0\.0\.0|11434|:1234|\bport\b|/api/|/v1/' "$PY_PART")
chk "python names no loopback address, runtime port or API path" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
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
chk "no path is resolved through links (no realpath, no stat that follows)" "$(grep -qE 'realpath|os\.stat\(|os\.path\.(exists|isdir|isfile|getsize)\(|follow_symlinks=True' "$PY_PART" && echo 0 || echo 1)"

##############################################################################
echo "[privacy] names and sizes only: nothing but a manifest or an Info.plist is ever opened"
# read_file is the only reader; open_regular is only reached through it. Two
# call sites, each named: the Ollama manifest and the app's Info.plist. A new
# read anywhere (a blob, a GGUF header, a history or settings file) is a third
# call site and turns this red.
# PAT-2096: the shared helpers gained errno-carrying twins. open_regular_errno
# is reached only from read_file_errno (and the open_regular wrapper, which
# nothing here calls), and read_file_errno only from read_file.
chk "open_regular is called only inside read_file" \
    "$([[ "$(grep -cE '(^|[^_A-Za-z])open_regular\(' "$PY_PART")" == 1 && "$(grep -cE 'open_regular_errno\(' "$PY_PART")" == 3 && "$(grep -cE 'read_file_errno\(' "$PY_PART")" == 2 ]] && echo 1 || echo 0)"
chk "read_file has exactly two call sites" "$([[ "$(grep -cE '(^|[^_A-Za-z])read_file\(' "$PY_PART")" == 3 ]] && echo 1 || echo 0)"
chk "one reads the Ollama manifest" "$([[ "$(grep -c 'read_file(path, MANIFEST_CAP)' "$PY_PART")" == 1 ]] && echo 1 || echo 0)"
chk "one reads Contents/Info.plist" "$([[ "$(grep -c 'read_file(os.path.join(contents, "Info.plist"), PLIST_CAP)' "$PY_PART")" == 1 ]] && echo 1 || echo 0)"
chk "no read_head, and the only os.read is read_file's" "$([[ "$(grep -c 'read_head' "$PY_PART")" == 0 && "$(grep -c 'os\.read(' "$PY_PART")" == 1 ]] && echo 1 || echo 0)"
hits=$(grep -niE 'history|conversation|chat|prompt|id_ed25519|\.pub\b|\blogs?\b|settings|\.sqlite|\.db\b|cache/lm-studio/(conversations|logs)' "$PY_PART" | grep -v '"lm-studio", "models"')
chk "python names no history, conversation, prompt, key, log or settings file" "$([[ -z "$hits" ]] && echo 1 || echo 0)"
[[ -n "$hits" ]] && print -r -- "$hits"
# PAT-2040: the blob path is built once and goes to blob_size, and to the
# issue that records a refused blob by its path, and nowhere else.
chk "blobs are only ever lstat'd (the blob path goes to blob_size and its issue only)" "$([[ "$(grep -c '"sha256-" + d' "$PY_PART")" == 1 && "$(grep -c '^ *blob = os.path.join(blobs, "sha256-" + d)$' "$PY_PART")" == 1 && "$(grep -oE '[A-Za-z_.]+\([^()]*\bblob\)' "$PY_PART" | tr '\n' '|')" == 'blob_size(blob)|issue("blob_unreadable", blob)|' && "$(grep -oE '\bblob\b' "$PY_PART" | wc -l | tr -d ' ')" == 3 ]] && echo 1 || echo 0)"

##############################################################################
echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
