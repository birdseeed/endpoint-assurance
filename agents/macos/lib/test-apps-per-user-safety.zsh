#!/bin/zsh
# Additional PAT-2075 cases; source the immutable initial collector harness.
source "${0:A:h}/test-apps-per-user.zsh"
# Deterministic listing refusal: does not rely on root's chmod semantics.
DENIED_ROOT=""
find() {
    [[ -n "$DENIED_ROOT" && "$1" == "$DENIED_ROOT" ]] && return 1
    command find "$@"
}
new_case denied
DENIED_ROOT="$APPS_ROOTS[2]"
make_app "$APPS_ROOTS[1]" Machine
make_app "$APPS_ROOTS[3]" Bob
collect_payload
check 'denied user partial, readable user complete' 'sorted((u["user_account"], u["collection_status"]) for u in p["collection_status"].get("apps_users", [])) == [("synthetic_alice", "partial"), ("synthetic_bob", "complete")]'
check 'denied user leaves machine and sibling observations intact' 'p["collection_status"]["apps"] == "complete" and any(a.get("user_account") == "synthetic_bob" for a in p["apps"])'
DENIED_ROOT=""
new_case unresolved
mkdir -p "$CASE_DIR/Users/unknown-home/Applications"
APPS_ROOTS+=("$CASE_DIR/Users/unknown-home/Applications")
make_app "$APPS_ROOTS[4]" Unresolved
collect_payload
check 'unresolved user is never reclassified machine-wide' 'not any(a["identifier"] == "com.synthetic.Unresolved" for a in p["apps"])'
check 'unresolved user never has complete authority' 'set(u["user_account"] for u in p["collection_status"].get("apps_users", [])) == {"synthetic_alice", "synthetic_bob"}'
new_case symlink
mkdir -p "$CASE_DIR/hidden"
make_app "$CASE_DIR/hidden" Hidden
ln -s "$CASE_DIR/hidden" "$APPS_ROOTS[2]/linked-folder"
collect_payload
check 'symlink-hidden user content cannot authorise pruning' 'any(u["user_account"] == "synthetic_alice" and u["collection_status"] == "partial" for u in p["collection_status"].get("apps_users", []))'
check 'symlink is never followed to invent observations' 'not any(a["identifier"] == "com.synthetic.Hidden" for a in p["apps"])'
new_case machinefailure
DENIED_ROOT="$APPS_ROOTS[1]"
make_app "$APPS_ROOTS[2]" Alice
collect_payload
check 'machine failure keeps readable per-user rows' 'p["collection_status"]["apps"] != "complete" and any(a["identifier"] == "com.synthetic.Alice" and a.get("user_account") == "synthetic_alice" for a in p["apps"])'
check 'machine failure keeps independent per-user authority' 'any(u["user_account"] == "synthetic_alice" and u["collection_status"] == "complete" for u in p["collection_status"].get("apps_users", []))'
print -r -- "PAT-2075 safety total: $pass passed; $fail failed"
(( fail == 0 ))
