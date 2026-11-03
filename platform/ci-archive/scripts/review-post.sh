#!/usr/bin/env bash
# review-post.sh — post a GitHub-Non-Author-Review as the `patched-reviewer` GitHub App.
# Sets the required check run `patched/non-author-review` (the gate) and posts the review
# summary on the PR. The check run is what blocks merge; the review is informational UX.
#
# Required env:
#   PATCHED_REVIEWER_APP_ID      GitHub App ID
#   PATCHED_REVIEWER_INSTALL_ID  Installation ID (org install)
#   PATCHED_REVIEWER_KEY         Path to the App private-key PEM (chmod 600)
#
# Usage:
#   review-post.sh --repo Patched-LTD/updater --pr 77 --conclusion failure --body-file review.md
#
# IMPORTANT: run this from the *review* pass, not the authoring session — a separate,
# clean-context review is what makes the gate meaningful (the identity only makes it enforceable).
set -euo pipefail

API="https://api.github.com"
CHECK_NAME="patched/non-author-review"
PY=/usr/bin/python3

REPO=""; PR=""; CONCLUSION=""; BODY_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)        REPO="$2"; shift 2;;
    --pr)          PR="$2"; shift 2;;
    --conclusion)  CONCLUSION="$2"; shift 2;;   # success | failure
    --body-file)   BODY_FILE="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done
: "${REPO:?--repo owner/name}" "${PR:?--pr N}" "${CONCLUSION:?--conclusion success|failure}" "${BODY_FILE:?--body-file path}"
: "${PATCHED_REVIEWER_APP_ID:?set PATCHED_REVIEWER_APP_ID}"
: "${PATCHED_REVIEWER_INSTALL_ID:?set PATCHED_REVIEWER_INSTALL_ID}"
: "${PATCHED_REVIEWER_KEY:?set PATCHED_REVIEWER_KEY}"
[[ -f "$BODY_FILE" ]] || { echo "body file not found: $BODY_FILE" >&2; exit 1; }
[[ "$CONCLUSION" == "success" || "$CONCLUSION" == "failure" ]] || { echo "--conclusion must be success|failure" >&2; exit 1; }

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# 1. App JWT (RS256, <=10 min)
now=$(date +%s)
h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
p=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' "$((now-60))" "$((now+540))" "$PATCHED_REVIEWER_APP_ID" | b64url)
sig=$(printf '%s' "$h.$p" | openssl dgst -sha256 -sign "$PATCHED_REVIEWER_KEY" -binary | b64url)
jwt="$h.$p.$sig"

# 2. Short-lived installation token
tok=$(curl -fsS -X POST \
  -H "Authorization: Bearer $jwt" -H "Accept: application/vnd.github+json" \
  "$API/app/installations/$PATCHED_REVIEWER_INSTALL_ID/access_tokens" \
  | "$PY" -c 'import sys,json; print(json.load(sys.stdin)["token"])')
auth=(-H "Authorization: token $tok" -H "Accept: application/vnd.github+json")

# 3. PR head SHA (check runs attach to a commit)
head_sha=$(curl -fsS "${auth[@]}" "$API/repos/$REPO/pulls/$PR" \
  | "$PY" -c 'import sys,json; print(json.load(sys.stdin)["head"]["sha"])')

# 4. The gate: completed check run with success|failure
title=$([[ "$CONCLUSION" == success ]] && echo "Non-author review passed" || echo "Non-author review: changes requested")
check_payload=$("$PY" - "$CHECK_NAME" "$head_sha" "$CONCLUSION" "$title" "$BODY_FILE" <<'PYEOF'
import sys, json
name, sha, concl, title, bf = sys.argv[1:6]
summary = open(bf, encoding="utf-8").read()[:65000]
print(json.dumps({"name": name, "head_sha": sha, "status": "completed",
                  "conclusion": concl, "output": {"title": title, "summary": summary}}))
PYEOF
)
curl -fsS -X POST "${auth[@]}" "$API/repos/$REPO/check-runs" -d "$check_payload" >/dev/null
echo "check run set: $CHECK_NAME=$CONCLUSION on ${head_sha:0:12}"

# 5. Review summary (informational; app is not the author so APPROVE/REQUEST_CHANGES is allowed)
event=$([[ "$CONCLUSION" == success ]] && echo "APPROVE" || echo "REQUEST_CHANGES")
review_payload=$("$PY" - "$event" "$BODY_FILE" <<'PYEOF'
import sys, json
event, bf = sys.argv[1:3]
print(json.dumps({"event": event, "body": open(bf, encoding="utf-8").read()}))
PYEOF
)
if curl -fsS -X POST "${auth[@]}" "$API/repos/$REPO/pulls/$PR/reviews" -d "$review_payload" >/dev/null; then
  echo "review posted: $event"
else
  echo "warning: review post failed — the check run is the gate, continuing"
fi
