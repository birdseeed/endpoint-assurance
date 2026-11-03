#!/usr/bin/env python3
"""
linear_client.py — minimal Linear GraphQL API client (PAT-912, extended PAT-985).

Stdlib-only (urllib), no SDK dependency. Originally implemented exactly what
verifier/alerting.py needs to turn a verification 'alert' into visible signal:
look up the PAT team, ensure the 'supply-chain' label exists (create it if
not), find an already-open issue for a given finding, open a new issue, and
comment on an existing one.

PAT-985 added the read side needed by verifier/done_audit.py: paginated
completed-issue listing (with labels and a bounded window of comments
inlined, to avoid one request per issue) and a single-issue-by-number lookup
with its full comment history (used to find PAT-985 itself and read back the
audit's own previous-run marker).

Auth: Linear's REST-flavoured API-key auth sends the raw key in the
Authorization header (no "Bearer " prefix) — this is a personal/workspace API
key (LINEAR_API_TOKEN), not an OAuth access token.

Every method raises LinearAPIError on a transport failure or a GraphQL
errors[] response; callers decide what that means for them (the retired
verify.py, deleted 2026-09-30 by PAT-2304, logged a
warning and did not change its own exit code — alerting is additional
signal, not the primary failure gate. See docs/verification-agent-design.md
§7 and the "Assert Linear alerting token present" step in
daily-vendor-verify.yml for where an absent token is instead treated as fatal
on the canonical scheduled run. verifier/done_audit.py takes the stricter
line: querying and posting to Linear IS its entire job, so it treats a
transport/API failure as fatal rather than a gracefully-degraded warning).

No network calls happen at import time or module load — every request is
made explicitly through a LinearClient instance, so tests can stub the class
out entirely without touching urllib.
"""

import json
import urllib.error
import urllib.request

GRAPHQL_URL = "https://api.linear.app/graphql"

# Comments inlined per issue in get_completed_issues()'s bulk listing query.
# Bounded rather than fully paginated, deliberately: this keeps the bulk
# sweep to one request per page of ISSUES (not one request per issue per
# comment page) for a 780+-issue workspace. An issue with more than this
# many comments could in principle carry evidence past the cut that the
# sweep would then miss — an accepted limitation of a "worth checking"
# heuristic, not a correctness guarantee. See done_audit.py's module
# docstring.
ISSUE_COMMENT_PAGE_SIZE = 200


class LinearAPIError(RuntimeError):
    """Transport failure or a GraphQL errors[] response."""


class LinearClient:
    def __init__(self, token: str, endpoint: str = GRAPHQL_URL, timeout: int = 30):
        if not token:
            raise ValueError("LinearClient requires a non-empty API token")
        self._token = token
        self._endpoint = endpoint
        self._timeout = timeout

    def _request(self, query: str, variables: dict) -> dict:
        body = json.dumps({"query": query, "variables": variables}).encode()
        req = urllib.request.Request(
            self._endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": self._token,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            raise LinearAPIError(f"HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise LinearAPIError(f"transport error: {e}") from e
        except json.JSONDecodeError as e:
            raise LinearAPIError(f"non-JSON response: {e}") from e
        if payload.get("errors"):
            raise LinearAPIError(f"GraphQL errors: {payload['errors']}")
        if "data" not in payload:
            raise LinearAPIError(f"GraphQL response missing 'data': {payload}")
        return payload["data"]

    def get_team_id(self, key: str) -> str:
        """Return the Linear internal id of the team with the given key
        (e.g. 'PAT'). Raises LinearAPIError if no such team exists."""
        data = self._request(
            """
            query($key: String!) {
              teams(filter: { key: { eq: $key } }) {
                nodes { id key }
              }
            }
            """,
            {"key": key},
        )
        nodes = data["teams"]["nodes"]
        if not nodes:
            raise LinearAPIError(f"no Linear team with key {key!r}")
        return nodes[0]["id"]

    def ensure_label(self, team_id: str, name: str) -> str:
        """Return the id of the issue label 'name' on this team, creating it
        if it does not already exist."""
        data = self._request(
            """
            query($teamId: ID!, $name: String!) {
              issueLabels(filter: {
                team: { id: { eq: $teamId } }
                name: { eq: $name }
              }) {
                nodes { id name }
              }
            }
            """,
            {"teamId": team_id, "name": name},
        )
        nodes = data["issueLabels"]["nodes"]
        if nodes:
            return nodes[0]["id"]

        data = self._request(
            """
            mutation($teamId: String!, $name: String!) {
              issueLabelCreate(input: { teamId: $teamId, name: $name }) {
                success
                issueLabel { id }
              }
            }
            """,
            {"teamId": team_id, "name": name},
        )
        result = data["issueLabelCreate"]
        if not result["success"] or not result.get("issueLabel"):
            raise LinearAPIError(f"issueLabelCreate failed for label {name!r}")
        return result["issueLabel"]["id"]

    def find_open_issue_by_marker(self, team_id: str, label_id: str, marker: str) -> str | None:
        """Search open (not completed/canceled) issues on this team carrying
        the given label for one whose description contains `marker`. Returns
        the issue id, or None if no match. `marker` is the finding-fingerprint
        HTML-comment string alerting.py embeds in the issue description —
        this is the idempotency check."""
        data = self._request(
            """
            query($teamId: ID!, $labelId: ID!) {
              issues(
                filter: {
                  team: { id: { eq: $teamId } }
                  labels: { some: { id: { eq: $labelId } } }
                  completedAt: { null: true }
                  canceledAt: { null: true }
                }
                first: 100
              ) {
                nodes { id description }
              }
            }
            """,
            {"teamId": team_id, "labelId": label_id},
        )
        for node in data["issues"]["nodes"]:
            if marker in (node.get("description") or ""):
                return node["id"]
        return None

    def create_issue(self, team_id: str, label_id: str, title: str, description: str) -> str:
        data = self._request(
            """
            mutation($teamId: String!, $labelId: String!, $title: String!, $description: String!) {
              issueCreate(input: {
                teamId: $teamId
                labelIds: [$labelId]
                title: $title
                description: $description
              }) {
                success
                issue { id identifier }
              }
            }
            """,
            {"teamId": team_id, "labelId": label_id, "title": title, "description": description},
        )
        result = data["issueCreate"]
        if not result["success"] or not result.get("issue"):
            raise LinearAPIError(f"issueCreate failed for title {title!r}")
        return result["issue"]["id"]

    def create_comment(self, issue_id: str, body: str) -> str:
        data = self._request(
            """
            mutation($issueId: String!, $body: String!) {
              commentCreate(input: { issueId: $issueId, body: $body }) {
                success
                comment { id }
              }
            }
            """,
            {"issueId": issue_id, "body": body},
        )
        result = data["commentCreate"]
        if not result["success"] or not result.get("comment"):
            raise LinearAPIError(f"commentCreate failed for issue {issue_id!r}")
        return result["comment"]["id"]

    # ----------------------------------------------------------------
    # PAT-985: done-without-evidence audit reads
    # ----------------------------------------------------------------

    def get_completed_issues(self, team_key: str, completed_after: str,
                              page_size: int = 50):
        """Yield every completed issue on `team_key` with completedAt >=
        `completed_after` (an ISO-8601 UTC string, e.g.
        "2026-12-26T00:00:00Z"), fully paginated via cursor (`after`) so a
        workspace with hundreds of completed issues is never silently
        truncated to the first page.

        Each yielded dict: id, identifier, title, description, url,
        completedAt, labels (list of label name strings), comments (list of
        comment body strings, capped at ISSUE_COMMENT_PAGE_SIZE — see that
        constant's docstring).

        Batches labels and a bounded comment window into the same request as
        the issue itself (GraphQL nested connections) rather than issuing a
        separate request per issue, to stay well inside rate limits against
        a 780+-issue workspace.
        """
        query = """
        query($teamKey: String!, $completedAfter: DateTimeOrDuration!,
              $after: String, $pageSize: Int!, $commentPageSize: Int!) {
          issues(
            filter: {
              team: { key: { eq: $teamKey } }
              completedAt: { gte: $completedAfter }
            }
            first: $pageSize
            after: $after
            orderBy: updatedAt
          ) {
            pageInfo { hasNextPage endCursor }
            nodes {
              id
              identifier
              title
              description
              url
              completedAt
              labels { nodes { name } }
              comments(first: $commentPageSize) {
                nodes { body }
              }
            }
          }
        }
        """
        after = None
        while True:
            data = self._request(query, {
                "teamKey": team_key,
                "completedAfter": completed_after,
                "after": after,
                "pageSize": page_size,
                "commentPageSize": ISSUE_COMMENT_PAGE_SIZE,
            })
            conn = data["issues"]
            for node in conn["nodes"]:
                yield {
                    "id": node["id"],
                    "identifier": node["identifier"],
                    "title": node.get("title") or "",
                    "description": node.get("description") or "",
                    "url": node.get("url") or "",
                    "completedAt": node.get("completedAt"),
                    "labels": [n["name"] for n in node.get("labels", {}).get("nodes", [])],
                    "comments": [c["body"] or "" for c in node.get("comments", {}).get("nodes", [])],
                }
            page_info = conn["pageInfo"]
            if not page_info["hasNextPage"]:
                break
            after = page_info["endCursor"]

    def get_issue_by_number(self, team_key: str, number: int) -> dict | None:
        """Return {id, identifier, comments: [{'body', 'createdAt'}, ...]}
        for the single issue identified by team key + issue number (e.g.
        team_key='PAT', number=985 for "PAT-985"), or None if no such issue
        exists. Unlike get_completed_issues(), comments here are paginated
        to completeness rather than capped — this is used to read the
        audit's own report thread back, so a stale cap could hide the most
        recent marker and cause a duplicate post."""
        query = """
        query($teamKey: String!, $number: Float!) {
          issues(
            filter: { team: { key: { eq: $teamKey } }, number: { eq: $number } }
            first: 1
          ) {
            nodes { id identifier }
          }
        }
        """
        data = self._request(query, {"teamKey": team_key, "number": float(number)})
        nodes = data["issues"]["nodes"]
        if not nodes:
            return None
        issue_id = nodes[0]["id"]
        return {
            "id": issue_id,
            "identifier": nodes[0]["identifier"],
            "comments": list(self._iter_all_comments(issue_id)),
        }

    def _iter_all_comments(self, issue_id: str, page_size: int = 100):
        query = """
        query($issueId: String!, $after: String, $pageSize: Int!) {
          issue(id: $issueId) {
            comments(first: $pageSize, after: $after) {
              pageInfo { hasNextPage endCursor }
              nodes { body createdAt }
            }
          }
        }
        """
        after = None
        while True:
            data = self._request(query, {"issueId": issue_id, "after": after, "pageSize": page_size})
            conn = data["issue"]["comments"]
            for node in conn["nodes"]:
                yield {"body": node.get("body") or "", "createdAt": node.get("createdAt")}
            page_info = conn["pageInfo"]
            if not page_info["hasNextPage"]:
                break
            after = page_info["endCursor"]
