"""Platform read-API client for the Patched customer portal.

The portal holds no estate state and has no database. Every page load reads
customer-scoped data from the platform's public portal endpoints
(https://api.patched.im/v1/portal/*, PAT-693), forwarding the caller's CF
Access JWT verbatim in Cf-Access-Jwt-Assertion. The platform re-verifies
the JWT and derives the tenant from the verified identity - the portal
never sends a tenant identifier.

Env:
  PLATFORM_BASE_URL  default https://api.patched.im
"""

import os

import requests

TIMEOUT_SECONDS = 15
# An error body is only ever parsed for a short refusal message; never hold
# an arbitrarily large one in memory.
MAX_ERROR_BODY_CHARS = 65536
JWT_HEADER = "Cf-Access-Jwt-Assertion"

_session = requests.Session()


def base_url() -> str:
    return os.environ.get("PLATFORM_BASE_URL", "https://api.patched.im").rstrip("/")


class UpstreamError(Exception):
    """Platform call failed. `kind` drives which page the portal renders.

    kinds:
      auth          upstream 401 - identity rejected, send user to re-auth
      forbidden     upstream 403 - verified identity has no estate access
                    (no portal_users row yet, PAT-699) - not a session issue
      not_enabled   upstream 503 - portal access not yet enabled for tenant
      not_found     upstream 404
      rate_limited  upstream 429 - caller is being throttled (e.g. the
                    enrolment-token mint, PAT-453); show a friendly retry
                    message, not a generic error page
      unavailable   network error / timeout / other 5xx
      error         anything else unexpected
    """

    def __init__(self, kind: str, detail: str = "", status: int | None = None,
                 body: str = ""):
        self.kind = kind
        self.detail = detail
        # PAT-2008: the approval write needs the platform's own refusal body
        # ({"error","message","items"}) to tell the customer which product
        # was refused and why. Carried alongside, never logged: callers log
        # only `kind`, as before.
        self.status = status
        self.body = body
        super().__init__(f"{kind}: {detail}")


def _classify(status_code: int) -> str:
    if status_code == 401:
        return "auth"
    if status_code == 403:
        return "forbidden"
    if status_code == 503:
        return "not_enabled"
    if status_code == 404:
        return "not_found"
    if status_code == 429:
        return "rate_limited"
    if status_code >= 500:
        return "unavailable"
    return "error"


def _request(
    method: str, path: str, jwt_token: str, stream: bool = False, payload=None,
    params: dict | None = None, data: dict | None = None, files: dict | None = None,
    extra_headers: dict | None = None,
) -> requests.Response:
    url = f"{base_url()}{path}"
    headers = {JWT_HEADER: jwt_token}
    if extra_headers:
        headers.update(extra_headers)
    try:
        resp = _session.request(
            method, url, headers=headers, timeout=TIMEOUT_SECONDS, stream=stream,
            json=payload, params=params, data=data, files=files,
        )
    except requests.RequestException as exc:
        raise UpstreamError("unavailable", str(exc)) from exc
    if resp.status_code == 400:
        # Platform rejected the submitted values (validation). Surface the
        # reason so the page can show it next to the form.
        raise UpstreamError("invalid", resp.text.strip() or f"{method} {path} -> 400",
                            status=400, body=resp.text[:MAX_ERROR_BODY_CHARS])
    if resp.status_code >= 400:
        raise UpstreamError(_classify(resp.status_code), f"{method} {path} -> {resp.status_code}",
                            status=resp.status_code, body=resp.text[:MAX_ERROR_BODY_CHARS])
    return resp


def get_json(path: str, jwt_token: str, params: dict | None = None) -> dict | list:
    """`params` is form-encoded onto the URL (e.g. findings pagination's
    `limit`/`offset`, PAT-1201) - never appended to `path` by callers, so it
    stays properly escaped."""
    resp = _request("GET", path, jwt_token, params=params)
    try:
        return resp.json()
    except ValueError as exc:
        raise UpstreamError("error", f"non-JSON body from {path}") from exc


def post_json(path: str, jwt_token: str, payload: dict | None = None) -> dict | list:
    """POST, optionally with a JSON body (payload=None sends none, matching
    the pre-existing no-body callers like report generation)."""
    resp = _request("POST", path, jwt_token, payload=payload)
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise UpstreamError("error", f"non-JSON body from {path}") from exc


def post_multipart(
    path: str, jwt_token: str, fields: dict[str, str], screenshot: tuple | None,
    portal_build: str, browser: str,
) -> dict | list:
    """Forward the bounded feedback form without retaining any customer data.

    ``requests`` owns multipart boundary generation.  The portal only adds
    the verified session JWT and its own build identifier; tenant and actor
    remain entirely platform-derived.
    """
    # Always multipart (PAT-2233): with files=None, requests silently falls
    # back to application/x-www-form-urlencoded, which the platform rejects,
    # so every report without a screenshot failed. Text fields go as
    # (None, value) parts, which requests encodes as plain form fields.
    files: dict[str, tuple] = {name: (None, value) for name, value in fields.items()}
    if screenshot:
        files["screenshot"] = screenshot
    resp = _request(
        "POST", path, jwt_token, files=files,
        extra_headers={"X-Portal-Build": portal_build, "User-Agent": browser},
    )
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise UpstreamError("error", f"non-JSON body from {path}") from exc


# A rendered list PDF is a few pages of text; refuse anything wildly larger
# rather than hold it in memory.
MAX_POST_BYTES_RESPONSE = 64 * 1024 * 1024


def post_bytes(path: str, jwt_token: str, payload: dict,
               accept: str = "application/pdf") -> bytes:
    """POST a JSON body upstream and return the raw bytes of a binary answer
    (PAT-2405: the platform renders a list export as a PDF). Same timeout,
    JWT header and error mapping as every other call; the answer must carry
    the expected media type, otherwise it is a platform fault, never bytes
    to hand a customer as a download."""
    resp = _request("POST", path, jwt_token, stream=True, payload=payload,
                    extra_headers={"Accept": accept})
    try:
        content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != accept:
            raise UpstreamError("error", f"unexpected content type from {path}")
        chunks: list[bytes] = []
        size = 0
        try:
            for chunk in resp.iter_content(chunk_size=65536):
                size += len(chunk)
                if size > MAX_POST_BYTES_RESPONSE:
                    raise UpstreamError("unavailable", f"oversized body from {path}")
                chunks.append(chunk)
        except requests.exceptions.RequestException as exc:
            raise UpstreamError("unavailable", str(exc)) from exc
        if not size:
            raise UpstreamError("error", f"empty body from {path}")
        return b"".join(chunks)
    finally:
        resp.close()


def put_json(path: str, jwt_token: str, payload: dict) -> dict | list:
    """PUT a JSON body upstream (PAT-703 report schedule). The JWT is
    forwarded verbatim, exactly as for reads; the platform re-verifies it
    and derives the tenant server-side."""
    resp = _request("PUT", path, jwt_token, payload=payload)
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise UpstreamError("error", f"non-JSON body from {path}") from exc


def patch_json(path: str, jwt_token: str, payload: dict) -> dict | list:
    """PATCH bounded metadata with the caller's JWT and no local identity."""
    resp = _request("PATCH", path, jwt_token, payload=payload)
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise UpstreamError("error", f"non-JSON body from {path}") from exc


def delete_json(path: str, jwt_token: str) -> dict | list:
    """DELETE with no body (PAT-2135's device-list clear). The JWT is
    forwarded verbatim, exactly as for reads; the platform re-verifies it
    and derives the tenant server-side."""
    resp = _request("DELETE", path, jwt_token)
    if not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise UpstreamError("error", f"non-JSON body from {path}") from exc


def stream(path: str, jwt_token: str, params: dict | None = None) -> requests.Response:
    """Streamed GET for report downloads and proxied CSV exports (PAT-2147).
    Caller must close the response. `params` is form-encoded onto the URL
    exactly like get_json's, never appended to `path` by callers."""
    # iter_content decodes compression, while download proxies retain the
    # upstream Content-Length to detect truncated transfers. Request identity
    # so the declared length describes exactly the bytes we will deliver.
    resp = _request("GET", path, jwt_token, stream=True, params=params,
                    extra_headers={"Accept-Encoding": "identity"})
    if resp.headers.get("Content-Encoding", "identity").strip().lower() not in ("", "identity"):
        # Refuse an upstream that ignores negotiation before committing a 200.
        # Dropping the length would hide truncation; decoding with it retained
        # would produce invalid framing. Do not buffer unbounded downloads.
        resp.close()
        raise UpstreamError("unavailable", "unexpected encoding on streamed download")
    return resp


class UpstreamStreamError(Exception):
    """A streamed transfer (a report PDF download) broke partway through,
    after headers were already sent to the client. Distinct from
    UpstreamError, which is only ever raised before the response starts."""


def iter_stream(resp: requests.Response, chunk_size: int = 65536):
    """Iterate a streamed response's body, raising instead of ending quietly
    if the transfer breaks partway through.

    By the time this runs, the caller's HTTP response has already committed
    its 200 status and headers, so raising here cannot change the status
    code - a caller streaming this into a StreamingResponse must also
    forward the upstream Content-Length when available (see main.py's
    download_report) so a short transfer aborts the connection at the
    framing layer instead of completing as if it had succeeded. Without a
    declared Content-Length, this exception on its own is not enough: the
    portal's global JWT middleware is a BaseHTTPMiddleware, which swallows
    an exception raised deep in a streaming response and finishes the
    connection cleanly regardless.
    """
    try:
        yield from resp.iter_content(chunk_size=chunk_size)
    except requests.exceptions.RequestException as exc:
        raise UpstreamStreamError(f"stream interrupted: {exc}") from exc


def unwrap_list(data, key: str) -> list:
    """Accept either a bare JSON array or an object wrapping it under `key`.

    Anything else is a platform contract violation, not an empty result. An
    empty tenant is `[]` or `{key: []}` - both handled above. A response
    that is some other shape (a dict missing `key`, `key` holding something
    other than a list, a bare string/number, null...) must not be silently
    turned into an empty list: that would render pages like Findings or
    Devices as a clean, empty estate when the real story is a broken or
    drifted platform contract - an incident, not "nothing to report".
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        value = data.get(key)
        if isinstance(value, list):
            return value
    raise UpstreamError(
        "error", f"unexpected response shape for '{key}': {type(data).__name__}"
    )
