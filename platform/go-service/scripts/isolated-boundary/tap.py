"""Recording reverse proxy between the staff console and the platform's internal API.

Logs method, path, and whether the Authorization header carried exactly the
throwaway admin token (the token itself is never written), then forwards the
request unchanged. Used to prove what the console sends upstream.

Usage: python tap.py <listen-port> <upstream-port> <log-file> <admin-token-file>
"""
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN, UPSTREAM, LOG, TOKEN_FILE = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
TOKEN = open(TOKEN_FILE).read().strip()
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length"}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        auth = self.headers.get("Authorization", "")
        entry = {
            "t": time.time(), "method": self.command, "path": self.path,
            "auth": "admin" if auth == f"Bearer {TOKEN}" else ("none" if not auth else "other"),
            "body_len": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
            "body_text": body[:2000].decode("utf-8", "replace"),
            "header_names": sorted(k.lower() for k in self.headers.keys()),
            "x_actor": self.headers.get("X-Actor") or self.headers.get("X-Admin-Actor") or "",
        }
        req = urllib.request.Request(f"http://127.0.0.1:{UPSTREAM}{self.path}", data=body or None, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in HOP:
                req.add_header(k, v)
        try:
            resp = urllib.request.urlopen(req, timeout=60)
            status, data, hdrs = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            status, data, hdrs = e.code, e.read(), e.headers
        except Exception as e:  # upstream down
            status, data, hdrs = 502, str(e).encode(), {}
        entry["status"] = status
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self.send_response(status)
        for k, v in hdrs.items():
            if k.lower() not in HOP:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _do

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", LISTEN), H).serve_forever()
