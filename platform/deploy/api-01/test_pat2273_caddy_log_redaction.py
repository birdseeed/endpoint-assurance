"""PAT-2273: every access `log` block in api-vps-artefacts/Caddyfile.api must
delete credential-bearing headers before the entry is written.

Before this ticket both site blocks used plain `format json`, so the portal's
`Cf-Access-Jwt-Assertion` (a bearer JWT for a user's Cloudflare Access session)
and the agent/webhook HMAC signatures were written verbatim to
/var/log/caddy/*.access.log. Caddy's default `log_credentials off` only masks
Authorization/Cookie/Set-Cookie values; it does not know about these headers.

Same technique as the other guards in this directory: read the real file as
text and assert on it. Each `log { ... }` block must use `format filter` and
contain a `<field> delete` line for every entry in REQUIRED_DELETES. Field
names are case-sensitive in Caddy's filter encoder and must match the
canonical header spelling that appears in the JSON log.

Run with: python3 -m unittest discover -s deploy/api-01 -p 'test_pat2273_*.py' -v
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CADDYFILE = REPO_ROOT / "api-vps-artefacts" / "Caddyfile.api"

REQUIRED_DELETES = (
    "request>headers>Authorization",
    "request>headers>Proxy-Authorization",
    "request>headers>Cookie",
    "request>headers>Cf-Access-Jwt-Assertion",
    "request>headers>Cf-Access-Client-Id",
    "request>headers>Cf-Access-Client-Secret",
    "request>headers>X-Patched-Signature",
    "request>headers>Linear-Signature",
    "resp_headers>Set-Cookie",
)


def _strip_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def log_blocks(text: str) -> list[str]:
    """Return the body of every `log { ... }` directive, brace-matched."""
    text = _strip_comments(text)
    blocks = []
    for m in re.finditer(r"(?m)^\s*log\s*\{", text):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        if depth:
            raise AssertionError(f"unbalanced braces in log block at offset {m.start()}")
        blocks.append(text[m.end() : i - 1])
    return blocks


class CaddyLogRedactionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.blocks = log_blocks(CADDYFILE.read_text())

    def test_access_log_blocks_exist(self) -> None:
        # Two access logs today (public ingestion + Tailscale admin). If a
        # block disappears this guard would otherwise pass vacuously.
        self.assertGreaterEqual(len(self.blocks), 2, "expected >=2 log blocks in Caddyfile.api")

    def test_every_log_block_uses_filter_encoder(self) -> None:
        for n, body in enumerate(self.blocks, 1):
            with self.subTest(block=n):
                self.assertRegex(body, r"(?m)^\s*format\s+filter\s*\{", f"log block {n} must use `format filter`")
                self.assertNotRegex(body, r"(?m)^\s*format\s+json\s*$", f"log block {n} still uses bare `format json`")

    def test_every_log_block_deletes_credential_headers(self) -> None:
        for n, body in enumerate(self.blocks, 1):
            for field in REQUIRED_DELETES:
                with self.subTest(block=n, field=field):
                    self.assertRegex(
                        body,
                        rf"(?m)^\s*{re.escape(field)}\s+delete\s*$",
                        f"log block {n} in Caddyfile.api does not delete {field}",
                    )


if __name__ == "__main__":
    unittest.main()
