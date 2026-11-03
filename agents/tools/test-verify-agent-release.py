#!/usr/bin/env python3
"""
test-verify-agent-release.py - CI self-test for verify-agent-release.py (PAT-892).

Exercises the tool fully offline via --sums / --hmac / --key-file, no
network required. Pure Python 3 stdlib, same as the tool under test.

Covers the PAT-892 fail-before/pass-after contract:
  - Valid case: correctly signed fixture with matching checksum passes.
  - Tampered artifact, attacker-regenerated SHA256SUMS: this is the exact
    PAT-892 scenario (attacker who can push a release asset regenerates a
    self-consistent SHA256SUMS to match the tampered file). The checksum
    alone is consistent, but the HMAC was computed by CI over the original
    bytes with a key the attacker does not have, so it now fails to verify
    over the tampered bytes. Confirms the checksum-only predecessor of this
    tool would have accepted this file; the fixed tool rejects it.
  - Wrong signing key: correct file, correct SHA256SUMS, correct .hmac
    asset, but verifying with the wrong key recomputes a different HMAC and
    fails.
  - Missing .hmac asset: fails closed rather than silently falling back to
    the SHA256SUMS-only check.
  - Missing signing key entirely: fails closed with guidance, rather than
    treating "no key configured" as "skip the signature check".
"""

import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPT = os.path.join(_HERE, "verify-agent-release.py")
_SPEC = importlib.util.spec_from_file_location("verify_agent_release", _SCRIPT)
assert _SPEC and _SPEC.loader
_VERIFIER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_VERIFIER)

SIGNING_KEY = "test-signing-key-not-a-real-secret"
WRONG_KEY = "wrong-key-does-not-match"


def _hmac_hex(key: str, data: bytes) -> str:
    return hmac.new(key.encode(), data, digestmod=hashlib.sha256).hexdigest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_github_token_authorization_header_is_optional():
    """Private-release auth is environment-only and public requests stay anonymous."""
    assert _VERIFIER.GITHUB_TOKEN_ENV == "GITHUB_TOKEN"
    previous = os.environ.pop("GITHUB_TOKEN", None)
    try:
        unauthenticated = _VERIFIER._github_request(
            "https://api.github.com/repos/Patched-LTD/updater/releases/tags/test",
            "application/vnd.github+json",
        )
        assert unauthenticated.get_header("Authorization") is None

        os.environ["GITHUB_TOKEN"] = "test-github-token-not-a-real-secret"
        authenticated = _VERIFIER._github_request(
            "https://api.github.com/repos/Patched-LTD/updater/releases/tags/test",
            "application/vnd.github+json",
        )
        assert authenticated.get_header("Authorization") == "Bearer test-github-token-not-a-real-secret"
    finally:
        if previous is None:
            os.environ.pop("GITHUB_TOKEN", None)
        else:
            os.environ["GITHUB_TOKEN"] = previous
    print("PASS: GitHub Authorization header is present only when GITHUB_TOKEN is set")


def test_private_release_asset_api_urls_keep_authorization():
    """Authenticated asset fetches must use the API URL, not a redirecting browser URL."""
    asset_name = "patched-updater-test.tar.gz.hmac"
    api_url = "https://api.github.com/repos/Patched-LTD/updater/releases/assets/42"
    browser_url = "https://github.com/Patched-LTD/updater/releases/download/test/asset.hmac"
    payload = json.dumps({
        "assets": [{"name": asset_name, "url": api_url, "browser_download_url": browser_url}],
    }).encode()
    requests = []

    class Response:
        def __init__(self, body: bytes, headers=None):
            self.body = body
            self.headers = headers or {}
            self.offset = 0

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc_value, _traceback):
            return False

        def read(self, size=-1) -> bytes:
            if size is None or size < 0:
                size = len(self.body) - self.offset
            result = self.body[self.offset:self.offset + size]
            self.offset += len(result)
            return result

    def fake_urlopen(request, timeout):
        requests.append(request)
        if request.full_url.startswith(_VERIFIER.GH_RELEASES_API):
            return Response(payload)
        if request.full_url in (api_url, browser_url):
            return Response(b"signature")
        raise AssertionError(f"unexpected URL: {request.full_url}")

    previous_token = os.environ.pop("GITHUB_TOKEN", None)
    try:
        with patch.object(_VERIFIER.urllib.request, "urlopen", side_effect=fake_urlopen):
            public_assets = _VERIFIER._get_release_assets("test")
            assert public_assets[asset_name] == browser_url
            assert requests[-1].get_header("Authorization") is None
            assert _VERIFIER._fetch_text(public_assets[asset_name]) == "signature"
            assert requests[-1].full_url == browser_url
            assert requests[-1].get_header("Authorization") is None

            os.environ["GITHUB_TOKEN"] = "test-github-token-not-a-real-secret"
            private_assets = _VERIFIER._get_release_assets("test")
            assert private_assets[asset_name] == api_url
            assert requests[-1].get_header("Authorization") == "Bearer test-github-token-not-a-real-secret"
            assert _VERIFIER._fetch_text(private_assets[asset_name]) == "signature"
            assert requests[-1].full_url == api_url
            assert requests[-1].get_header("Authorization") == "Bearer test-github-token-not-a-real-secret"
    finally:
        if previous_token is None:
            os.environ.pop("GITHUB_TOKEN", None)
        else:
            os.environ["GITHUB_TOKEN"] = previous_token
    print("PASS: private release assets use API URLs with Authorization; public assets stay anonymous")


def test_asset_fetch_http_error_fails_cleanly():
    """Private asset-access failures should not expose an urllib traceback."""
    def fake_urlopen(request, timeout):
        raise _VERIFIER.urllib.error.HTTPError(request.full_url, 404, "not found", None, None)

    with patch.object(_VERIFIER.urllib.request, "urlopen", side_effect=fake_urlopen):
        try:
            _VERIFIER._fetch_text("https://api.github.com/repos/Patched-LTD/updater/releases/assets/42")
        except SystemExit as error:
            assert str(error) == "FATAL: GitHub asset request returned 404 - check release access and asset availability"
        else:
            raise AssertionError("asset HTTP error must fail closed")
    print("PASS: asset HTTP errors fail cleanly without an urllib traceback")


def test_asset_fetch_network_error_fails_cleanly():
    """Network, TLS, and timeout failures must fail closed without a traceback."""
    def fake_urlopen(request, timeout):
        raise _VERIFIER.urllib.error.URLError("network unavailable")

    with patch.object(_VERIFIER.urllib.request, "urlopen", side_effect=fake_urlopen):
        try:
            _VERIFIER._fetch_text("https://api.github.com/repos/Patched-LTD/updater/releases/assets/42")
        except SystemExit as error:
            message = str(error)
            assert message == "FATAL: GitHub asset request failed due to a network, TLS, or timeout error"
            assert "Traceback" not in message
        else:
            raise AssertionError("asset network error must fail closed")
    print("PASS: asset network errors fail cleanly without an urllib traceback")


def test_artifact_download_streams_and_replaces_atomically():
    """Large artifacts are chunked and only replace the destination once complete."""
    data = b"x" * (_VERIFIER.ARTIFACT_CHUNK_BYTES * 2 + 17)

    class Response:
        headers = {"Content-Length": str(len(data))}

        def __init__(self):
            self.offset = 0
            self.read_sizes = []

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc_value, _traceback):
            return False

        def read(self, size=-1):
            self.read_sizes.append(size)
            if size is None or size < 0:
                size = len(data) - self.offset
            result = data[self.offset:self.offset + size]
            self.offset += len(result)
            return result

    response = Response()
    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory) / "agent.tar.gz"
        destination.write_bytes(b"previous artifact")
        with patch.object(_VERIFIER.urllib.request, "urlopen", return_value=response):
            _VERIFIER._fetch_bytes("https://example.test/agent.tar.gz", destination)
        assert destination.read_bytes() == data
        assert len(response.read_sizes) > 2
        assert set(response.read_sizes) == {_VERIFIER.ARTIFACT_CHUNK_BYTES}
        assert not list(Path(directory).glob(".agent.tar.gz.*.part"))
    print("PASS: artifact download is chunked and atomically replaces the destination")


def test_oversized_responses_are_rejected_before_writing():
    """Declared oversize text and artifacts fail closed without touching a destination."""
    class OversizedResponse:
        def __init__(self, limit):
            self.headers = {"Content-Length": str(limit + 1)}

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc_value, _traceback):
            return False

        def read(self, _size=-1):
            raise AssertionError("oversize Content-Length must reject before reading")

    with patch.object(
        _VERIFIER.urllib.request, "urlopen", return_value=OversizedResponse(_VERIFIER.MAX_TEXT_RESPONSE_BYTES)
    ):
        try:
            _VERIFIER._fetch_text("https://example.test/SHA256SUMS")
        except SystemExit as error:
            assert str(error) == "FATAL: GitHub text asset exceeds the maximum allowed size"
        else:
            raise AssertionError("oversized text response must fail closed")

    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory) / "agent.tar.gz"
        destination.write_bytes(b"previous artifact")
        with patch.object(
            _VERIFIER.urllib.request, "urlopen", return_value=OversizedResponse(_VERIFIER.MAX_ARTIFACT_BYTES)
        ):
            try:
                _VERIFIER._fetch_bytes("https://example.test/agent.tar.gz", destination)
            except SystemExit as error:
                assert str(error) == "FATAL: GitHub artifact exceeds the maximum allowed size"
            else:
                raise AssertionError("oversized artifact response must fail closed")
        assert destination.read_bytes() == b"previous artifact"
        assert not list(Path(directory).glob(".agent.tar.gz.*.part"))

    class MisreportedResponse:
        headers = {"Content-Length": "1"}

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc_value, _traceback):
            return False

        def read(self, _size=-1):
            if hasattr(self, "read_once"):
                return b""
            self.read_once = True
            return b"123456"

    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory) / "agent.tar.gz"
        destination.write_bytes(b"previous artifact")
        with patch.object(_VERIFIER, "MAX_ARTIFACT_BYTES", 5), patch.object(
            _VERIFIER.urllib.request, "urlopen", return_value=MisreportedResponse()
        ):
            try:
                _VERIFIER._fetch_bytes("https://example.test/agent.tar.gz", destination)
            except SystemExit as error:
                assert str(error) == "FATAL: GitHub artifact exceeds the maximum allowed size"
            else:
                raise AssertionError("misreported artifact size must still fail closed")
        assert destination.read_bytes() == b"previous artifact"
        assert not list(Path(directory).glob(".agent.tar.gz.*.part"))
    print("PASS: oversized text and artifacts are rejected before writing")


def _run(tmp: Path, filename: str, sums_text: str, hmac_text: str | None,
          key_env: str | None = None, key_file: str | None = None) -> subprocess.CompletedProcess:
    sums_path = tmp / "SHA256SUMS"
    sums_path.write_text(sums_text)

    args = [
        sys.executable, _SCRIPT,
        "--sums", str(sums_path),
        "--file", str(tmp / filename),
    ]

    if hmac_text is not None:
        hmac_path = tmp / f"{filename}.hmac"
        hmac_path.write_text(hmac_text)
        args += ["--hmac", str(hmac_path)]

    if key_file is not None:
        args += ["--key-file", key_file]

    env = dict(os.environ)
    env.pop("ARTIFACT_SIGNING_KEY", None)
    if key_env is not None:
        env["ARTIFACT_SIGNING_KEY"] = key_env

    return subprocess.run(args, cwd=tmp, env=env, capture_output=True, text=True)


def test_valid_release_passes():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        filename = "patched-agent-macos-9.9.9.tar.gz"
        data = b"legitimate release bytes, built by CI"
        (tmp / filename).write_bytes(data)

        sha = _sha256_hex(data)
        mac = _hmac_hex(SIGNING_KEY, data)
        sums_text = f"{sha}  {filename}\n"

        result = _run(tmp, filename, sums_text, mac, key_env=SIGNING_KEY)
        assert result.returncode == 0, f"expected pass, got exit {result.returncode}\n{result.stdout}\n{result.stderr}"
        assert "OK" in result.stdout
        print("PASS: valid release with matching HMAC and SHA-256 verifies")


def test_tampered_artifact_with_regenerated_checksum_fails():
    """The exact PAT-892 scenario: attacker replaces the artifact and
    regenerates SHA256SUMS to match it, but cannot regenerate a valid HMAC
    without ARTIFACT_SIGNING_KEY. The original (real) HMAC was computed over
    the original bytes, so it fails to verify against the tampered file."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        filename = "patched-agent-macos-9.9.9.tar.gz"

        original_data = b"legitimate release bytes, built by CI"
        real_hmac = _hmac_hex(SIGNING_KEY, original_data)

        tampered_data = b"malicious payload swapped in by an attacker"
        (tmp / filename).write_bytes(tampered_data)

        # Attacker regenerates SHA256SUMS against the tampered bytes - this
        # is exactly what the pre-PAT-892 tool alone could not catch.
        tampered_sha = _sha256_hex(tampered_data)
        sums_text = f"{tampered_sha}  {filename}\n"

        # The .hmac asset is untouched (attacker has no way to forge it
        # without the key); it still reflects the original artifact.
        result = _run(tmp, filename, sums_text, real_hmac, key_env=SIGNING_KEY)
        assert result.returncode != 0, "tampered artifact with regenerated checksum must be rejected"
        assert "HMAC" in result.stdout and ("MISMATCH" in result.stdout or "FAIL" in result.stdout)
        print("PASS: tampered artifact + attacker-regenerated SHA256SUMS is rejected by HMAC check")


def test_wrong_signing_key_fails():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        filename = "patched-agent-macos-9.9.9.tar.gz"
        data = b"legitimate release bytes, built by CI"
        (tmp / filename).write_bytes(data)

        sha = _sha256_hex(data)
        mac = _hmac_hex(SIGNING_KEY, data)
        sums_text = f"{sha}  {filename}\n"

        result = _run(tmp, filename, sums_text, mac, key_env=WRONG_KEY)
        assert result.returncode != 0, "verifying with the wrong key must fail"
        assert "MISMATCH" in result.stdout
        print("PASS: verifying with the wrong signing key fails")


def test_missing_hmac_asset_fails_closed():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        filename = "patched-agent-macos-9.9.9.tar.gz"
        data = b"legitimate release bytes, built by CI"
        (tmp / filename).write_bytes(data)

        sha = _sha256_hex(data)
        sums_text = f"{sha}  {filename}\n"

        # No --hmac supplied and no --release to fetch one from.
        result = _run(tmp, filename, sums_text, hmac_text=None, key_env=SIGNING_KEY)
        assert result.returncode != 0, "missing .hmac must fail closed, not fall back to checksum-only"
        combined = result.stdout + result.stderr
        assert "--hmac" in combined
        print("PASS: missing .hmac asset fails closed instead of falling back to checksum-only")


def test_missing_signing_key_fails_closed():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        filename = "patched-agent-macos-9.9.9.tar.gz"
        data = b"legitimate release bytes, built by CI"
        (tmp / filename).write_bytes(data)

        sha = _sha256_hex(data)
        mac = _hmac_hex(SIGNING_KEY, data)
        sums_text = f"{sha}  {filename}\n"

        # No key supplied at all (env cleared, no --key-file).
        result = _run(tmp, filename, sums_text, mac, key_env=None)
        assert result.returncode != 0, "missing signing key must fail closed"
        combined = result.stdout + result.stderr
        assert "signing key" in combined.lower()
        print("PASS: missing signing key fails closed with guidance")


def test_key_file_argument_works():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        filename = "patched-agent-macos-9.9.9.tar.gz"
        data = b"legitimate release bytes, built by CI"
        (tmp / filename).write_bytes(data)

        sha = _sha256_hex(data)
        mac = _hmac_hex(SIGNING_KEY, data)
        sums_text = f"{sha}  {filename}\n"

        key_file = tmp / "signing.key"
        key_file.write_text(SIGNING_KEY + "\n")  # trailing newline, as an editor would save it

        result = _run(tmp, filename, sums_text, mac, key_env=None, key_file=str(key_file))
        assert result.returncode == 0, f"expected pass via --key-file, got exit {result.returncode}\n{result.stdout}\n{result.stderr}"
        print("PASS: --key-file supplies the signing key correctly (trailing newline stripped)")


def test_empty_key_file_fails_closed():
    """An empty or whitespace-only --key-file must be treated as no key at all,
    not silently accepted as a real (empty-bytes) HMAC key."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        filename = "patched-agent-macos-9.9.9.tar.gz"
        data = b"legitimate release bytes, built by CI"
        (tmp / filename).write_bytes(data)

        sha = _sha256_hex(data)
        mac = _hmac_hex(SIGNING_KEY, data)
        sums_text = f"{sha}  {filename}\n"

        key_file = tmp / "empty.key"
        key_file.write_text("\n")  # blank file

        result = _run(tmp, filename, sums_text, mac, key_env=None, key_file=str(key_file))
        assert result.returncode != 0, "empty --key-file must fail closed"
        combined = result.stdout + result.stderr
        assert "signing key" in combined.lower()
        print("PASS: empty --key-file fails closed rather than verifying with an empty key")


def test_key_file_not_found_fails_with_clear_error():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        filename = "patched-agent-macos-9.9.9.tar.gz"
        data = b"legitimate release bytes, built by CI"
        (tmp / filename).write_bytes(data)

        sha = _sha256_hex(data)
        mac = _hmac_hex(SIGNING_KEY, data)
        sums_text = f"{sha}  {filename}\n"

        missing_key_file = str(tmp / "does-not-exist.key")
        result = _run(tmp, filename, sums_text, mac, key_env=None, key_file=missing_key_file)
        assert result.returncode != 0, "a nonexistent --key-file must fail"
        combined = result.stdout + result.stderr
        assert "FATAL" in combined and "key-file" in combined
        assert "Traceback" not in combined, "should report a clean FATAL error, not a raw Python traceback"
        print("PASS: nonexistent --key-file fails with a clean error, not a traceback")


def test_sums_without_hmac_and_with_release_still_fails_closed():
    """--sums combined with --release (but no --hmac) must not silently mix a
    local checksum override with a signature fetched live from --release."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        filename = "patched-agent-macos-9.9.9.tar.gz"
        data = b"legitimate release bytes, built by CI"
        (tmp / filename).write_bytes(data)

        sha = _sha256_hex(data)
        sums_text = f"{sha}  {filename}\n"
        sums_path = tmp / "SHA256SUMS"
        sums_path.write_text(sums_text)

        env = dict(os.environ)
        env["ARTIFACT_SIGNING_KEY"] = SIGNING_KEY
        result = subprocess.run(
            [sys.executable, _SCRIPT,
             "--release", "macos-agent-v9.9.9",
             "--sums", str(sums_path),
             "--file", str(tmp / filename)],
            cwd=tmp, env=env, capture_output=True, text=True,
        )
        assert result.returncode != 0, "--sums with --release but no --hmac must be rejected before any network call"
        combined = result.stdout + result.stderr
        assert "--hmac" in combined
        print("PASS: --sums plus --release without --hmac is rejected (no mixed-provenance fetch)")


def main() -> int:
    tests = [
        test_github_token_authorization_header_is_optional,
        test_private_release_asset_api_urls_keep_authorization,
        test_asset_fetch_http_error_fails_cleanly,
        test_asset_fetch_network_error_fails_cleanly,
        test_artifact_download_streams_and_replaces_atomically,
        test_oversized_responses_are_rejected_before_writing,
        test_valid_release_passes,
        test_tampered_artifact_with_regenerated_checksum_fails,
        test_wrong_signing_key_fails,
        test_missing_hmac_asset_fails_closed,
        test_missing_signing_key_fails_closed,
        test_key_file_argument_works,
        test_empty_key_file_fails_closed,
        test_key_file_not_found_fails_with_clear_error,
        test_sums_without_hmac_and_with_release_still_fails_closed,
    ]
    failures = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failures += 1
            print(f"FAIL: {t.__name__}: {e}")
        except Exception as e:
            failures += 1
            print(f"ERROR: {t.__name__}: {e!r}")

    if failures:
        print(f"\n{failures} test(s) failed")
        return 1
    print(f"\nAll {len(tests)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
