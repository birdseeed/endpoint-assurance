"""Portable fixture-owner contract; temporary records do not claim queue ownership."""
import json
from pathlib import Path

import pytest

from tests.pat1966_support import assert_owner


@pytest.fixture(autouse=True)
def clean_test_owner_env(monkeypatch):
    monkeypatch.delenv("QUEUE_RUN_TEST_OWNER_PATH", raising=False)
    monkeypatch.delenv("QUEUE_RUN_TEST_OWNER_NONCE", raising=False)


def test_unset_pair_never_reads_owner_state(monkeypatch):
    def forbidden_read(*args, **kwargs):
        pytest.fail("Unset test owner configuration must not read any file")
    monkeypatch.setattr(Path, "read_text", forbidden_read)
    assert_owner()


@pytest.mark.parametrize("path,nonce", [
    (None, ""), ("", None), ("record.json", None), (None, "fixture-nonce"),
    ("record.json", ""), ("", "fixture-nonce"), ("", ""),
])
def test_incomplete_pair_fails_before_read(monkeypatch, path, nonce):
    if path is not None:
        monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_PATH", path)
    if nonce is not None:
        monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_NONCE", nonce)
    def forbidden_read(*args, **kwargs):
        pytest.fail("Incomplete configuration must fail before any file read")
    monkeypatch.setattr(Path, "read_text", forbidden_read)
    with pytest.raises(AssertionError, match="nonempty"):
        assert_owner()


@pytest.mark.parametrize("failure", ["missing", "permission"])
def test_unreadable_record_fails_closed(tmp_path, monkeypatch, failure):
    owner = tmp_path / "owned-test-record.json"
    monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_PATH", str(owner))
    monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_NONCE", "fixture-nonce")
    if failure == "permission":
        def denied(path, *args, **kwargs):
            assert path == owner
            raise PermissionError("Test-only denied read")
        monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(AssertionError, match="unreadable or malformed"):
        assert_owner()


@pytest.mark.parametrize("payload", ["not JSON", "{}", "[]", "null", '"scalar"'])
def test_malformed_record_fails_closed(tmp_path, monkeypatch, payload):
    owner = tmp_path / "owned-test-record.json"
    owner.write_text(payload)
    monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_PATH", str(owner))
    monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_NONCE", "fixture-nonce")
    with pytest.raises(AssertionError, match="unreadable or malformed"):
        assert_owner()


@pytest.mark.parametrize("actual", ["different-fixture-nonce", None])
def test_nonce_mismatch_fails_closed(tmp_path, monkeypatch, actual):
    owner = tmp_path / "owned-test-record.json"
    owner.write_text(json.dumps({"owner_nonce": actual}))
    monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_PATH", str(owner))
    monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_NONCE", "fixture-nonce")
    with pytest.raises(AssertionError, match="nonce mismatch"):
        assert_owner()


def test_matching_owned_record_reads_exact_configured_path(tmp_path, monkeypatch):
    owner = tmp_path / "explicit-test-record.json"
    owner.write_text(json.dumps({"owner_nonce": "fixture-nonce"}))
    monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_PATH", str(owner))
    monkeypatch.setenv("QUEUE_RUN_TEST_OWNER_NONCE", "fixture-nonce")
    original_read = Path.read_text
    reads = []
    def read_exact(path, *args, **kwargs):
        reads.append(path)
        assert path == owner
        return original_read(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", read_exact)
    assert_owner()
    assert reads == [owner]
