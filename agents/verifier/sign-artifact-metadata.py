#!/usr/bin/env python3
"""
sign-artifact-metadata.py — sign Windows agent self-update artifact metadata
with an Ed25519 key (PAT-1248).

Reads a small JSON metadata document from --input (at minimum: version,
platform, channel, artifact_url, artifact_sha256), signs it with the private
key from --key (a base64-encoded 32-byte Ed25519 seed, same format as
CATALOGUE_SIGNING_KEY_B64 / AGENT_CONFIG_SIGNING_KEY) or --kms-key-resource,
and writes a signed JSON envelope to --output.

The signed envelope uses the same shared wire format as sign-catalogue.py:
  {
    "signed_payload": "<base64 of canonical metadata JSON bytes>",
    "signature":      "<base64 of 64-byte Ed25519 signature>",
    "key_id":         "<hex key identifier>"
  }

Verification is done by the Windows agent using the pinned Ed25519 public key
in windows/src/Shared/Verification/ArtifactTrust.cs — see BootstrapUpdater.cs,
which replaces the never-provisioned ARTIFACT_SIGNING_KEY symmetric-HMAC
design this script's key deliberately does NOT reuse: that key also signs the
release MSI itself for human/out-of-band verification
(tools/verify-agent-release.py) and must never be shipped to an endpoint.

KEY SEPARATION (PAT-516): the artifact-metadata key MUST be a distinct
Ed25519 key pair from BOTH the catalogue key and the agent-config key. This
script enforces that by rejecting both known key_ids at runtime, exactly like
sign-catalogue.py rejects the agent-config key_id:

  ARTIFACT_METADATA_SIGNING_KEY_ID  !=  "ecd47f2c5b3d5705"  (agent-config key id)
  ARTIFACT_METADATA_SIGNING_KEY_ID  !=  "734eba29d9f804a0"  (catalogue key id)

See docs/signing-key-architecture.md.

── Signing modes ────────────────────────────────────────────────────────────

Production (GCP Cloud HSM, mirrors PAT-497):
    python3 verifier/sign-artifact-metadata.py \\
        --input  artifact-metadata.json \\
        --kms-key-resource "projects/patched-prod/locations/europe-west1/keyRings/signing/cryptoKeys/artifact-metadata-signing/cryptoKeyVersions/1" \\
        --key-id "$ARTIFACT_METADATA_SIGNING_KEY_ID" \\
        --output artifact-metadata.signed.json

    Requires: pip install google-cloud-kms
    CI auth:  google-github-actions/auth with Workload Identity Federation
    No raw key material ever leaves the HSM.

Development / staging (raw seed):
    python3 verifier/sign-artifact-metadata.py \\
        --input  artifact-metadata.json \\
        --key    "$ARTIFACT_METADATA_SIGNING_KEY" \\
        --key-id "$ARTIFACT_METADATA_SIGNING_KEY_ID" \\
        --output artifact-metadata.signed.json

    Requires: pip install cryptography
    Use only with a dev-only key (NEVER the production key here).
    Generate a dev key with: python3 tools/generate-signing-key.py

── Key ID ───────────────────────────────────────────────────────────────────

The key_id is the first 8 bytes (16 hex chars) of the SHA-256 of the public
key bytes. Generate it with tools/generate-signing-key.py or extract it from
an existing key with tools/generate-signing-key.py --from-seed "$KEY_B64".
The pinned key_id in ArtifactTrust.cs must match — and, until Andy provisions
the real production key pair, currently does NOT (see that file's
ProductionKeyId placeholder) by design; see docs/signing-key-runbook.md.
"""

import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path

# PAT-516 key separation: the artifact-metadata key must never equal either
# of the two other purpose-specific keys already in use.
_AGENT_CONFIG_KEY_ID = "ecd47f2c5b3d5705"
_CATALOGUE_KEY_ID = "734eba29d9f804a0"

# Required fields in the (unsigned) metadata document. At minimum per PAT-1248.
_REQUIRED_FIELDS = ("version", "platform", "channel", "artifact_url", "artifact_sha256")

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _sign_via_gcp_kms(payload: bytes, key_resource: str) -> bytes:
    """Sign using GCP Cloud KMS Ed25519 HSM key (production path)."""
    try:
        from google.cloud import kms as gcp_kms
    except ImportError:
        sys.exit(
            "FATAL: google-cloud-kms not installed.\n"
            "Run: pip install google-cloud-kms\n"
            "Or use --key for the seed-based path (dev/staging only)."
        )
    client = gcp_kms.KeyManagementServiceClient()
    response = client.asymmetric_sign(
        request={"name": key_resource, "data": payload}
    )
    sig = bytes(response.signature)
    if len(sig) != 64:
        sys.exit(
            f"FATAL: GCP KMS returned {len(sig)}-byte signature "
            "(expected 64 for Ed25519 — check the key type is EC_SIGN_ED25519)"
        )
    return sig


def _sign_via_seed(payload: bytes, seed_b64: str) -> bytes:
    """Sign using raw Ed25519 seed (development / staging only)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        sys.exit("FATAL: 'cryptography' package not installed. Run: pip install cryptography")
    seed = base64.b64decode(seed_b64)
    if len(seed) != 32:
        sys.exit(f"FATAL: key must be a 32-byte Ed25519 seed (got {len(seed)} bytes)")
    return Ed25519PrivateKey.from_private_bytes(seed).sign(payload)


def sign(payload: bytes, *, seed_b64: str | None, kms_key_resource: str | None) -> bytes:
    if kms_key_resource:
        return _sign_via_gcp_kms(payload, kms_key_resource)
    if seed_b64:
        return _sign_via_seed(payload, seed_b64)
    sys.exit("FATAL: one of --key or --kms-key-resource must be provided")


def validate_metadata(parsed_payload: object) -> None:
    """Fail-closed validation of the (unsigned) artifact metadata document.

    Enforce-only — never mutates or re-serializes the payload, so the bytes
    signed by main() are exactly the bytes read from --input.
    """
    if not isinstance(parsed_payload, dict):
        sys.exit(
            "FATAL: --input JSON is not an object; "
            f"got {type(parsed_payload).__name__}"
        )

    missing = [f for f in _REQUIRED_FIELDS if not parsed_payload.get(f)]
    if missing:
        sys.exit(
            "FATAL: artifact metadata missing required field(s): "
            f"{', '.join(missing)} (PAT-1248 requires at minimum {_REQUIRED_FIELDS})"
        )

    artifact_url = parsed_payload["artifact_url"]
    if not isinstance(artifact_url, str) or not artifact_url.startswith("https://"):
        sys.exit(
            f"FATAL: artifact_url must be an https:// URL (got {artifact_url!r}) — "
            "refusing to sign metadata for a non-HTTPS download"
        )

    artifact_sha256 = parsed_payload["artifact_sha256"]
    if not isinstance(artifact_sha256, str) or not _SHA256_RE.match(artifact_sha256):
        sys.exit(
            f"FATAL: artifact_sha256 must be a 64-character hex SHA-256 digest "
            f"(got {artifact_sha256!r})"
        )

    platform = parsed_payload["platform"]
    if not isinstance(platform, str) or not platform.strip():
        sys.exit(f"FATAL: platform must be a non-empty string (got {platform!r})")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Sign Windows agent self-update artifact metadata (Ed25519, PAT-1248)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--input", required=True, help="path to artifact metadata JSON")
    ap.add_argument("--output", required=True, help="path for signed envelope JSON")
    ap.add_argument("--key-id", required=True,
                    help="hex key identifier (ARTIFACT_METADATA_SIGNING_KEY_ID)")

    key_group = ap.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--kms-key-resource",
        help="GCP Cloud KMS key resource name (production). "
             "e.g. projects/patched-prod/locations/europe-west1/keyRings/signing/"
             "cryptoKeys/artifact-metadata-signing/cryptoKeyVersions/1",
    )
    key_group.add_argument(
        "--key",
        metavar="SEED_B64",
        help="base64-encoded 32-byte Ed25519 seed (dev/staging ONLY — "
             "never use the production key here)",
    )
    key_group.add_argument(
        "--key-env",
        metavar="ENV_NAME",
        help="read the base64 seed from a named environment variable (keeps key value out of argv)",
    )

    args = ap.parse_args()

    # PAT-516 / PAT-1248: reject the other two purpose-specific key ids to
    # enforce key separation across all three signing purposes. This
    # prevents accidental reuse even if CI secrets are misconfigured (the
    # exact PAT-996 failure mode this pattern already guards against for the
    # catalogue key).
    if args.key_id == _AGENT_CONFIG_KEY_ID:
        sys.exit(
            "FATAL: ARTIFACT_METADATA_SIGNING_KEY_ID must not match the agent-config "
            f"key id ({_AGENT_CONFIG_KEY_ID}). Generate a separate artifact-metadata "
            "key pair (see docs/signing-key-architecture.md)."
        )
    if args.key_id == _CATALOGUE_KEY_ID:
        sys.exit(
            "FATAL: ARTIFACT_METADATA_SIGNING_KEY_ID must not match the catalogue "
            f"key id ({_CATALOGUE_KEY_ID}). Generate a separate artifact-metadata "
            "key pair (see docs/signing-key-architecture.md)."
        )

    payload = Path(args.input).read_bytes()

    try:
        parsed_payload = json.loads(payload)
    except json.JSONDecodeError as exc:
        sys.exit(f"FATAL: --input is not valid JSON: {exc}")

    validate_metadata(parsed_payload)

    seed = args.key
    if args.key_env:
        seed = os.environ.get(args.key_env)
        if not seed:
            sys.exit(f"FATAL: environment variable {args.key_env} is unset or empty")
    sig = sign(payload, seed_b64=seed, kms_key_resource=args.kms_key_resource)

    envelope = {
        "signed_payload": base64.b64encode(payload).decode(),
        "signature": base64.b64encode(sig).decode(),
        "key_id": args.key_id,
    }
    Path(args.output).write_text(json.dumps(envelope, indent=2) + "\n")
    mode = "GCP KMS" if args.kms_key_resource else "local seed"
    print(f"Signed artifact metadata written to {args.output}  [{mode}, key_id={args.key_id}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
