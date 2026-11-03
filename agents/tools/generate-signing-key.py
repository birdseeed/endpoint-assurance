#!/usr/bin/env python3
"""Generate or inspect an Ed25519 signing key pair (PAT-497).

Use cases:
  1. Generate a fresh dev/staging key pair:
       python3 tools/generate-signing-key.py

  2. Derive the public key and key_id from an existing seed:
       python3 tools/generate-signing-key.py --from-seed "$CATALOGUE_SIGNING_KEY_B64"

Output for case 1:
  CATALOGUE_SIGNING_KEY_B64=<base64 seed>     ← store in GitHub Actions secret (dev only)
  CATALOGUE_SIGNING_KEY_ID=<16-char hex>      ← store in secret; embed in Ed25519Verifier.cs
  Public key (base64): <base64>               ← embed as PinnedPubKeyBase64 in Ed25519Verifier.cs

NEVER use this tool to generate the production key. Production keys must be
generated inside GCP Cloud HSM (EC_SIGN_ED25519) or AWS KMS. This tool is
for dev/staging keys that live in GitHub Actions secrets.

Requires: pip install cryptography
"""

import argparse
import base64
import hashlib
import sys


def _derive(seed_b64: str | None) -> tuple[str, str, str]:
    """Return (seed_b64, pub_b64, key_id) for a new or existing seed."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, NoEncryption, PrivateFormat,
        )
    except ImportError:
        sys.exit("FATAL: cryptography not installed. Run: pip install cryptography")

    if seed_b64:
        seed = base64.b64decode(seed_b64)
        if len(seed) != 32:
            sys.exit(f"FATAL: seed must be 32 bytes (got {len(seed)})")
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
    else:
        private_key = Ed25519PrivateKey.generate()
        seed = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
    return base64.b64encode(seed).decode(), base64.b64encode(pub_bytes).decode(), key_id


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate or inspect an Ed25519 signing key pair (PAT-497)"
    )
    ap.add_argument("--from-seed", metavar="SEED_B64",
                    help="derive key_id and public key from an existing base64 seed")
    args = ap.parse_args()

    seed_b64, pub_b64, key_id = _derive(args.from_seed)

    if args.from_seed:
        print("── Existing key inspection ──────────────────────────────────────")
        print(f"  CATALOGUE_SIGNING_KEY_ID={key_id}")
        print(f"  Public key (PinnedPubKeyBase64): {pub_b64}")
    else:
        print("── Generated a NEW dev/staging Ed25519 key pair ─────────────────")
        print("  WARNING: For production, generate inside GCP Cloud HSM (PAT-497)")
        print()
        print(f"  CATALOGUE_SIGNING_KEY_B64={seed_b64}")
        print(f"  CATALOGUE_SIGNING_KEY_ID={key_id}")
        print()
        print("  Embed in Ed25519Verifier.cs (windows/src/Shared/Config/):")
        print(f'  internal const string PinnedPubKeyBase64 = "{pub_b64}"; // gitleaks:allow')
        print(f'  internal const string PinnedKeyId        = "{key_id}";')
        print()
        print("  Store CATALOGUE_SIGNING_KEY_B64 as a GitHub Actions secret.")
        print("  The public key and key_id are safe to commit.")


if __name__ == "__main__":
    main()
