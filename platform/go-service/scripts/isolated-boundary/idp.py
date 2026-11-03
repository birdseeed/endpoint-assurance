"""Local stand-in for Cloudflare Access: an HTTPS JWKS endpoint and a JWT minter.

Everything here is synthetic. The RSA keys and the throwaway CA/leaf certificate
are generated at run time into the scratch directory and never committed.

Serve:  python idp.py serve <scratch-dir> <port>
Mint (library use):  from idp import Minter
"""
import base64
import datetime
import ipaddress
import json
import ssl
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

KID = "ib-synthetic-key-1"


def _b64u(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk_for(public_key, kid):
    nums = public_key.public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64u(nums.n), "e": _b64u(nums.e)}


def generate_keys(scratch: Path):
    """Create the signing key, a rogue key (same kid, never published), and a CA + leaf cert."""
    keys = scratch / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    for name in ("signing", "rogue"):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (keys / f"{name}.pem").write_bytes(k.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ib-synthetic-test-ca")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (keys / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (keys / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (keys / "leaf.key").write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    for p in keys.iterdir():
        p.chmod(0o600)


def serve(scratch: Path, port: int):
    keys = scratch / "keys"
    pub = serialization.load_pem_private_key((keys / "signing.pem").read_bytes(), None).public_key()
    body = json.dumps({"keys": [jwk_for(pub, KID)], "public_cert": {}, "public_certs": []}).encode()

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.split("?")[0] == "/cdn-cgi/access/certs":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(keys / "leaf.pem", keys / "leaf.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


class Minter:
    """Mints Access-style JWTs for synthetic principals."""

    def __init__(self, scratch: Path, port: int, audience: str):
        keys = Path(scratch) / "keys"
        self.signing = (keys / "signing.pem").read_bytes()
        self.rogue = (keys / "rogue.pem").read_bytes()
        self.issuer = f"https://127.0.0.1:{port}"
        self.audience = audience

    def mint_unsigned_for_denial_tests(self, **kw):
        """An alg=none token, for the denial tests only. Never use it as a credential."""
        return self.mint(_unsigned_for_denial_tests=True, **kw)

    def mint(self, email=None, common_name=None, *, iss=None, aud=None, ttl=300, nbf=None,
             kid=KID, key="signing", alg="RS256", extra=None, exp=None, _unsigned_for_denial_tests=False):
        if alg == "none" or _unsigned_for_denial_tests:
            alg = "none"
        now = int(time.time())
        claims = {"iss": iss or self.issuer, "aud": [aud or self.audience], "iat": now,
                  "exp": exp if exp is not None else now + ttl, "sub": str(uuid.uuid4()), "type": "app"}
        if nbf is not None:
            claims["nbf"] = nbf
        if email is not None:
            claims["email"] = email
        if common_name is not None:
            claims["common_name"] = common_name
        if extra:
            claims.update(extra)
        if alg == "none" and not _unsigned_for_denial_tests:
            raise ValueError("alg=none is only available through mint_unsigned_for_denial_tests")
        if alg == "none":
            head = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT", "kid": kid}).encode()).rstrip(b"=")
            payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
            return (head + b"." + payload + b".").decode()
        pem = self.signing if key == "signing" else self.rogue
        return jwt.encode(claims, pem, algorithm=alg, headers={"kid": kid})


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(Path(sys.argv[2]), int(sys.argv[3]))
