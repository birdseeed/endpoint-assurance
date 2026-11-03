# Signing pipeline — secrets reference (PAT-8)

GitHub Actions repository secrets that unlock the `sign-notarize` and
`hello-world-notarize` workflows. Add them once PAT-7 delivers the Developer ID
certs. Until then every workflow run builds and does structural checks, then
cleanly skips the live notarization with a notice rather than failing.

---

## Secret inventory

| Secret name | What it is | Required for |
|---|---|---|
| `DEVELOPER_ID_APPLICATION_CERT_P12_B64` | base64-encoded Developer ID Application `.p12` | Signing `PatchedUpdater.app` (PAT-51) |
| `DEVELOPER_ID_INSTALLER_CERT_P12_B64` | base64-encoded Developer ID Installer `.p12` | Signing the endpoint `.pkg` |
| `DEVELOPER_ID_CERT_PASSWORD` | Passphrase used to protect **both** `.p12` files | Importing either cert |
| `SIGNING_KEYCHAIN_PASSWORD` | One-time passphrase for the ephemeral CI keychain | Creating the temp keychain |
| `APPLE_TEAM_ID` | 10-character Apple Team ID (e.g. `AB12CD34EF`) | **Sole** signing-identity selector — `codesign`/`pkgbuild --sign "$APPLE_TEAM_ID"` matches the Developer ID cert by its CN substring |
| `APPLE_ASC_API_KEY_P8_B64` | base64-encoded App Store Connect API key (`.p8` file) | Authenticating to notarytool |
| `APPLE_ASC_API_KEY_ID` | Key ID from App Store Connect (short alphanumeric) | notarytool auth |
| `APPLE_ASC_API_KEY_ISSUER_ID` | Issuer UUID from App Store Connect | notarytool auth |

---

## How to produce each secret

### Developer ID certificates

Developer ID certs are issued by Apple through the Apple Developer portal.
Patched must be enrolled as an Apple Developer (individual or organisation —
PAT-7 tracks that decision).

**Where to generate:**
`developer.apple.com` → Certificates, Identifiers & Profiles → Certificates → `+`

**Two certs needed:**
1. **Developer ID Application** — signs Mach-O binaries and `.app` bundles.
2. **Developer ID Installer** — signs `.pkg` installer packages.

**Generating CSRs without a laptop private key:**

Per PAT-7 — generate CSRs inside the CI environment so private key material
never touches a developer laptop:

```bash
# Run on a trusted machine (or a fresh macOS runner) — outputs CSR + private key.
security create-keychain -p "STRONG_TEMP_PW" /tmp/sign.keychain-db
security set-keychain-settings -lut 3600 /tmp/sign.keychain-db
security unlock-keychain -p "STRONG_TEMP_PW" /tmp/sign.keychain-db

# Generate a 2048-bit RSA private key and a CSR.
# Repeat for Application and Installer — use distinct -subj CNs.
openssl req -newkey rsa:2048 -nodes \
    -keyout /tmp/developer-id-application.key \
    -out    /tmp/developer-id-application.csr \
    -subj   "/CN=Developer ID Application: Patched.im Ltd/C=GB"
```

Upload the `.csr` to the Apple Developer portal. Apple issues the signed cert.
Download it (`.cer`), then combine with the private key into a `.p12`:

```bash
# Convert Apple's .cer to PEM
openssl x509 -inform DER -in DeveloperIDApplication.cer \
    -out DeveloperIDApplication.pem

# Bundle .pem + private key into a .p12 (you will be prompted for an export passphrase)
openssl pkcs12 -export \
    -inkey  /tmp/developer-id-application.key \
    -in     DeveloperIDApplication.pem \
    -out    developer-id-application.p12
```

**Base64-encode for the secret:**

```bash
base64 -i developer-id-application.p12 | pbcopy   # macOS — pastes into clipboard
# or
base64 < developer-id-application.p12             # print to stdout
```

Paste the output (a long single-line or multi-line base64 string) as the secret
value. Repeat for the Installer cert.

**Use the same passphrase for both `.p12` files** — the workflow imports them
with a shared `DEVELOPER_ID_CERT_PASSWORD`. If you choose different passphrases,
split into `DEVELOPER_ID_APPLICATION_CERT_PASSWORD` and
`DEVELOPER_ID_INSTALLER_CERT_PASSWORD` and update the workflow imports.

---

### `SIGNING_KEYCHAIN_PASSWORD`

A one-time random string. The CI workflow creates and deletes a temporary
keychain on every run; this password secures it for the duration of the job.
It never leaves the runner.

Generate with:
```bash
openssl rand -base64 32 | tr -d '\n'
```

---

### `APPLE_TEAM_ID`

Your 10-character Apple Team ID. Find it in:
- `developer.apple.com` → Account → Membership → Team ID
- Or in any cert's CN: `Developer ID Application: Patched.im Ltd (AB12CD34EF)` →
  `AB12CD34EF` is the Team ID.

The `sign-notarize` and `hello-world-notarize` workflows sign with
`--sign "$APPLE_TEAM_ID"` — they do **not** hardcode the organisation name. This
keeps moving the signing account (individual → Patched.im Ltd org, a different
Team ID and a different cert CN) a pure secret swap: update `APPLE_TEAM_ID` and
the two cert `.p12` secrets, and no workflow code changes.

---

### App Store Connect API key (notarytool auth)

`notarytool` authenticates via an App Store Connect API key — no Apple ID
password required. Generate one at:
`App Store Connect` → Users and Access → Integrations → Team Keys → `+`

Role required: **Developer** (minimum for notarization).

Download the `.p8` file (downloadable only once). Record:
- **Key ID** (`APPLE_ASC_API_KEY_ID`) — shown in the key list
- **Issuer ID** (`APPLE_ASC_API_KEY_ISSUER_ID`) — shown above the key list

Base64-encode the `.p8`:
```bash
base64 -i AuthKey_XXXXXXXXXX.p8 | pbcopy
```

Paste as `APPLE_ASC_API_KEY_P8_B64`.

---

## Adding secrets to the repository

```
GitHub → Patched-LTD/updater → Settings → Secrets and variables → Actions → New repository secret
```

Add each secret from the table above as a **repository secret** (not
environment-scoped — both workflows share the same set).

---

## Validating the pipeline once certs land

1. Run `hello-world-notarize` via `workflow_dispatch`. This uses a trivial
   throwaway `.pkg` (installs nothing harmful) to prove the full
   sign → notarize → staple → verify chain works with the new certs.
2. Once that passes, push an `endpoint-v*` tag to trigger `sign-notarize` on
   the real endpoint bundle.
3. Download the artifact and run `pkgutil --check-signature` and
   `spctl --assess --type install` locally to confirm end-to-end.

---

## Rotation

- **Certs**: Developer ID certs are 5-year validity. When they expire, generate
  new CSRs, upload to Apple, re-export `.p12`, update the two cert secrets and
  `DEVELOPER_ID_CERT_PASSWORD`.
- **ASC API key**: No expiry, but rotate if the key is ever exposed. Delete the
  old key in App Store Connect, generate a new one, update the three ASC secrets.
- **Keychain password**: Rotate freely — it only protects the ephemeral
  per-job keychain and has no persistence.
