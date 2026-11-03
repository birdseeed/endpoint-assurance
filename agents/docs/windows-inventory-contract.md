# Windows inventory version identity

The payload's `agent_version` and the installed-software row for `Patched Agent`
published by `Patched` use the running service's stamped informational version.
Commit provenance is removed; the complete numeric release identity is retained.
For example, `0.15.1.2+00cc3f440f684c68eff34748197ec5ce32e9e257` reports
`0.15.1.2`, rather than the encoded MSI version `2.15.102` or file version
`2.15.102.0`.

`windows/installer/resolve-release-version.sh` converts beta tags `X.Y.Z-beta.N`
to numeric identities `X.Y.Z.N`. Inventory accepts four-part stamped identities
with major at most 253, minor at most 255, patch at most 654 and revision 1 through
99. All components must be canonical ASCII decimal without leading zeroes, and
the stamp must end with exactly `+` and 40 hexadecimal commit characters. Raw
beta tags, other prerelease forms and unstamped builds are not release evidence.

Three-part stamped identities retain the earlier inventory parser's patch bound
of 65535 for compatibility. This is an inventory acceptance rule; the current
release resolver's three-part patch bound is 655 because it encodes the patch
into the MSI version.

When the stamp is missing or invalid, `agent_version` is explicitly `0.0.0-dev`.
The own-app row retains its observed ARP display version, without decoding or
inventing a beta revision. Other applications and rows with a different publisher
retain their observed display versions regardless of the service's version.


## Per-user applications (PAT-2075)

The Windows reader opens HKLM and currently loaded real-user `S-1-5-21-*` HKU
hives read-only, including native and WOW6432Node Uninstall paths. It never loads
NTUSER.DAT. Service identities, `_Classes` and malformed SID keys are excluded.
Each user row carries `user_account`: the account name the SID translates to
(`DOMAIN\user` or `MACHINE\user`, the same translation as browser inventory),
falling back to the SID string when translation fails. The platform treats it as
an opaque key and its payload contract describes it the same way. Rows retain the original ARP
identifier and version normalisation. Deduplication is confined to one scope.

`collection_status.apps` describes machine rows only. `apps_users` lists each
attempted user with `complete` or `partial`; a denied hive, key or value cannot
authorise removal. Missing Uninstall paths in an opened loaded hive are empty
reads. An absent user hive produces no authority. Multiple hives resolving to one
account combine conservatively. Account names over 128 characters are skipped,
never truncated. Machine failure does not discard successful user observations.

Per-user rows do not borrow metering, reviewed installation evidence or
Authenticode results from matching machine identifiers. They stay explicitly
unknown/unavailable and do not enter the HKLM/Program Files helper probes.

macOS uses the same wire contract for `/Users/*/Applications`, resolving the
short account name from DirectoryService home metadata. `/Applications`,
`/Applications/Utilities` and `/Users/Shared/Applications` are machine scope:
`/Users/Shared` is nobody's home, so its folder is scanned and reported with the
machine rows and covered by `collection_status.apps`. Machine `complete` is
claimed only when every machine root that exists was listed; a machine root that
is a symlink is not followed and makes the machine scope `partial`. Every home that
resolves to an account is listed: one with no `Applications` folder is `complete`
with no rows, so the platform can resolve what it still stores for that home.
Unresolved identities are omitted, failed user walks are partial, and unlisted homes acquire
no authority. A symlinked user root, bundle or folder (down to the listing depth,
outside bundles) that may hide user content withholds that user's completeness
and is never followed by find. Links inside a bundle are bundle internals and
do not.

### `apps_users[].home`

Each `apps_users` entry may carry `home`, the absolute path of that user's home
directory exactly as the agent resolved it, with no trailing slash. It is optional
on both platforms and is never derived from the account name.

- macOS sends the directory the user's `Applications` folder was found in, the
  same string the account was resolved from (`/Users/<directory>`). An account
  resolved from two directories sends no `home`.
- Windows sends the `ProfileImagePath` registered for the loaded SID in HKLM
  ProfileList, read-only, only when it is a clean drive-letter path and every
  loaded SID of the account agrees on it. Otherwise the field is omitted. A failed
  lookup never changes the user's `collection_status` or rows.

The platform uses `home` for one thing: deciding who owns an application row that
a macOS agent before PAT-2075 stored machine-wide from a user's `~/Applications`.
A report that carries `apps_users` has no machine-wide authority over such a row;
it is pruned only when its owner is `complete` with a `home` equal to the row's
home directory, re-homed when the user lists it, and otherwise held. See
`go-service/docs/PAYLOAD_SCHEMA.md`, "Legacy user-located rows", in the platform
repository.

**Release order.** A platform without `home` in its contract rejects the whole
inventory report with 400 (an `apps_users` entry with an extra field). The
platform change must be deployed and verified on `example-api-host` before any agent
build that sends `home` is released, on either operating system.

Portable evidence: `PerUserAppWireTests`, `PerUserAppBehaviorTests`,
`PerUserAppVersionTests`, `PerUserAppHomeTests` and the
`macos/lib/test-apps-per-user*.zsh` and `test-apps-account-identity.zsh` scripts
use synthetic keys/bundles. macOS tests
require native plist tools. Real Windows ACL behaviour and installed staging
reports, logout survival and same-user authoritative prune remain release gates.

The first macOS upgrade depends on the platform's legacy provenance hold: older
reports stored home applications as machine-wide, and an inaccessible home on the
first scoped report has no existing user scope to hold its legacy row. The
platform holds those rows until positive evidence or their owner's `complete`
report with a matching `home` resolves them. That platform change, like the
`home` field itself, must be live before this agent is released; an agent-local
marker cannot prove that the server reconciled them.
