# Verified self-update channel

macOS bootstrap and Windows service select the self-update channel only from a
pinned-key verified, enrolled-tenant config. Tenant-wide configs may contain
`device_channel_overrides`, keyed by the canonical server device UUID. Exactly
one own-device `beta` entry overrides the validated tenant channel. Foreign,
malformed or absent entries do not override it. Hardware UUIDs are never keys.
The tenant pin remains in beta requests. A device-scoped config is already the
server's effective projection, including a due P0 stable floor; its map is not
reapplied locally.

`update_channel_source` is an additive signed field (`tenant` or
`device_override`). Device-scoped consumers report an absent or invalid source
as null, never infer a source from the channel. The platform must supply this
field for fully attributed device-scoped telemetry.

Windows enrolment persists the response's canonical `device_id`, bound to the
tenant and bearer credential fingerprint. Re-enrolment without a valid ID
clears it; uninstall purges it. Existing Windows installations without this ID
cannot apply an own-device override until an authorised identity refresh.
macOS uses the existing `/etc/patched/device-id`, not its hardware UUID.

The original signed envelope is persisted and reverified across restart.
Windows also requires exact-byte agreement with the canonical cache and its
tenant rollback floor. A plaintext cache alone cannot authorise an update;
missing proof forces a complete config fetch instead of a conditional 304.
macOS stores its original envelope in protected state, checks the config-poll
floor and its own last verified version, and never accepts unsigned/decode-only
authority. Corrupt authority yields stable defaults or no telemetry opinion,
without replacing a corrupt floor. Existing non-update cache readers retain
their prior behaviour.

`agent_health.update_channel` is healthy selection telemetry, independent of
`degraded`. It reports `effective_channel`, nullable `source`, nullable
`config_version` and `observed_at`; it does not claim a successful download or
installation. Corrupt health state is not silently repaired. Windows scopes
persisted telemetry to the enrolled tenant/device; macOS reverifies the envelope
before emitting it. Platform ingestion must preserve this additive object.

## Operating proof

Unit tests use temporary state, fake HTTP and test-only signing seams. No test
enrols a host or changes a real override. After independent review and an
authorised test-device selection, capture the existing installed version,
identity and signed config; set only that device to beta; verify the signed
source, beta request and retained pin plus uploaded healthy telemetry; clear the
override and verify a stable request and tenant source. Repeat on macOS and
Windows. Any real enrolment, endpoint installation or live override change is a
separate authority gate, and is not established by local tests.
