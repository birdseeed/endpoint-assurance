# driverblock test fixtures (PAT-2263)

Hand-written, small documents in the shape of the two live sources. Nothing
here was fetched, and no hash here is a real driver's: every hash is either an
obviously synthetic pattern or the digest of a synthetic file the Windows
agent's own tests build (`updater`
`windows/tests/Service.Tests/KernelDriverCollectorTests.cs`), so the platform
can be tested end to end against the exact bytes the agent sends.

- `DriverPolicy_Enforced.xml`: the shape of
  `VulnerableDriverBlockList/DriverPolicy_Enforced.xml` inside the zip at
  https://aka.ms/VulnerableDriverBlockList (a SiPolicy: VersionEx, FileRules
  with `Hash Sha1`, `Hash Sha256` and `Hash Page` Deny rules, FileName rules,
  FileAttrib, Signers, SigningScenarios). Tests zip it the way Microsoft
  publishes it.
- `drivers.json`: the shape of https://www.loldrivers.io/api/drivers.json (an
  array of drivers with Id, Category, Tags and KnownVulnerableSamples carrying
  SHA256, SHA1, MD5 and Authentihash).

Hashes that matter to the tests:

| Hash | Where | Why |
| --- | --- | --- |
| `8812f0c8...eff841` | Microsoft, `ID_DENY_SYNTH_PE_SHA256` | Authenticode SHA-256 of the agent's synthetic `pe.sys` |
| `49eb0bea...bb8dade` | Microsoft, `ID_DENY_SYNTH_PE_SHA1` | its Authenticode SHA-1; dropped because the rule has a SHA-256 |
| `357c27a0...507cf1` | loldrivers, sample `gdrv.sys` | flat SHA-256 of the agent's synthetic `flat.sys`: a renamed file still matches |
