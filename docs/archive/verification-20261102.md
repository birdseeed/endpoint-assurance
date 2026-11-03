# Verification follow-up, 2 November 2026

This follow-up records bounded checks against the private personal snapshot at `f5f1f2d16f1383f5f6215776565d72b589210ff2`. It supplements the earlier candidate record; it does not rewrite its historical results or certify the product.

The Windows fixture repair received an independent static Astra review before its final run.

## Scope and evidence

The exact Go 1.27.2 archive was checked against the official Go release JSON and SHA-256 metadata before safe extraction. The report records the precise commands, exit codes, outputs, checksums, source manifests and prerequisite-recovery evidence in the persistent Codex Security artifact `artifacts/exact-tool-checks/REPORT.md` (44 accompanying evidence files). The verified binary reported `go version go1.27.2 darwin/arm64`.

On the retained `platform/go-service` source, offline module verification and `go build ./...` passed with `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off` and `GOFLAGS=-mod=readonly`. The vetted PDF test pattern `Test(RenderTablePDF|PortalTablePDF|PortalTableExports)` passed 26 top-level tests and 55 subchecks, with no failures.

The check used an isolated temporary tool path and build cache. It did not start broad handlers, listeners, database or integration suites, network integration tests, workflows, services, installers or deployment. No source files changed: the recorded comparison covered 1,711 copied source files with zero hash mismatches. The original repository and its metadata were not written.

## Targeted native Windows fixtures

The separate Windows credential-fixture run completed on 2 November. The first bounded job, run 41418814348 at source `b61a7bc73d6f564927214a2eb769ae7880dfb707`, executed 15 fixtures: 14 passed and one failed because the fixture expected Windows to preserve an explicit ACE as inherited. Windows normalised that ACL representation. This exposed a test assumption, not a production-code failure. The original run and its failure are retained.

An independently reviewed test-only repair now creates a genuinely inherited ACE and retains the direct leaf guard and private explicit-ACE case. The changed file is `agents/windows/tests/Shared.Tests/CredentialFileTrustRegressionTests.cs`: the previous personal-copy SHA-256 was `c00f01020eb18fd21f8ad646c8e7c97db65ed20531dd0ba8d89c76f0f1a85cc1`; the reviewed follow-up SHA-256 is `f412dfbb735ec06db02cafa6b00467e196ff6dab971f2bd7b0320dbc68c8ff13`. The final run checked out organisation commit `fac3b182802dcd9ed49fb255f8d1177a03331266` and passed all 15 fixtures: 15 passed, 0 failed, 0 not executed. Its actual inheritance case passed. The production Shared source tree at `b612977fedcdf5c5e09716d6dcac1abcef09d1a5` matched this personal snapshot's original baseline `f5f1f2d16f1383f5f6215776565d72b589210ff2`; the follow-up repair changed the test fixture only.

The portable build succeeded. Its focused tests reported 23 passed and 15 native-only fixtures skipped. The final Windows job then ran and passed those 15 fixtures natively. The owner-approved cap was at most three jobs of five minutes each; two jobs were used, taking 231 seconds total. Actions were disabled between runs, the temporary workflow was removed during organisation cleanup, and Actions were never enabled for this personal copy. Cleanup left organisation `main` at `dc3817ef9bd81cd85f10d3473e889a5f7c8be110`, with default tree `a0a440d78d81a422f03c254682cb896fbb1fa6b0` matching the original tree; no jobs remained queued or running. These results establish only the listed credential fixtures, not full Windows application behaviour or the complete native product.

## Limits

These checks establish only the listed Go checks and targeted Windows credential fixtures on their recorded toolchains and runner. They do not establish full native Windows or Mac application behaviour, complete security, release readiness or deployed remediation. The five-finding source audit and historical dependency/advisory records remain distinct. No advisory database refresh or full security closure is claimed.
