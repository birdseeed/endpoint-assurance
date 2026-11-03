// PAT-1983: block forever and say nothing.
//
// The caller (InstallationEvidenceProbe.RunHelperAsync, exercised by
// WindowsInstallationEvidenceTests.HelperTimeoutTerminatesTheProcessAndReturnsUnknown)
// gives this process a budget it is meant to exceed, then force-terminates it with
// Process.Kill(entireProcessTree: true). There is deliberately no shutdown handling
// and no signal handler: being killed outright is the behaviour under test, and a
// graceful exit path would let the process end for a reason the test did not cause.
//
// PAT-1991: the one argument, when given, is a path the helper creates once it is
// running and about to block. The test waits for that file before the deadline can
// matter, so it proves the child was genuinely hung when it was killed rather than
// still booting the runtime. Without it the test could not tell a hung child from one
// that exits quickly, because process start-up alone outlasted the old budget.
//
// Nothing is written to stdout or stderr. RunHelperAsync reads both streams under the
// same deadline and treats any stderr output as a helper failure, so output here could
// turn a timeout into a different verdict and hide the defect the test guards.
//
// Apart from that readiness file no files or registry keys are touched, no network
// call is made and no privilege is required, so the child cannot itself become a
// source of CI flakiness.

using System.IO;
using System.Threading;

if (args.Length == 1)
    File.WriteAllBytes(args[0], []);

Thread.Sleep(Timeout.Infinite);
