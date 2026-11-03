"""Shared harness pieces for the deploy/api-01 signal tests.

Both deploy.sh and emergency-api-only.sh swap binaries under a signal trap, and
both are tested by interrupting a real run at a chosen instant. That only works
if the fake the script is blocked on parks correctly, so the park helper lives
here in one copy rather than once per test module: it was tuned by measurement
under PAT-1938 and a second, drifting copy of it would be a second truth about
how these tests synchronise.
"""

from __future__ import annotations

import textwrap


# Every fake gets this. A fake that parks is how the signal tests pin the
# moment the script under test is interrupted. It blocks as a foreground child
# so the signal lands while Bash is in `wait`, the one point in a shell script
# where trap dispatch is unambiguous.
#
# Three properties make it reliable, and each was learned by watching it fail.
#
# It blocks without forking a child of its own. The script under test is itself
# waiting on this fake, and Bash defers acting on a signal until its foreground
# child completes, so any grandchild here has to die before the script's trap
# can run. os.killpg reaches only the processes that exist at the instant it
# is called, so a `sleep` forked a moment later never sees the signal at all
# and holds that deferral open for its full duration. Reading a fifo nobody
# writes to blocks in this very process instead.
#
# It installs no signal handling of its own. Left at the default
# disposition the fake simply dies where it blocks, and the script then
# observes an interrupted child and runs its trap. Trapping the signal here
# to re-raise it looked tidier and lost SIGINT outright in 200 runs out of
# 200: deploy.sh carried on past the restart as if nothing had happened
# (PAT-1938). Leave these functions trap-free.
#
# Arming and blocking are separate so that nothing forks between the moment
# a fake publishes its readiness and the moment it is blocked. Every fork in
# the fifo setup happens in park_arm, before readiness is visible; the
# readiness write itself is a redirection, not `touch`, so it forks nothing
# either. A fake that is still forking when the signal arrives defers its
# own death until that child exits, and the child was created too late to
# have been signalled at all.
PARK_HELPER = textwrap.dedent(
    """
    park_arm() {
      local fifo
      fifo="$(mktemp -u "${TMPDIR:-/tmp}/patched-park.XXXXXX")"
      mkfifo "$fifo"
      exec {PARK_FD}<>"$fifo"
      rm -f "$fifo"
    }
    park_block() {
      read -r -t "${1:-30}" -u "$PARK_FD" || true
    }
    """
)
