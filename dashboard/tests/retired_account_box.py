"""PAT-2312: a scratch box for scripts/deploy.sh's remove_retired_account.

The function runs getent, pgrep, userdel and groupdel. Here each is a shim
backed by files under a scratch directory, so no test can read or change a
real account. find and cmp are the real ones, run over scratch paths only.

A test can only create files it owns, so the scratch account's uid is the
invoking user's: every file a test plants counts as the account's. The scan
root therefore holds nothing but the directories the function prunes (the
home and the two tmp directories), and the tunnel directory sits outside it,
so the scaffolding never reads as a stray file the account owns.

Not a test module: pytest collects test_*.py only.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

TUNNEL_JSON = "5d9bda0f-ac65-4014-aa2c-3e523a3f9139.json"
# Low-entropy placeholders: nothing here may look like a real credential.
TUNNEL_JSON_BODY = '{"AccountTag":"placeholder","TunnelID":"placeholder"}\n'
TMP_FILE = "tmp.FVD6FpE2gb"
ACCOUNT_GID = 4242


def _q(value: object) -> str:
    return shlex.quote(str(value))


def _shims(db: Path, procs: Path, calls: Path) -> dict[str, str]:
    """getent, userdel, groupdel and pgrep, each logging its arguments to
    calls and answering from db (passwd, group) and procs. Environment knobs
    make each fail on demand."""
    passwd, group = db / "passwd", db / "group"
    return {
        "getent": (
            "#!/usr/bin/env bash\n"
            f"echo \"getent $*\" >> {_q(calls)}\n"
            "[ -z \"${GETENT_RC:-}\" ] || exit \"$GETENT_RC\"\n"
            f"db={_q(db)}/\"$1\"\n"
            "[ -f \"$db\" ] || exit 1\n"
            "if [ $# -lt 2 ]; then cat \"$db\"; exit 0; fi\n"
            "line=\"$(awk -F: -v k=\"$2\" '$1 == k { print; exit }' \"$db\")\"\n"
            "[ -n \"$line\" ] || exit 2\n"
            "printf '%s\\n' \"$line\"\n"
        ),
        # userdel -r NAME: drops the passwd entry and every group membership,
        # the user's own group (unless USERDEL_KEEPS_GROUP), then the home
        # (unless USERDEL_LEAVES_HOME, which exits 12 as the real one does
        # when it cannot remove the home).
        "userdel": (
            "#!/usr/bin/env bash\n"
            f"echo \"userdel $*\" >> {_q(calls)}\n"
            "{ [ \"$1\" = -r ] && [ $# -eq 2 ]; } || exit 2\n"
            "[ -z \"${USERDEL_RC:-}\" ] || exit \"$USERDEL_RC\"\n"
            "name=$2\n"
            f"home=\"$(awk -F: -v n=\"$name\" '$1 == n {{ print $6 }}' {_q(passwd)})\"\n"
            "[ -n \"$home\" ] || exit 6\n"
            f"awk -F: -v n=\"$name\" '$1 != n' {_q(passwd)} > {_q(passwd)}.new && mv {_q(passwd)}.new {_q(passwd)}\n"
            "awk -F: -v OFS=: -v n=\"$name\" -v keep=\"${USERDEL_KEEPS_GROUP:-}\" '\n"
            "    $1 == n && keep == \"\" { next }\n"
            "    { m = \",\" $4 \",\"; gsub(\",\" n \",\", \",\", m); gsub(/^,+|,+$/, \"\", m); $4 = m; print }\n"
            f"' {_q(group)} > {_q(group)}.new && mv {_q(group)}.new {_q(group)}\n"
            "[ -z \"${USERDEL_LEAVES_HOME:-}\" ] || exit 12\n"
            "rm -rf \"$home\"\n"
        ),
        "groupdel": (
            "#!/usr/bin/env bash\n"
            f"echo \"groupdel $*\" >> {_q(calls)}\n"
            "[ -z \"${GROUPDEL_RC:-}\" ] || exit \"$GROUPDEL_RC\"\n"
            f"awk -F: -v n=\"$1\" '$1 != n' {_q(group)} > {_q(group)}.new && mv {_q(group)}.new {_q(group)}\n"
        ),
        # procs holds one "FLAG UID PID" line per process: -u for an
        # effective uid, -U for a real one.
        "pgrep": (
            "#!/usr/bin/env bash\n"
            f"echo \"pgrep $*\" >> {_q(calls)}\n"
            "[ -z \"${PGREP_RC:-}\" ] || exit \"$PGREP_RC\"\n"
            f"found=\"$(awk -v f=\"$1\" -v u=\"$2\" '$1 == f && $2 == u {{ print $3 }}' {_q(procs)})\"\n"
            "[ -n \"$found\" ] || exit 1\n"
            "printf '%s\\n' \"$found\"\n"
        ),
    }


class RetiredAccountBox:
    """A scratch patched-prod-01 as far as the retired-account step sees it."""

    def __init__(self, base: Path, name: str = "pat2312-dryrun") -> None:
        self.base = base
        self.name = name
        self.uid = os.getuid()
        self.root = base / "root"
        self.home = self.root / "home-retired"
        self.tmp = self.root / "tmp"
        self.var_tmp = self.root / "var-tmp"
        self.tunnel = base / "etc-cloudflared"
        self.db = base / "db"
        self.procs = base / "procs"
        self.calls_file = base / "calls"
        self.bin = base / "retired-bin"
        self.log = base / "deploy.log"
        for directory in (self.tmp, self.var_tmp, self.tunnel, self.db, self.bin):
            directory.mkdir(parents=True, exist_ok=True)
        self.procs.write_text("")
        self.write_db(passwd=["someone:x:1000:1000::/home/someone:/bin/bash"], group=["someone:x:1000:"])
        for name, body in _shims(self.db, self.procs, self.calls_file).items():
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)

    def write_db(self, *, passwd: list[str], group: list[str]) -> None:
        (self.db / "passwd").write_text("".join(f"{line}\n" for line in passwd))
        (self.db / "group").write_text("".join(f"{line}\n" for line in group))

    def add_account(self, *, uid: int | None = None, home: Path | None = None, group_gid: int = ACCOUNT_GID) -> None:
        """The account as it is on patched-prod-01: a passwd entry, its own
        group, sudo and users memberships, a home with a tunnel credential
        that /etc/cloudflared also holds, and one scratch file in /tmp."""
        uid = self.uid if uid is None else uid
        home = self.home if home is None else home
        self.write_db(
            passwd=[
                "someone:x:1000:1000::/home/someone:/bin/bash",
                f"{self.name}:x:{uid}:{ACCOUNT_GID}:,,,:{home}:/bin/bash",
            ],
            group=[
                f"sudo:x:27:{self.name}",
                f"users:x:100:someone,{self.name}",
                f"{self.name}:x:{group_gid}:",
                "someone:x:1000:",
            ],
        )
        cloudflared = self.home / ".cloudflared"
        (self.home / ".ssh").mkdir(parents=True, exist_ok=True)
        cloudflared.mkdir(parents=True, exist_ok=True)
        (self.home / ".bashrc").write_text("# placeholder\n")
        (self.home / ".ssh" / "authorized_keys").write_text("ssh-ed25519 placeholder\n")
        (cloudflared / "cert.pem").write_text("placeholder\n")
        (cloudflared / TUNNEL_JSON).write_text(TUNNEL_JSON_BODY)
        (self.tunnel / TUNNEL_JSON).write_text(TUNNEL_JSON_BODY)
        (self.tmp / TMP_FILE).write_text("scratch\n")

    def run_process(self, flag: str = "-u", pid: int = 4242) -> None:
        with self.procs.open("a") as procs:
            procs.write(f"{flag} {self.uid} {pid}\n")

    def assignments(self) -> str:
        """Shell assignments pointing the step at this box. The caller's
        PATH must put self.bin first."""
        return (
            f"RETIRED_ACCOUNT={_q(self.name)}\nRETIRED_ACCOUNT_UID={self.uid}\n"
            f"RETIRED_ACCOUNT_HOME={_q(self.home)}\n"
            f"RETIRED_ACCOUNT_TMP_DIRS={_q(f'{self.tmp} {self.var_tmp}')}\n"
            f"RETIRED_ACCOUNT_SCAN_ROOT={_q(self.root)}\n"
            f"RETIRED_ACCOUNT_TUNNEL_DIR={_q(self.tunnel)}\n"
            "RETIRED_ACCOUNT_PATH=$PATH\n"
        )

    def passwd(self) -> str:
        return (self.db / "passwd").read_text()

    def group(self) -> str:
        return (self.db / "group").read_text()

    def calls(self) -> list[str]:
        return self.calls_file.read_text().splitlines() if self.calls_file.exists() else []

    def log_text(self) -> str:
        return self.log.read_text() if self.log.exists() else ""


def absent_account_assignments(base: Path, fakebin: Path) -> str:
    """For harnesses that drive sync_box_config for something else: a getent
    in fakebin that finds nobody, and scratch paths that do not exist, so the
    retired-account step logs "already absent" and can reach no real account
    or filesystem. The caller's PATH must put fakebin first."""
    getent = fakebin / "getent"
    getent.write_text("#!/usr/bin/env bash\n[ $# -ge 2 ] && exit 2\nexit 0\n")
    getent.chmod(0o755)
    missing = base / "no-retired-account"
    return (
        "RETIRED_ACCOUNT=pat2312-no-such-account\nRETIRED_ACCOUNT_UID=4294967294\n"
        f"RETIRED_ACCOUNT_HOME={_q(missing / 'home')}\n"
        f"RETIRED_ACCOUNT_TMP_DIRS={_q(missing / 'tmp')}\n"
        f"RETIRED_ACCOUNT_SCAN_ROOT={_q(missing)}\n"
        f"RETIRED_ACCOUNT_TUNNEL_DIR={_q(missing / 'cloudflared')}\n"
        "RETIRED_ACCOUNT_PATH=$PATH\n"
    )
