"""Create an unprivileged scratch script with a checked, fixed test PATH.

Test instrumentation only. Never imported or packaged by endpoint scripts.
The caller must stop on failure before attempting to execute the destination.
"""
import os
from pathlib import Path
import re
import shlex
import stat
import sys

SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
SOURCE_LINE = 'export PATH="' + SYSTEM_PATH + '"'


def owned_directory(directory):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("scratch directory must be owned, non-symlink and not group/world writable")


def rewrite(source, destination, stub_path):
    if os.geteuid() == 0:
        raise ValueError("fixture copies must never run as root")
    source, destination = Path(source), Path(destination)
    owned_directory(destination.parent)
    if destination.parent.resolve() == source.parent.resolve():
        raise ValueError("fixture destination must be isolated from product source")
    # Refuse an existing output rather than risk executing a stale earlier copy
    # after a failed rewrite. Callers create each copy once or remove it first.
    if destination.exists() or destination.is_symlink():
        raise ValueError("fixture destination already exists")
    directories = stub_path.split(":")
    if not directories or any(not item or not Path(item).is_absolute() for item in directories):
        raise ValueError("stub directories must be nonempty absolute paths")
    for item in directories:
        owned_directory(Path(item))
    text = source.read_text()
    declarations = re.findall(r"^export PATH=.*$", text, re.M)
    if declarations != [SOURCE_LINE]:
        raise ValueError("expected exactly one literal system-only source PATH line")
    replacement = "export PATH=" + shlex.quote(":".join(directories) + ":" + SYSTEM_PATH)
    rewritten = text.replace(SOURCE_LINE, replacement, 1)
    if re.findall(r"^export PATH=.*$", rewritten, re.M) != [replacement]:
        raise ValueError("expected exactly one rewritten fixed fixture PATH line")
    with destination.open("x") as output:
        output.write(rewritten)
    destination.chmod(0o700)


if __name__ == "__main__":
    try:
        rewrite(*sys.argv[1:])
    except (OSError, ValueError, TypeError) as error:
        sys.exit("FATAL fixture isolation: " + str(error))
