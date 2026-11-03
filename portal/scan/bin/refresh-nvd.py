#!/usr/bin/env python3
"""refresh-nvd.py — (re)build the local NVD dataset for the scan service.

Operator tool, NOT called from any request. The scan app never downloads the
NVD feed at request time (the box may have no outbound internet); instead the
operator runs this to seed / refresh nvd.db.

Usage (on the box, as the scan user, with the state dir writable):

    # Uses NVD_DB_PATH from the env (systemd sets it to
    # /var/lib/patched-scan/nvd.db). Reaches out to the fkie-cad NVD mirror.
    sudo -u scan NVD_DB_PATH=/var/lib/patched-scan/nvd.db \
        /opt/patched-scan/venv/bin/python /opt/patched-scan/bin/refresh-nvd.py

    # Or build locally, then copy the file up:
    NVD_DB_PATH=./nvd.db python scan/bin/refresh-nvd.py

Schedule it (cron / systemd timer) to keep the dataset current, e.g. daily.
"""

import os
import sys
import time

# Allow running from anywhere: put the scan app dir (parent of bin/) on the path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import NVD_DB_PATH, sync_nvd_local_dataset  # noqa: E402


def main() -> int:
    target = os.getenv("NVD_DB_PATH", NVD_DB_PATH)
    print(f"[refresh-nvd] building NVD dataset at {target} ...")
    start = time.time()
    sync_nvd_local_dataset(target)
    if not os.path.exists(target):
        print("[refresh-nvd] ERROR: dataset was not written (download failed?).")
        return 1
    size = os.path.getsize(target)
    print(f"[refresh-nvd] done in {time.time() - start:.0f}s — {size / 1024:.0f} KB at {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
