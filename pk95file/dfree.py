"""smb.conf "dfree command" (docs/design.md §8): what Explorer shows as size and free space of a share.

smbd runs `dfree <directory>` inside the share and reads "<total> <free> [<block size>]". With a soft quota the
share looks like a disk of the quota's size (free = size - last scanned usage, never more than really free);
without one the real filesystem is reported. Not a limit – only what clients see.
"""

from __future__ import annotations

import json
import os
import sys

BLOCK = 1024


def answer(fs_total: int, fs_free: int, quota: int, used: int) -> tuple[int, int]:
    """(total bytes, free bytes) to report (pure)."""
    if not quota:
        return fs_total, fs_free
    return quota, max(0, min(quota - used, fs_free))


def main(argv: list[str]) -> int:
    data_root = os.environ.get("PK95FILE_DATA_ROOT", "/srv/files")
    data_dir = os.environ.get("PK95FILE_DATA_DIR", "/var/lib/pk95file")
    target = os.path.realpath(argv[1] if len(argv) > 1 else ".")
    st = os.statvfs(target)
    fs_total, fs_free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
    rel = os.path.relpath(target, os.path.join(data_root, "shares"))
    share = rel.split(os.sep, 1)[0] if not rel.startswith("..") else ""
    quota = used = 0
    try:
        with open(os.path.join(data_dir, "shares.json"), encoding="utf-8") as fh:
            for s in json.load(fh):
                if s["name"] == share:
                    quota = (s.get("soft_quota") or {}).get("size_bytes", 0)
        with open(os.path.join(data_root, ".pk95", "usage.json"), encoding="utf-8") as fh:
            used = json.load(fh).get("shares", {}).get(share, {}).get("bytes", 0)
    except (OSError, ValueError, KeyError):
        pass
    total, free = answer(fs_total, fs_free, quota, used)
    print(f"{total // BLOCK} {free // BLOCK} {BLOCK}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
