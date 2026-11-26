"""Preflight of the data root (docs/design.md §6, GET /api/setup → storage)."""

from __future__ import annotations

import errno
import fcntl
import os
import tempfile

OK_FS = ("zfs", "ext4", "xfs", "btrfs")
FICLONE = 0x40049409
GIB = 1024 ** 3
MIN_FREE_BYTES = 5 * GIB
MIN_FREE_PERCENT = 20


def fs_type(path: str, mountinfo: str = "/proc/self/mountinfo") -> str:
    """Type of the filesystem path lives on (longest mount point prefix)."""
    best, typ = "", ""
    try:
        with open(mountinfo, encoding="utf-8") as fh:
            for line in fh:
                left, _, right = line.partition(" - ")
                fields = left.split()
                if len(fields) < 5:
                    continue
                mnt = fields[4].replace("\\040", " ")
                if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(best):
                    best, typ = mnt, right.split()[0] if right.split() else ""
    except OSError:
        pass
    return typ


def _xattr_ok(d: str) -> bool:
    try:
        with tempfile.NamedTemporaryFile(dir=d, prefix=".pk95-xattr-") as fh:
            os.setxattr(fh.name, "user.NTACL", b"pk95")
            return os.getxattr(fh.name, "user.NTACL") == b"pk95"
    except OSError:
        return False


def _hardlink_ok(d: str) -> bool:
    try:
        with tempfile.TemporaryDirectory(dir=d, prefix=".pk95-link-") as tmp:
            a, sub = os.path.join(tmp, "a"), os.path.join(tmp, "sub")
            os.mkdir(sub)
            open(a, "w").close()
            os.link(a, os.path.join(sub, "b"))
            return os.stat(a).st_nlink == 2
    except OSError:
        return False


def _reflink_ok(d: str) -> bool:
    try:
        with tempfile.NamedTemporaryFile(dir=d, prefix=".pk95-src-") as src, \
                tempfile.NamedTemporaryFile(dir=d, prefix=".pk95-dst-") as dst:
            src.write(b"pk95")
            src.flush()
            fcntl.ioctl(dst.fileno(), FICLONE, src.fileno())
            return True
    except OSError:
        return False


def evaluate(info: dict) -> dict:
    """German problems (block setup) and warnings from the raw checks (pure)."""
    problems, warnings = [], []
    if not info["exists"]:
        problems.append(f"{info['path']} fehlt. Bitte in Proxmox einen Mountpoint unter /srv/pk95/files einhängen.")
    elif not info["writable"]:
        problems.append(f"{info['path']} ist nicht beschreibbar.")
    else:
        if info["fs_type"] and info["fs_type"] not in OK_FS:
            problems.append(f"Dateisystem {info['fs_type']} wird nicht unterstützt (erlaubt: zfs, ext4, xfs, btrfs).")
        if not info["xattr"]:
            problems.append("Das Dateisystem unterstützt keine user.*-Attribute.")
        if not info["hardlinks"]:
            problems.append("Das Dateisystem unterstützt keine Hardlinks (für Vorgängerversionen nötig).")
        if info["on_system_disk"]:
            problems.append("Die Daten lägen auf der Systemplatte des LXC. Bitte in Proxmox einen eigenen Mountpoint "
                            "unter /srv/pk95/files einhängen.")
        total, free = info["total_bytes"], info["free_bytes"]
        if total and (free < MIN_FREE_BYTES or free * 100 < total * MIN_FREE_PERCENT):
            warnings.append(f"Nur {free / GIB:.1f} GB frei ({free * 100 // total} %).")
    return {**info, "problems": problems, "warnings": warnings}


def preflight(data_root: str, data_dir: str) -> dict:
    info = {"path": data_root, "fs_type": "", "total_bytes": 0, "free_bytes": 0, "on_system_disk": False,
            "xattr": False, "hardlinks": False, "reflink": False, "exists": os.path.isdir(data_root),
            "writable": False}
    if info["exists"]:
        info["writable"] = os.access(data_root, os.W_OK)
        info["fs_type"] = fs_type(os.path.realpath(data_root))
        st = os.statvfs(data_root)
        info["total_bytes"] = st.f_blocks * st.f_frsize
        info["free_bytes"] = st.f_bavail * st.f_frsize
        try:
            info["on_system_disk"] = os.stat(data_root).st_dev == os.stat(data_dir).st_dev
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise
        if info["writable"]:
            info["xattr"] = _xattr_ok(data_root)
            info["hardlinks"] = _hardlink_ok(data_root)
            info["reflink"] = _reflink_ok(data_root)
    out = evaluate(info)
    out.pop("exists")
    out.pop("writable")
    return out


def same_device(a: str, b: str) -> bool:
    try:
        return os.stat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return False


def usage(path: str) -> dict:
    try:
        st = os.statvfs(path)
    except OSError:
        return {"total_bytes": 0, "free_bytes": 0, "used_bytes": 0, "free_percent": 0}
    total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
    return {"total_bytes": total, "free_bytes": free, "used_bytes": total - st.f_bfree * st.f_frsize,
            "free_percent": int(free * 100 // total) if total else 0}
