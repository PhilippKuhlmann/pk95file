"""Usage scan and soft quota (docs/design.md §8): a walk per share every scan_interval_minutes, written to
.pk95/usage.json (read by the dfree script, the share objects and the dashboard).

The soft quota ("Kontingent (Warnung)") is never a hard limit: warning and exceeded events once per crossing, and
with lock_when_exceeded the share turns read-only until a scan finds it below the size again.
"""

from __future__ import annotations

import logging
import os
import threading
import time

from . import events
from .errors import conflict, not_found
from .smbconf import RID_LOW, RID_HIGH
from .store import load_json, now_ms, save_json

log = logging.getLogger("pk95file.usage")

OWNERS_KEEP = 50


def scan_tree(root: str, skip: tuple[str, ...] = (".recycle",)) -> tuple[int, int, dict[int, list[int]]]:
    """(bytes, files, {uid: [bytes, files]}) of a folder; top-level names in skip are left out."""
    total, files, owners = 0, 0, {}
    for dirpath, dirs, names in os.walk(root):
        if dirpath == root:
            dirs[:] = [d for d in dirs if d not in skip]
        for n in names:
            try:
                st = os.lstat(os.path.join(dirpath, n))
            except OSError:
                continue
            total += st.st_size
            files += 1
            o = owners.setdefault(st.st_uid, [0, 0])
            o[0] += st.st_size
            o[1] += 1
    return total, files, owners


def quota_level(used: int, q: dict) -> str:
    """"ok" | "warning" | "exceeded" for a share's soft quota (pure)."""
    size = q.get("size_bytes", 0)
    if not size:
        return "ok"
    if used > size:
        return "exceeded"
    if used * 100 >= size * q.get("warn_percent", 90):
        return "warning"
    return "ok"


def uid_to_sid(uid: int, domain_sid: str) -> str:
    """rid backend: Unix ID 10000 + RID (pure). Other IDs have no domain SID."""
    if domain_sid and RID_LOW <= uid <= RID_HIGH:
        return f"{domain_sid}-{uid - RID_LOW}"
    return ""


class Usage:
    def __init__(self, app):
        self.app = app
        self.path = os.path.join(app.cfg.meta_root, "usage.json")
        self._lock = threading.Lock()

    def data(self) -> dict:
        return load_json(self.path, {"scanned_at": 0, "shares": {}, "quota_state": {}})

    # -- scan ---------------------------------------------------------------------------------------------------
    def scan(self, job=None) -> dict:
        if not self._lock.acquire(blocking=False):
            raise conflict("Es läuft bereits ein Scan.")
        try:
            old = self.data()
            out = {"scanned_at": 0, "shares": {}, "quota_state": dict(old.get("quota_state", {}))}
            shares = self.app.shares.raw()
            for i, s in enumerate(shares, 1):
                path = self.app.shares.path(s["name"])
                b, f, owners = scan_tree(path)
                rb = scan_tree(os.path.join(path, ".recycle"), ())[0] if os.path.isdir(os.path.join(path, ".recycle")) else 0
                idx = load_json(os.path.join(self.app.cfg.meta_root, "snapshots", s["name"], "index.json"), {})
                sb = sum(v.get("unique_bytes", 0) for v in idx.values())
                top = sorted(owners.items(), key=lambda kv: kv[1][0], reverse=True)[:OWNERS_KEEP]
                out["shares"][s["name"]] = {"bytes": b, "files": f, "recycle_bytes": rb, "snapshot_bytes": sb,
                                            "scanned_at": now_ms(),
                                            "owners": {str(uid): {"bytes": v[0], "files": v[1]} for uid, v in top}}
                if job is not None:
                    job.progress(i, len(shares), "shares")
            out["scanned_at"] = now_ms()
            save_json(self.path, out)
            self._quotas(out)
            return out
        finally:
            self._lock.release()

    def _quotas(self, data: dict) -> None:
        state = data.setdefault("quota_state", {})
        for s in self.app.shares.raw():
            used = data["shares"].get(s["name"], {}).get("bytes", 0)
            q = s.get("soft_quota") or {}
            level = quota_level(used, q)
            prev = state.get(s["name"], "ok")
            lock = level == "exceeded" and q.get("lock_when_exceeded", False)
            if bool(s.get("locked")) != lock:
                self.app.shares.set_locked(s["name"], lock)
            if level != prev:
                size = q.get("size_bytes", 0)
                if level == "warning":
                    self.app.events.send(events.SOFT_QUOTA_WARNING, "warning",
                                         f"Freigabe „{s['name']}“: {used * 100 // size} % des Kontingents belegt",
                                         "", {"share": s["name"], "used_bytes": used, "size_bytes": size})
                elif level == "exceeded":
                    self.app.events.send(events.SOFT_QUOTA_EXCEEDED, "warning",
                                         f"Freigabe „{s['name']}“ über dem Kontingent",
                                         "Die Freigabe ist jetzt schreibgeschützt." if lock else "",
                                         {"share": s["name"], "used_bytes": used, "size_bytes": size, "locked": lock})
            state[s["name"]] = level
        save_json(self.path, data)

    def start_scan(self):
        if self._lock.locked() or self.app.jobs.busy("scan", ""):
            raise conflict("Es läuft bereits ein Scan.")
        return self.app.jobs.start("scan", lambda job: self.scan(job))

    def task(self, now, done: set[str]) -> list[str]:
        """Scheduler task: a scan every scan_interval_minutes (no slots to remember)."""
        interval = self.app.app_settings()["scan_interval_minutes"] * 60
        if time.time() - self.data().get("scanned_at", 0) / 1000 >= interval and not self._lock.locked():
            self.scan()
        return []

    # -- API ------------------------------------------------------------------------------------------------------
    def info(self) -> dict:
        from . import storage

        self.app.require_ready()
        d = self.data()
        u = storage.usage(self.app.cfg.data_root)
        shares = []
        for s in self.app.shares.raw():
            v = d["shares"].get(s["name"], {})
            size = (s.get("soft_quota") or {}).get("size_bytes", 0)
            shares.append({"name": s["name"], "bytes": v.get("bytes", 0), "files": v.get("files", 0),
                           "recycle_bytes": v.get("recycle_bytes", 0), "snapshot_bytes": v.get("snapshot_bytes", 0),
                           "soft_quota_bytes": size, "percent": v.get("bytes", 0) * 100 // size if size else 0})
        interval = self.app.app_settings()["scan_interval_minutes"] * 60000
        return {"filesystem": {"path": self.app.cfg.data_root, "fs_type": "", "total_bytes": u["total_bytes"],
                               "free_bytes": u["free_bytes"],
                               "on_system_disk": False},
                "shares": shares, "scanned_at": d.get("scanned_at", 0),
                "next_scan_at": d.get("scanned_at", 0) + interval if d.get("scanned_at") else 0}

    def owners(self, name: str) -> dict:
        self.app.require_ready()
        if not any(s["name"].lower() == name.lower() for s in self.app.shares.raw()):
            raise not_found("Unbekannte Freigabe.")
        real = next(s["name"] for s in self.app.shares.raw() if s["name"].lower() == name.lower())
        dsid = self.app.settings.get("domain_sid", "")
        items = []
        for uid, v in (self.data()["shares"].get(real, {}).get("owners") or {}).items():
            sid = uid_to_sid(int(uid), dsid)
            res = self.app.shares.resolver.sid_to_name(sid) if sid else None
            items.append({"sid": sid, "name": res[0] if res else f"Unix-Benutzer {uid}", "bytes": v["bytes"],
                          "files": v["files"]})
        return {"items": sorted(items, key=lambda x: x["bytes"], reverse=True)}
