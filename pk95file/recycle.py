"""Recycle bin per share (docs/api.md → Recycle bin): list, restore, empty and the daily retention.

vfs_recycle moves a deleted file to <share>/.recycle/<user>/<original path> and sets its mtime to the time of
deletion (recycle:touch_mtime), so "deleted_at" and the retention both use the mtime. A moved file keeps its NT ACL
(user.NTACL travels with the inode); folders the restore has to create again get the ACL inherited from their parent.
"""

from __future__ import annotations

import logging
import os
import shutil
import time

from .errors import Fields, not_found

log = logging.getLogger("pk95file.recycle")

RESTORED = " (Wiederhergestellt)"
MAX_LIMIT = 1000


def recycle_dir(share_dir: str) -> str:
    return os.path.join(share_dir, ".recycle")


def safe_rel(path) -> str | None:
    """Normalised relative path inside .recycle, or None for anything that leaves it (pure)."""
    if not isinstance(path, str) or not path.strip() or path.startswith("/") or "\x00" in path:
        return None
    parts = [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def free_name(path: str) -> str:
    """path, or path with " (Wiederhergestellt)" (and a number) before the extension if it exists (pure-ish)."""
    if not os.path.lexists(path):
        return path
    root, ext = os.path.splitext(path)
    if os.path.isdir(path):
        root, ext = path, ""
    cand = f"{root}{RESTORED}{ext}"
    n = 2
    while os.path.lexists(cand):
        cand = f"{root}{RESTORED[:-1]} {n}){ext}"
        n += 1
    return cand


def entries(share_dir: str) -> list[dict]:
    """All files in the recycle bin: {"path", "user", "size", "deleted_at"} (path relative to .recycle)."""
    base = recycle_dir(share_dir)
    out = []
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            out.append({"path": rel, "user": rel.split("/", 1)[0], "size": st.st_size,
                        "deleted_at": int(st.st_mtime * 1000)})
    return out


def listing(share_dir: str, user: str = "", search: str = "", offset: int = 0, limit: int = 100) -> dict:
    items = entries(share_dir)
    total_bytes = sum(e["size"] for e in items)
    if user:
        items = [e for e in items if e["user"].lower() == user.lower()]
    if search:
        s = search.lower()
        items = [e for e in items if s in e["path"].lower()]
    items.sort(key=lambda e: e["deleted_at"], reverse=True)
    return {"items": items[offset:offset + limit], "total": len(items), "bytes": total_bytes}


def purge(share_dir: str, older_than_days: int, now: float | None = None) -> int:
    """Delete entries older than the given days (0 = all), then empty folders. Returns the number of files."""
    base = recycle_dir(share_dir)
    if not os.path.isdir(base):
        return 0
    cutoff = (time.time() if now is None else now) - older_than_days * 86400
    n = 0
    for dirpath, dirs, files in os.walk(base, topdown=False):
        for name in files:
            full = os.path.join(dirpath, name)
            try:
                if older_than_days == 0 or os.lstat(full).st_mtime < cutoff:
                    os.unlink(full)
                    n += 1
            except OSError as exc:
                log.warning("recycle purge %s: %s", full, exc)
        if dirpath != base:
            try:
                os.rmdir(dirpath)  # only succeeds when empty
            except OSError:
                pass
    return n


class Recycle:
    def __init__(self, app):
        self.app = app

    def _share(self, name: str) -> dict:
        self.app.require_ready()
        for s in self.app.shares.raw():
            if s["name"].lower() == name.lower():
                return s
        raise not_found("Unbekannte Freigabe.")

    def list(self, name: str, q) -> dict:
        s = self._share(name)
        f = Fields()
        try:
            offset, limit = int(q.q("offset", "0")), int(q.q("limit", "100"))
        except ValueError:
            offset, limit = -1, 0
        if offset < 0:
            f.add("offset", "Bitte eine Zahl ab 0 angeben.")
        if not 1 <= limit <= MAX_LIMIT:
            f.add("limit", f"Erlaubt sind 1 bis {MAX_LIMIT}.")
        f.raise_if_any()
        return listing(self.app.shares.path(s["name"]), q.q("user"), q.q("search"), offset, limit)

    def restore(self, name: str, body: dict):
        s = self._share(name)
        paths = body.get("paths")
        f = Fields()
        rels = []
        if not isinstance(paths, list) or not 1 <= len(paths) <= 1000:
            f.add("paths", "Bitte 1 bis 1000 Pfade angeben.")
        else:
            base = recycle_dir(self.app.shares.path(s["name"]))
            for i, p in enumerate(paths):
                rel = safe_rel(p)
                if rel is None or "/" not in rel:
                    f.add(f"paths.{i}", "Ungültiger Pfad.")
                elif not os.path.isfile(os.path.join(base, rel)):
                    f.add(f"paths.{i}", "Nicht im Papierkorb.")
                else:
                    rels.append(rel)
        f.raise_if_any()
        return self.app.jobs.start("recycle_restore", lambda job: self._restore(s["name"], rels, job),
                                   share=s["name"])

    def _restore(self, name: str, rels: list[str], job) -> None:
        share_dir = self.app.shares.path(name)
        base = recycle_dir(share_dir)
        dsid = self.app.settings["domain_sid"]
        errors = []
        job.progress(0, len(rels), "files")
        for i, rel in enumerate(rels, 1):
            original = rel.split("/", 1)[1]  # strip the user folder
            target = free_name(os.path.join(share_dir, original))
            try:
                self._make_parents(share_dir, os.path.dirname(target), dsid, name)
                shutil.move(os.path.join(base, rel), target)
            except Exception as exc:  # noqa: BLE001 - report per file
                errors.append(f"{rel}: {exc}")
            job.progress(i)
        if errors:
            raise RuntimeError(f"{len(errors)} Dateien nicht wiederhergestellt, z. B. {errors[0]}")

    def _make_parents(self, share_dir: str, folder: str, dsid: str, service: str) -> None:
        """Create missing folders below the share root with the ACL inherited from their parent."""
        missing = []
        d = folder
        while not os.path.isdir(d) and os.path.commonpath([d, share_dir]) == share_dir and d != share_dir:
            missing.append(d)
            d = os.path.dirname(d)
        for d in reversed(missing):
            os.mkdir(d)
            os.chmod(d, 0o777)
            self.app.acls.inherit(d, dsid, service)

    def empty(self, name: str, body: dict):
        s = self._share(name)
        days = body.get("older_than_days", 0)
        if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= 3650:
            Fields({"older_than_days": "Erlaubt sind 0 bis 3650 Tage."}).raise_if_any()
        path = self.app.shares.path(s["name"])
        return self.app.jobs.start("recycle_empty", lambda job: job.progress(purge(path, days), unit="files"),
                                   share=s["name"])

    def retention(self) -> dict[str, int]:
        """Daily run: every share with the recycle bin on loses entries older than keep_days."""
        out = {}
        for s in self.app.shares.raw():
            rec = s.get("recycle") or {}
            if rec.get("enabled"):
                out[s["name"]] = purge(self.app.shares.path(s["name"]), int(rec.get("keep_days", 30)))
        return out

    def task(self, now, done: set[str]) -> list[str]:
        """Scheduler task: once a day at the maintenance time (PK95FILE_MAINTENANCE_TIME, default 03:30)."""
        from .scheduler import due_slot

        key = due_slot([self.app.cfg.maintenance_time], [1, 2, 3, 4, 5, 6, 7], now, done)
        if not key:
            return []
        removed = self.retention()
        log.info("recycle retention: %s", removed)
        return [key]
