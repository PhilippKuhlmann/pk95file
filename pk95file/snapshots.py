"""Snapshots ("Vorgängerversionen", docs/design.md §7): rsync --link-dest copies per share, shown by shadow_copy2.

  /srv/files/.pk95/snapshots/<share>/@GMT-YYYY.MM.DD-HH.MM.SS/   one snapshot (UTC), an image of the share root
  /srv/files/.pk95/snapshots/<share>/index.json                  per snapshot: manual, files, unique_bytes, duration

A snapshot hardlinks unchanged files to the previous snapshot – never to the live share, where smbd writes in place.
So the first snapshot is a full copy and every changed file costs its whole size again (the UI says so). Runs are
serialised across shares (I/O) and skipped while the data root has less than snapshot_min_free_percent free.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone

from . import events, storage
from .errors import conflict, not_found
from .scheduler import due_slot, next_slot
from .store import load_json, now_ms, save_json

log = logging.getLogger("pk95file.snapshots")

FORMAT = "@GMT-%Y.%m.%d-%H.%M.%S"
NAME_RE = re.compile(r"^@GMT-\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}$")
RSYNC_TIMEOUT = 6 * 3600


def snap_id(at: datetime) -> str:
    return at.astimezone(timezone.utc).strftime(FORMAT)


def parse_id(name: str) -> datetime | None:
    if not NAME_RE.match(name):
        return None
    return datetime.strptime(name, FORMAT).replace(tzinfo=timezone.utc)


def to_delete(ids: list[str], keep: dict, now: datetime) -> list[str]:
    """Snapshot ids the retention removes (pure). Kept: the `recent` newest; the newest of each of the last `daily`
    days; the newest of each of the last `weekly` ISO weeks (local time). A snapshot stays if any rule keeps it."""
    dated = sorted(((parse_id(i), i) for i in ids if parse_id(i)), reverse=True)
    keepers = {i for _, i in dated[:keep.get("recent", 12)]}
    local = [(at.astimezone(now.tzinfo) if now.tzinfo else at.astimezone().replace(tzinfo=None), i) for at, i in dated]
    day0 = now.date()
    seen_days, seen_weeks = set(), set()
    for at, i in local:
        d = at.date()
        if (day0 - d).days < keep.get("daily", 14) and d not in seen_days:
            seen_days.add(d)
            keepers.add(i)
        wk = d.isocalendar()[:2]
        if (day0 - d).days < 7 * keep.get("weekly", 8) and wk not in seen_weeks:
            seen_weeks.add(wk)
            keepers.add(i)
    return [i for _, i in dated if i not in keepers]


def measure(snap_path: str) -> tuple[int, int]:
    """(files, unique bytes) of one snapshot. Unique = apparent size (st_size) of the files with link count 1, i.e.
    not hardlinked to another snapshot: the whole share for the first snapshot (a full copy), only changed files
    after that. st_size, not st_blocks: right after rsync, ZFS reports almost no blocks until the transaction group
    is written (and compression shrinks them further) – the live test saw 2048 bytes for an 81 MB first copy."""
    files, unique = 0, 0
    for dirpath, _dirs, names in os.walk(snap_path):
        for n in names:
            try:
                st = os.lstat(os.path.join(dirpath, n))
            except OSError:
                continue
            files += 1
            if st.st_nlink == 1:
                unique += st.st_size
    return files, unique


def smb_lines(share_dir: str, snap_dir: str) -> list[str]:
    """shadow_copy2 options for one share: the share root is the "mount point" and each snapshot an image of it."""
    return [
        f"    shadow:mountpoint = {share_dir}",
        f"    shadow:snapdir = {snap_dir}",
        f"    shadow:format = {FORMAT}",
        "    shadow:sort = desc",
        "    shadow:localtime = no",
        "    shadow:snapdirseverywhere = no",
    ]


class Snapshots:
    def __init__(self, app):
        self.app = app
        self._run_lock = threading.Lock()  # one snapshot at a time across all shares
        self.state_path = app.cfg.path("snapshots.json")
        self.state = load_json(self.state_path, {"last_run_at": 0, "last_ok": True, "failed_shares": []})

    # -- paths and index -------------------------------------------------------------------------------------------
    def snap_dir(self, share: str) -> str:
        return os.path.join(self.app.cfg.meta_root, "snapshots", share)

    def _index(self, share: str) -> dict:
        return load_json(os.path.join(self.snap_dir(share), "index.json"), {})

    def _save_index(self, share: str, idx: dict) -> None:
        save_json(os.path.join(self.snap_dir(share), "index.json"), idx)

    def ids(self, share: str) -> list[str]:
        try:
            return sorted((n for n in os.listdir(self.snap_dir(share)) if NAME_RE.match(n)), reverse=True)
        except OSError:
            return []

    def _share(self, name: str) -> dict:
        self.app.require_ready()
        for s in self.app.shares.raw():
            if s["name"].lower() == name.lower():
                return s
        raise not_found("Unbekannte Freigabe.")

    # -- API ----------------------------------------------------------------------------------------------------
    def list(self, name: str) -> dict:
        s = self._share(name)
        idx = self._index(s["name"])
        keep = s["snapshots"]["keep"]
        now = datetime.now().astimezone()
        doomed = set(to_delete(self.ids(s["name"]), keep, now))
        items = []
        for i in self.ids(s["name"]):
            meta = idx.get(i, {})
            items.append({"id": i, "created_at": int(parse_id(i).timestamp() * 1000), "manual": meta.get("manual", False),
                          "files": meta.get("files", 0), "unique_bytes": meta.get("unique_bytes", 0),
                          "duration_ms": meta.get("duration_ms", 0), "kept_by": [] if i in doomed else
                          self._kept_by(i, keep, now)})
        return {"items": items, "backend": "rsync"}

    @staticmethod
    def _kept_by(i: str, keep: dict, now: datetime) -> list[str]:
        out = []
        at = parse_id(i).astimezone()
        if (now.date() - at.date()).days < keep.get("daily", 14):
            out.append("daily")
        if (now.date() - at.date()).days < 7 * keep.get("weekly", 8):
            out.append("weekly")
        return ["recent"] + out

    def create(self, name: str, manual: bool = True):
        s = self._share(name)
        if self.app.jobs.busy("snapshot", s["name"]):
            raise conflict("Für diese Freigabe läuft bereits ein Snapshot.")
        return self.app.jobs.start("snapshot", lambda job: self._create(s["name"], manual, job), share=s["name"])

    def delete(self, name: str, snap: str):
        s = self._share(name)
        if snap not in self.ids(s["name"]):
            raise not_found("Unbekannter Snapshot.")
        return self.app.jobs.start("snapshot_delete", lambda job: self._remove(s["name"], [snap]), share=s["name"])

    # -- the work -------------------------------------------------------------------------------------------------
    def _create(self, share: str, manual: bool, job=None) -> str | None:
        with self._run_lock:
            st = self.app.app_settings()
            u = storage.usage(self.app.cfg.data_root)
            if u["total_bytes"] and u["free_percent"] < st["snapshot_min_free_percent"]:
                msg = (f"Snapshot von „{share}“ übersprungen: nur {u['free_percent']} % frei "
                       f"(Minimum {st['snapshot_min_free_percent']} %).")
                self.app.events.send(events.SNAPSHOT_SKIPPED, "warning", f"Snapshot von „{share}“ übersprungen", msg,
                                     {"share": share, "free_percent": u["free_percent"]})
                raise RuntimeError(msg)
            src = self.app.shares.path(share).rstrip("/") + "/"
            base = self.snap_dir(share)
            # 0755: shadow_copy2 reads the snapshots as the connected user; the NT ACLs inside still decide
            os.makedirs(base, exist_ok=True)
            os.chmod(os.path.dirname(base), 0o755)
            os.chmod(base, 0o755)
            sid = snap_id(datetime.now(timezone.utc))
            while os.path.exists(os.path.join(base, sid)):  # two runs within one second
                time.sleep(1)
                sid = snap_id(datetime.now(timezone.utc))
            tmp = os.path.join(base, sid + ".tmp")
            shutil.rmtree(tmp, ignore_errors=True)
            argv = ["rsync", "-aHAX", "--numeric-ids", "--delete", "--exclude=/.recycle/"]
            prev = self.ids(share)
            if prev:
                argv.append(f"--link-dest={os.path.join(base, prev[0])}")
            argv += [src, tmp + "/"]
            started = time.monotonic()
            try:
                res = subprocess.run(argv, capture_output=True, text=True, timeout=RSYNC_TIMEOUT)
            except subprocess.TimeoutExpired:
                shutil.rmtree(tmp, ignore_errors=True)
                raise RuntimeError("rsync brauchte länger als 6 Stunden.") from None
            # 24 = some files vanished during the run: the snapshot is still usable (not atomic, docs/design.md §7)
            if res.returncode not in (0, 24):
                shutil.rmtree(tmp, ignore_errors=True)
                lines = (res.stderr or res.stdout).strip().splitlines()
                raise RuntimeError(f"rsync fehlgeschlagen (Code {res.returncode}): {lines[-1] if lines else ''}")
            os.rename(tmp, os.path.join(base, sid))
            files, unique = measure(os.path.join(base, sid))
            idx = self._index(share)
            idx[sid] = {"manual": manual, "files": files, "unique_bytes": unique,
                        "duration_ms": int((time.monotonic() - started) * 1000)}
            self._save_index(share, idx)
            if job is not None:
                job.progress(files, files, "files")
            self.prune(share)
            return sid

    def _remove(self, share: str, ids: list[str]) -> None:
        idx = self._index(share)
        for i in ids:
            shutil.rmtree(os.path.join(self.snap_dir(share), i), ignore_errors=True)
            idx.pop(i, None)
        self._save_index(share, idx)

    def prune(self, share: str) -> list[str]:
        s = next((x for x in self.app.shares.raw() if x["name"] == share), None)
        if not s:
            return []
        doomed = to_delete(self.ids(share), s["snapshots"]["keep"], datetime.now().astimezone())
        if doomed:
            self._remove(share, doomed)
        return doomed

    # -- schedule ---------------------------------------------------------------------------------------------------
    def task(self, now: datetime, done: set[str]) -> list[str]:
        """Scheduler task: every share with snapshots on, at its times and weekdays (local time)."""
        handled = []
        failed = []
        ran = False
        for s in self.app.shares.raw():
            snaps = s.get("snapshots") or {}
            if not snaps.get("enabled") or not s.get("enabled", True):
                continue
            sched = snaps["schedule"]
            slot = due_slot(sched["times"], sched["weekdays"], now, {k.split("|", 1)[1] for k in done
                                                                      if k.split("|", 1)[0] == s["name"]})
            if not slot:
                continue
            handled.append(f"{s['name']}|{slot}")
            ran = True
            try:
                self._create(s["name"], manual=False)
            except Exception as exc:  # noqa: BLE001 - next share, then report
                log.error("snapshot %s: %s", s["name"], exc)
                failed.append(s["name"])
                if "übersprungen" not in str(exc):
                    self.app.events.send(events.SNAPSHOT_FAILED, "warning", f"Snapshot von „{s['name']}“ fehlgeschlagen",
                                         str(exc), {"share": s["name"], "error": str(exc)})
        if ran:
            self.state = {"last_run_at": now_ms(), "last_ok": not failed, "failed_shares": failed}
            save_json(self.state_path, self.state)
        return handled

    def dashboard(self) -> dict:
        nxt = None
        now = datetime.now()
        count = 0
        for s in self.app.shares.raw():
            count += len(self.ids(s["name"]))
            snaps = s.get("snapshots") or {}
            if snaps.get("enabled") and s.get("enabled", True):
                n = next_slot(snaps["schedule"]["times"], snaps["schedule"]["weekdays"], now)
                if n and (nxt is None or n < nxt):
                    nxt = n
        return {"last_run_at": self.state.get("last_run_at", 0), "last_ok": self.state.get("last_ok", True),
                "next_run_at": int(nxt.timestamp() * 1000) if nxt else 0,
                "failed_shares": list(self.state.get("failed_shares", [])), "count": count}

