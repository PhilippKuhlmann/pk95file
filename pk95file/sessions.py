"""Sessions and open files from `smbstatus --json` (docs/api.md → Sessions and open files).

The JSON layout of smbstatus is read defensively (keys may be missing between Samba versions); the parsing is pure
so it is unit tested with a sample. Samba cannot close a single file, only a whole session (its smbd process).
"""

from __future__ import annotations

import os
import signal
import threading
import time
from datetime import datetime

from . import samba
from .errors import not_found

CACHE = 2.0


def _ms(value) -> int:
    """ISO time from smbstatus ("2026-11-26T07:01:02.123456+01:00") to Unix ms, 0 if unknown (pure)."""
    if not isinstance(value, str) or not value:
        return 0
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return 0


def _pid(obj) -> int:
    sid = (obj or {}).get("server_id") or {}
    try:
        return int(str(sid.get("pid", 0)))
    except ValueError:
        return 0


def _cipher(obj) -> bool:
    c = (obj or {}).get("cipher", "")
    return bool(c) and c not in ("-", "")


def parse_sessions(st: dict) -> list[dict]:
    tcons = list((st.get("tcons") or {}).values())
    opens_per_pid: dict[int, int] = {}
    for f in (st.get("open_files") or {}).values():
        for o in (f.get("opens") or {}).values():
            p = _pid(o)
            opens_per_pid[p] = opens_per_pid.get(p, 0) + 1
    out = []
    for key, s in (st.get("sessions") or {}).items():
        pid = _pid(s)
        sid = str(s.get("session_id", key))
        shares = sorted({t.get("service", "") for t in tcons if str(t.get("session_id", "")) == sid
                         and t.get("service") and t.get("service").upper() != "IPC$"})
        out.append({"id": sid, "pid": pid, "user": s.get("username", ""), "machine": s.get("remote_machine", ""),
                    "hostname": s.get("hostname", ""), "protocol": s.get("session_dialect", ""),
                    "encrypted": _cipher(s.get("encryption")), "signed": _cipher(s.get("signing")),
                    "connected_at": _ms(s.get("creation_time") or s.get("auth_time")),
                    "shares": shares, "open_files": opens_per_pid.get(pid, 0)})
    return sorted(out, key=lambda x: x["connected_at"])


def parse_open_files(st: dict, share_paths: dict[str, str]) -> list[dict]:
    """share_paths: {share name: share root}. Paths are returned relative to the share root."""
    users = {_pid(s): (str(s.get("session_id", k)), s.get("username", ""))
             for k, s in (st.get("sessions") or {}).items()}
    out = []
    for f in (st.get("open_files") or {}).values():
        root = f.get("service_path", "")
        share = next((n for n, p in share_paths.items() if root.rstrip("/") == p.rstrip("/")), "")
        for o in (f.get("opens") or {}).values():
            pid = _pid(o)
            mask = o.get("access_mask") or {}
            write = any(mask.get(k) for k in ("WRITE_DATA", "APPEND_DATA", "WRITE_ATTRIBUTES", "DELETE"))
            oplock = o.get("oplock") or {}
            text = oplock.get("text") if isinstance(oplock, dict) else str(oplock)
            sid, user = users.get(pid, ("", ""))
            out.append({"share": share, "path": f.get("filename", ""), "user": user, "session_id": sid,
                        "mode": "write" if write else "read", "oplock": (text or "").lower(),
                        "opened_at": _ms(o.get("opened_at"))})
    return out


class Sessions:
    def __init__(self, app):
        self.app = app
        self._lock = threading.Lock()
        self._cache: tuple[float, dict] = (0.0, {})

    def status(self) -> dict:
        with self._lock:
            at, st = self._cache
            if time.monotonic() - at > CACHE:
                st = samba.smbstatus()
                self._cache = (time.monotonic(), st)
            return st

    def list(self) -> dict:
        self.app.require_ready()
        items = parse_sessions(self.status())
        return {"items": items, "total": len(items)}

    def open_files(self, share: str = "") -> dict:
        self.app.require_ready()
        paths = {s["name"]: self.app.shares.path(s["name"]) for s in self.app.shares.raw()}
        items = parse_open_files(self.status(), paths)
        if share:
            items = [i for i in items if i["share"].lower() == share.lower()]
        return {"items": items, "total": len(items)}

    def disconnect(self, session_id: str) -> None:
        self.app.require_ready()
        with self._lock:
            self._cache = (0.0, {})
        for s in parse_sessions(samba.smbstatus()):
            if s["id"] == session_id and s["pid"] > 1:
                try:
                    os.kill(s["pid"], signal.SIGTERM)  # ends that client's smbd; Windows reconnects on next access
                except ProcessLookupError:
                    pass
                return
        raise not_found("Unbekannte Sitzung.")

    def counts(self) -> tuple[int, int]:
        st = self.status()
        return len(st.get("sessions") or {}), sum(len(f.get("opens") or {}) for f in (st.get("open_files") or {}).values())
