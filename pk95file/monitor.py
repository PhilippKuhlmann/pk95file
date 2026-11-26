"""Watches smbd/winbindd, the server address, the trust, free space and the RID range; sends the events of
docs/api.md (frozen list) once per change of state."""

from __future__ import annotations

import logging
import threading
import time

from . import events, netinfo, samba, storage
from .smbconf import MAX_RID
from .store import now_ms
from .supervisor import tcp_open

log = logging.getLogger("pk95file.monitor")

TICK = 30.0
DOWN_AFTER = 60.0
TRUST_EVERY = 300.0
TRUST_FAILS = 3
IP_EVERY = 300.0
RID_EVERY = 3600.0
RID_WARN_PERCENT = 90


class Monitor:
    def __init__(self, app):
        self.app = app
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.smb_ok = False
        self.down_since = 0.0
        self.down_reported = False
        self.trust = {"ok": True, "checked_at": 0, "message": ""}
        self._trust_fails = 0
        self._trust_reported = False
        self._next_trust = 0.0
        self.ip = {"present": False, "conflict": False, "mac": ""}
        self._next_ip = 0.0
        self.disk_level = "ok"
        self.idmap = {"next_rid": 0, "checked_at": 0}
        self._next_rid = 0.0
        self._rid_reported = False

    def start(self) -> None:
        if self._thread or not self.app.cfg.manage_processes:
            return
        self._thread = threading.Thread(target=self._run, name="monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - the monitor must keep running
                log.exception("monitor tick failed")
            self._stop.wait(TICK)

    def tick(self, now: float | None = None) -> None:
        app = self.app
        if app.state() != "ready" or app.backup_active:
            return
        now = time.monotonic() if now is None else now
        s = app.settings
        for p in app.procs.values():
            p.mark_running()
        self._check_ip(now, s)
        up = all(p.running() for p in app.procs.values()) and tcp_open(s["ip"], 445)
        self._smb(up, now)
        if now >= self._next_trust:
            self._next_trust = now + TRUST_EVERY
            self._check_trust()
        self._check_disk()
        if now >= self._next_rid:
            self._next_rid = now + RID_EVERY
            self._check_rid()

    def _smb(self, up: bool, now: float) -> None:
        self.smb_ok = up
        if up:
            if self.down_reported:
                secs = int(now - self.down_since)
                self.app.events.send(events.SMBD_UP, "info", "Dateiserver antwortet wieder",
                                     f"Nach {secs} s wieder erreichbar.", {"down_seconds": secs})
            self.down_since, self.down_reported = 0.0, False
            return
        if not self.down_since:
            self.down_since = now
        if not self.down_reported and now - self.down_since >= DOWN_AFTER:
            self.down_reported = True
            procs = self.app.procs
            dead = [n for n, p in procs.items() if not p.running()]
            name = dead[0] if dead else "smbd"
            err = procs[name].last_exit or f"Port 445 auf {self.app.settings['ip']} antwortet nicht."
            self.app.events.send(events.SMBD_DOWN, "critical", "Dateiserver ist nicht erreichbar", err,
                                 {"process": name, "exit_code": None, "error": err})

    def _check_ip(self, now: float, s: dict) -> None:
        addrs = netinfo.addresses()
        self.ip["present"] = netinfo.present(s["ip"], addrs)
        if not self.ip["present"] and s.get("ip_mode", "managed") == "managed":
            log.warning("server address %s missing, adding it again", s["ip"])
            self.app.ensure_ip(strict=False)
            self.ip["present"] = netinfo.present(s["ip"])
        if now >= self._next_ip:
            self._next_ip = now + IP_EVERY
            free, mac = netinfo.dad(s["ip"], s.get("iface") or netinfo.default_interface())
            conflict = not free
            if conflict and not self.ip["conflict"]:
                self.app.events.send(events.IP_CONFLICT, "critical", f"Adresse {s['ip']} doppelt vergeben",
                                     f"Ein anderes Gerät ({mac or 'unbekannt'}) antwortet auf {s['ip']}.",
                                     {"ip": s["ip"], "mac": mac})
            self.ip["conflict"], self.ip["mac"] = conflict, mac

    def _check_trust(self) -> None:
        ok, msg = samba.trust_ok()
        self.trust = {"ok": ok, "checked_at": now_ms(), "message": msg}
        if ok:
            if self._trust_reported:
                self.app.events.send(events.TRUST_OK, "info", "Vertrauensstellung zur Domäne funktioniert wieder")
            self._trust_fails, self._trust_reported = 0, False
            return
        self._trust_fails += 1
        if self._trust_fails >= TRUST_FAILS and not self._trust_reported:
            self._trust_reported = True
            self.app.events.send(events.TRUST_BROKEN, "critical", "Vertrauensstellung zur Domäne gestört",
                                 f"wbinfo -t: {msg}. Neu beitreten (POST /api/join).", {"error": msg})

    def _check_disk(self) -> None:
        u = storage.usage(self.app.cfg.data_root)
        if not u["total_bytes"]:
            return
        st = self.app.app_settings()
        level = "ok"
        if u["free_percent"] < st["disk_critical_percent"]:
            level = "critical"
        elif u["free_percent"] < st["disk_warn_percent"]:
            level = "warning"
        if level != "ok" and level != self.disk_level:
            gb = u["free_bytes"] / 1024 ** 3
            self.app.events.send(events.DISK_LOW, level, f"Dateiserver: nur noch {u['free_percent']} % frei",
                                 f"{gb:.1f} GB frei auf {self.app.cfg.data_root}.",
                                 {"free_bytes": u["free_bytes"], "free_percent": u["free_percent"]})
        self.disk_level = level

    def _check_rid(self) -> None:
        rid = samba.highest_rid()
        if rid is None:
            return
        self.idmap = {"next_rid": rid + 1, "checked_at": now_ms()}
        if rid * 100 >= MAX_RID * RID_WARN_PERCENT and not self._rid_reported:
            self._rid_reported = True
            self.app.events.send(events.RID_LIMIT, "warning", "Die Domäne nähert sich der RID-Grenze",
                                 rid_warning(rid + 1), {"next_rid": rid + 1, "max_rid": MAX_RID})


def rid_warning(next_rid: int) -> str:
    if next_rid * 100 < MAX_RID * RID_WARN_PERCENT:
        return ""
    return (f"Die Domäne hat RID {next_rid:,} erreicht. Ab RID {MAX_RID + 1:,} können neue Konten keine Freigaben "
            "mehr öffnen.").replace(",", " ")
