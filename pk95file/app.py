"""The application: settings, Samba processes, setup, shares, status and dashboard (docs/api.md)."""

from __future__ import annotations

import logging
import os
import threading
import time

from . import VERSION, events, netinfo, samba, smbconf, storage
from .acl import Acls
from .errors import NOT_READY, ApiError, Fields
from .jobs import Jobs
from .monitor import Monitor, rid_warning
from .recycle import Recycle
from .scheduler import Scheduler
from .setup import Setup
from .shares import Shares
from .store import load_json, now_ms, save_json, write_text

log = logging.getLogger("pk95file.app")

BACKUP_RESUME = 600.0
APP_DEFAULTS = {"scan_interval_minutes": 60, "disk_warn_percent": 20, "disk_critical_percent": 10,
                "snapshot_min_free_percent": 15, "smb_encryption": "if_required", "min_protocol": "SMB2_10"}


def manifest() -> dict:
    return {
        "id": "file",
        "name": "PK95 File",
        "version": VERSION,
        "protocol": 1,
        "icon": "box",
        "menu": [
            {"key": "server", "label": "Dateiserver", "icon": "server"},
            {"key": "shares", "label": "Freigaben", "icon": "box"},
            {"key": "sessions", "label": "Sitzungen", "icon": "user"},
        ],
        "capabilities": ["events", "backup"],
        "events": list(events.ALL),
    }


class App:
    def __init__(self, cfg, resolver=None):
        self.cfg = cfg
        self.started_at = now_ms()
        self.settings: dict = load_json(cfg.path("settings.json"), {})
        self.events = events.Sender(cfg.core_url, cfg.token)
        self.jobs = Jobs()
        self.acls = Acls(cfg.smb_conf)
        self.procs = samba.processes(self._on_crash)
        self.setup = Setup(self)
        self.shares = Shares(self, resolver)
        self.monitor = Monitor(self)
        self.recycle = Recycle(self)
        self.scheduler = Scheduler(self)
        self.scheduler.add("recycle", self.recycle.task)
        self.backup_active = False
        self._backup_timer: threading.Timer | None = None
        self._lock = threading.RLock()

    # -- settings ----------------------------------------------------------------------------------------------
    def update_settings(self, values: dict, joined: bool | None = None) -> None:
        with self._lock:
            self.settings.update(values)
            if joined:
                self.settings["joined_at"] = now_ms()
            save_json(self.cfg.path("settings.json"), self.settings)

    def app_settings(self) -> dict:
        return {k: self.settings.get(k, v) for k, v in APP_DEFAULTS.items()}

    def put_app_settings(self, body: dict) -> dict:
        f = Fields()
        new = self.app_settings()
        rules = {"scan_interval_minutes": (15, 1440), "disk_warn_percent": (1, 50), "disk_critical_percent": (1, 50),
                 "snapshot_min_free_percent": (5, 50)}
        for key, (low, high) in rules.items():
            if key in body:
                v = body[key]
                if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
                    f.add(key, f"Erlaubt sind {low} bis {high}.")
                else:
                    new[key] = v
        if new["disk_warn_percent"] <= new["disk_critical_percent"]:
            f.add("disk_warn_percent", "Muss größer als disk_critical_percent sein.")
        for key, allowed in (("smb_encryption", ("if_required", "desired", "required")),
                             ("min_protocol", ("SMB2_10", "SMB3_00", "SMB3_11"))):
            if key in body:
                if body[key] not in allowed:
                    f.add(key, "Erlaubt: " + ", ".join(allowed) + ".")
                else:
                    new[key] = body[key]
        f.raise_if_any()
        self.update_settings(new)
        if self.state() == "ready":
            self.write_config(reload=True)
        return self.app_settings()

    # -- state -------------------------------------------------------------------------------------------------
    def state(self) -> str:
        return self.setup.state

    def require_ready(self) -> None:
        if self.state() != "ready":
            raise ApiError(409, NOT_READY)

    def usage_of(self, name: str) -> dict:
        return load_json(os.path.join(self.cfg.meta_root, "usage.json"), {}).get("shares", {}).get(name, {})

    # -- configuration -----------------------------------------------------------------------------------------
    def write_config(self, reload: bool = False) -> None:
        s = {**self.settings, **self.app_settings()}
        if not s.get("hostname"):
            return
        write_text(self.cfg.smb_conf, smbconf.render(s, self.shares.raw(), self.cfg.shares_root))
        write_text(self.cfg.krb5_conf, smbconf.krb5(s))
        try:
            with open(self.cfg.hosts_file, encoding="utf-8") as fh:
                hosts = fh.read()
            with open(self.cfg.hosts_file, "w", encoding="utf-8") as fh:  # Docker's /etc/hosts: write in place
                fh.write(smbconf.hosts(hosts, s))
        except OSError as exc:
            log.warning("cannot update %s: %s", self.cfg.hosts_file, exc)
        if reload and self.procs["smbd"].running():
            samba.reload_config()

    def ensure_ip(self, strict: bool) -> None:
        if not self.cfg.manage_processes:
            return
        s = self.settings
        if s.get("ip_mode") == "existing":
            if not netinfo.present(s["ip"]) and strict:
                raise RuntimeError(f"Die Adresse {s['ip']} ist im LXC nicht vorhanden.")
            return
        if netinfo.present(s["ip"]):
            return
        err = netinfo.add(s["ip"], s["prefix"], s["iface"])
        if err and strict:
            raise RuntimeError(f"Die Adresse {s['ip']} konnte nicht eingerichtet werden: {err}")

    def prepare_data_root(self) -> None:
        os.makedirs(self.cfg.shares_root, mode=0o755, exist_ok=True)
        os.makedirs(self.cfg.meta_root, mode=0o700, exist_ok=True)
        write_text(os.path.join(self.cfg.data_root, ".pxarexclude"), "/.pk95/snapshots\n")

    # -- processes ---------------------------------------------------------------------------------------------
    def _on_crash(self, code, message) -> None:
        log.error("samba process crashed: %s", message)

    def start_process(self, name: str) -> None:
        if self.cfg.manage_processes:
            self.procs[name].start()

    def stop_samba(self, state: str = "stopped") -> None:
        for name in ("smbd", "winbindd"):
            self.procs[name].stop(state=state)

    def wait_smb(self, timeout: float) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if tcp_open_ip(self.settings["ip"]):
                self.procs["smbd"].mark_running()
                self.procs["winbindd"].mark_running()
                return True
            time.sleep(1)
        return False

    def boot(self) -> None:
        self.events.start()
        if self.state() != "ready" or not self.cfg.manage_processes:
            return
        self.write_config()
        self.ensure_ip(strict=False)
        self.start_process("winbindd")
        self.start_process("smbd")
        self.on_ready()

    def on_ready(self) -> None:
        self.monitor.start()
        self.scheduler.start()

    def shutdown(self) -> None:
        self.monitor.stop()
        self.scheduler.stop()
        self.stop_samba()
        if self.cfg.manage_processes and self.settings.get("ip_mode") == "managed" and self.settings.get("ip"):
            netinfo.remove(self.settings["ip"], self.settings["prefix"], self.settings["iface"])
        self.events.stop()

    def backup_prepare(self) -> None:
        if self.state() != "ready":
            return
        self.backup_active = True
        self.stop_samba(state="backup")
        if self._backup_timer:
            self._backup_timer.cancel()
        self._backup_timer = threading.Timer(BACKUP_RESUME, self._backup_resume)
        self._backup_timer.daemon = True
        self._backup_timer.start()

    def _backup_resume(self) -> None:
        log.warning("container still running 10 minutes after backup prepare: starting Samba again")
        self.backup_active = False
        self.start_process("winbindd")
        self.start_process("smbd")

    # -- status and dashboard ----------------------------------------------------------------------------------
    def status(self) -> dict:
        s = self.settings
        ready = self.state() == "ready"
        mon = self.monitor
        server = None
        if s.get("joined_at"):
            server = {"hostname": s["hostname"], "fqdn": f"{s['hostname']}.{s['realm']}", "realm": s["realm"],
                      "workgroup": s["workgroup"], "dc": f"{s['dc']['hostname']}.{s['realm']}"}
        next_rid = mon.idmap["next_rid"]
        return {
            "version": VERSION,
            "core_mode": self.cfg.core_mode,
            "state": self.state(),
            "started_at": self.started_at,
            "smbd": self.procs["smbd"].info(),
            "winbindd": self.procs["winbindd"].info(),
            "trust": dict(mon.trust) if ready else {"ok": False, "checked_at": 0, "message": ""},
            "ip": {"address": s.get("ip", ""), "mode": s.get("ip_mode", ""), "interface": s.get("iface", ""),
                   "present": mon.ip["present"] if ready else False, "conflict": mon.ip["conflict"]},
            "idmap": {"backend": "rid", "range": [smbconf.RID_LOW, smbconf.RID_HIGH], "max_rid": smbconf.MAX_RID,
                      "next_rid": next_rid, "percent": next_rid * 100 // smbconf.MAX_RID,
                      "checked_at": mon.idmap["checked_at"], "warning": rid_warning(next_rid)},
            "server": server,
        }

    def dashboard(self) -> dict:
        shares = self.shares.raw()
        u = storage.usage(self.cfg.data_root)
        scan = load_json(os.path.join(self.cfg.meta_root, "usage.json"), {})
        per = scan.get("shares", {})
        snap_bytes = sum(v.get("snapshot_bytes", 0) for v in per.values())
        rec_bytes = sum(v.get("recycle_bytes", 0) for v in per.values())
        share_bytes = sum(v.get("bytes", 0) for v in per.values())
        sessions, open_files = samba.counts(samba.smbstatus()) if self.state() == "ready" else (0, 0)
        st = self.app_settings()
        warnings = []
        mon = self.monitor
        if self.state() == "ready":
            if not mon.trust["ok"]:
                warnings.append({"level": "critical", "code": "trust",
                                 "message": "Vertrauensstellung zur Domäne gestört: " + mon.trust["message"]})
            if not self.procs["smbd"].running():
                warnings.append({"level": "critical", "code": "smbd", "message": "smbd läuft nicht."})
            if mon.ip["conflict"]:
                warnings.append({"level": "critical", "code": "ip",
                                 "message": f"Die Adresse {self.settings['ip']} ist doppelt vergeben."})
        if u["total_bytes"] and u["free_percent"] < st["disk_warn_percent"]:
            level = "critical" if u["free_percent"] < st["disk_critical_percent"] else "warning"
            warnings.append({"level": level, "code": "disk",
                             "message": f"Nur noch {u['free_percent']} % frei ({u['free_bytes'] / 1024 ** 3:.1f} GB)."})
        if self.state() == "ready" and storage.same_device(self.cfg.data_root, self.cfg.data_dir):
            warnings.append({"level": "warning", "code": "system_disk",
                             "message": "Die Daten liegen auf der Systemplatte des LXC."})
        for s in shares:
            pub = self.shares.public(s)
            if pub["status"] in ("soft_quota_warning", "soft_quota_exceeded"):
                q = s["soft_quota"]
                pct = pub["usage"]["bytes"] * 100 // q["size_bytes"] if q["size_bytes"] else 0
                warnings.append({"level": "warning", "code": "soft_quota",
                                 "message": f"Freigabe „{s['name']}“: {pct} % des Kontingents belegt."})
            if any(p.get("unresolved") for p in pub["permissions"]):
                warnings.append({"level": "warning", "code": "permissions",
                                 "message": f"Freigabe „{s['name']}“ enthält eine Gruppe, die es nicht mehr gibt."})
        rid_msg = rid_warning(mon.idmap["next_rid"])
        if rid_msg:
            warnings.append({"level": "warning", "code": "idmap", "message": rid_msg})
        return {
            "shares": len(shares),
            "storage": {"total_bytes": u["total_bytes"], "used_bytes": u["used_bytes"], "free_bytes": u["free_bytes"],
                        "free_percent": u["free_percent"], "share_bytes": share_bytes, "snapshot_bytes": snap_bytes,
                        "recycle_bytes": rec_bytes, "scanned_at": scan.get("scanned_at", 0)},
            "sessions": sessions,
            "open_files": open_files,
            "snapshots": {"last_run_at": 0, "last_ok": True, "next_run_at": 0, "failed_shares": [], "count": 0},
            "warnings": warnings,
        }


def tcp_open_ip(ip: str) -> bool:
    from .supervisor import tcp_open

    return tcp_open(ip, 445, timeout=1.0)
