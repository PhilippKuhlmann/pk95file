"""First setup and rejoin (docs/api.md → Setup, frozen): preflight, server address, offline domain join."""

from __future__ import annotations

import base64
import binascii
import glob
import logging
import os
import threading
import time

from . import events, netinfo, samba, storage, validate
from .errors import Fields, conflict
from .store import load_json, now_ms, save_json

log = logging.getLogger("pk95file.setup")

STATES = ("unconfigured", "joining", "ready", "failed")
LOG_KEEP = 200
SUGGEST_TTL = 60.0
MAX_ODJ = 64 * 1024
TRUST_WAIT = 90.0
DEFAULT_HOSTNAME = "files"


def check_ip(ip, mode: str, subnet: str, host_ips: list[str], dc_ip: str = "", dad=None) -> str | None:
    """German message why ip cannot be the server address, or None (docs/api.md → ip-check)."""
    err = validate.ip_in_subnet(ip, subnet) if subnet else validate.ipv4(ip)
    if err:
        return err
    if dc_ip and ip == dc_ip:
        return "Das ist die Adresse des Domänencontrollers."
    if mode == "existing":
        return None if ip in host_ips else f"Die Adresse {ip} ist im LXC nicht vorhanden."
    if ip in host_ips:
        return f"Die Adresse {ip} gehört schon dem LXC. Für eine vorhandene Adresse „vorhanden“ wählen."
    if dad is not None:
        free, mac = dad(ip)
        if not free:
            return f"Die Adresse {ip} ist im Netz bereits vergeben" + (f" (MAC {mac})." if mac else ".")
    return None


def odj_matches(blob: str, hostname: str) -> bool:
    """Does the provisioning data name this computer? (UTF-16 strings inside the NDR blob; heuristic, pure)."""
    try:
        raw = base64.b64decode(blob.strip(), validate=True)
    except (binascii.Error, ValueError):
        return False
    want = hostname.upper()
    for offset in (0, 1):
        if want in raw[offset:].decode("utf-16-le", errors="ignore").upper():
            return True
    return want.encode() in raw.upper()


class Setup:
    def __init__(self, app):
        self.app = app
        self.cfg = app.cfg
        self._lock = threading.Lock()
        st = load_json(self.cfg.path("setup.json"), {})
        self.state = st.get("state", "unconfigured")
        if self.state == "joining":  # the container stopped while joining
            self.state, st["error"] = "failed", "Der Beitritt wurde unterbrochen (Container neu gestartet)."
        self.error = st.get("error", "")
        self.started_at = st.get("started_at", 0)
        self.finished_at = st.get("finished_at", 0)
        self.log_lines: list[str] = st.get("log", [])
        self._suggest: tuple[float, str, str] = (0.0, "", "")

    # -- state -------------------------------------------------------------------------------------------------
    def _save(self) -> None:
        save_json(self.cfg.path("setup.json"), {"state": self.state, "error": self.error,
                                                "started_at": self.started_at, "finished_at": self.finished_at,
                                                "log": self.log_lines[-LOG_KEEP:]})

    def _log(self, line: str) -> None:
        log.info("setup: %s", line)
        self.log_lines.append(line)
        del self.log_lines[:-LOG_KEEP]
        self._save()

    # -- GET /api/setup ----------------------------------------------------------------------------------------
    def network(self) -> dict:
        if not self.cfg.manage_processes:
            return {"interface": "", "subnet": "", "host_ips": [], "own": None}
        iface = netinfo.default_interface()
        addrs = netinfo.addresses()
        own = netinfo.primary(addrs, iface)
        return {"interface": iface, "subnet": netinfo.subnet(own), "host_ips": [a["ip"] for a in addrs], "own": own}

    def suggestion(self, net: dict) -> tuple[str, str]:
        """(ip, source): the operator's PK95FILE_DEFAULT_IP, else the first DAD-free address after the LXC's own."""
        if self.cfg.default_ip:
            return self.cfg.default_ip, "env"
        if not net["own"] or self.state == "ready" or not self.cfg.manage_processes:
            return "", ""
        at, ip, src = self._suggest
        if time.monotonic() - at < SUGGEST_TTL:
            return ip, src
        ip, src = "", ""
        for cand in netinfo.candidates(net["own"]["ip"], net["own"]["prefix"], set(net["host_ips"])):
            if netinfo.dad(cand, net["interface"])[0]:
                ip, src = cand, "probe"
                break
        self._suggest = (time.monotonic(), ip, src)
        return ip, src

    def info(self) -> dict:
        net = self.network()
        ip, src = self.suggestion(net)
        s = self.app.settings
        server = None
        if s.get("joined_at"):
            server = {"hostname": s["hostname"], "fqdn": f"{s['hostname']}.{s['realm']}",
                      "netbios_name": s["hostname"].upper(), "ip": s["ip"], "realm": s["realm"],
                      "workgroup": s["workgroup"], "dc": dict(s["dc"])}
        return {
            "state": self.state, "error": self.error, "started_at": self.started_at,
            "finished_at": self.finished_at, "log": self.log_lines[-LOG_KEEP:],
            "defaults": {"hostname": DEFAULT_HOSTNAME, "ip": ip, "ip_source": src, "interface": net["interface"],
                         "subnet": net["subnet"], "host_ips": net["host_ips"]},
            "storage": storage.preflight(self.cfg.data_root, self.cfg.data_dir),
            "server": server,
        }

    def ip_check(self, ip: str, mode: str = "managed") -> dict:
        net = self.network()
        dad = (lambda x: netinfo.dad(x, net["interface"])) if self.cfg.manage_processes and mode == "managed" else None
        msg = check_ip(ip, mode, net["subnet"], net["host_ips"], dad=dad)
        return {"ip": ip, "ok": msg is None, "message": msg or ""}

    # -- POST /api/setup ---------------------------------------------------------------------------------------
    def _validate(self, body: dict, rejoin: bool) -> dict:
        f = Fields()
        s = self.app.settings
        v: dict = {}
        if not rejoin:
            v["hostname"] = str(body.get("hostname", "")).strip().lower()
            f.add("hostname", validate.hostname(v["hostname"]))
            v["realm"] = str(body.get("realm", "")).strip().lower()
            f.add("realm", validate.realm(v["realm"]))
            v["workgroup"] = str(body.get("workgroup", "")).strip().upper()
            f.add("workgroup", validate.workgroup(v["workgroup"]))
            dc = body.get("dc") if isinstance(body.get("dc"), dict) else {}
            v["dc"] = {"hostname": str(dc.get("hostname", "")).strip().lower(), "ip": str(dc.get("ip", "")).strip()}
            f.add("dc.hostname", validate.hostname(v["dc"]["hostname"]))
            f.add("dc.ip", validate.ipv4(v["dc"]["ip"]))
            if not f.get("hostname") and v["hostname"] in (v["dc"]["hostname"], v["workgroup"].lower()):
                f.add("hostname", "Der Name muss sich vom Domänencontroller und von der Domäne unterscheiden.")
            v["ip_mode"] = body.get("ip_mode", "managed")
            if v["ip_mode"] not in ("managed", "existing"):
                f.add("ip_mode", "Bitte managed oder existing angeben.")
                v["ip_mode"] = "managed"
            v["ip"] = str(body.get("ip", "")).strip()
            net = self.network()
            dad = None
            if self.cfg.manage_processes and v["ip_mode"] == "managed":
                dad = lambda x: netinfo.dad(x, net["interface"])  # noqa: E731
            f.add("ip", check_ip(v["ip"], v["ip_mode"], net["subnet"], net["host_ips"], v["dc"]["ip"], dad))
            own = net["own"] or {}
            v["iface"] = net["interface"]
            v["prefix"] = own.get("prefix", 24)
            for a in netinfo.addresses() if self.cfg.manage_processes and v["ip_mode"] == "existing" else []:
                if a["ip"] == v["ip"]:
                    v["iface"], v["prefix"] = a["iface"], a["prefix"]
            allow = body.get("allow_system_disk", False)
            if not isinstance(allow, bool):
                f.add("allow_system_disk", "Bitte true oder false angeben.")
                allow = False
            pre = storage.preflight(self.cfg.data_root, self.cfg.data_dir)
            if pre["on_system_disk"] and not allow:
                f.add("allow_system_disk", "Die Daten lägen auf der Systemplatte des LXC. Bitte einen eigenen "
                                           "Mountpoint einhängen oder ausdrücklich bestätigen.")
            v["allow_system_disk"] = allow
        hostname = s.get("hostname", "") if rejoin else v.get("hostname", "")
        odj = body.get("odj")
        user, password = body.get("join_user"), body.get("join_password")
        if odj is not None:
            if not isinstance(odj, str) or not odj.strip():
                f.add("odj", "Bitte die Beitrittsdaten angeben.")
            elif len(odj) > MAX_ODJ:
                f.add("odj", "Die Beitrittsdaten sind zu groß (höchstens 64 KiB).")
            elif hostname and not f.get("hostname") and not odj_matches(odj, hostname):
                f.add("odj", "Die Beitrittsdaten gehören zu einem anderen Computer.")
            v["odj"] = odj.strip() if isinstance(odj, str) else ""
        elif user is not None or password is not None:
            if not isinstance(user, str) or not user.strip():
                f.add("join_user", "Bitte einen Benutzer angeben.")
            if not isinstance(password, str) or not password:
                f.add("join_password", "Bitte das Kennwort angeben.")
            v["join_user"], v["join_password"] = user, password
        else:
            f.add("odj", "Bitte die Beitrittsdaten (odj) oder Benutzer und Kennwort angeben.")
        f.raise_if_any()
        return v

    def start(self, body: dict) -> None:
        with self._lock:
            if self.state == "joining":
                raise conflict("Der Beitritt läuft bereits.")
            if self.state == "ready":
                raise conflict("Der Dateiserver ist bereits eingerichtet.")
            v = self._validate(body, rejoin=False)
            self._begin()
        threading.Thread(target=self._run, args=(v, False), name="setup", daemon=True).start()

    def rejoin(self, body: dict) -> None:
        with self._lock:
            if self.state == "joining":
                raise conflict("Der Beitritt läuft bereits.")
            if not self.app.settings.get("joined_at"):
                raise conflict("Der Dateiserver wurde noch nie eingerichtet. Bitte zuerst POST /api/setup.")
            v = self._validate(body, rejoin=True)
            self._begin()
        threading.Thread(target=self._run, args=(v, True), name="rejoin", daemon=True).start()

    def _begin(self) -> None:
        self.state, self.error, self.started_at, self.finished_at = "joining", "", now_ms(), 0
        self.log_lines = []
        self._save()

    # -- the steps ---------------------------------------------------------------------------------------------
    def _run(self, v: dict, rejoin: bool) -> None:
        app = self.app
        try:
            if not rejoin:
                self._log("Prüfe das Datenverzeichnis …")
                pre = storage.preflight(self.cfg.data_root, self.cfg.data_dir)
                problems = [p for p in pre["problems"]
                            if not (v["allow_system_disk"] and "Systemplatte" in p)]
                if problems:
                    raise RuntimeError(" ".join(problems))
                for w in pre["warnings"]:
                    self._log("Hinweis: " + w)
                settings = {k: v[k] for k in ("hostname", "ip", "ip_mode", "iface", "prefix", "realm", "workgroup",
                                              "dc")}
                app.update_settings(settings, joined=False)
                self._log(f"Serveradresse {v['ip']} ({'verwaltet' if v['ip_mode'] == 'managed' else 'vorhanden'}) …")
                app.ensure_ip(strict=True)
            app.stop_samba()
            app.write_config()
            # Setup and rejoin start from a fresh secrets.tdb and empty winbind caches: requestodj into an existing
            # machine secret (or a winbindd still caching the old one) leaves the trust broken.
            self._clear_secrets()
            self._log("Tritt der Domäne bei …")
            if v.get("odj"):
                samba.requestodj(v["odj"])
            else:
                s = app.settings
                samba.join_with_password(v["join_user"], v["join_password"], f"{s['hostname']}.{s['realm']}")
            self._log("Starte winbindd und prüfe die Vertrauensstellung …")
            app.start_process("winbindd")
            ok, msg = False, ""
            end = time.monotonic() + TRUST_WAIT
            while time.monotonic() < end:
                ok, msg = samba.trust_ok()
                if ok:
                    break
                time.sleep(3)
            if not ok:
                raise RuntimeError(f"Die Vertrauensstellung zur Domäne funktioniert nicht: {msg}")
            ok, msg = samba.netlogon_ok()
            if not ok:
                raise RuntimeError(f"Netlogon zum Domänencontroller schlägt fehl: {msg}")
            dsid = samba.domain_sid(app.settings["workgroup"])
            gid = samba.sid_to_gid(f"{dsid}-513")
            if gid != 10513:
                raise RuntimeError(f"Domain Users wird nicht auf 10513 abgebildet (sondern {gid}). idmap prüfen.")
            self._log(f"Domäne {app.settings['workgroup']} ({dsid}), Domain Users → {gid}.")
            err = samba.grant("SeDiskOperatorPrivilege", f"{app.settings['workgroup']}\\Domain Admins")
            if err:
                self._log(f"Hinweis: SeDiskOperatorPrivilege für Domain Admins nicht gesetzt: {err}")
            app.update_settings({"domain_sid": dsid}, joined=True)
            if not rejoin:
                app.prepare_data_root()
            self._log("Starte smbd …")
            app.start_process("smbd")
            if not app.wait_smb(30):
                raise RuntimeError(f"smbd antwortet nicht auf {app.settings['ip']}:445.")
            app.shares.apply_all()
            self.state, self.finished_at = "ready", now_ms()
            self._log("Fertig.")
            s = app.settings
            app.events.send(events.SETUP_DONE, "info", f"Dateiserver {s['hostname']}.{s['realm']} ist bereit",
                            f"Freigaben unter \\\\{s['hostname']}.{s['realm']}",
                            {"hostname": s["hostname"], "ip": s["ip"], "realm": s["realm"]})
            app.on_ready()
        except Exception as exc:  # noqa: BLE001 - every failure ends in state "failed" with a German message
            log.exception("setup failed")
            self.state, self.error, self.finished_at = "failed", str(exc), now_ms()
            self._log("Fehler: " + str(exc))
            app.events.send(events.SETUP_FAILED, "critical", "Einrichtung des Dateiservers fehlgeschlagen",
                            str(exc), {"error": str(exc)})
        finally:
            v.pop("odj", None)
            v.pop("join_password", None)
            self._save()

    def _clear_secrets(self) -> None:
        """A new setup after a failed one starts without the old machine secret and caches."""
        for pattern in ("private/secrets.tdb", "private/secrets.ldb", "*.tdb"):
            for path in glob.glob(os.path.join(self.cfg.samba_dir, pattern)):
                if os.path.basename(path) in ("share_info.tdb", "account_policy.tdb"):
                    continue
                try:
                    os.unlink(path)
                except OSError:
                    pass
        for path in glob.glob("/var/cache/samba/*.tdb"):
            try:
                os.unlink(path)
            except OSError:
                pass
