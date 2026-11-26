"""Shares (docs/api.md → Shares, frozen): store, validation, folders and root ACLs."""

from __future__ import annotations

import copy
import logging
import os
import shutil
import threading
import time

from . import acl, samba, validate
from .errors import Fields, conflict, not_found
from .store import load_json, now_ms, save_json

log = logging.getLogger("pk95file.shares")

GIB = 1024 ** 3
MAX_PERMISSIONS = 50
NAME_TTL = 300.0

DEFAULT_RECYCLE = {"enabled": True, "keep_days": 30, "max_file_mb": 0, "exclude": ["*.tmp", "~$*", "*.~*"]}
DEFAULT_SNAPSHOTS = {"enabled": True, "schedule": {"times": ["07:00", "12:00", "17:00"], "weekdays": [1, 2, 3, 4, 5]},
                     "keep": {"recent": 12, "daily": 14, "weekly": 8}}
DEFAULT_SOFT_QUOTA = {"size_bytes": 0, "warn_percent": 90, "lock_when_exceeded": False}
EMPTY_USAGE = {"bytes": 0, "files": 0, "recycle_bytes": 0, "snapshot_bytes": 0, "scanned_at": 0}


def open_dir(path: str) -> None:
    """Create a folder smbd manages: mode 0777, so the kernel never blocks what the NT ACL allows. With
    "acl_xattr:ignore system acls" smbd checks only the NT ACL; POSIX bits of folders the app creates itself
    (share roots, .recycle) would otherwise stop users (e.g. root-owned 0755 → nobody but root can create files)."""
    os.makedirs(path, exist_ok=True)
    os.chmod(path, 0o777)


class Resolver:
    """SID ↔ name through winbind, cached for a few minutes (tests pass their own)."""

    def __init__(self):
        self._cache: dict[str, tuple[float, tuple[str, int] | None]] = {}
        self._lock = threading.Lock()

    def sid_to_name(self, sid: str) -> tuple[str, int] | None:
        with self._lock:
            hit = self._cache.get(sid)
            if hit and time.monotonic() - hit[0] < NAME_TTL:
                return hit[1]
        res = samba.sid_to_name(sid)
        with self._lock:
            self._cache[sid] = (time.monotonic(), res)
        return res

    def name_to_sid(self, name: str) -> tuple[str, int] | None:
        return samba.name_to_sid(name)


def _bool(f: Fields, field: str, value, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        f.add(field, "Bitte true oder false angeben.")
        return default
    return value


def validate_recycle(raw, current: dict, f: Fields) -> dict:
    if raw is None:
        return current
    if not isinstance(raw, dict):
        f.add("recycle", "Bitte ein Objekt angeben.")
        return current
    out = dict(current)
    out["enabled"] = _bool(f, "recycle.enabled", raw.get("enabled"), current["enabled"])
    for key, low, high in (("keep_days", 1, 365), ("max_file_mb", 0, 102400)):
        if key in raw:
            f.add(f"recycle.{key}", validate.int_range(raw[key], low, high))
            out[key] = raw[key]
    if "exclude" in raw:
        ex = raw["exclude"]
        if not isinstance(ex, list) or len(ex) > 20:
            f.add("recycle.exclude", "Höchstens 20 Muster.")
        else:
            for i, p in enumerate(ex):
                if not isinstance(p, str) or not p or len(p) > 64 or "/" in p or "|" in p:
                    f.add(f"recycle.exclude.{i}", "1–64 Zeichen, ohne / und |.")
            out["exclude"] = ex
    return out


def validate_snapshots(raw, current: dict, f: Fields) -> dict:
    if raw is None:
        return current
    if not isinstance(raw, dict):
        f.add("snapshots", "Bitte ein Objekt angeben.")
        return current
    out = copy.deepcopy(current)
    out["enabled"] = _bool(f, "snapshots.enabled", raw.get("enabled"), current["enabled"])
    sch = raw.get("schedule")
    if sch is not None:
        if not isinstance(sch, dict):
            f.add("snapshots.schedule", "Bitte ein Objekt angeben.")
        else:
            if "times" in sch:
                t = sch["times"]
                if not isinstance(t, list) or not 1 <= len(t) <= 24 or len(set(map(str, t))) != len(t) \
                        or not all(validate.time_of_day(x) for x in t):
                    f.add("snapshots.schedule.times", "1–24 verschiedene Uhrzeiten im Format HH:MM.")
                else:
                    out["schedule"]["times"] = sorted(t)
            if "weekdays" in sch:
                w = sch["weekdays"]
                if not isinstance(w, list) or not 1 <= len(w) <= 7 or len(set(map(str, w))) != len(w) \
                        or not all(isinstance(x, int) and not isinstance(x, bool) and 1 <= x <= 7 for x in w):
                    f.add("snapshots.schedule.weekdays", "1–7 verschiedene Wochentage (1 = Montag … 7 = Sonntag).")
                else:
                    out["schedule"]["weekdays"] = sorted(w)
    keep = raw.get("keep")
    if keep is not None:
        if not isinstance(keep, dict):
            f.add("snapshots.keep", "Bitte ein Objekt angeben.")
        else:
            for key, low, high in (("recent", 1, 100), ("daily", 0, 365), ("weekly", 0, 104)):
                if key in keep:
                    f.add(f"snapshots.keep.{key}", validate.int_range(keep[key], low, high))
                    out["keep"][key] = keep[key]
    return out


def validate_soft_quota(raw, current: dict, f: Fields) -> dict:
    if raw is None:
        return current
    if not isinstance(raw, dict):
        f.add("soft_quota", "Bitte ein Objekt angeben.")
        return current
    out = dict(current)
    if "size_bytes" in raw:
        v = raw["size_bytes"]
        if isinstance(v, bool) or not isinstance(v, int) or (v != 0 and v < GIB) or v < 0:
            f.add("soft_quota.size_bytes", "0 (kein Kontingent) oder mindestens 1 GiB.")
        out["size_bytes"] = v
    if "warn_percent" in raw:
        f.add("soft_quota.warn_percent", validate.int_range(raw["warn_percent"], 50, 99))
        out["warn_percent"] = raw["warn_percent"]
    out["lock_when_exceeded"] = _bool(f, "soft_quota.lock_when_exceeded", raw.get("lock_when_exceeded"),
                                      current["lock_when_exceeded"])
    return out


class Shares:
    def __init__(self, app, resolver=None):
        self.app = app
        self.cfg = app.cfg
        self.resolver = resolver or Resolver()
        self._lock = threading.RLock()
        self._items: list[dict] = load_json(self.cfg.path("shares.json"), [])

    # -- store -------------------------------------------------------------------------------------------------
    def _save(self) -> None:
        save_json(self.cfg.path("shares.json"), self._items)

    def raw(self) -> list[dict]:
        with self._lock:
            return copy.deepcopy(self._items)

    def _find(self, name: str) -> dict:
        for s in self._items:
            if s["name"].lower() == name.lower():
                return s
        raise not_found("Unbekannte Freigabe.")

    def path(self, name: str) -> str:
        return os.path.join(self.cfg.shares_root, name)

    # -- output ------------------------------------------------------------------------------------------------
    def _principal(self, sid: str, access: str) -> dict:
        res = self.resolver.sid_to_name(sid)
        if res is None:
            return {"sid": sid, "name": "", "type": "", "access": access, "unresolved": True}
        name, typ = res
        return {"sid": sid, "name": name, "type": samba.KIND.get(typ, "group"), "access": access}

    def _status(self, s: dict, usage: dict) -> str:
        if not s.get("enabled", True):
            return "disabled"
        if s.get("locked"):
            return "locked"
        size = s["soft_quota"]["size_bytes"]
        if size:
            if usage["bytes"] > size:
                return "soft_quota_exceeded"
            if usage["bytes"] * 100 >= size * s["soft_quota"]["warn_percent"]:
                return "soft_quota_warning"
        return "ok"

    def public(self, s: dict) -> dict:
        st = self.app.settings
        host, realm = st.get("hostname", ""), st.get("realm", "")
        dsid = st.get("domain_sid", "")
        usage = {**EMPTY_USAGE, **self.app.usage_of(s["name"])}
        snaps = copy.deepcopy(s["snapshots"])
        snaps["estimate_bytes"] = usage["bytes"]  # the first snapshot is a full copy (docs/design.md §7)
        return {
            "name": s["name"],
            "description": s.get("description", ""),
            "enabled": s.get("enabled", True),
            "hidden": s["name"].endswith("$"),
            "path": f"shares/{s['name']}",
            "unc": f"\\\\{host}.{realm}\\{s['name']}" if host else "",
            "unc_short": f"\\\\{host.upper()}\\{s['name']}" if host else "",
            "permissions": [self._principal(p["sid"], p["access"]) for p in s["permissions"]],
            "fixed_permissions": [self._principal(e["sid"], e["access"]) for e in acl.fixed_entries(dsid)]
            if dsid else [],
            "abe": s.get("abe", True),
            "recycle": copy.deepcopy(s["recycle"]),
            "snapshots": snaps,
            "soft_quota": copy.deepcopy(s["soft_quota"]),
            "usage": usage,
            "status": self._status(s, usage),
            "created_at": s.get("created_at", 0),
        }

    def list(self) -> dict:
        items = [self.public(s) for s in self.raw()]
        return {"items": items, "total": len(items)}

    def get(self, name: str) -> dict:
        with self._lock:
            return self.public(copy.deepcopy(self._find(name)))

    # -- validation --------------------------------------------------------------------------------------------
    def _permissions(self, raw, f: Fields) -> list[dict]:
        if not isinstance(raw, list) or len(raw) > MAX_PERMISSIONS:
            f.add("permissions", f"Bitte eine Liste mit höchstens {MAX_PERMISSIONS} Einträgen angeben.")
            return []
        dsid = self.app.settings.get("domain_sid", "")
        fixed = {e["sid"] for e in acl.fixed_entries(dsid)} if dsid else set()
        out, seen = [], set()
        for i, e in enumerate(raw):
            if not isinstance(e, dict):
                f.add(f"permissions.{i}", "Bitte ein Objekt mit sid oder name und access angeben.")
                continue
            access = e.get("access")
            if access not in validate.ACCESS:
                f.add(f"permissions.{i}.access", "Bitte read, change oder full angeben.")
            sid = e.get("sid")
            if sid is not None:
                if not validate.sid(sid) or self.resolver.sid_to_name(sid) is None:
                    f.add(f"permissions.{i}.sid", "Unbekannte Gruppe oder unbekannter Benutzer.")
                    continue
            else:
                name = e.get("name")
                res = self.resolver.name_to_sid(name) if isinstance(name, str) and name.strip() else None
                if res is None:
                    f.add(f"permissions.{i}.name", "Unbekannte Gruppe oder unbekannter Benutzer.")
                    continue
                sid = res[0]
            if sid in fixed:
                f.add(f"permissions.{i}.sid", "Domain Admins und SYSTEM haben immer Vollzugriff.")
                continue
            if sid in seen:
                f.add(f"permissions.{i}.sid", "Doppelter Eintrag.")
                continue
            seen.add(sid)
            if access in validate.ACCESS:
                out.append({"sid": sid, "access": access})
        return out

    def _fields(self, body: dict, current: dict, f: Fields) -> dict:
        out = copy.deepcopy(current)
        if "description" in body:
            d = body["description"]
            if not isinstance(d, str) or len(d) > 256:
                f.add("description", "Höchstens 256 Zeichen.")
            else:
                out["description"] = d
        out["enabled"] = _bool(f, "enabled", body.get("enabled"), current["enabled"])
        out["abe"] = _bool(f, "abe", body.get("abe"), current["abe"])
        out["recycle"] = validate_recycle(body.get("recycle"), current["recycle"], f)
        snaps = body.get("snapshots")
        if isinstance(snaps, dict):
            snaps = {k: v for k, v in snaps.items() if k != "estimate_bytes"}
        out["snapshots"] = validate_snapshots(snaps, current["snapshots"], f)
        out["soft_quota"] = validate_soft_quota(body.get("soft_quota"), current["soft_quota"], f)
        return out

    # -- changes -----------------------------------------------------------------------------------------------
    def create(self, body: dict) -> dict:
        self.app.require_ready()
        f = Fields()
        name = body.get("name")
        f.add("name", validate.share_name(name))
        with self._lock:
            if not f.get("name") and any(s["name"].lower() == name.lower() for s in self._items):
                f.add("name", "Eine Freigabe mit diesem Namen gibt es bereits.")
            adopt = _bool(f, "adopt", body.get("adopt"), False)
            if not f.get("name") and os.path.lexists(self.path(name)) and not adopt:
                f.add("name", "Der Ordner existiert bereits. Übernehmen?")
            base = {"name": name, "description": "", "enabled": True, "abe": True, "permissions": [],
                    "recycle": dict(DEFAULT_RECYCLE), "snapshots": copy.deepcopy(DEFAULT_SNAPSHOTS),
                    "soft_quota": dict(DEFAULT_SOFT_QUOTA), "locked": False, "created_at": now_ms()}
            share = self._fields(body, base, f)
            if "permissions" in body:
                share["permissions"] = self._permissions(body["permissions"], f)
            f.raise_if_any()
            existed = os.path.isdir(self.path(name))
            open_dir(self.path(name))
            self._items.append(share)
            self._save()
            self.app.write_config(reload=True)
            try:
                if not (existed and adopt):
                    self.apply_acl(share)
                else:
                    share["permissions"] = self.read_permissions(share) or share["permissions"]
                    self._save()
                self.apply_share_sd(share)
                self.ensure_recycle(share)
            except Exception:
                self._items.remove(share)
                self._save()
                self.app.write_config(reload=True)
                if not existed:
                    shutil.rmtree(self.path(name), ignore_errors=True)
                raise
            return self.public(copy.deepcopy(share))

    def update(self, name: str, body: dict) -> dict:
        self.app.require_ready()
        f = Fields()
        for key in ("name", "permissions", "adopt"):
            if key in body and not (key == "name" and isinstance(body[key], str)
                                    and body[key].lower() == name.lower()):
                f.add(key, "Kann hier nicht geändert werden." if key != "name" else
                      "Der Name kann nicht geändert werden (neue Freigabe anlegen und Daten verschieben).")
        with self._lock:
            cur = self._find(name)
            new = self._fields(body, cur, f)
            f.raise_if_any()
            cur.update(new)
            self._save()
            self.app.write_config(reload=True)
            self.ensure_recycle(cur)
            return self.public(copy.deepcopy(cur))

    def set_permissions(self, name: str, body: dict):
        """Returns (share, job or None)."""
        self.app.require_ready()
        f = Fields()
        propagate = _bool(f, "propagate", body.get("propagate"), False)
        with self._lock:
            cur = self._find(name)
            perms = self._permissions(body.get("permissions"), f)
            f.raise_if_any()
            if self.app.jobs.busy("permissions", cur["name"]):
                raise conflict("Für diese Freigabe läuft bereits ein solcher Auftrag.")
            old = cur["permissions"]
            cur["permissions"] = perms
            try:
                self.apply_acl(cur)
                self.apply_share_sd(cur)
            except Exception:
                cur["permissions"] = old
                raise
            self._save()
            self.ensure_recycle(cur)
            job = None
            if propagate:  # after the root ACL is written: the walk inherits from the new one
                job = self.app.jobs.start("permissions", lambda j: self._propagate(cur["name"], j),
                                          share=cur["name"], exclusive=True)
            return self.public(copy.deepcopy(cur)), job

    def _propagate(self, name: str, job) -> None:
        res = self.app.acls.propagate(self.path(name), self.app.settings["domain_sid"], name, [".recycle"])
        job.progress(res.get("done", 0), res.get("done", 0), "files")
        if res.get("errors"):
            raise RuntimeError(f"{len(res['errors'])} Einträge nicht geändert, z. B. {res['errors'][0]}")

    def delete(self, name: str, delete_data: bool):
        self.app.require_ready()
        with self._lock:
            cur = self._find(name)
            self._items.remove(cur)
            self._save()
            self.app.write_config(reload=True)
        if not delete_data:
            return None
        path = self.path(cur["name"])
        snaps = os.path.join(self.cfg.meta_root, "snapshots", cur["name"])
        return self.app.jobs.start("delete_share", lambda j: self._remove_tree(path, snaps), share=cur["name"])

    @staticmethod
    def _remove_tree(*paths: str) -> None:
        for p in paths:
            if os.path.isdir(p):
                shutil.rmtree(p)

    def orphans(self) -> dict:
        known = {s["name"].lower() for s in self.raw()}
        out = []
        try:
            entries = list(os.scandir(self.cfg.shares_root))
        except OSError:
            entries = []
        for e in entries:
            if e.is_dir(follow_symlinks=False) and e.name.lower() not in known:
                snaps = os.path.join(self.cfg.meta_root, "snapshots", e.name)
                out.append({"name": e.name, "bytes": self.app.usage_of(e.name).get("bytes", 0),
                            "snapshots": len(os.listdir(snaps)) if os.path.isdir(snaps) else 0,
                            "modified_at": int(e.stat(follow_symlinks=False).st_mtime * 1000)})
        return {"items": sorted(out, key=lambda x: x["name"].lower())}

    def delete_orphan(self, name: str):
        if not any(o["name"] == name for o in self.orphans()["items"]):
            raise not_found("Unbekannter Ordner.")
        path = self.path(name)
        snaps = os.path.join(self.cfg.meta_root, "snapshots", name)
        return self.app.jobs.start("delete_orphan", lambda j: self._remove_tree(path, snaps), share=name)

    # -- ACLs --------------------------------------------------------------------------------------------------
    def apply_acl(self, share: dict) -> None:
        dsid = self.app.settings["domain_sid"]
        self.app.acls.set(self.path(share["name"]), acl.share_root_sddl(dsid, share["permissions"]), dsid,
                          share["name"])

    def apply_share_sd(self, share: dict) -> None:
        """Share-level security descriptor (share_info.tdb). "access based share enum" filters the share list by
        it, not by the folder ACL: Domain Admins, SYSTEM and the share's principals get FULL at share level (the NT
        ACL on the folder decides read/change/full), everybody else does not see the share."""
        samba.set_share_acl(share["name"], self.app.settings["domain_sid"], [p["sid"] for p in share["permissions"]])

    def read_permissions(self, share: dict) -> list[dict]:
        dsid = self.app.settings["domain_sid"]
        try:
            got = self.app.acls.get(self.path(share["name"]), dsid, share["name"])
        except acl.AclError:
            return []
        return acl.parse_permissions(got.get("aces", []), dsid)

    def ensure_recycle(self, share: dict) -> None:
        if not share["recycle"]["enabled"]:
            return
        rec = os.path.join(self.path(share["name"]), ".recycle")
        open_dir(rec)
        dsid = self.app.settings["domain_sid"]
        self.app.acls.set(rec, acl.recycle_sddl(dsid, share["permissions"]), dsid, share["name"])

    def apply_all(self) -> None:
        """After a (re)setup: folders and root ACLs of the shares already in shares.json."""
        for s in self.raw():
            try:
                open_dir(self.path(s["name"]))
                self.apply_acl(s)
                self.apply_share_sd(s)
                self.ensure_recycle(s)
            except Exception as exc:  # noqa: BLE001 - one share must not stop the others
                log.error("share %s: %s", s["name"], exc)

    def set_locked(self, name: str, locked: bool) -> None:
        with self._lock:
            cur = self._find(name)
            if cur.get("locked") != locked:
                cur["locked"] = locked
                self._save()
                self.app.write_config(reload=True)

