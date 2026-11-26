"""Route table (docs/api.md)."""

from __future__ import annotations

from . import VERSION, samba
from .app import App, manifest
from .errors import invalid
from .httpapi import Response, Router

NAME = "{name:[^/]+}"


def build(app: App) -> Router:
    r = Router()

    def ready(fn):
        def handler(req):
            app.require_ready()
            return fn(req)
        return handler

    def job_response(job, fallback=None):
        if job is None:
            return fallback if fallback is not None else Response(204)
        return Response(202, {"job": job.info()})

    # Core protocol
    r.add("GET", "/core/health", lambda req: {"ok": True, "version": VERSION, "state": app.state()}, auth=False)
    r.add("GET", "/core/manifest", lambda req: manifest())

    def backup_prepare(req):
        app.backup_prepare()
        return Response(204)
    r.add("POST", "/core/backup/prepare", backup_prepare)

    # Setup
    r.add("GET", "/api/setup", lambda req: app.setup.info())

    def ip_check(req):
        mode = req.q("mode", "managed")
        if mode not in ("managed", "existing"):
            raise invalid({"mode": "Bitte managed oder existing angeben."})
        return app.setup.ip_check(req.q("ip"), mode)
    r.add("GET", "/api/setup/ip-check", ip_check)

    def setup_start(req):
        app.setup.start(req.json())
        return Response(202, {"state": "joining"})
    r.add("POST", "/api/setup", setup_start)

    def rejoin(req):
        app.setup.rejoin(req.json())
        return Response(202, {"state": "joining"})
    r.add("POST", "/api/join", rejoin)

    # Status
    r.add("GET", "/api/status", lambda req: app.status())
    r.add("GET", "/api/dashboard", lambda req: app.dashboard())

    # Shares
    r.add("GET", "/api/shares", ready(lambda req: app.shares.list()))
    r.add("POST", "/api/shares", ready(lambda req: Response(201, app.shares.create(req.json()))))
    r.add("GET", f"/api/shares/{NAME}", ready(lambda req: app.shares.get(req.params["name"])))
    r.add("PUT", f"/api/shares/{NAME}", ready(lambda req: app.shares.update(req.params["name"], req.json())))

    def set_permissions(req):
        share, job = app.shares.set_permissions(req.params["name"], req.json())
        return Response(202, {**share, "job": job.info()}) if job else share
    r.add("PUT", f"/api/shares/{NAME}/permissions", ready(set_permissions))

    def delete_share(req):
        return job_response(app.shares.delete(req.params["name"], req.flag("delete_data")))
    r.add("DELETE", f"/api/shares/{NAME}", ready(delete_share))

    r.add("GET", "/api/orphans", ready(lambda req: app.shares.orphans()))
    r.add("DELETE", f"/api/orphans/{NAME}", ready(lambda req: job_response(app.shares.delete_orphan(req.params["name"]))))

    # Sessions (smbstatus)
    def sessions(req):
        st = samba.smbstatus()
        items = []
        for sid, s in (st.get("sessions") or {}).items():
            items.append({"id": str(sid), "pid": int(str(s.get("server_id", {}).get("pid", 0)) or 0),
                          "user": s.get("username", ""), "machine": s.get("remote_machine", ""),
                          "hostname": s.get("hostname", ""), "protocol": s.get("session_dialect", ""),
                          "encrypted": bool((s.get("encryption") or {}).get("cipher")),
                          "signed": bool((s.get("signing") or {}).get("cipher")),
                          "connected_at": 0, "shares": [], "open_files": 0})
        return {"items": items, "total": len(items)}
    r.add("GET", "/api/sessions", ready(sessions))

    # Jobs and settings
    r.add("GET", "/api/jobs", lambda req: {"items": app.jobs.list(req.q("kind"), req.q("state"))})
    r.add("GET", "/api/jobs/{id:[0-9a-f]{12}}", lambda req: app.jobs.get(req.params["id"]))
    r.add("GET", "/api/settings", lambda req: app.app_settings())
    r.add("PUT", "/api/settings", lambda req: app.put_app_settings(req.json()))
    return r
