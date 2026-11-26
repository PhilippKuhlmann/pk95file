"""End-to-end test of PK95 File against a real PK95 AD domain (GitHub Actions, Docker with userns-remap).

  python3 tests/integration/run.py <file image> <ad image> <data root on the host>

Topology like the unprivileged LXC: the DC (pk95-ad) and PK95 File share one network namespace
(--network container:ci-dc), as both run with network_mode host there. The DC owns 172.30.0.10 with port 445,
PK95 File adds 172.30.0.53 to eth0 and binds smbd only to it. A client container on the same Docker network uses
smbclient/kinit/smbcacls as domain users. A small HTTP server plays PK95 Core and collects the events.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FILE_IMAGE, AD_IMAGE, DATA_ROOT = sys.argv[1], sys.argv[2], sys.argv[3]
AD_TOKEN = os.environ.get("AD_TOKEN") or "a" * 48
FILE_TOKEN = os.environ.get("FILE_TOKEN") or "f" * 48
NET, SUBNET = "pk95ci", "172.30.0.0/24"
DC_IP, FILES_IP, CLIENT_IP, GATEWAY = "172.30.0.10", "172.30.0.53", "172.30.0.100", "172.30.0.1"
REALM, REALM_UP, WG = "ci.example.test", "CI.EXAMPLE.TEST", "CIEXAMPLE"
AD_API, FILE_API = "http://127.0.0.1:18389", "http://127.0.0.1:18445"
ADMIN_PW, USER_PW = "Ci-Admin-2026!", "Ci-User-2026!"
SHARE = "Buchhaltung"
SHARE_DIR = f"/srv/files/shares/{SHARE}"

RESULTS: list[tuple[bool, str]] = []
EVENTS: list[dict] = []


def check(ok: bool, name: str, detail: str = "") -> bool:
    RESULTS.append((bool(ok), name + ("" if ok or not detail else f" – {detail}")))
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok or not detail else f" – {detail}"), flush=True)
    return bool(ok)


def sh(*argv: str, stdin: str | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, input=stdin, timeout=timeout)


def dexec(container: str, *argv: str, stdin: str | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
    return sh("docker", "exec", *(["-i"] if stdin is not None else []), container, *argv, stdin=stdin, timeout=timeout)


def api(base: str, token: str, method: str, path: str, body=None, timeout: float = 60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + token,
                                          **({"Content-Type": "application/json"} if data else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else None
        except ValueError:
            return exc.code, raw.decode(errors="replace")
    except (urllib.error.URLError, OSError) as exc:  # not listening yet, connection reset while starting
        return 0, {"error": str(exc)}


def ad(method, path, body=None, timeout=60):
    return api(AD_API, AD_TOKEN, method, path, body, timeout)


def fs(method, path, body=None, timeout=60):
    return api(FILE_API, FILE_TOKEN, method, path, body, timeout)


def wait(fn, timeout: float, every: float = 2.0):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        last = fn()
        if last:
            return last
        time.sleep(every)
    return last


class CoreHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        ok = self.path == "/api/v1/events" and self.headers.get("Authorization") == "Bearer " + FILE_TOKEN
        if ok:
            EVENTS.append(body)
            print(f"      event: {body.get('type')} ({body.get('severity')}) {body.get('title')}", flush=True)
        self.send_response(202 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"id": len(EVENTS)}).encode())


def smb(user: str, cmd: str, target: str = f"//{FILES_IP}/{SHARE}", kerberos: bool = False) -> str:
    argv = ["smbclient", target, "-m", "SMB3", "-c", cmd]
    argv += ["--use-kerberos=required"] if kerberos else ["-U", f"{WG}\\{user}%{USER_PW}"]
    res = dexec("ci-client", *argv)
    return res.stdout + res.stderr


def cacls(user: str, path: str, *args: str) -> str:
    pw = ADMIN_PW if user == "Administrator" else USER_PW
    res = dexec("ci-client", "smbcacls", f"//{FILES_IP}/{SHARE}", path, "-U", f"{WG}\\{user}%{pw}", *args)
    return res.stdout + res.stderr


def diag(label: str) -> None:
    """Diagnostics for a failed file check: where files are, the share section, the ACL and the share SD."""
    print(f"----- diagnostics: {label} -----", flush=True)
    for cmd in (["sh", "-c", f"ls -la {SHARE_DIR} {SHARE_DIR}/.recycle 2>&1; find /srv/files -maxdepth 4 | head -40"],
                ["sh", "-c", f"sed -n '/^\\[{SHARE}\\]/,/^\\[/p' /etc/samba/smb.conf"],
                ["sh", "-c", f"for f in {SHARE_DIR} {SHARE_DIR}/*; do echo \"$f:\"; "
                             "python3 -m pk95file.acl_helper /etc/samba/smb.conf get \"$f\" "
                             f"$(wbinfo -D {WG} | sed -n 's/^SID *: //p') {SHARE} 2>&1 | tail -n 1; done"],
                ["sharesec", SHARE, "--view"]):
        res = dexec("ci-file", *cmd)
        print((res.stdout + res.stderr).rstrip(), flush=True)
    print("-----", flush=True)


def logs(label: str) -> None:
    print(f"----- logs: {label} -----", flush=True)
    res = sh("docker", "logs", "--tail", "120", "ci-file")
    print((res.stdout + res.stderr).rstrip(), flush=True)
    res = dexec("ci-file", "sh", "-c", "tail -n 60 /var/log/samba/log.winbindd /var/log/samba/log.smbd 2>&1")
    print(res.stdout.rstrip(), flush=True)
    print("-----", flush=True)


def ok_out(out: str, *want: str) -> bool:
    """smbclient succeeded: no NT_STATUS error, and every wanted name is in the output."""
    return "NT_STATUS" not in out and all(w in out for w in want)


def dc_a_records() -> str:
    res = dexec("ci-dc", "samba-tool", "dns", "query", "127.0.0.1", REALM, "dc1", "A", "-U", f"Administrator%{ADMIN_PW}")
    return " ".join(sorted(re.findall(r"A: (\S+)", res.stdout))) or res.stdout + res.stderr


def cleanup() -> None:
    for c in ("ci-client", "ci-file", "ci-dc"):
        sh("docker", "rm", "-f", c)
    sh("docker", "network", "rm", NET)


def main() -> int:
    cleanup()
    core = ThreadingHTTPServer(("0.0.0.0", 18080), CoreHandler)
    threading.Thread(target=core.serve_forever, daemon=True).start()
    sh("docker", "network", "create", "--subnet", SUBNET, NET)

    # --- DC ---------------------------------------------------------------------------------------------------
    res = sh("docker", "run", "-d", "--name", "ci-dc", "--hostname", "dc1", "--network", NET, "--ip", DC_IP,
             "-p", "127.0.0.1:18389:8389", "-p", "127.0.0.1:18445:8445", "-e", f"PK95AD_TOKEN={AD_TOKEN}",
             "-e", "TZ=Europe/Berlin", AD_IMAGE, timeout=600)
    if not check(res.returncode == 0, "DC container started", res.stderr):
        return 1
    wait(lambda: ad("GET", "/core/health")[0] == 200, 120)
    st, _ = ad("POST", "/api/setup", {"realm": REALM, "netbios_domain": WG, "hostname": "dc1", "host_ip": DC_IP,
                                      "dns_forwarder": "127.0.0.1", "admin_password": ADMIN_PW})
    state = wait(lambda: (lambda b: isinstance(b, dict) and b.get("state") in ("ready", "failed") and b["state"])(
        ad("GET", "/api/setup")[1]), 300, 3)
    if not check(st == 202 and state == "ready", f"DC provisioned ({AD_IMAGE})", str(state)):
        return 1
    sam = "/var/lib/samba/private/sam.ldb"
    for user in ("alice", "bob", "carol", "dave"):
        dexec("ci-dc", "samba-tool", "user", "create", user, USER_PW, "-H", sam)
    for group, member in (("Buchhaltung", "alice"), ("Lesen", "carol"), ("Leitung", "dave")):
        dexec("ci-dc", "samba-tool", "group", "add", group, "-H", sam)
        dexec("ci-dc", "samba-tool", "group", "addmembers", group, member, "-H", sam)
    sids = {}
    for group in ("Buchhaltung", "Lesen", "Leitung"):
        st, body = ad("GET", f"/api/groups?search={group}")
        items = [g for g in (body or {}).get("items", []) if g.get("name") == group]
        sids[group] = items[0].get("sid", "") if items else ""
    check(all(s.startswith("S-1-5-21-") for s in sids.values()), "group SIDs from GET /api/groups (AD 1.5.0)", str(sids))
    alice_sid = re.search(r"objectSid: (\S+)", dexec("ci-dc", "samba-tool", "user", "show", "alice", "-H", sam,
                                                     "--attributes=objectSid").stdout).group(1)
    alice_uid = 10000 + int(alice_sid.rsplit("-", 1)[1])
    records_before = dc_a_records()

    # --- PK95 File ----------------------------------------------------------------------------------------------
    res = sh("docker", "run", "-d", "--name", "ci-file", "--network", "container:ci-dc",
             "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
             "-e", "PK95_CORE_MODE=1", "-e", f"PK95_CORE_TOKEN={FILE_TOKEN}",
             "-e", f"PK95_CORE_URL=http://{GATEWAY}:18080", "-e", f"PK95FILE_DEFAULT_IP={FILES_IP}",
             "-e", "TZ=Europe/Berlin",
             "-v", "ci_file_samba:/var/lib/samba", "-v", "ci_file_config:/etc/samba",
             "-v", "ci_file_data:/var/lib/pk95file", "-v", f"{DATA_ROOT}:/srv/files", FILE_IMAGE)
    if not check(res.returncode == 0, "file container started in the DC's network namespace", res.stderr):
        return 1
    check(wait(lambda: fs("GET", "/core/health")[0] == 200, 60), "GET /core/health")
    st, body = fs("GET", "/core/manifest")
    check(st == 200 and body["id"] == "file" and len(body["events"]) == 13, "manifest")
    st, info = fs("GET", "/api/setup")
    check(st == 200 and info["state"] == "unconfigured", "GET /api/setup: unconfigured")
    d = info["defaults"]
    check(d["ip"] == FILES_IP and d["ip_source"] == "env" and d["subnet"] == SUBNET and DC_IP in d["host_ips"],
          "setup defaults: IP from PK95FILE_DEFAULT_IP, subnet, host IPs", json.dumps(d))
    stg = info["storage"]
    check(stg["fs_type"] == "ext4" and not stg["problems"] and not stg["on_system_disk"] and stg["xattr"]
          and stg["hardlinks"], "storage preflight: own ext4, user.* xattrs, hardlinks", json.dumps(stg))
    check(fs("GET", f"/api/setup/ip-check?ip={FILES_IP}")[1]["ok"], "ip-check: .53 free")
    st, body = fs("GET", f"/api/setup/ip-check?ip={DC_IP}")
    check(not body["ok"] and "gehört schon" in body["message"], "ip-check: the LXC's own address refused", body["message"])
    check(not fs("GET", f"/api/setup/ip-check?ip={FILES_IP}&mode=existing")[1]["ok"], "ip-check existing: .53 not there")

    st, odj = ad("POST", "/api/computers/odj", {"name": "files", "dns_hostname": f"files.{REALM}",
                                               "description": "PK95 File CI"})
    if not check(st == 200 and odj.get("odj"), "ODJ blob from PK95 AD", str(st)):
        return 1
    setup = {"hostname": "files", "ip": FILES_IP, "ip_mode": "managed", "realm": REALM, "workgroup": WG,
             "dc": {"hostname": "dc1", "ip": DC_IP}}
    st, body = fs("POST", "/api/setup", {**setup, "odj": "QUJDREVG"})
    check(st == 422 and "odj" in body["fields"], "setup with foreign ODJ data → 422 odj", json.dumps(body))
    st, _ = fs("POST", "/api/setup", {**setup, "odj": odj["odj"]})
    check(st == 202, "POST /api/setup → 202")
    state = wait(lambda: (lambda s: isinstance(s, dict) and s.get("state") in ("ready", "failed") and s)(fs("GET", "/api/setup")[1]), 240, 3)
    if not check(state and state["state"] == "ready", "setup ready", json.dumps(state)[-1500:] if state else ""):
        logs("setup")
        return 1
    check(state["server"]["fqdn"] == f"files.{REALM}", "setup: server block")
    check(wait(lambda: any(e["type"] == "file.setup.done" for e in EVENTS), 30), "event file.setup.done")
    status = wait(lambda: (lambda s: isinstance(s, dict) and s.get("trust", {}).get("checked_at") and s)(fs("GET", "/api/status")[1]), 90, 3)
    check(status and status["smbd"]["state"] == "running" and status["winbindd"]["state"] == "running",
          "status: smbd and winbindd running", json.dumps(status and status["smbd"]))
    check(status and status["trust"]["ok"] and status["ip"]["present"], "status: trust ok, address present")
    check(status and status["idmap"]["next_rid"] > 1000 and status["idmap"]["warning"] == "",
          "status: RID high-water mark read", json.dumps(status and status["idmap"]))
    listen = dexec("ci-file", "ss", "-Hltn", "sport = :445").stdout.split()
    check(f"{FILES_IP}:445" in listen and "0.0.0.0:445" not in listen and f"{DC_IP}:445" in listen,
          "445: DC on .10, PK95 File only on .53", " ".join(listen))
    upd = dexec("ci-dc", "samba_dnsupdate", "--verbose", "--use-samba-tool", timeout=180)
    check(FILES_IP not in upd.stdout + upd.stderr, "samba_dnsupdate on the DC does not see .53")
    check(dc_a_records() == records_before, "DC A records unchanged", f"{records_before} → {dc_a_records()}")

    # --- shares -------------------------------------------------------------------------------------------------
    st, body = fs("POST", "/api/shares", {"name": "a/b"})
    check(st == 422 and "name" in body["fields"], "POST share: bad name → 422")
    st, body = fs("POST", "/api/shares", {"name": "X", "permissions": [{"sid": sids["Lesen"] + "9", "access": "read"}]})
    check(st == 422 and "permissions.0.sid" in body["fields"], "POST share: unknown SID → 422")
    perms = [{"sid": sids["Buchhaltung"], "access": "change"}, {"sid": sids["Lesen"], "access": "read"},
             {"name": f"{WG}\\Leitung", "access": "full"}]
    st, share = fs("POST", "/api/shares", {"name": SHARE, "description": "Belege", "permissions": perms})
    if not check(st == 201, "POST /api/shares → 201", json.dumps(share)):
        return 1
    check(share["unc"] == f"\\\\files.{REALM}\\{SHARE}" and not share["hidden"] and share["status"] == "ok",
          "share: unc, hidden, status")
    check([(p["name"].split("\\")[-1].lower(), p["access"], p["type"]) for p in share["permissions"]]
          == [("buchhaltung", "change", "group"), ("lesen", "read", "group"), ("leitung", "full", "group")],
          "share: permissions resolved", json.dumps(share["permissions"]))
    check(len(share["fixed_permissions"]) == 2 and share["recycle"]["enabled"], "share: fixed entries, recycle on")
    check(fs("POST", "/api/shares", {"name": SHARE.lower()})[0] == 422, "duplicate name (case) → 422")
    check(fs("GET", "/api/shares")[1]["total"] == 1, "GET /api/shares")
    check(dexec("ci-file", "getfattr", "-n", "user.NTACL", SHARE_DIR).returncode == 0, "share root ACL in user.NTACL")

    # --- client: read / change / full / none --------------------------------------------------------------------
    sh("docker", "run", "-d", "--name", "ci-client", "--network", NET, "--ip", CLIENT_IP,
       "--add-host", f"files.{REALM}:{FILES_IP}", "--add-host", f"dc1.{REALM}:{DC_IP}", "--entrypoint", "sleep",
       FILE_IMAGE, "infinity")
    krb5 = (f"[libdefaults]\n default_realm = {REALM_UP}\n dns_lookup_kdc = false\n rdns = false\n"
            f"[realms]\n {REALM_UP} = {{\n  kdc = {DC_IP}\n }}\n")
    dexec("ci-client", "sh", "-c", "cat > /etc/krb5.conf", stdin=krb5)
    dexec("ci-client", "sh", "-c", "cat > /etc/samba/smb.conf", stdin=f"[global]\n workgroup = {WG}\n realm = {REALM_UP}\n")

    out = smb("alice", "put /etc/hostname a.txt; mkdir Ordner; put /etc/hostname Ordner/b.txt; ls")
    if not check(ok_out(out, "a.txt", "Ordner"), "alice (change) writes", out[-400:]):
        diag("alice write")
    check(dexec("ci-file", "getfattr", "-n", "user.NTACL", f"{SHARE_DIR}/Ordner/b.txt").returncode == 0,
          "inherited ACL in user.NTACL on a new file")
    owner = dexec("ci-file", "stat", "-c", "%u", f"{SHARE_DIR}/a.txt").stdout.strip()
    check(owner == str(alice_uid), f"file owner = alice's rid uid {alice_uid}", owner)
    dexec("ci-client", "sh", "-c", f"echo '{USER_PW}' | kinit alice@{REALM_UP}")
    out = smb("alice", "put /etc/hostname k.txt; ls", target=f"//files.{REALM}/{SHARE}", kerberos=True)
    check(ok_out(out, "k.txt"), "alice with Kerberos (cifs/files.<realm>)", out[-300:])
    out = smb("carol", "get a.txt /tmp/a; put /etc/hostname c.txt")
    if not check("getting file" in out and "NT_STATUS_ACCESS_DENIED opening remote file \\c.txt" in out
                 and out.count("NT_STATUS") == 1, "carol (read) reads, cannot write", out[-300:]):
        diag("carol read")
    out = smb("bob", "ls")
    check("NT_STATUS_ACCESS_DENIED" in out, "bob (no permission) is denied", out[-200:])
    out_bob = smb("bob", "", target=f"//{FILES_IP}/IPC$").strip()
    lst_bob = dexec("ci-client", "smbclient", "-L", f"//{FILES_IP}", "-U", f"{WG}\\bob%{USER_PW}").stdout
    lst_alice = dexec("ci-client", "smbclient", "-L", f"//{FILES_IP}", "-U", f"{WG}\\alice%{USER_PW}").stdout
    if not check(SHARE not in lst_bob and SHARE in lst_alice, "ABE: bob does not see the share, alice does",
                 (lst_bob + out_bob)[-300:]):
        diag("share list")
    check("NT_STATUS_ACCESS_DENIED" in cacls("alice", "/", "--add", f"ACL:{WG}\\bob:ALLOWED/OI|CI/READ"),
          "alice (change) cannot change ACLs")
    out = cacls("dave", "/Ordner", "--add", f"ACL:{WG}\\bob:ALLOWED/0x0/READ")
    check("NT_STATUS" not in out, "dave (full) changes ACLs", out[-200:])
    check(ok_out(smb("dave", "mkdir Geheim")), "dave (full) creates a folder")
    out = cacls("dave", "/Geheim", "--add", f"ACL:{WG}\\Leitung:ALLOWED/OI|CI/FULL")
    out += cacls("dave", "/Geheim", "--inherit", "remove")  # after the explicit ACE, or dave locks himself out
    check("NT_STATUS" not in out, "dave restricts a folder to Leitung", out[-200:])
    check("Geheim" not in smb("alice", "ls") and "Geheim" in smb("dave", "ls"), "ABE: alice does not see Geheim")
    check(ok_out(smb("alice", "rm a.txt")), "alice deletes a.txt")
    rec = dexec("ci-file", "sh", "-c", f"ls {SHARE_DIR}/.recycle/*/a.txt").stdout
    if not check("a.txt" in rec, "recycle bin: deleted file in .recycle/<user>", rec):
        diag("recycle")
    check(".recycle" not in smb("carol", "ls"), "recycle bin hidden from carol")
    check(dexec("ci-file", "getfattr", "-n", "user.NTACL", f"{SHARE_DIR}/.recycle").returncode == 0, ".recycle ACL set")

    def job_done(resp):
        st, body = resp
        if st != 202 or not isinstance(body, dict) or "job" not in body:
            return None
        return wait(lambda: (lambda j: isinstance(j, dict) and j.get("state") in ("done", "failed") and j)(
            fs("GET", f"/api/jobs/{body['job']['id']}")[1]), 60)

    st, rec = fs("GET", f"/api/shares/{SHARE}/recycle")
    item = next((i for i in (rec or {}).get("items", []) if i["path"].endswith("/a.txt")), None)
    check(st == 200 and item and item["size"] > 0 and item["deleted_at"] > 0 and rec["bytes"] >= item["size"],
          "GET recycle lists alice's a.txt", json.dumps(rec)[:300])
    if item:
        job = job_done(fs("POST", f"/api/shares/{SHARE}/recycle/restore", {"paths": [item["path"]]}))
        check(job and job["state"] == "done", "recycle restore job done", json.dumps(job))
        check(ok_out(smb("alice", "get a.txt /tmp/a2"), "getting file"), "alice reads the restored file")
    check(fs("POST", f"/api/shares/{SHARE}/recycle/restore", {"paths": ["../../etc/passwd"]})[0] == 422,
          "recycle restore outside .recycle → 422")
    smb("alice", "rm a.txt")
    job = job_done(fs("POST", f"/api/shares/{SHARE}/recycle/empty", {"older_than_days": 0}))
    check(job and job["state"] == "done" and fs("GET", f"/api/shares/{SHARE}/recycle")[1]["total"] == 0,
          "recycle empty", json.dumps(job))

    # --- changes --------------------------------------------------------------------------------------------------
    st, body = fs("PUT", f"/api/shares/{SHARE}/permissions",
                  {"permissions": [perms[0], {"sid": sids["Leitung"], "access": "full"}], "propagate": True})
    check(st == 202 and body.get("job"), "PUT permissions with propagate → 202 job", json.dumps(body)[-300:])
    job = wait(lambda: (lambda j: j["state"] in ("done", "failed") and j)(fs("GET", f"/api/jobs/{body['job']['id']}")[1]),
               120) if st == 202 else None
    check(job and job["state"] == "done", "propagate job done", json.dumps(job))
    out = smb("carol", "get k.txt /tmp/k")
    check("NT_STATUS_ACCESS_DENIED" in out, "carol lost read after removing Lesen", out[-200:])
    st, body = fs("PUT", f"/api/shares/{SHARE}", {"description": "Neu", "abe": False, "recycle": {"enabled": False}})
    check(st == 200 and body["description"] == "Neu" and not body["abe"], "PUT share")
    conf = dexec("ci-file", "cat", "/etc/samba/smb.conf").stdout
    check("hide unreadable = no" in conf and "recycle:repository" not in conf, "smb.conf follows the share settings")
    check(fs("PUT", f"/api/shares/{SHARE}", {"name": "Anders"})[0] == 422, "rename refused → 422")

    st, dash = fs("GET", "/api/dashboard")
    check(st == 200 and dash["shares"] == 1 and dash["storage"]["total_bytes"] > 0 and isinstance(dash["sessions"], int),
          "GET /api/dashboard", json.dumps(dash)[:400])

    check(fs("DELETE", f"/api/shares/{SHARE}")[0] == 204, "DELETE share (keep data)")
    st, body = fs("GET", "/api/orphans")
    check(any(o["name"] == SHARE for o in body["items"]), "orphans list the folder")
    st, body = fs("POST", "/api/shares", {"name": SHARE})
    check(st == 422 and "name" in body["fields"], "recreate without adopt → 422")
    st, body = fs("POST", "/api/shares", {"name": SHARE, "adopt": True})
    got = sorted((p["name"].split("\\")[-1].lower(), p["access"]) for p in body.get("permissions", []))
    check(st == 201 and got == [("buchhaltung", "change"), ("leitung", "full")], "adopt reads the ACL back", str(got))

    # --- rejoin and backup ------------------------------------------------------------------------------------------
    st, odj2 = ad("POST", "/api/computers/odj", {"name": "files", "dns_hostname": f"files.{REALM}", "reset": True})
    st, _ = fs("POST", "/api/join", {"odj": odj2["odj"]})
    state = wait(lambda: (lambda s: isinstance(s, dict) and s.get("state") in ("ready", "failed") and s)(fs("GET", "/api/setup")[1]), 180, 3)
    if not check(st == 202 and state and state["state"] == "ready", "rejoin with a new blob",
                 json.dumps(state)[-800:] if state else ""):
        logs("rejoin")
    check(dexec("ci-file", "wbinfo", "-t").returncode == 0, "trust after rejoin")
    dexec("ci-client", "sh", "-c", f"kdestroy; echo '{USER_PW}' | kinit alice@{REALM_UP}")
    check("NT_STATUS" not in smb("alice", "ls", target=f"//files.{REALM}/{SHARE}", kerberos=True),
          "Kerberos access after rejoin")
    check(fs("POST", "/core/backup/prepare")[0] == 204, "POST /core/backup/prepare → 204")
    st, status = fs("GET", "/api/status")
    check(st == 200 and status["smbd"]["state"] == "backup" and fs("GET", "/core/health")[0] == 200,
          "Samba stopped for the backup, API still up", json.dumps(status)[:300])
    check({e["type"] for e in EVENTS} <= set(fs("GET", "/core/manifest")[1]["events"]), "events are in the manifest list")
    return 0


if __name__ == "__main__":
    try:
        rc = main()
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        check(False, "integration script crashed", str(exc))
        rc = 1
    failed = [n for ok, n in RESULTS if not ok]
    print(f"\n===== {len(RESULTS) - len(failed)} passed, {len(failed)} failed =====")
    for n in failed:
        print("FAIL  " + n)
    sys.exit(1 if failed or rc else 0)
