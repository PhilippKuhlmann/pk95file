"""Samba processes (winbindd, smbd) and the command line tools the app calls."""

from __future__ import annotations

import json
import logging
import re
import subprocess

from .supervisor import Process

log = logging.getLogger("pk95file.samba")

# wbinfo / lsa SID types
SID_USER, SID_DOM_GROUP, SID_DOMAIN, SID_ALIAS, SID_WKN_GROUP = 1, 2, 3, 4, 5
KIND = {SID_USER: "user", SID_DOM_GROUP: "group", SID_ALIAS: "group", SID_WKN_GROUP: "well_known"}


class SambaError(Exception):
    pass


def run(argv: list[str], timeout: float = 30, stdin: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=stdin)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", f"{argv[0]}: Zeitüberschreitung nach {timeout:.0f} s")
    except OSError as exc:
        return subprocess.CompletedProcess(argv, 127, "", f"{argv[0]}: {exc}")


def _detail(res: subprocess.CompletedProcess) -> str:
    lines = (res.stderr or res.stdout or "").strip().splitlines()
    return lines[-1] if lines else f"Code {res.returncode}"


def processes(on_crash) -> dict[str, Process]:
    return {
        "winbindd": Process("winbindd", lambda: ["winbindd", "--foreground", "--no-process-group",
                                                 "--debug-stdout"], on_crash=on_crash, label="winbindd"),
        "smbd": Process("smbd", lambda: ["smbd", "--foreground", "--no-process-group", "--debug-stdout"],
                        on_crash=on_crash, label="smbd"),
    }


def requestodj(blob: str) -> None:
    """net offlinejoin requestodj -i: the blob goes in on stdin, never to disk or into argv (docs/design.md §4)."""
    res = run(["net", "offlinejoin", "requestodj", "-i"], stdin=blob.strip() + "\n", timeout=60)
    if res.returncode != 0:
        raise SambaError(f"Domänenbeitritt fehlgeschlagen (net offlinejoin requestodj): {_detail(res)}")


def join_with_password(user: str, password: str, dns_hostname: str) -> None:
    """Fallback join (docs/api.md → POST /api/setup); the password goes in on stdin, never in argv or logs."""
    res = run(["net", "ads", "join", "-U", user, "--no-dns-updates", f"dnshostname={dns_hostname}"],
              stdin=password + "\n", timeout=120)
    if res.returncode != 0:
        raise SambaError(f"Domänenbeitritt fehlgeschlagen (net ads join): {_detail(res)}")


def trust_ok() -> tuple[bool, str]:
    res = run(["wbinfo", "-t"], timeout=15)
    return res.returncode == 0, "" if res.returncode == 0 else _detail(res)


def netlogon_ok() -> tuple[bool, str]:
    res = run(["wbinfo", "-P"], timeout=30)
    return res.returncode == 0, "" if res.returncode == 0 else _detail(res)


def domain_sid(workgroup: str) -> str:
    res = run(["wbinfo", "-D", workgroup], timeout=30)
    m = re.search(r"^SID\s*:\s*(S-1-[\d-]+)", res.stdout, re.M)
    if not m:
        raise SambaError(f"Domänen-SID nicht lesbar: {_detail(res)}")
    return m.group(1)


def name_to_sid(name: str) -> tuple[str, int] | None:
    res = run(["wbinfo", "-n", name], timeout=30)
    parts = res.stdout.split()
    if res.returncode != 0 or len(parts) < 2 or not parts[0].startswith("S-1-"):
        return None
    last = parts[-1].strip("()")
    return parts[0], int(last) if last.isdigit() else _type_word(parts[1:])


def _type_word(words: list[str]) -> int:
    text = " ".join(words).lower()
    if "user" in text:
        return SID_USER
    if "alias" in text:
        return SID_ALIAS
    if "well" in text:
        return SID_WKN_GROUP
    return SID_DOM_GROUP if "group" in text else 0


def sid_to_name(sid: str) -> tuple[str, int] | None:
    """("DOMAIN\\name", sid type) or None if the SID does not resolve."""
    res = run(["wbinfo", "-s", sid], timeout=30)
    line = res.stdout.strip()
    if res.returncode != 0 or not line:
        return None
    name, _, typ = line.rpartition(" ")
    return (name, int(typ)) if typ.isdigit() else (line, 0)


def sid_to_uid(sid: str) -> int | None:
    res = run(["wbinfo", "--sid-to-uid", sid], timeout=30)
    out = res.stdout.strip()
    return int(out) if res.returncode == 0 and out.isdigit() else None


def sid_to_gid(sid: str) -> int | None:
    res = run(["wbinfo", "--sid-to-gid", sid], timeout=30)
    out = res.stdout.strip()
    return int(out) if res.returncode == 0 and out.isdigit() else None


def grant(privilege: str, principal: str) -> str | None:
    res = run(["net", "sam", "rights", "grant", principal, privilege], timeout=30)
    return None if res.returncode == 0 else _detail(res)


def share_acl_entries(domain_sid: str, sids: list[str]) -> str:
    """sharesec ACL list: Domain Admins, SYSTEM and the given SIDs with FULL at share level (pure)."""
    out = [f"{domain_sid}-512", "S-1-5-18"]
    out += [s for s in sids if s not in out]
    return ",".join(f"ACL:{s}:ALLOWED/0x0/FULL" for s in out)


def set_share_acl(share: str, domain_sid: str, sids: list[str]) -> None:
    res = run(["sharesec", share, f"--replace={share_acl_entries(domain_sid, sids)}"], timeout=30)
    if res.returncode != 0:
        raise SambaError(f"Freigabe-Berechtigungen für {share} nicht gesetzt (sharesec): {_detail(res)}")


def reload_config() -> None:
    res = run(["smbcontrol", "smbd", "reload-config"], timeout=15)
    if res.returncode != 0:
        log.warning("smbcontrol reload-config: %s", _detail(res))


def testparm(conf: str) -> str | None:
    res = run(["testparm", "-s", "--suppress-prompt", conf], timeout=30)
    return None if res.returncode == 0 else _detail(res)


def smbstatus() -> dict:
    """smbstatus --json (Samba >= 4.16); {} when smbd is down."""
    res = run(["smbstatus", "--json"], timeout=15)
    if res.returncode != 0:
        return {}
    try:
        return json.loads(res.stdout)
    except ValueError:
        return {}


def counts(status: dict) -> tuple[int, int]:
    """(sessions, open files) from smbstatus --json (pure)."""
    return len(status.get("sessions") or {}), len(status.get("open_files") or {})


RID_RE = re.compile(r"^objectSid:\s*S-1-5-21-\d+-\d+-\d+-(\d+)\s*$", re.M)


def highest_rid() -> int | None:
    """Highest RID of all users, groups and computers, read over LDAP with the machine account."""
    res = run(["net", "ads", "search", "-P",
               "(|(objectClass=user)(objectClass=group)(objectClass=computer))", "objectSid"], timeout=120)
    rids = [int(x) for x in RID_RE.findall(res.stdout)]
    return max(rids) if res.returncode == 0 and rids else None
