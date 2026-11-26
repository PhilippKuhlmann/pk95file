"""NT ACLs of share roots (docs/design.md §9).

The descriptors are built here as SDDL (pure, unit tested). Reading and writing goes through
`python3 -m pk95file.acl_helper` in a child process: it loads the current smb.conf *with its shares* into
Samba's s3 parameter context (samba.samba3.param), the way Samba's own provisioning does for SYSVOL, and calls
samba.ntacls.setntacl(..., service=<share>). Without the share loaded, smbd's VFS refuses the connection
("Unknown Service (snum == -1) denied due to security descriptor", seen in the ODJ spike). A fresh process per
call also picks up a share that was just added to smb.conf.

Owner and group of a share root stay Unix root (S-1-22-1-0 / S-1-22-2-0): with "acl_xattr:ignore system acls"
an owner change makes vfs_acl_common chown through the POSIX layer first, which is refused.
"""

from __future__ import annotations

import json
import subprocess
import sys

from .errors import ApiError

ACCESS_MASK = {
    "read": 0x001200A9,    # Read & Execute
    "change": 0x001301BF,  # Modify
    "full": 0x001F01FF,    # Full Control
}
MASK_ACCESS = {v: k for k, v in ACCESS_MASK.items()}

SYSTEM = "S-1-5-18"
ROOT_USER = "S-1-22-1-0"
ROOT_GROUP = "S-1-22-2-0"
DOMAIN_ADMINS_RID = 512
INHERIT = "OICI"

HELPER_TIMEOUT = 120


class AclError(ApiError):
    def __init__(self, message: str):
        super().__init__(500, message)


def domain_admins(domain_sid: str) -> str:
    return f"{domain_sid}-{DOMAIN_ADMINS_RID}"


def fixed_entries(domain_sid: str) -> list[dict]:
    """ACEs every share root has; shown read-only in Core (docs/api.md → fixed_permissions)."""
    return [{"sid": domain_admins(domain_sid), "access": "full"}, {"sid": SYSTEM, "access": "full"}]


def _ace(sid: str, access: str, flags: str = INHERIT) -> str:
    return f"(A;{flags};0x{ACCESS_MASK[access]:08x};;;{sid})"


def share_root_sddl(domain_sid: str, permissions: list[dict]) -> str:
    """Protected DACL (no inheritance from /srv/files/shares): fixed entries, then one ACE per permission."""
    aces = [_ace(e["sid"], e["access"]) for e in fixed_entries(domain_sid)]
    aces += [_ace(p["sid"], p["access"]) for p in permissions]
    return f"O:{ROOT_USER}G:{ROOT_GROUP}D:PAI" + "".join(aces)


CREATOR_OWNER = "S-1-3-0"
# This folder only: traverse + create folders + read attributes + synchronize. vfs_recycle moves a deleted file
# into .recycle/<user>/… as that user, so whoever may delete ("change") must be able to create their folder.
RECYCLE_ENTER = 0x001000A4


def recycle_sddl(domain_sid: str, permissions: list[dict]) -> str:
    """.recycle (docs/design.md §9): Domain Admins, SYSTEM and "full" principals see everything; "change" principals
    may only create their own folder, which CREATOR OWNER makes theirs alone. Protected, no inheritance from the root."""
    aces = [_ace(e["sid"], e["access"]) for e in fixed_entries(domain_sid)]
    aces += [_ace(p["sid"], "full") for p in permissions if p["access"] == "full"]
    aces += [f"(A;;0x{RECYCLE_ENTER:08x};;;{p['sid']})" for p in permissions if p["access"] == "change"]
    aces.append(f"(A;OICIIO;0x{ACCESS_MASK['full']:08x};;;{CREATOR_OWNER})")
    return f"O:{ROOT_USER}G:{ROOT_GROUP}D:PAI" + "".join(aces)


def parse_permissions(entries: list[dict], domain_sid: str) -> list[dict]:
    """Explicit ACEs of a share root (from acl_helper "get") back to [{"sid", "access"}], fixed ones left out."""
    fixed = {e["sid"] for e in fixed_entries(domain_sid)}
    out = []
    for e in entries:
        if e.get("type") != 0 or e.get("inherited") or e["sid"] in fixed:
            continue
        access = MASK_ACCESS.get(e["mask"])
        if access:
            out.append({"sid": e["sid"], "access": access})
    return out


class Acls:
    """Runs the helper. smb_conf must already contain the share (service) being touched."""

    def __init__(self, smb_conf: str, python: str = sys.executable):
        self.smb_conf = smb_conf
        self.python = python

    def _run(self, *args: str) -> dict:
        argv = [self.python, "-m", "pk95file.acl_helper", self.smb_conf, *args]
        try:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=HELPER_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AclError(f"ACL-Hilfsprogramm lief nicht: {exc}") from None
        if res.returncode != 0:
            detail = (res.stderr or res.stdout).strip().splitlines()
            raise AclError("NT-ACL konnte nicht gesetzt werden: " + (detail[-1] if detail else f"Code {res.returncode}"))
        try:
            return json.loads(res.stdout.strip().splitlines()[-1]) if res.stdout.strip() else {}
        except (ValueError, IndexError):
            return {}

    def set(self, path: str, sddl: str, domain_sid: str, service: str) -> None:
        self._run("set", path, sddl, domain_sid, service)

    def get(self, path: str, domain_sid: str, service: str) -> dict:
        """{"sddl", "owner", "group", "protected", "aces": [{"sid", "type", "flags", "mask", "inherited"}]}"""
        return self._run("get", path, domain_sid, service)

    def propagate(self, root: str, domain_sid: str, service: str, skip: list[str]) -> dict:
        """Recompute inherited ACEs below root (explicit ones are kept). {"done": n, "errors": [...]}"""
        return self._run("propagate", root, domain_sid, service, json.dumps(skip))
