"""Child process for NT ACLs (started by pk95file.acl.Acls; prints one JSON line).

  python3 -m pk95file.acl_helper <smb.conf> set <path> <sddl> <domain_sid> <service>
  python3 -m pk95file.acl_helper <smb.conf> get <path> <domain_sid> <service>
  python3 -m pk95file.acl_helper <smb.conf> propagate <root> <domain_sid> <service> <skip-json>

The share has to be in smb.conf: its section is loaded into Samba's s3 parameter context, so smbd's VFS
(acl_xattr with user.NTACL) runs for that share. Samba imports stay inside the functions, so the pure
inheritance rules can be unit tested without Samba.
"""

from __future__ import annotations

import json
import os
import sys

OI, CI, NP, IO, ID = 0x01, 0x02, 0x04, 0x08, 0x10   # SEC_ACE_FLAG_*
DACL_PROTECTED = 0x1000                              # SEC_DESC_DACL_PROTECTED


def child_flags(flags: int, is_dir: bool) -> int | None:
    """Flags of the ACE a child inherits from a parent ACE with `flags`, or None if it inherits nothing."""
    if is_dir:
        if flags & CI:
            return ID if flags & NP else (flags & ~IO) | ID
        if flags & OI and not flags & NP:
            return OI | IO | ID  # passes through to files below, does not apply to the folder itself
        return None
    return ID if flags & OI else None


def _load(conf: str):
    from samba.param import LoadParm
    from samba.samba3 import param as s3param

    lp = LoadParm()
    lp.load(conf)
    s3 = s3param.get_context()
    s3.load(conf)  # with the share sections: smbd's lp_servicenumber(<service>) must find the share
    return lp


def _session():
    from samba.auth_util import system_session_unix

    return system_session_unix()


def _get(lp, path: str, service: str):
    from samba.ntacls import getntacl

    return getntacl(lp, path, _session(), direct_db_access=False, service=service)


def _set(lp, path: str, sddl: str, domain_sid: str, service: str) -> None:
    from samba.ntacls import setntacl

    setntacl(lp, path, sddl, domain_sid, _session(), use_ntvfs=False, service=service)


def describe(sd, domain_sid: str) -> dict:
    from samba.dcerpc import security

    aces = []
    if sd.dacl is not None:
        for ace in sd.dacl.aces:
            aces.append({"sid": str(ace.trustee), "type": int(ace.type), "flags": int(ace.flags),
                         "mask": int(ace.access_mask), "inherited": bool(ace.flags & ID)})
    return {"sddl": sd.as_sddl(security.dom_sid(domain_sid)), "owner": str(sd.owner_sid),
            "group": str(sd.group_sid), "protected": bool(sd.type & DACL_PROTECTED), "aces": aces}


def rebuild(sd, parent, is_dir: bool, domain_sid: str):
    """sd with its inherited ACEs replaced by those inherited from parent; explicit ACEs come first and stay."""
    from samba.dcerpc import security

    if sd.type & DACL_PROTECTED:
        return sd
    new = security.descriptor.from_sddl(f"O:{sd.owner_sid}G:{sd.group_sid}D:AI", security.dom_sid(domain_sid))
    for ace in (sd.dacl.aces if sd.dacl is not None else []):
        if not ace.flags & ID:
            new.dacl_add(ace)
    for pace in (parent.dacl.aces if parent.dacl is not None else []):
        flags = child_flags(int(pace.flags), is_dir)
        if flags is None:
            continue
        ace = security.ace()
        ace.type = pace.type
        ace.flags = flags
        ace.access_mask = pace.access_mask
        ace.trustee = pace.trustee
        new.dacl_add(ace)
    return new


def propagate(lp, root: str, domain_sid: str, service: str, skip: list[str]) -> dict:
    from samba.dcerpc import security

    dsid = security.dom_sid(domain_sid)
    done, errors = 0, []
    stack = [(root, _get(lp, root, service))]
    while stack:
        dirpath, parent = stack.pop()
        try:
            entries = sorted(os.scandir(dirpath), key=lambda e: e.name)
        except OSError as exc:
            errors.append(f"{dirpath}: {exc.strerror}")
            continue
        for entry in entries:
            rel = os.path.relpath(entry.path, root)
            if rel in skip or entry.is_symlink():
                continue
            is_dir = entry.is_dir(follow_symlinks=False)
            try:
                sd = _get(lp, entry.path, service)
                new = rebuild(sd, parent, is_dir, domain_sid)
                if new.as_sddl(dsid) != sd.as_sddl(dsid):
                    _set(lp, entry.path, new.as_sddl(dsid), domain_sid, service)
                    new = _get(lp, entry.path, service)
                done += 1
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the walk
                errors.append(f"{rel}: {exc}")
                continue
            if is_dir:
                stack.append((entry.path, new))
    return {"done": done, "errors": errors[:50]}


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    conf, cmd, args = argv[1], argv[2], argv[3:]
    lp = _load(conf)
    if cmd == "set" and len(args) == 4:
        path, sddl, domain_sid, service = args
        _set(lp, path, sddl, domain_sid, service)
        print(json.dumps(describe(_get(lp, path, service), domain_sid)))
    elif cmd == "get" and len(args) == 3:
        path, domain_sid, service = args
        print(json.dumps(describe(_get(lp, path, service), domain_sid)))
    elif cmd == "propagate" and len(args) == 4:
        root, domain_sid, service, skip = args
        print(json.dumps(propagate(lp, root, domain_sid, service, json.loads(skip))))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
