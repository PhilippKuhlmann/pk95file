"""smb.conf, krb5.conf and /etc/hosts rendered from the settings and shares (docs/design.md §3, §5, §9).

smb.conf is written on every start and every change; manual edits are overwritten.
"""

from __future__ import annotations

import os

HEADER = (
    "# Written by PK95 File on every start and every change from its settings - manual changes are overwritten.\n"
    "# Change the shares in PK95 Core (Dateiserver → Freigaben).\n"
)
RID_LOW, RID_HIGH = 10000, 64999   # idmap rid: Unix ID = 10000 + RID (docs/design.md §5)
DEFAULT_LOW, DEFAULT_HIGH = 3000, 7999
MAX_RID = RID_HIGH - RID_LOW
HOSTS_MARK = "# pk95file"


def _esc(value: str) -> str:
    return value.replace("\n", " ").replace("\r", " ")


def global_section(s: dict) -> list[str]:
    wg = s["workgroup"].upper()
    lines = [
        "[global]",
        f"    netbios name = {s['hostname'].upper()}",
        f"    workgroup = {wg}",
        f"    realm = {s['realm'].upper()}",
        "    security = ads",
        "    server role = member server",
        f"    password server = {s['dc']['hostname']}.{s['realm'].lower()}",
        f"    interfaces = {s['ip']}/{s['prefix']}",
        "    bind interfaces only = yes",
        "    smb ports = 445",
        "    disable netbios = yes",
        "    dns proxy = no",
        "    multicast dns register = no",
        "    server min protocol = SMB2_10",
        f"    server smb encrypt = {s.get('smb_encryption', 'if_required')}",
        "    kerberos method = secrets only",
        "    winbind refresh tickets = yes",
        "    winbind enum users = no",
        "    winbind enum groups = no",
        "    winbind use default domain = no",
        "    idmap config * : backend = tdb",
        f"    idmap config * : range = {DEFAULT_LOW}-{DEFAULT_HIGH}",
        f"    idmap config {wg} : backend = rid",
        f"    idmap config {wg} : range = {RID_LOW}-{RID_HIGH}",
        "    template shell = /bin/false",
        "    template homedir = /nonexistent",
        "    vfs objects = acl_xattr",
        "    acl_xattr:security_acl_name = user.NTACL",
        "    acl_xattr:ignore system acls = yes",
        "    map acl inherit = yes",
        "    store dos attributes = yes",
        "    access based share enum = yes",
        "    load printers = no",
        "    printing = bsd",
        "    printcap name = /dev/null",
        "    disable spoolss = yes",
        "    log file = /var/log/samba/log.%m",
        "    max log size = 1000",
        "    log level = 1",
    ]
    if s.get("min_protocol") and s["min_protocol"] != "SMB2_10":
        lines[lines.index("    server min protocol = SMB2_10")] = f"    server min protocol = {s['min_protocol']}"
    return lines


def share_section(share: dict, shares_root: str, snapshots_root: str = "") -> list[str]:
    from .snapshots import smb_lines

    path = os.path.join(shares_root, share["name"])
    vfs = ["acl_xattr"]
    lines = [
        "",
        f"[{share['name']}]",
        f"    path = {path}",
        f"    comment = {_esc(share.get('description', ''))}",
        f"    read only = {'yes' if share.get('locked') else 'no'}",
        f"    available = {'yes' if share.get('enabled', True) else 'no'}",
        f"    hide unreadable = {'yes' if share.get('abe', True) else 'no'}",
        "    veto files = /.pk95-*/",
    ]
    if snapshots_root and (share.get("snapshots") or {}).get("enabled"):
        vfs.append("shadow_copy2")  # previous versions in Explorer (docs/design.md §7)
        lines += smb_lines(path, os.path.join(snapshots_root, share["name"]))
    rec = share.get("recycle") or {}
    if rec.get("enabled"):
        vfs.append("recycle")
        lines += [
            "    recycle:repository = .recycle/%U",
            "    recycle:keeptree = yes",
            "    recycle:versions = yes",
            "    recycle:touch_mtime = yes",
            "    recycle:directory_mode = 0777",   # the NT ACL (CREATOR OWNER) protects it, POSIX must not
            "    recycle:subdir_mode = 0777",
            "    recycle:exclude_dir = .recycle",
            "    hide files = /.recycle/",
        ]
        if rec.get("exclude"):
            lines.append("    recycle:exclude = " + "|".join(rec["exclude"]))
        if rec.get("max_file_mb"):
            lines.append(f"    recycle:maxsize = {int(rec['max_file_mb']) * 1024 * 1024}")
    lines.insert(3, f"    vfs objects = {' '.join(vfs)}")
    return lines


def render(settings: dict, shares: list[dict], shares_root: str, snapshots_root: str = "") -> str:
    lines = [HEADER] + global_section(settings)
    for share in sorted(shares, key=lambda x: x["name"].lower()):
        lines += share_section(share, shares_root, snapshots_root)
    return "\n".join(lines) + "\n"


def krb5(settings: dict) -> str:
    realm = settings["realm"].upper()
    return "\n".join([
        "# Written by PK95 File on every start.",
        "[libdefaults]",
        f"    default_realm = {realm}",
        "    dns_lookup_realm = false",
        "    dns_lookup_kdc = true",
        "    rdns = false",
        "[realms]",
        f"    {realm} = {{",
        f"        kdc = {settings['dc']['hostname']}.{settings['realm'].lower()}",
        "    }",
        "[domain_realm]",
        f"    .{settings['realm'].lower()} = {realm}",
        f"    {settings['realm'].lower()} = {realm}",
        "",
    ])


def hosts(text: str, settings: dict) -> str:
    """/etc/hosts with the DC and the server itself (one line each, marked), so nothing depends on DNS."""
    lines = [line for line in text.splitlines() if not line.rstrip().endswith(HOSTS_MARK)]
    realm = settings["realm"].lower()
    dc = settings["dc"]
    lines.append(f"{dc['ip']}\t{dc['hostname']}.{realm} {dc['hostname']}\t{HOSTS_MARK}")
    lines.append(f"{settings['ip']}\t{settings['hostname']}.{realm} {settings['hostname']}\t{HOSTS_MARK}")
    return "\n".join(lines) + "\n"
