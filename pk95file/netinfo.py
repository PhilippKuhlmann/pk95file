"""The LXC's network as the app sees it in host network mode: addresses, DAD and its own secondary address
(docs/design.md §3, option A)."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess

SKIP_IFACES = ("lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "vxlan", "kube")
SUGGEST_TRIES = 10


def _ip_json(*args: str) -> list:
    try:
        res = subprocess.run(["ip", "-j", *args], capture_output=True, text=True, timeout=10)
        return json.loads(res.stdout) if res.returncode == 0 and res.stdout.strip() else []
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def default_interface() -> str:
    routes = _ip_json("-4", "route", "show", "default")
    return routes[0].get("dev", "") if routes else ""


def addresses() -> list[dict]:
    """[{"iface", "ip", "prefix"}] of the global IPv4 addresses (Docker bridges and loopback left out)."""
    out = []
    for link in _ip_json("-4", "addr", "show"):
        name = link.get("ifname", "")
        if name.startswith(SKIP_IFACES):
            continue
        for a in link.get("addr_info", []):
            if a.get("family") == "inet" and a.get("scope") == "global":
                out.append({"iface": name, "ip": a["local"], "prefix": int(a["prefixlen"])})
    return out


def primary(addrs: list[dict], iface: str) -> dict | None:
    """The first address of iface – the LXC's own address (a managed secondary one is added later)."""
    for a in addrs:
        if a["iface"] == iface:
            return a
    return None


def subnet(addr: dict | None) -> str:
    if not addr:
        return ""
    return str(ipaddress.IPv4Interface(f"{addr['ip']}/{addr['prefix']}").network)


def candidates(own_ip: str, prefix: int, taken: set[str], tries: int = SUGGEST_TRIES) -> list[str]:
    """The next addresses after own_ip in its subnet, without taken ones, network and broadcast (pure)."""
    net = ipaddress.IPv4Interface(f"{own_ip}/{prefix}").network
    out, ip = [], ipaddress.IPv4Address(own_ip)
    while len(out) < tries:
        ip += 1
        if ip not in net or ip == net.broadcast_address:
            break
        if str(ip) not in taken:
            out.append(str(ip))
    return out


MAC_RE = re.compile(r"\[([0-9A-Fa-f:]{17})\]")


def dad(ip: str, iface: str) -> tuple[bool, str]:
    """(free, mac of the other host). arping -D exits 0 when nobody answered."""
    try:
        res = subprocess.run(["arping", "-D", "-c", "2", "-w", "3", "-I", iface, ip],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return True, ""  # cannot check: do not block the user
    if res.returncode == 0:
        return True, ""
    m = MAC_RE.search(res.stdout)
    return False, m.group(1).lower() if m else ""


def add(ip: str, prefix: int, iface: str) -> str | None:
    res = subprocess.run(["ip", "addr", "replace", f"{ip}/{prefix}", "dev", iface],
                         capture_output=True, text=True, timeout=10)
    if res.returncode != 0:
        return (res.stderr or res.stdout).strip() or f"ip addr replace: Code {res.returncode}"
    subprocess.run(["arping", "-U", "-c", "2", "-I", iface, ip], capture_output=True, timeout=10)
    return None


def remove(ip: str, prefix: int, iface: str) -> None:
    subprocess.run(["ip", "addr", "del", f"{ip}/{prefix}", "dev", iface], capture_output=True, timeout=10)


def present(ip: str, addrs: list[dict] | None = None) -> bool:
    return any(a["ip"] == ip for a in (addresses() if addrs is None else addrs))
