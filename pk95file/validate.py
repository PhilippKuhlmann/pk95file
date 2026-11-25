"""Field rules of docs/api.md (pure functions, German messages; None = valid)."""

from __future__ import annotations

import ipaddress
import re

HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$")
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
WORKGROUP_RE = re.compile(r"^[A-Z0-9-]{1,15}$")
SID_RE = re.compile(r"^S-1-\d+(-\d+)+$")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

SHARE_FORBIDDEN = set('\\/[]:|<>+=;,*?"')
SHARE_RESERVED = {"global", "homes", "printers", "ipc$", "print$", "home$", "redirect$"}
ACCESS = ("read", "change", "full")


def hostname(v) -> str | None:
    if not isinstance(v, str) or not v:
        return "Bitte einen Namen angeben."
    if not HOST_RE.match(v):
        return "1–15 Zeichen: Kleinbuchstaben, Ziffern und Bindestriche, nicht am Anfang oder Ende."
    if v.isdigit():
        return "Der Name darf nicht nur aus Ziffern bestehen."
    return None


def realm(v) -> str | None:
    if not isinstance(v, str) or not v:
        return "Bitte die AD-Domäne angeben."
    labels = v.split(".")
    if len(labels) < 2 or not all(LABEL_RE.match(x) for x in labels):
        return "Bitte einen gültigen DNS-Namen angeben, z. B. ad.example.com."
    return None


def workgroup(v) -> str | None:
    if not isinstance(v, str) or not WORKGROUP_RE.match(v) or v.isdigit():
        return "1–15 Zeichen: Großbuchstaben, Ziffern und Bindestriche."
    return None


def ipv4(v) -> str | None:
    if not isinstance(v, str):
        return "Bitte eine IPv4-Adresse angeben."
    try:
        ipaddress.IPv4Address(v)
    except ValueError:
        return "Bitte eine gültige IPv4-Adresse angeben."
    return None


def ip_in_subnet(ip: str, subnet: str) -> str | None:
    err = ipv4(ip)
    if err:
        return err
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        return None  # subnet unknown: nothing to compare against
    addr = ipaddress.IPv4Address(ip)
    if addr not in net:
        return f"Die Adresse liegt nicht im Netz {net}."
    if net.prefixlen < 31 and addr in (net.network_address, net.broadcast_address):
        return "Netz- und Broadcast-Adresse sind nicht erlaubt."
    return None


def share_name(v) -> str | None:
    if not isinstance(v, str) or not v.strip():
        return "Bitte einen Namen angeben."
    if v != v.strip():
        return "Der Name darf nicht mit Leerzeichen beginnen oder enden."
    if len(v) > 80:
        return "Höchstens 80 Zeichen."
    if v in (".", "..") or v.lower() in SHARE_RESERVED:
        return "Dieser Name ist reserviert."
    if any(c in SHARE_FORBIDDEN or ord(c) < 32 for c in v):
        return 'Diese Zeichen sind nicht erlaubt: \\ / [ ] : | < > + = ; , * ? "'
    return None


def sid(v) -> bool:
    return isinstance(v, str) and bool(SID_RE.match(v))


def int_range(v, low: int, high: int) -> str | None:
    if isinstance(v, bool) or not isinstance(v, int):
        return "Bitte eine ganze Zahl angeben."
    if not low <= v <= high:
        return f"Erlaubt sind {low} bis {high}."
    return None


def time_of_day(v) -> bool:
    return isinstance(v, str) and bool(TIME_RE.match(v))
