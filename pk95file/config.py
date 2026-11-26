"""Configuration from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Config:
    listen_host: str = "0.0.0.0"
    listen_port: int = 8445
    data_dir: str = "/var/lib/pk95file"     # settings, shares, state (Docker volume "data")
    data_root: str = "/srv/files"            # share data (bind mount of /srv/pk95/files)
    samba_dir: str = "/var/lib/samba"        # secrets.tdb, idmap, caches (volume "samba")
    smb_conf: str = "/etc/samba/smb.conf"    # generated (volume "config")
    krb5_conf: str = "/etc/krb5.conf"
    hosts_file: str = "/etc/hosts"
    default_ip: str = ""                     # PK95FILE_DEFAULT_IP: the operator's suggestion for the wizard
    maintenance_time: str = "03:30"          # PK95FILE_MAINTENANCE_TIME: daily recycle retention (local time)
    core_mode: bool = False
    core_url: str = ""
    token: str = ""
    manage_processes: bool = True            # False in unit tests: never start winbindd/smbd, never touch the network

    def path(self, name: str) -> str:
        return os.path.join(self.data_dir, name)

    @property
    def shares_root(self) -> str:
        return os.path.join(self.data_root, "shares")

    @property
    def meta_root(self) -> str:
        return os.path.join(self.data_root, ".pk95")


def _flag(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def load(env=None) -> Config:
    env = os.environ if env is None else env
    cfg = Config()
    host, _, port = env.get("PK95FILE_LISTEN", "0.0.0.0:8445").rpartition(":")
    cfg.listen_host = host.strip("[]") or "0.0.0.0"
    cfg.listen_port = int(port)
    cfg.data_dir = env.get("PK95FILE_DATA_DIR", cfg.data_dir)
    cfg.data_root = env.get("PK95FILE_DATA_ROOT", cfg.data_root)
    cfg.default_ip = env.get("PK95FILE_DEFAULT_IP", "").strip()
    mt = env.get("PK95FILE_MAINTENANCE_TIME", "").strip()
    if len(mt) == 5 and mt[2] == ":" and mt[:2].isdigit() and mt[3:].isdigit() and int(mt[:2]) < 24 and int(mt[3:]) < 60:
        cfg.maintenance_time = mt
    cfg.core_mode = _flag(env.get("PK95_CORE_MODE"), False)
    cfg.core_url = env.get("PK95_CORE_URL", "").rstrip("/")
    cfg.token = env.get("PK95_CORE_TOKEN", "") if cfg.core_mode else env.get("PK95FILE_TOKEN", "")
    return cfg
