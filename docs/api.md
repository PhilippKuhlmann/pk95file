# PK95 File – HTTP API

Status: **contract for the PK95 Core module** (agreed with the master session on 2026-11-25). The ODJ spike passed
against PK95 AD 1.5.0, which ships `POST /api/computers/odj` and `sid` in the group list. Design and decisions:
`docs/design.md`.

### Frozen parts (v1.0)

Core builds against these now. Within them only **additive** changes are allowed (new optional response fields, new
optional request fields with a default, new `warnings[].code` values, new events). Anything else – renaming, removing,
changing a type, a status code or a validation rule – needs the master session's agreement, and every change to this
file is reported to it with the diff.

| Part | Sections |
|---|---|
| Setup | `GET /api/setup` (incl. `defaults` and the `storage` preflight result), `GET /api/setup/ip-check`, `POST /api/setup`, `POST /api/join` |
| Status and Core figures | `GET /api/status`, `GET /api/dashboard` |
| Shares | share object, `GET`/`POST`/`PUT`/`DELETE /api/shares…`, `PUT /api/shares/{name}/permissions`, field rules |
| Events | the manifest's `events` list and the events table |

Not frozen yet (may still change before v1.0): snapshots, recycle bin, sessions and open files, usage, jobs, settings,
orphans.

PK95 File runs a Samba domain member file server in the PK95 AD domain and exposes one JSON admin API for the
PK95 Core module `file` (app protocol v1, see `PK95Core/docs/app-protocol.md`). There is no own web UI.
Default listen address `0.0.0.0:8445` (`PK95FILE_LISTEN`). The container runs with `network_mode: host`.

## Conventions

The same as PK95 AD:

- Request and response bodies are JSON (`Content-Type: application/json`).
- Timestamps are Unix **milliseconds** (integers). `0` means "never/none". Sizes are bytes (integers).
- Errors: `{"error": "German message"}` with a fitting status. Validation errors are
  `422 {"error": "Bitte Eingaben prüfen.", "fields": {"<field>": "German message"}}`. Field names are the JSON keys
  of the request body, `permissions.2.sid` for array items, `snapshots.keep.daily` for nested objects.
- `401` without a valid token, `404` unknown share/snapshot/job, `413` body over 2 MiB, `415` writing request with a
  body but without `Content-Type: application/json`. Routes without payload accept no body, `{}` and `[]`.
- `409 {"error": "Der Dateiserver ist noch nicht eingerichtet."}` for every share, session and usage route while
  `state` is not `ready`. `409` also for conflicts (setup already running, a job of the same kind already running).
- Shares are identified by their **name** (case-insensitive, URL-encoded in paths, e.g. `/api/shares/Projekte%24`).
  Names cannot be changed (a rename would break every mapped drive); to rename, create a new share and move the data.
- Security principals (groups, users) are identified by their **SID**. The API resolves names through winbind and
  returns both. Core takes the SIDs from PK95 AD's group list.
- Long-running work (permission propagation, snapshots, usage scans, restores) runs as a **job**:
  `202 {"job": {"id": "…", "kind": "…", "state": "queued"}}`, then poll `GET /api/jobs/{id}`.

## Authentication

**Core mode** (`PK95_CORE_MODE=1`): every `/api/*` and `/core/*` route except `GET /core/health` requires
`Authorization: Bearer <PK95_CORE_TOKEN>` (`hmac.compare_digest`; tokens shorter than 32 chars never match).

**Standalone**: `Authorization: Bearer <PK95FILE_TOKEN>` (at least 32 chars); without `PK95FILE_TOKEN` only
`/core/health` answers.

## Core protocol routes

- `GET /core/health` → `200 {"ok": true, "version": "1.0.0", "state": "ready"}` as soon as the API serves requests,
  also before setup (`state: "unconfigured"`) and while smbd is down.
- `GET /core/manifest` → see below.
- `POST /core/backup/prepare` → `204`. Stops smbd and winbindd (all tdbs closed) and keeps them stopped
  (`smbd.state: backup`). Core stops the container right after; if it does not within 10 minutes, both are started
  again. The file data under `/srv/files` is **not** part of Core's backup (bind mount); Proxmox backs it up.

### Manifest

```json
{
  "id": "file",
  "name": "PK95 File",
  "version": "1.0.0",
  "protocol": 1,
  "icon": "box",
  "menu": [
    { "key": "server", "label": "Dateiserver", "icon": "server" },
    { "key": "shares", "label": "Freigaben", "icon": "box" },
    { "key": "sessions", "label": "Sitzungen", "icon": "user" }
  ],
  "capabilities": ["events", "backup"],
  "events": ["file.setup.done", "file.setup.failed", "file.smbd.down", "file.smbd.up",
             "file.trust.broken", "file.trust.ok", "file.ip.conflict", "file.disk.low",
             "file.soft_quota.warning", "file.soft_quota.exceeded", "file.idmap.rid_limit",
             "file.snapshot.failed", "file.snapshot.skipped"]
}
```

The setup wizard belongs to the `server` page (shown while `GET /api/setup` says `state != "ready"`), like `domain`
in PK95 AD. The same page shows the dashboard.

### Events

| type | severity | when | `data` |
|---|---|---|---|
| `file.setup.done` | info | joined, smbd running | `hostname`, `ip`, `realm` |
| `file.setup.failed` | critical | setup or rejoin failed | `error` |
| `file.smbd.down` | critical | smbd or winbindd exited unexpectedly, or 445 on the IP has not answered for 60 s (not during backup) | `process`, `exit_code`, `error` |
| `file.smbd.up` | info | answers again after `file.smbd.down` | `down_seconds` |
| `file.trust.broken` | critical | `wbinfo -t` failed 3 times in a row (checked every 5 min) | `error` |
| `file.trust.ok` | info | the trust works again | – |
| `file.ip.conflict` | critical | another host answers ARP for the server IP | `ip`, `mac` |
| `file.disk.low` | warning / critical | free space of the data root below `disk_warn_percent` / `disk_critical_percent` (once per crossing) | `free_bytes`, `free_percent` |
| `file.soft_quota.warning` | warning | a share crossed `warn_percent` of its soft quota | `share`, `used_bytes`, `size_bytes` |
| `file.soft_quota.exceeded` | warning | a share is over its soft quota (`locked: true` if it was switched to read-only) | `share`, `used_bytes`, `size_bytes`, `locked` |
| `file.idmap.rid_limit` | warning | the domain's RID high-water mark crossed 90 % of the rid range (once) | `next_rid`, `max_rid` |
| `file.snapshot.failed` | warning | a scheduled snapshot failed | `share`, `error` |
| `file.snapshot.skipped` | warning | a snapshot was skipped for lack of space | `share`, `free_percent` |

Buffered and retried for up to one hour like the other apps.

## Setup

States: `unconfigured` | `joining` | `ready` | `failed`.

### `GET /api/setup`

```json
{
  "state": "unconfigured",
  "error": "",
  "started_at": 0,
  "finished_at": 0,
  "log": [],
  "defaults": {
    "hostname": "files",
    "ip": "192.168.1.20",
    "ip_source": "probe",
    "interface": "eth0",
    "subnet": "192.168.1.0/24",
    "host_ips": ["192.168.1.10"]
  },
  "storage": {
    "path": "/srv/files",
    "fs_type": "zfs",
    "total_bytes": 536870912000,
    "free_bytes": 530000000000,
    "on_system_disk": false,
    "xattr": true,
    "hardlinks": true,
    "reflink": false,
    "problems": [],
    "warnings": []
  },
  "server": null
}
```

- `defaults.ip`: the suggested server address. `PK95FILE_DEFAULT_IP` if set (the operator's value from Core's `.env`);
  otherwise the app tries the next up to 10 addresses after the LXC's own `eth0` address (skipping `host_ips`, network and
  broadcast) and suggests the first that passes `arping -D`. Empty if none is free. `defaults.ip_source`: `env` |
  `probe` | `""`.
- `defaults.interface`/`subnet`: interface and subnet of the default route; the server IP must lie in that subnet.
  `host_ips`: addresses the LXC already has. For `ip_mode: managed` the wizard does not offer them; for
  `ip_mode: existing` it offers only them (minus the DC's address).
- `storage`: preflight of the data root (`docs/design.md` §6). `problems` (German) block setup; `warnings` do not.
- `server` after setup: `{"hostname", "fqdn", "netbios_name", "ip", "realm", "workgroup", "dc"}`.

### `GET /api/setup/ip-check?ip=192.168.1.20`

`200 {"ip": "192.168.1.20", "ok": false, "message": "Die Adresse 192.168.1.20 ist im Netz bereits vergeben (MAC bc:24:11:…)."}`.
Checks for `ip_mode: managed`: valid IPv4, inside `subnet`, not the network or broadcast address, not one of
`host_ips`, no answer to `arping -D` (2 s). With `&mode=existing`: the address is configured on an interface of the
LXC and is not the DC's address.

### `POST /api/setup`

```json
{
  "hostname": "files",
  "ip": "192.168.1.20",
  "ip_mode": "managed",
  "realm": "ad.example.com",
  "workgroup": "EXAMPLE",
  "dc": { "hostname": "dc1", "ip": "192.168.1.10" },
  "odj": "<base64 of the ODJ provisioning file>",
  "allow_system_disk": false
}
```

Fallback join instead of `odj` (open decision 2): `"join_user": "Administrator", "join_password": "…"` (neither
stored nor logged).

→ `202 {"state": "joining"}`, then poll `GET /api/setup` (about 10–30 s). `409` while `joining` or when `ready`. After
`failed` a new `POST` starts over (secrets, caches and the generated smb.conf are removed first; the data root is never
touched).

| field | rule |
|---|---|
| `hostname` | 1–15 chars `a-z0-9-`, no leading/trailing hyphen, not only digits, lowercase (normalised); must differ from `dc.hostname` and `workgroup` |
| `ip` | IPv4 chosen by the user; prefix and interface come from `defaults.interface`/`subnet`. `managed`: as in `ip-check` („Die Adresse liegt nicht im Netz 192.168.1.0/24.“). `existing`: must already be configured on an interface of the LXC („Die Adresse 192.168.1.20 ist im LXC nicht vorhanden.“) |
| `ip_mode` | `managed` (default: the app adds the address to `eth0` after a DAD check and removes it on stop) \| `existing` (the operator configured it in Proxmox, e.g. `net1`; the app only binds to it) |
| `realm`, `workgroup` | as in PK95 AD; Core copies them from `GET ad:/api/domain` |
| `dc` | the DC's short hostname and IPv4 (written to `/etc/hosts` and `krb5.conf` as a fallback to DNS) |
| `odj` | base64, at most 64 KiB; must decode to an ODJ provisioning file for `realm` and `hostname` („Die Beitrittsdaten gehören zu einem anderen Computer.“) |
| `allow_system_disk` | must be `true` if `storage.on_system_disk` (otherwise `422` on `allow_system_disk`) |

Steps (each appears in `log`): preflight, IP check, add the IP to the interface (`managed` only), write `smb.conf`/`krb5.conf`/
`resolv.conf`, `net offlinejoin requestodj`, start winbindd, `wbinfo -t`, `wbinfo -P`, resolve
`Domain Users` to a Unix ID (rid: 10513), read the RID high-water mark, grant Domain Admins `SeDiskOperatorPrivilege`, create `shares/` and `.pk95/`, start smbd, check 445 on the IP, send `file.setup.done`.

### `POST /api/join`

Rejoin with a new blob after a broken trust or a restore: `{"odj": "…"}` (or the fallback credentials). Stops
smbd/winbindd, replaces `secrets.tdb`, starts both, checks the trust. `202`, progress in `GET /api/setup`
(`state: "joining"`). Only allowed after a previous successful setup.

## Status and dashboard

### `GET /api/status`

```json
{
  "version": "1.0.0",
  "core_mode": true,
  "state": "ready",
  "started_at": 1764090000000,
  "smbd":     { "state": "running", "pid": 52, "since": 1764090003000, "restarts": 0, "last_exit": "" },
  "winbindd": { "state": "running", "pid": 48, "since": 1764090002000, "restarts": 0, "last_exit": "" },
  "trust": { "ok": true, "checked_at": 1764093600000, "message": "" },
  "ip": { "address": "192.168.1.20", "mode": "managed", "interface": "eth0", "present": true, "conflict": false },
  "idmap": { "backend": "rid", "range": [10000, 64999], "max_rid": 54999, "next_rid": 1650,
             "percent": 3, "checked_at": 1764093600000, "warning": "" },
  "server": { "hostname": "files", "fqdn": "files.ad.example.com", "realm": "ad.example.com",
              "workgroup": "EXAMPLE", "dc": "dc1.ad.example.com" }
}
```

`state` of `smbd`/`winbindd`: `stopped`, `starting`, `running`, `restarting` (backoff 5 s … 5 min), `backup`.

`idmap`: the domain range maps RID *r* to Unix ID `10000 + r`, so RIDs above `max_rid` (54999) get no Unix ID and those
accounts cannot open shares. `next_rid` is the domain's RID high-water mark (`rIDNextRID` of the DC's RID set read
with the machine account, fallback: the highest RID of all users, groups and computers), checked every hour. From
90 % `warning` says „Die Domäne hat RID 49 800 erreicht. Ab RID 55 000 können neue Konten keine Freigaben mehr öffnen.“
and the dashboard shows it.

### `GET /api/dashboard`

Everything the `server` page shows, in one call (cheap: the values come from the last scan and smbstatus).

```json
{
  "shares": 6,
  "storage": { "total_bytes": 536870912000, "used_bytes": 214748364800, "free_bytes": 322122547200,
               "free_percent": 60, "share_bytes": 158913789952, "snapshot_bytes": 53687091200, "recycle_bytes": 2147483648,
               "scanned_at": 1764093600000 },
  "sessions": 4,
  "open_files": 11,
  "snapshots": { "last_run_at": 1764082800000, "last_ok": true, "next_run_at": 1764100800000,
                 "failed_shares": [], "count": 214 },
  "warnings": [
    { "level": "warning", "code": "soft_quota", "message": "Freigabe „Projekte“: 93 % des Kontingents belegt." }
  ]
}
```

`storage` leads the page: a bar of the data root split into `share_bytes` (live data), `snapshot_bytes` and
`recycle_bytes` plus free space, because on the 50 GB mount point the snapshots are the largest consumer.
`snapshot_bytes`/`recycle_bytes` come from the last scan; `free_bytes` is live (`statvfs`). From `disk_warn_percent`
(20 %) the bar turns orange and `warnings` has a `disk` entry, from `disk_critical_percent` (10 %) red.

`warnings[].code`: `trust`, `smbd`, `ip`, `disk`, `system_disk`, `soft_quota`, `snapshot`, `idmap` (RID high-water
mark near the limit, see `GET /api/status` → `idmap`), `permissions` (a share references a SID that no longer exists).

## Shares

### Share object

```json
{
  "name": "Buchhaltung",
  "description": "Rechnungen und Belege",
  "enabled": true,
  "hidden": false,
  "path": "shares/Buchhaltung",
  "unc": "\\\\files.ad.example.com\\Buchhaltung",
  "unc_short": "\\\\FILES\\Buchhaltung",
  "permissions": [
    { "sid": "S-1-5-21-…-1107", "name": "EXAMPLE\\Buchhaltung", "type": "group", "access": "change" },
    { "sid": "S-1-5-21-…-1110", "name": "EXAMPLE\\Geschäftsführung", "type": "group", "access": "read" }
  ],
  "fixed_permissions": [
    { "sid": "S-1-5-21-…-512", "name": "EXAMPLE\\Domain Admins", "type": "group", "access": "full" },
    { "sid": "S-1-5-18", "name": "NT AUTHORITY\\SYSTEM", "type": "well_known", "access": "full" }
  ],
  "abe": true,
  "recycle": { "enabled": true, "keep_days": 30, "max_file_mb": 0, "exclude": ["*.tmp", "~$*", "*.~*"] },
  "snapshots": {
    "enabled": true,
    "schedule": { "times": ["07:00", "12:00", "17:00"], "weekdays": [1, 2, 3, 4, 5] },
    "keep": { "recent": 12, "daily": 14, "weekly": 8 },
    "estimate_bytes": 62914560000
  },
  "soft_quota": { "size_bytes": 107374182400, "warn_percent": 90, "lock_when_exceeded": false },
  "usage": { "bytes": 52428800000, "files": 81234, "recycle_bytes": 104857600, "snapshot_bytes": 10737418240,
             "scanned_at": 1764093600000 },
  "status": "ok",
  "created_at": 1764090000000
}
```

- `hidden`: derived from the name (ends with `$`); hidden shares are not listed in Explorer but can be mapped.
- `permissions[].access`: `read` | `change` | `full`. `type`: `group` | `user` (resolved by winbind).
  `name` is empty and `unresolved: true` when the SID no longer exists in AD (deleted group); shown as a warning.
- `abe`: `hide unreadable` on the share (default `true`). The share list is always filtered (`access based share enum`).
- `soft_quota` („Kontingent (Warnung)“): a warning threshold, **not a hard limit** (`docs/design.md` §8). `size_bytes`
  `0` = none. Explorer shows `size_bytes` as the size of the share (dfree). With `lock_when_exceeded` the share becomes
  read-only once a scan finds it over the size; until then usage can overshoot.
- `snapshots.estimate_bytes`: rough extra space the snapshots will take (share size + changed files over the
  retention), for the UI text „Vorgängerversionen brauchen etwa das Doppelte an Platz“.
- `status`: `ok` | `soft_quota_warning` | `soft_quota_exceeded` | `locked` | `disabled`.
- `usage` comes from the last scan (`scanned_at`); `snapshot_bytes` counts the data only snapshots hold (files not
  shared by hardlink with another snapshot), estimated from link counts.

### Routes

| Route | Body | Answer |
|---|---|---|
| `GET /api/shares` | – | `200 {"items": [share…], "total": 6}` |
| `GET /api/shares/{name}` | – | `200` share |
| `POST /api/shares` | share fields (below) | `201` share |
| `PUT /api/shares/{name}` | any writable field except `name`, `permissions`, `adopt` | `200` share |
| `PUT /api/shares/{name}/permissions` | `{"permissions": [...], "propagate": false}` | `200` share, or `202` job when `propagate` |
| `DELETE /api/shares/{name}?delete_data=0` | – | `204`, or `202` job with `delete_data=1` |

Writable fields: `name` (create only), `description`, `enabled`, `permissions` (on create; afterwards through
`/permissions`), `abe`, `recycle`, `snapshots` (without `estimate_bytes`), `soft_quota`, `adopt` (create only).

| field | rule |
|---|---|
| `name` | 1–80 chars; not `global`, `homes`, `printers`, `ipc$`, `print$`, `home$`, `redirect$` (reserved); not `.` or `..`; none of `\ / [ ] : \| < > + = ; , * ? "` and no control characters; may end with `$`; unique case-insensitively („Eine Freigabe mit diesem Namen gibt es bereits.“) |
| `description` | at most 256 chars |
| `permissions` | 0–50 entries, each `{"sid" or "name", "access"}`; must resolve through winbind („Unbekannte Gruppe oder unbekannter Benutzer.“); no duplicates; the fixed entries are not allowed here |
| `adopt` | when the folder `shares/<name>` already exists (data left from a deleted share): `true` takes it over with its ACLs, otherwise `422` on `name` („Der Ordner existiert bereits. Übernehmen?“) |
| `recycle.keep_days` | 1–365 |
| `recycle.max_file_mb` | 0 (no limit) – 102400 |
| `recycle.exclude` | up to 20 patterns, each at most 64 chars, no `/` |
| `snapshots.schedule.times` | 1–24 entries `HH:MM`, unique |
| `snapshots.schedule.weekdays` | 1–7 entries of 1 (Mon) … 7 (Sun) |
| `snapshots.keep.recent` | 1–100 |
| `snapshots.keep.daily` / `.weekly` | 0–365 / 0–104 |
| `soft_quota.size_bytes` | 0 or at least 1 GiB |
| `soft_quota.warn_percent` | 50–99 |

`DELETE` without `delete_data` removes the share from `smb.conf` and its schedules; the folder, its recycle bin and its
snapshots stay (listed under `GET /api/orphans`; a new share of the same name can adopt them). `delete_data=1`
deletes the folder, recycle bin and snapshots as a job (Core asks the user to type the share name first).

`PUT /api/shares/{name}/permissions` rewrites the root ACL at once (`200`). With `"propagate": true` it also
starts a job that recomputes the inherited ACEs below the root and keeps explicit ones (`202`, job kind
`permissions`). While that job runs, another permissions change on the same share returns `409`.

### `GET /api/orphans`

`200 {"items": [{"name": "Alt", "bytes": 1073741824, "snapshots": 12, "modified_at": …}]}`: folders below `shares/`
that belong to no share. `DELETE /api/orphans/{name}` → `202` job.

## Snapshots

| Route | Body | Answer |
|---|---|---|
| `GET /api/shares/{name}/snapshots` | – | `200 {"items": [snapshot…], "backend": "rsync"}` |
| `POST /api/shares/{name}/snapshots` | – | `202` job (kind `snapshot`); `409` while one runs for this share |
| `DELETE /api/shares/{name}/snapshots/{id}` | – | `202` job (kind `snapshot_delete`) |
| `GET /api/shares/{name}/snapshots/{id}/files?path=Ordner/Unterordner` | – | `200 {"items": [{"name", "type", "size", "modified_at"}]}` (optional, for restoring in Core) |
| `POST /api/shares/{name}/snapshots/{id}/restore` | `{"path": "Ordner/Datei.xlsx", "mode": "copy"}` | `202` job (optional) |

Snapshot object:

```json
{ "id": "@GMT-2026.11.25-11.00.00", "created_at": 1764068400000, "manual": false,
  "files": 81201, "unique_bytes": 734003200, "duration_ms": 48211, "kept_by": ["recent", "daily"] }
```

- `restore.mode`: `copy` restores next to the original as `<Name> (Wiederhergestellt 25.11.2026 12-00)`;
  `overwrite` replaces the current file or folder (the replaced version goes to the recycle bin). `path` is relative to
  the share root, without `..`.
- Users restore themselves in Explorer (Eigenschaften → Vorgängerversionen); the API restore is for admins.
- `backend: "zfs-host"` (later): list only; `POST` and `DELETE` answer `409` („Snapshots werden auf dem Proxmox-Host
  verwaltet.“).

## Recycle bin

| Route | Body | Answer |
|---|---|---|
| `GET /api/shares/{name}/recycle?user=&search=&offset=0&limit=100` | – | `200 {"items": [{"path": "max.muster/Ordner/Datei.docx", "user": "max.muster", "size", "deleted_at"}], "total", "bytes"}` |
| `POST /api/shares/{name}/recycle/restore` | `{"paths": ["max.muster/Ordner/Datei.docx"]}` | `202` job; restores to the original place, with the suffix ` (Wiederhergestellt)` if the name is taken again |
| `POST /api/shares/{name}/recycle/empty` | `{"older_than_days": 0}` | `202` job |

`deleted_at` is the mtime set by `recycle:touch_mtime`. The daily retention run (in Core's maintenance window, 03:30
local time) deletes entries older than `recycle.keep_days`.

## Sessions and open files

From `smbstatus --json` (Samba 4.22), refreshed per request (at most once every 2 s).

### `GET /api/sessions`

```json
{
  "items": [
    { "id": "3121", "pid": 4711, "user": "EXAMPLE\\max.muster", "machine": "192.168.1.112",
      "hostname": "PC-01", "protocol": "SMB3_11", "encrypted": false, "signed": true,
      "connected_at": 1764090100000, "shares": ["Buchhaltung", "Projekte"], "open_files": 3 }
  ],
  "total": 1
}
```

`DELETE /api/sessions/{id}` → `204`: disconnects the session (ends its smbd process); open files of that client are
closed without saving. Windows reconnects on the next access.

### `GET /api/open-files?share=`

```json
{
  "items": [
    { "share": "Buchhaltung", "path": "2026/Rechnungen.xlsx", "user": "EXAMPLE\\max.muster",
      "session_id": "3121", "mode": "write", "oplock": "batch", "opened_at": 1764090200000 }
  ],
  "total": 1
}
```

Samba cannot close a single file (no `NetFileClose`); the UI offers "Sitzung trennen" instead.

## Usage

### `GET /api/usage`

```json
{
  "filesystem": { "path": "/srv/files", "fs_type": "zfs", "total_bytes": 536870912000,
                  "free_bytes": 322122547200, "on_system_disk": false },
  "shares": [
    { "name": "Buchhaltung", "bytes": 52428800000, "files": 81234, "recycle_bytes": 104857600,
      "snapshot_bytes": 10737418240, "soft_quota_bytes": 107374182400, "percent": 49 }
  ],
  "scanned_at": 1764093600000,
  "next_scan_at": 1764097200000
}
```

### `GET /api/shares/{name}/usage/owners`

Usage per file owner (Unix UID → AD name) from the last scan: `200 {"items": [{"sid", "name", "bytes", "files"}]}`.
Report only; per-user limits cannot be enforced (`docs/design.md` §8).

### `POST /api/usage/scan`

→ `202` job (kind `scan`); `409` while a scan runs.

## Jobs

`GET /api/jobs?kind=&state=` → `200 {"items": [job…]}` (the last 100). `GET /api/jobs/{id}` →

```json
{ "id": "a1b2c3", "kind": "snapshot", "share": "Buchhaltung", "state": "running",
  "progress": { "done": 41200, "total": 81234, "unit": "files" },
  "started_at": 1764090000000, "finished_at": 0, "error": "" }
```

`kind`: `permissions`, `snapshot`, `snapshot_delete`, `restore`, `recycle_restore`, `recycle_empty`, `scan`,
`delete_share`, `delete_orphan`. `state`: `queued`, `running`, `done`, `failed`. Jobs on the same share run one after
another; snapshots run one share at a time.

## Settings

### `GET /api/settings` / `PUT /api/settings`

```json
{
  "scan_interval_minutes": 60,
  "disk_warn_percent": 20,
  "disk_critical_percent": 10,
  "snapshot_min_free_percent": 15,
  "smb_encryption": "if_required",
  "min_protocol": "SMB2_10"
}
```

| field | rule |
|---|---|
| `scan_interval_minutes` | 15–1440 |
| `disk_warn_percent` / `disk_critical_percent` | 1–50, warn > critical (thresholds for free space) |
| `snapshot_min_free_percent` | 5–50 |
| `smb_encryption` | `if_required` \| `desired` \| `required` (`server smb encrypt`) |
| `min_protocol` | `SMB2_10` \| `SMB3_00` \| `SMB3_11` |

Changing a setting rewrites `smb.conf` and reloads smbd (`smbcontrol smbd reload-config`); sessions stay.

## Needed from PK95 AD (proposed contract)

No Unix ID changes are needed in PK95 AD: the file server uses the `rid` backend (`docs/design.md` §5).

### 1. `POST /api/computers/odj` (new, depends on the ODJ spike)

Creates (or resets) a computer account and returns an offline-join provisioning blob. No admin password involved:
PK95 AD writes the account in-process as system and composes the blob with `net offlinejoin composeodj`.

```json
{
  "name": "files",
  "dns_hostname": "files.ad.example.com",
  "ou_id": "",
  "description": "PK95 File",
  "reset": false
}
```

| field | rule |
|---|---|
| `name` | 1–15 chars `a-z0-9-`, like `hostname` in setup; the account is `FILES$` |
| `dns_hostname` | must be `<name>.<realm>` (other suffixes `422`) |
| `ou_id` | optional OU (`objectGUID`), default `CN=Computers` |
| `description` | optional, at most 1024 chars |
| `reset` | if the account exists: `false` → `409 {"error": "Das Computerkonto FILES gibt es bereits."}`; `true` → new random password (breaks the old join on purpose: rejoin) |

What the account gets: `objectClass computer`, `sAMAccountName FILES$`, `userAccountControl` 4096
(`WORKSTATION_TRUST_ACCOUNT`), a random 120-character password, `dNSHostName`, `servicePrincipalName`
(`HOST/files`, `HOST/files.ad.example.com`, `RestrictedKrbHost/files`, `RestrictedKrbHost/files.ad.example.com`),
`msDS-SupportedEncryptionTypes` 24 (AES), `description`. Refused (`403`) for domain controllers.

→ `200`, header `Cache-Control: no-store`:

```json
{
  "computer": { "id": "…", "name": "FILES", "dns_hostname": "files.ad.example.com" },
  "created": true,
  "odj": "<base64 of the provisioning file as written by net offlinejoin … savefile=>",
  "domain": { "realm": "ad.example.com", "netbios_domain": "EXAMPLE",
              "dc": { "hostname": "dc1", "ip": "192.168.1.10" } }
}
```

(`computer` is the normal computer details object.) PK95 AD never logs or stores the blob or the password. If the
account was created but composing failed, the account is deleted again (no half-created state).

### 2. Group list with SIDs (small change) and existing routes

- `GET /api/groups` list items need `sid` (today only the details have it) – the permission picker stores SIDs.
- `GET /api/domain` (realm, NetBIOS domain, DC name and IP) – exists.
- `POST /api/dns/zones/{zone}/records` (A record `files` → server IP) – exists.
- `DELETE /api/computers/{id}` when the app is removed – exists.
- Later: `homeDirectory`/`homeDrive` on users, Folder Redirection as a curated GPO setting.

## Needed from PK95 Core (proposed)

- Catalog `catalog/file.yaml`:

```yaml
id: file
name: PK95 File
summary: Dateiserver (Samba) in der PK95-AD-Domäne mit Freigaben, Berechtigungen über AD-Gruppen, Papierkorb, Vorgängerversionen und Kontingent-Warnungen. Braucht eine eigene IP-Adresse im LAN und einen Proxmox-Mountpoint unter /srv/pk95/files.
image: ghcr.io/philippkuhlmann/pk95-file
tag: latest
port: 8445
icon: box
module: file
health: /core/health
network_mode: host
cap_add: [NET_ADMIN, NET_RAW]     # secondary IP on eth0, arping (DAD, gratuitous ARP)
volumes:
  - name: samba
    target: /var/lib/samba
  - name: config
    target: /etc/samba
  - name: data
    target: /var/lib/pk95file
binds:
  - source: /srv/pk95/files
    target: /srv/files
    create: true
env:
  PK95FILE_LISTEN: 0.0.0.0:8445
  PK95FILE_DATA_DIR: /var/lib/pk95file
  PK95FILE_DATA_ROOT: /srv/files
  # PK95FILE_DEFAULT_IP comes from Core's .env when the operator sets it (no LAN address in any repository)
```

- Module `file`: a setup wizard on the `server` page that requires PK95 AD in state `ready`, runs the flow in
  `docs/design.md` §4 (domain data → ODJ blob → A record → `POST /api/setup`) and never stores the blob; the shares
  page with a group picker fed from PK95 AD; a "Laufwerk zuordnen" shortcut that pre-fills a PK95 AD drive map with
  the share's `unc`.
- Server IP at runtime only (PK95 Core is public too, so neither its catalog nor lxc-setup.md contains a real address):
  - the wizard shows `GET file:/api/setup` → `defaults.ip` (operator value or the app's DAD-checked suggestion next to
    the LXC address), the user confirms or changes it, `GET /api/setup/ip-check` validates it before `POST /api/setup`;
  - optional operator default: `PK95FILE_DEFAULT_IP` in Core's `.env`, passed into the container's environment
    (e.g. as a Core setting referenced by the catalog, `"{setting:file_default_ip|}"`; empty = not set).
- `docs/lxc-setup.md`: mount point `mp0` at `/srv/pk95/files` with `backup=1`, a server IP outside the DHCP pool,
  the Proxmox IP filter note – all with example values (192.168.1.x).
