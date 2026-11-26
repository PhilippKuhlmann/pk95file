# PK95 File – Design

Status: **agreed with the master session on 2026-11-25** (section 11 records the decisions). Server IP and
the 50 GB ZFS mount point are decided and live on the target LXC. Still open: whether ODJ works (CI spike, section 4).

## 1. Goal

A Windows file server for the PK95 LXC: a Samba **domain member** (Samba 4.22, Debian trixie) in the PK95 AD
domain (`ad.example.com`, NetBIOS `EXAMPLE`), running as a Docker container that PK95 Core starts and
manages through the Core module `file` over the JSON API in `docs/api.md`.

v1 scope:

- Shares with permissions through AD groups (read / change / full).
- Access-based enumeration: users see only the shares and folders they can open.
- Recycle bin per share (`vfs_recycle`) with retention.
- Previous versions (`shadow_copy2`) from scheduled snapshots with retention.
- Soft quota per share („Kontingent (Warnung)“, section 8), never a hard limit. Per user: usage report only.
- UNC paths usable as targets of PK95 AD's drive-map GPP.
- Backup capability, events and dashboard figures for Core.

Planned now, built later: home drives per user and folder redirection (section 10).

Not in scope: being a DC, NFS, printers, clustering (CTDB), DFS namespaces, an own web UI.

App id **`file`** (repo `pk95file`, image `ghcr.io/philippkuhlmann/pk95-file`, Python package `pk95file`),
named the same way as `pk95ad` → `ad` → `pk95-ad`.

## 2. Structure (same as PK95 AD)

- Python 3 (stdlib only: `http.server`, `threading`, `json`) plus `python3-samba` for NT ACLs
  (`samba.ntacls`, `security.descriptor`). External tools where Samba has no binding:
  `net`, `wbinfo`, `smbstatus --json`, `smbcontrol`, `rsync`, `ip`, `arping`.
- Processes: `tini` (PID 1) → `python3 -m pk95file` → children `winbindd --foreground` and
  `smbd --foreground --no-process-group`, supervised with restart backoff the way PK95 AD supervises `samba`.
  Threads in the API process: HTTP server, monitor (every 30 s), scheduler (snapshots, retention, usage scans),
  event sender (buffers events for up to 1 h, like the other apps).
- API conventions from PK95 AD: JSON, Unix milliseconds, `422 {"error", "fields"}`, German messages, Bearer
  token compared with `hmac.compare_digest`, `409` while not set up.
- Repository layout: `pk95file/` (package), `tests/` (unit, no Samba), `tests/integration/run.py`
  (end-to-end), `catalog/file.yaml`, `Dockerfile`, `docker-compose.yml` (standalone), `.github/workflows/image.yml`.
- CI as in pk95ad: pyflakes + unit tests; integration under Docker `userns-remap` (65536 IDs, no
  `CAP_SYS_ADMIN`); image only after both pass; `latest` only from tag `v*`; amd64 + arm64.
  The integration job also starts the published `pk95-ad` image as DC (section 12).

## 3. Network and port 445

### Facts

- PK95 AD runs with `network_mode: host`, `interfaces = lo 192.168.1.10`, `bind interfaces only = yes`
  (`pk95ad/smbconf.py`). So the DC holds **445/139 on 192.168.1.10 and 127.0.0.1 only**, not on `0.0.0.0`.
  Another address in the same network namespace is free for a second smbd.
- Core starts apps only as containers on its own Docker host, with `network_mode` `bridge` or `host`.
  The catalog has no notion of macvlan/ipvlan networks or per-container LAN addresses.

### Options

| Option | Works in the unprivileged LXC? | Core changes | Verdict |
|---|---|---|---|
| **A. Second IP on the LXC's `eth0`, app in host network, smbd bound to that IP only** | Yes: root in the LXC has `CAP_NET_ADMIN` in its own netns, so `ip addr add` on `eth0` is allowed. The MAC stays the same, so Proxmox's MAC filter is not involved. | Only a catalog entry (`network_mode: host`, `cap_add: [NET_ADMIN, NET_RAW]`, as PK95 Proxy already has) | **Recommended** |
| B. Docker ipvlan L2 / macvlan network with its own LAN IP | Unconfirmed. Reports of Docker in an unprivileged LXC with ipvlan are mixed (runc sysctl problems); macvlan is broken by Proxmox's firewall MAC filter. An ipvlan/macvlan child **cannot reach its parent's IP**, and the DC *is* the parent's IP (192.168.1.10), so the container would need a second bridge network plus a host route just to talk to its own DC. | New catalog type (driver, parent, subnet, gateway, IP from the setup), attaching two networks, IP as a setup parameter | Rejected for v1 |
| C. Second LXC or VM | Works, but Core cannot start or manage it | Core would need a remote Docker host | Out of scope |
| D. Shares on the DC | Works; Samba advises against it (DC idmap, ABE and recycle bin on the DC's smbd) | AD would host the shares | Emergency only |

### Option A in detail

- Setup parameter `ip` (IPv4 in the LXC's subnet). The real address only ever comes in at runtime – no repository
  (this one, PK95 Core, PK95 AD; all public) contains it:
  - the user enters it in Core's setup wizard, which pre-fills `GET /api/setup` → `defaults.ip`;
  - `defaults.ip` is `PK95FILE_DEFAULT_IP` if the operator set it (in Core's `.env`, handed to the container), otherwise
    the app's own suggestion: the next addresses after the LXC's `eth0` address, the first one that passes the DAD check.
  The prefix and interface are taken from `eth0` (the interface of the route to the DC), not entered.
- Two modes (`ip_mode`):
  - `managed` (default): before first use the app checks the address with `arping -D` (duplicate address
    detection) and refuses a taken one („Die Adresse 192.168.1.20 ist im Netz bereits vergeben.“). On every start it
    runs `ip addr replace 192.168.1.20/24 dev eth0`, then sends gratuitous ARP (`arping -U -c 2`). The monitor adds
    the address again if it disappears and checks for conflicts. On a clean stop it removes it (`ip addr del`), so a
    stopped app leaves no orphan address.
  - `existing`: the operator configured the address in Proxmox (e.g. `net1` on the same bridge, which also shows it in
    the GUI and in the Proxmox IP filter). The app only checks that the address is present on an interface and binds
    to it. It never adds or removes it, and it skips the DAD check (the address is already ours). If the address is
    missing, smbd stays down with a German message („Die Adresse 192.168.1.20 ist im LXC nicht vorhanden.“).
- `smb.conf`: `interfaces = 192.168.1.20/24`, `bind interfaces only = yes`, `smb ports = 445`,
  `disable netbios = yes` (no nmbd: UDP 137/138 would collide with the DC's NBT server, and DNS is enough).
  smbd does not listen on 135 (RPC services run on demand over named pipes).
- winbindd talks to the DC (192.168.1.10) inside the same netns, so no routing tricks are needed.
- DNS: the container resolves through PK95 DNS on `127.0.0.1:53` (the realm is already forwarded to Samba on
  5300 for PK95 AD). The app rewrites `/etc/resolv.conf` the same way PK95 AD does (keeps the original lines as
  comments, and only once `127.0.0.1:53` answers the realm's SOA).
- Requirements on the operator, documented in `PK95Core/docs/lxc-setup.md`:
  the address must be outside the DHCP pool. If the Proxmox firewall's **IP filter** is on for `net0`, the
  address has to be added to the IP set `ipfilter-net0` (the MAC filter is no problem).
- In `managed` mode the address does not show in the Proxmox GUI. PK95 AD's `defaults.host_ips` will list it too
  (cosmetic; only used by AD's setup wizard).
- **The DC must not pick up the new address.** PK95 AD has `interfaces = lo 192.168.1.10` with `bind interfaces only`,
  so neither Samba's listeners nor `samba_dnsupdate` should see the new address. The integration test checks it: the DC's A records
  (`dc1`, `@`, `gc._msdcs` …) are identical before and after the second address appears, also after a forced
  `samba_dnsupdate` run.

### Name and DNS

- Default hostname `files` → `files.ad.example.com`, NetBIOS name `FILES` (1–15 chars, `a-z0-9-`).
- The computer account's `dNSHostName` and SPNs (`HOST/files`, `HOST/files.ad.example.com`,
  `RestrictedKrbHost/…`) come from the join (section 4). `cifs/…` is covered by `HOST/` through `sPNMappings`.
- The A record (and optionally the PTR) is created **by Core through PK95 AD's API**
  (`POST /api/dns/zones/ad.example.com/records`). The member cannot register itself: dynamic updates go
  to port 53, that is to PK95 DNS, which does not forward `UPDATE` (the same limit PK95 AD documents for clients).
  The app never calls `net ads dns register`.
- UNC paths for GPP drive maps: `\\files.ad.example.com\<share>` (preferred, Kerberos through the FQDN SPN).
  `\\FILES\<share>` works on domain clients through the DNS suffix search, not through NetBIOS.

## 4. Domain join

### Recommended: offline join (ODJ), no admin password through Core

Samba has `net offlinejoin` since 4.15. `net offlinejoin composeodj` came in 2023 (Samba 4.19 backport, written for
adcli/realmd). Debian trixie's Samba 4.22 has all three subcommands in **both** images (both ship the `net` tool).

- `provision` (DC side) needs network access and **admin credentials** (`-U`). PK95 AD deliberately stores
  no administrator password, so `provision` does not fit.
- `composeodj` builds the provisioning blob for an account **that already exists, from its known machine
  password and the domain data**, without contacting a DC. PK95 AD can create the computer account in-process
  (as system on `sam.ldb`, like everything else it does) with a random password, then call `composeodj`.
- `requestodj` (member side) consumes the blob, writes `secrets.tdb` and needs no credentials and no network.

Flow (orchestrated by the Core module; the file app never talks to PK95 AD directly):

1. Core: `GET ad:/api/domain` → realm, NetBIOS domain, DC name and IP.
2. Core: `POST ad:/api/computers/odj` `{"name": "files", "dns_hostname": "files.ad.example.com", …}` →
   blob (new AD endpoint, spec in `docs/api.md` → "Needed from PK95 AD").
3. Core: `POST ad:/api/dns/zones/ad.example.com/records` → A record `files` → 192.168.1.20.
4. Core: `POST file:/api/setup` with hostname, IP, realm, workgroup and the blob.
5. File app: `net offlinejoin requestodj loadfile=…` (blob from a `0600` temp file, deleted afterwards), start
   winbindd, check `wbinfo -t` (trust), `wbinfo -P` (netlogon), resolve a test group, start smbd.

The blob carries the machine password of the new account. That is not an admin secret, but it is a secret: AD sends it
with `Cache-Control: no-store`, Core never stores or logs it, and the file app deletes it after use.

Known Samba issue: `requestodj` fails with `kerberos method = secrets and keytab` (bug 15389). The member uses
the default `secrets only` (smbd decrypts tickets with the machine password from `secrets.tdb`; no keytab needed).

**Not verified yet.** The first build step is a spike in CI (`spike/odj/`): DC from
`ghcr.io/philippkuhlmann/pk95-ad:1.4.0`, a computer account created with a known password, `net offlinejoin composeodj`
in the DC container, `requestodj` in the member container, then Kerberos SMB access as a domain user. Its result decides
the AD endpoint. If `composeodj` cannot be fed from an account created that way, we use the fallback below.

### Fallback: one-time admin password

The setup form takes `join_user` / `join_password`. The app runs
`net ads join -U … --no-dns-updates dnshostname=… createcomputer=<OU>` with the password on stdin and never stores
or logs it. It passes through Core (HTTP inside the LXC). Acceptable, but ODJ is cleaner.

### Rejoin / repair

`POST /api/join` takes a new blob (AD resets the account password and composes again). This is needed after a broken
trust (`wbinfo -t` fails) and after restoring an old backup: winbindd rotates the machine password every
7 days (`machine password timeout`), so a backup older than the last rotation restores a stale `secrets.tdb`.

## 5. Unix IDs (idmap)

Decision: **`rid` backend**, no change on the DC.

```ini
idmap config * : backend = tdb
idmap config * : range = 3000-7999
idmap config EXAMPLE : backend = rid
idmap config EXAMPLE : range = 10000-64999
template shell = /bin/false
template homedir = /nonexistent
```

Why `rid` and not `ad` (RFC2307):

- PK95 AD sets no `uidNumber`/`gidNumber` (`pk95ad/idmap.py`). With `backend = ad` every user without them could not
  open any share, so AD would have to assign and backfill them, and with `idmap_ldb:use rfc2307 = yes` that would also
  change the DC's own mappings (risk for the SYSVOL ACLs). `rid` needs nothing from the DC.
- `rid` is deterministic: Unix ID = `10000 + RID`. Every future member server with the same range computes the same
  IDs without any shared state.
- There are no Linux or NFS clients that would need RFC2307 attributes.
- The range overlaps numerically with AD's 20000–59999. That does not matter: every container has its own filesystem,
  the file app's data is only ever touched by the file app, and PID namespaces keep the processes apart.

Details:

- **RID limit.** The range 10000–64999 maps RIDs 0–54999. A user, group or computer with a higher RID has no Unix ID
  on the member and cannot open shares. Samba allocates RIDs in pools of 500 per DC, starting around 1000; every
  object ever created consumes one, including deleted ones, and they are never reused. 55,000 is far beyond this
  domain, but it is a hard ceiling. The app reads the domain's RID high-water mark (`rIDNextRID` of the DC's RID set
  through `net ads search -P`, machine account; fallback: the highest RID of all users, groups and computers) every
  hour. `GET /api/status` → `idmap` reports it and warns from 90 % of the range
  („Die Domäne hat RID 49 800 erreicht. Ab RID 55 000 können neue Konten keine Freigaben mehr öffnen.“).
- `*` range 3000–7999 (the range in Samba's own member example): only BUILTIN and well-known SIDs (Everyone,
  Authenticated Users, SYSTEM, CREATOR OWNER, BUILTIN\Administrators …) land there, a few dozen IDs. It stays below
  the domain range and below 65536.
- No `username map` to root. `Administrator` (RID 500) is an ordinary domain user with Unix ID 10500; admins get their
  rights from the ACL (Domain Admins Full Control on every share root) and `SeDiskOperatorPrivilege`. Mapping
  Administrator to root was tried in the ODJ spike and refused by smbd with `NT_STATUS_INVALID_TOKEN`.
- With `acl_xattr:ignore system acls = yes` (section 9) the Unix IDs are only used for the process identity and file
  ownership, never for permission checks; those use the NT ACL with SIDs.

## 6. Storage

### Layout

The data root is a bind mount, not a Docker volume:

```
/srv/files/                       ← LXC: /srv/pk95/files (mp0 of the Proxmox container)
  shares/<Share>/                 ← share roots
  shares/<Share>/.recycle/        ← recycle bin (hidden, admin-only ACL)
  .pk95/snapshots/<Share>/@GMT-2026.11.25-12.00.00/
  .pk95/usage.json                ← last scan per share (read by the dfree script)
  homes/                          ← later (section 10)
  redirect/                       ← later
  .pxarexclude                    ← "/.pk95/snapshots" for Proxmox Backup
```

Why a bind mount:

- Core backs up **volumes** by stopping the container and tarring them. Hundreds of GB of user data do not belong
  in that backup, and binds are skipped by design (`app-protocol.md` §5). The data is backed up by Proxmox
  (vzdump/PBS of the container with `mp0,backup=1`; pxar keeps `user.*` xattrs, i.e. the NT ACLs, and hardlinks).
- The 32 GB root disk cannot hold file server data plus snapshots.

Catalog: `binds: [{source: /srv/pk95/files, target: /srv/files, create: true}]`. The path is fixed in the catalog
(Core only allows binds below `/srv/pk95`). It is configurable on the Proxmox side instead: the operator mounts any
storage there (`pct set <id> -mp0 <storage>:<size>,mp=/srv/pk95/files,backup=1`). Making the source a Core setting
would need `{setting:…}` support in `binds`, which is not needed.

Volumes (backed up by Core): `samba` → `/var/lib/samba` (`secrets.tdb` with the machine password, winbindd caches,
the `*` idmap tdb), `config` → `/etc/samba` (generated), `data` → `/var/lib/pk95file` (settings, shares, schedules,
state, setup log).

### The live mount point

`/srv/pk95/files` on the target LXC is a ZFS subvol mount point (`rpool/data/subvol-<vmid>-disk-1`, mp0, `backup=1`): ZFS, `xattr,posixacl`,
**50 GB**, owner root; `user.*` xattrs and hardlinks work (checked on 2026-11-25).
With rsync snapshots (at least 2× the data, section 7) that holds roughly **20–25 GB of share data**. So the
dashboard shows free space and snapshot usage prominently, and the disk warning starts early: warning below 20 %
free, critical below 10 % (settings `disk_warn_percent` / `disk_critical_percent`); snapshots are skipped below
`snapshot_min_free_percent` (15 %). The mount point can be grown in Proxmox later (`pct resize`) without changes here.

### Setup checks (preflight, also shown in `GET /api/setup`)

| Check | On failure |
|---|---|
| `/srv/files` writable as root | error |
| `user.*` xattr write/read (`user.NTACL` test) | error („Das Dateisystem unterstützt keine user.*-Attribute.“) |
| filesystem type (`/proc/self/mountinfo`): zfs, ext4, xfs, btrfs | error for other types (overlay, nfs, cifs, tmpfs) |
| same filesystem as the `data` volume (`st_dev`) → the data would sit on the LXC root disk | error unless `allow_system_disk: true` („Die Daten lägen auf der Systemplatte des LXC. Bitte in Proxmox einen eigenen Mountpoint unter /srv/pk95/files einhängen.“). A Proxmox mount point is its own ZFS subvol with its own `st_dev`, so it passes. |
| free space ≥ 5 GB and ≥ 20 % | warning |
| hardlinks between directories (snapshots need them) | error |
| `FICLONE`/reflink support | info only (enables cheaper snapshots later, section 7) |

## 7. Snapshots ("Vorgängerversionen")

ZFS/btrfs snapshots cannot be taken inside the unprivileged LXC. Two backends, chosen per installation:

### v1 default: `rsync` hardlink snapshots

Per share and schedule: `rsync -aHAX --numeric-ids --delete --link-dest=<previous> shares/<S>/ .pk95/snapshots/<S>/@GMT-<UTC>.tmp/`,
then rename to `@GMT-YYYY.MM.DD-HH.MM.SS`. `shadow_copy2` presents them:

```ini
shadow:mountpoint = /srv/files/shares/<S>
shadow:snapdir = /srv/files/.pk95/snapshots/<S>
shadow:format = @GMT-%Y.%m.%d-%H.%M.%S
shadow:sort = desc
shadow:localtime = no
```

(Setting `shadow:mountpoint` to the share root makes shadow_copy2 treat each snapshot folder as an image of the share.
The integration test has to confirm this, together with the order of the VFS modules.)

Cost and limits:

- **The first snapshot of a share is a full copy.** Snapshots must not hardlink to the *live* files: smbd writes
  in place, which would change the "old" version too. Only snapshots hardlink among themselves. Plan for **at least
  2× the share's size**, plus the volume of changes over the retention period.
- **Changes cost whole files.** One changed byte in a 2 GB PST costs 2 GB for every snapshot that keeps that version.
- **Run time grows with the number of files**, not with the volume of changes: rsync stats every live file and every
  file of the previous snapshot. Rough guide: 1–3 min per 100,000 files on SSD, much more on HDD. Each snapshot adds one
  directory entry per file (200,000 files × 30 snapshots = 6 million entries), and deleting an old snapshot walks it again.
- **Not atomic.** Files written during the run end up in some intermediate state; open database files may be
  inconsistent in the snapshot. Good enough for documents, not for databases.
- Snapshots live on the same disk, so they do not replace a backup.
- Snapshots keep the NT ACLs (`-X` copies `user.NTACL`): users only see previous versions they were allowed to open.
- Before each run the scheduler checks free space (`snapshot_min_free_percent`, default 15 %) and skips the run with a
  warning event instead of filling the disk.
- The Core UI says so where snapshots are switched on: „Vorgängerversionen brauchen etwa das Doppelte an Platz:
  Die erste Version ist eine vollständige Kopie der Freigabe, danach kostet jede geänderte Datei ihre volle Größe.“
  `GET /api/shares/{name}` returns the estimate (`snapshots.estimate_bytes`) for that text.

Optimisation: if setup detects `FICLONE` (e.g. ZFS ≥ 2.2 with block cloning on, XFS, btrfs), changed files are
reflinked from the live share instead of copied, so the first snapshot and changed files are nearly free until they
diverge. This needs an own copy walker (`os.copy_file_range`/`FICLONE`), with rsync as the fallback. Not in v1.0.

### Later option: `zfs-host` snapshots

If `/srv/pk95/files` is a ZFS dataset, a timer **on the Proxmox host** (outside PK95) runs
`zfs snapshot <dataset>@GMT-…` and prunes the snapshots; `shadow_copy2` reads `.zfs/snapshot`. Atomic and practically
free. Limits: Core cannot set it up or see it (no host access), and whether `.zfs/snapshot` automounts inside the
unprivileged LXC must be tested on the real host. The backend interface (list / create / delete) is kept small so this
can be added as `snapshot_backend: zfs-host` (list only; create and delete disabled).

### Schedule and retention

Per share: times of day plus weekdays (default 07:00, 12:00, 17:00, Mon–Fri) and a retention of
`recent` (the last N snapshots), `daily` (one per day for N days) and `weekly` (one per week for N weeks), default
12 / 14 / 8. A snapshot is kept if any rule keeps it. Manual snapshots ("Jetzt erstellen") count as `recent`.
Snapshots run one share at a time (I/O).

## 8. Soft quota („Kontingent (Warnung)“)

Decision: a soft quota only. It is **never called a hard limit** – not in the UI, not in the API. German label
„Kontingent (Warnung)“; the API field is `soft_quota`, the events are `file.soft_quota.*`.

The unprivileged LXC has no quota syscalls (`quotactl` on the bind mount fails), and ZFS `refquota` can only be set
on the host. What can actually be enforced:

| Mechanism | Effect | Enforces? |
|---|---|---|
| `dfree command` per share (a script reads `.pk95/usage.json` and reports the quota as the disk size; `dfree cache time = 60`) | Explorer shows the share as a disk whose size is the quota and the rest as free. Explorer and most apps refuse a copy larger than "free" up front. | **No**, a soft limit: many small files, files growing in place, robocopy … get through |
| Usage scan (walk per share, every 60 min by default and after snapshots) | `usage.bytes`, warnings at `warn_percent`, events | No |
| Optional lock on overrun (`lock_when_exceeded`) | The share is switched to `read only = yes` (smb.conf reload) until usage drops or the quota is raised | Yes, but coarse: users cannot delete to get back under the limit either, and usage can overshoot by up to one scan interval |
| A separate Proxmox mount point per share with ZFS `refquota` on the host | Real hard limit | Yes, but outside Core |

v1 = `dfree` + scan + warning events, plus the per-share option `lock_when_exceeded` („Bei Überschreitung schreibgeschützt
schalten“), off by default; its help text states the overshoot of up to one scan interval. Per-user quotas cannot be
enforced at all; the scan reports usage per file owner (Unix UID → AD name) per share.

## 9. Shares, permissions, ABE, recycle bin

### Permissions model

The Core UI shows three levels per AD group (or user): **Lesen**, **Ändern**, **Vollzugriff**. They become the
NTFS-style ACL of the share root, inherited by everything below. Share-level permissions (`share_info.tdb`, written
with `sharesec`) give Domain Admins, SYSTEM and every principal of the share FULL, and nobody else: `access based
share enum` filters the share list by this descriptor, not by the folder ACL, so users without any permission do
not see the share. Read/change/full is still decided by the folder ACL alone.

Folders the app creates itself (share roots, `.recycle`, folders a restore recreates) get mode 0777: with
`acl_xattr:ignore system acls` smbd checks only the NT ACL, and the kernel would otherwise refuse what the ACL allows
(a root-owned 0755 share root lets nobody but root create files).

**Conscious decision (agreed 2026-11-26):** the NT ACL is the only access control on the share data. That is safe
because only the PK95 File container mounts `/srv/pk95/files`, and every access from outside goes through smbd. The
flip side, stated plainly: local processes inside the container or on the LXC (and the Proxmox host) bypass the NT
ACLs completely – they see 0777 folders and plain Unix files. Nothing else may mount or work on the data root; backups
(vzdump/PBS) read it as root anyway and keep `user.NTACL` as an xattr.

| Level | ACE on the share root (container + object inherit) |
|---|---|
| read | Read & Execute (`0x1200a9`) |
| change | Modify (`0x1301bf`) |
| full | Full Control (`0x1f01ff`) |
| always | `Domain Admins` Full, `SYSTEM` Full (cannot be removed; shown read-only) |

ACLs are stored in `user.NTACL` (`acl_xattr:security_acl_name = user.NTACL`, like PK95 AD) and written in-process
with `samba.ntacls.setntacl` (session from `samba.auth_util.system_session_unix()`, as `samba-tool ntacl set` does
in 4.22; without `service`, because the smbd module only knows `[global]` – the `acl_xattr` options live there). With `acl_xattr:ignore system acls = yes` there is no POSIX ACL mirror (that would need a
Unix ID for every group in an ACE); smbd checks only the NT ACL. Users with Full Control may set finer ACLs on
subfolders in Explorer; Core manages only the root.

Changing the root ACL does not touch existing files and folders by itself. `PUT …/permissions` with
`"propagate": true` starts a job that recomputes the inherited ACEs of everything below (explicit ACEs on subfolders
are kept). That is a full tree walk, shown as a job with progress.

Setup grants Domain Admins `SeDiskOperatorPrivilege` (`net sam rights grant`), so admins can also manage share ACLs
from Windows (Computer Management).

### smb.conf (generated on every start and every change)

```ini
[global]
    netbios name = FILES
    workgroup = EXAMPLE
    realm = AD.EXAMPLE.COM
    security = ads
    server role = member server
    interfaces = 192.168.1.20/24
    bind interfaces only = yes
    smb ports = 445
    disable netbios = yes
    server min protocol = SMB2_10
    kerberos method = secrets only
    winbind refresh tickets = yes
    winbind enum users = no
    winbind enum groups = no
    # idmap block from section 5
    vfs objects = acl_xattr
    acl_xattr:security_acl_name = user.NTACL
    acl_xattr:ignore system acls = yes
    map acl inherit = yes
    store dos attributes = yes
    access based share enum = yes
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes
    log level = 1

[Buchhaltung]
    path = /srv/files/shares/Buchhaltung
    read only = no
    hide unreadable = yes
    vfs objects = acl_xattr shadow_copy2 recycle
    # shadow:* from section 7
    recycle:repository = .recycle/%U
    recycle:keeptree = yes
    recycle:versions = yes
    recycle:touch_mtime = yes
    recycle:exclude = *.tmp ~$* *.~*
    recycle:exclude_dir = .recycle
    hide files = /.recycle/
    dfree command = /opt/pk95file/bin/dfree Buchhaltung
```

- ABE = `access based share enum` (share list) + `hide unreadable` (folders and files). `hide unreadable` costs an
  ACL check per entry in large folders, which is acceptable for typical office shares.
- `.recycle` gets an explicit ACL (Domain Admins plus the share's `full` groups, no inheritance from the root), so
  normal users cannot browse other people's deleted files; they use "Vorgängerversionen" instead. Admins restore in
  Explorer or through Core (`/api/shares/{name}/recycle/restore`).
- Retention: a daily job deletes recycle bin entries older than `keep_days` (`touch_mtime` sets the mtime to the time
  of deletion, so retention does not depend on atime). `max_file_mb` maps to `recycle:maxsize`.
- Hidden shares: names ending with `$`.

## 9a. macOS clients (1.1.0)

One server setting `macos` (default off), not per share: `vfs_fruit` negotiates the Apple SMB extension (AAPL) at
the first tree connect of a connection, so all shares must use the same chain. When on, every share runs
`fruit streams_xattr acl_xattr [shadow_copy2] [recycle]` with

- `fruit:metadata = stream` (Finder info and tags as a stream in a `user.DosStream.*` xattr),
- `fruit:resource = file` – resource forks stay AppleDouble files (`._*`, hidden from Macs by `veto_appledouble`);
  as streams they would be limited to the 64 KiB a Linux xattr can hold (ext4: one 4 KiB block) and fail silently,
- `fruit:nfs_aces = no` – the default would write POSIX modes as NFS ACEs into the ACLs and fight the NT ACLs,
- `posix_rename`, `wipe_intentionally_left_blank_rfork`, `delete_empty_adfiles`, `convert_adfile` (existing `._*`
  files written by Macs before become streams on access).

`streams_xattr` also keeps Windows alternate data streams (e.g. `Zone.Identifier`, the "Mark of the Web"), which were
dropped before. Streams live as xattrs on the inode: rsync `-X` copies them into snapshots, the recycle bin moves the
inode with them. `._*` and `.DS_Store` are always excluded from the recycle bin. Switching the setting rewrites
smb.conf and reloads smbd; connected Macs keep their negotiated behaviour until they reconnect (the API says so).

## 10. Later: home drives and folder redirection (planned, not built)

- `homes/` and `redirect/` under the data root are reserved now.
- Home drives: a share `Home$` → `/srv/files/homes`, root ACL "Domain Users: this folder only, list + create folder",
  CREATOR OWNER Full. The app creates `homes/<sAMAccountName>` with an ACL for that user (when Core asks it to, after
  creating a user in AD, or through a sync job over the AD users). PK95 AD then needs `homeDirectory`/`homeDrive` on
  users (`\\files.ad.example.com\Home$\%USERNAME%`, `H:`), a new user field there.
- Folder redirection: a share `Redirect$` with the ACL Microsoft recommends. The GPO setting lives in PK95 AD
  (Folder Redirection CSE, `fdeploy1.ini` in SYSVOL), a new curated setting there. `csc policy = manual` on the share.
- Quotas per home folder come from the same soft-quota scan.

## 11. Decisions (agreed with the master session, 2026-11-25)

1. **Network / 445: accepted.** Second IP on `eth0`, host network, smbd bound only to that IP, NetBIOS off,
   `cap_add: [NET_ADMIN, NET_RAW]`. The IP is a setup parameter (prefix from `eth0`) with a DAD check before use;
   `ip_mode: existing` for an address the operator configured in Proxmox (`net1`), which the app never adds or
   removes. Integration test: the DC's DNS records are unchanged after the second address appears.
   **Decided (user):** a fixed address outside the DHCP pool, entered at runtime (Core wizard, or `PK95FILE_DEFAULT_IP`
   in Core's `.env`); no repository contains it. Examples everywhere use 192.168.1.20.
2. **Join: accepted.** ODJ (`composeodj` on the AD side, `requestodj` on the member), `join_user`/`join_password` as a
   one-time fallback. CI spike first against `ghcr.io/philippkuhlmann/pk95-ad:1.4.0`; its result decides the AD endpoint.
3. **idmap: changed to `rid`.** `EXAMPLE` rid 10000–64999 (RIDs up to 54999), `*` tdb 3000–7999. No change on
   the DC. RID limit documented, warning in `/api/status` from 90 %. The AD change for `uidNumber`/`gidNumber` is
   dropped.
4. **Storage: accepted.** Bind mount `/srv/pk95/files` → `/srv/files`, preflight, rsync `--link-dest` snapshots in
   v1 with the cost stated in the UI („braucht etwa das Doppelte an Platz“), `.pxarexclude`.
   **Decided (user):** mp0 on ZFS (own subvol), 50 GB, `backup=1`, live. Warnings from 20 % free.
5. **Quotas: soft only.** „Kontingent (Warnung)“, API `soft_quota`, never presented as a hard limit; option
   `lock_when_exceeded`.
6. **Accepted as proposed:** app id `file`, image `ghcr.io/philippkuhlmann/pk95-file`, port 8445, ABE, recycle bin,
   sessions.

Contract with PK95 AD: `POST /api/computers/odj` (subject to the spike) and `sid` in the `GET /api/groups` list items.
Contract with PK95 Core: catalog entry, module `file`, lxc-setup.md notes (`docs/api.md` → "Needed from PK95 Core").

## 12. Tests

- Unit (no Samba): smb.conf rendering, share and permission validation, retention selection, soft-quota maths,
  RID-limit warning, smbstatus JSON parsing, SDDL building, HTTP layer, events.
- ODJ spike (`spike/odj/`, first): proves `composeodj` + `requestodj` between `pk95-ad:1.4.0` and a Debian trixie member.
- Integration (GitHub Actions, `userns-remap`): Docker network `pk95ci` (172.30.0.0/24); `pk95-ad:1.4.0` provisions
  `ci.example.test` on 172.30.0.10 (it runs in bridge mode with `host_ip` set); the file container gets its secondary
  IP 172.30.0.53 through its own IP management (`ip_mode: managed`, `NET_ADMIN`), a second run uses `ip_mode: existing`;
  the DC's DNS records are compared before and after; the ODJ blob comes from the DC container; a client container with
  `smbclient`/`kinit` checks read/change/full per group, ABE (`ls` hides what is not readable), the recycle bin, a
  snapshot visible as a previous version (`smbclient … -c allinfo`), the dfree size, `smbstatus` sessions, backup
  prepare/resume and rejoin. Real Windows clients and the live LXC: manual acceptance.
