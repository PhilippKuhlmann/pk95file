# ODJ spike

Answers one question before the build starts (`docs/design.md` §4): can PK95 AD join a Samba member **without an
admin password**, by creating the computer account in-process and composing an offline-join blob with
`net offlinejoin composeodj`, which the member consumes with `net offlinejoin requestodj`?

Already known from Samba 4.22's source (`source3/utils/net_offlinejoin.c`): `composeodj` needs realm, workgroup,
domain SID and GUID, forest name, DC name (`-S`) and address (`-I`), the machine account and its password, and it
contacts no DC. `printblob` prints base64 text; `savefile=` writes the UTF-16 file Windows uses. `requestodj` reads
either (`-i` from stdin, `loadfile=`).

What `run.sh` checks against `ghcr.io/philippkuhlmann/pk95-ad:1.4.0`:

1. DC provisioned through the PK95 AD API; test user `alice` in a group.
2. Computer account `FILES$` created in-process on `sam.ldb` as system (`create_account.py`, the planned AD endpoint).
3. `composeodj` with the password from `$PASSWD` (fallback `--password`), blob as text and as file.
4. Member adds its own secondary IP (arping DAD, `ip addr add`, gratuitous ARP; design option A).
5. `requestodj`, then `wbinfo -t`, `wbinfo -P`, `net ads testjoin`.
6. rid mapping (`10000 + RID`, Domain Users → 10513), NSS lookup.
7. smbd listens on the secondary IP only.
8. NTLM and Kerberos SMB access as `alice`; file owner on disk and `user.NTACL`.

Run: `bash spike/odj/run.sh` on a Docker host (Linux, or macOS with Colima/OrbStack), or the workflow
`.github/workflows/odj-spike.yml` (manual or on a `spike/**` branch). `KEEP=1` leaves the containers running for
inspection. Output ends with a PASS/FAIL/INFO list.

Not covered here: DNS through PK95 DNS (hosts entries and a fixed KDC instead), the unprivileged LXC, Windows clients.
