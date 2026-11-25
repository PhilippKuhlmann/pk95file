# ODJ spike

Answers one question before the build starts (`docs/design.md` §4): can PK95 AD join a Samba member **without an
admin password**, by creating the computer account in-process and composing an offline-join blob with
`net offlinejoin composeodj`, which the member consumes with `net offlinejoin requestodj`?

Already known from Samba 4.22's source (`source3/utils/net_offlinejoin.c`): `composeodj` needs realm, workgroup,
domain SID and GUID, forest name, DC name (`-S`) and address (`-I`), the machine account and its password, and it
contacts no DC. `printblob` prints base64 text; `savefile=` writes the UTF-16 file Windows uses. `requestodj` reads
either (`-i` from stdin, `loadfile=`).

What `run.sh` checks against `ghcr.io/philippkuhlmann/pk95-ad:1.5.0` (`AD_IMAGE` overrides it):

1. DC provisioned through the PK95 AD API; test user `alice` in a group.
2. The blob from PK95 AD's `POST /api/computers/odj` (1.5.0): `no-store`, not in the DC log, `409` on a second call.
   `ODJ_SOURCE=script` instead creates the account with `create_account.py` and runs `composeodj` by hand (AD 1.4.0).
4. Member adds its own secondary IP (arping DAD, `ip addr add`, gratuitous ARP; design option A).
5. `requestodj`, then `wbinfo -t`, `wbinfo -P`, `net ads testjoin`.
6. rid mapping (`10000 + RID`, Domain Users → 10513), NSS lookup.
7. smbd listens on the secondary IP only.
8. Share root ACL set in-process with `samba.ntacls.setntacl` (as the app will); NTLM and Kerberos SMB access as
   `alice` (in the group); `bob` (not in the group) is denied; file owner on disk and inherited `user.NTACL`.
   Administrator (no `username map`) gets in through Domain Admins Full Control; `SeDiskOperatorPrivilege` granted.
9. Rejoin: `reset: true` returns a new blob, `requestodj` again, trust and Kerberos SMB work again.

Result against 1.4.0 with `ODJ_SOURCE=script` (2026-11-25, run 45678819056): all join checks passed (requestodj,
`wbinfo -t`/`-P`, `net ads testjoin`, rid mapping 11103 / 10513, smbd on the secondary IP only, NTLM, Kerberos with
`cifs/files.ci.example.test`). The only failure was a test bug: the share root had no NT ACL, so nothing was inherited.

Run: `bash spike/odj/run.sh` on a Docker host (Linux, or macOS with Colima/OrbStack), or the workflow
`.github/workflows/odj-spike.yml` (manual or on a `spike/**` branch). `KEEP=1` leaves the containers running for
inspection. Output ends with a PASS/FAIL/INFO list.

Not covered here: DNS through PK95 DNS (hosts entries and a fixed KDC instead), the unprivileged LXC, Windows clients.

Result against 1.5.0 with the real endpoint (run 45679133770): every join check passed, including `no-store`, the blob
not in the DC log, `409` without reset, and the rejoin (`reset: true` → new blob → `requestodj` → trust and Kerberos
SMB again). Failed: setting the root ACL over SMB as Administrator (`NT_STATUS_INVALID_TOKEN` with `username map` →
root), so the ACL checks had nothing to test. Decision: no `username map`; ACLs are set in-process with `setntacl`
(`samba.auth_util.system_session_unix`, not `samba.auth`), Administrator works through Domain Admins.
