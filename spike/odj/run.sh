#!/usr/bin/env bash
# ODJ spike for PK95 File (docs/design.md §4): does an offline domain join work between PK95 AD and a Samba member,
# with the computer account created in-process on the DC (no admin password) and the blob from `composeodj`?
#
#   DC      pk95-ad:1.5.0, provisions ci.example.test on 172.30.0.10 (API on 127.0.0.1:18389)
#   member  Debian trixie Samba member "files"; container IP .20, adds 172.30.0.53 itself (design option A)
#   client  same image, kinit + smbclient as a domain user
#
# ODJ_SOURCE=endpoint (default): the blob comes from PK95 AD's POST /api/computers/odj (AD >= 1.5.0).
# ODJ_SOURCE=script: account via create_account.py and composeodj by hand (works with AD 1.4.0).
# Needs Docker (Linux, or macOS with Colima/OrbStack), curl, openssl, python3. KEEP=1 leaves the containers running.
set -uo pipefail
cd "$(dirname "$0")"

AD_IMAGE=${AD_IMAGE:-ghcr.io/philippkuhlmann/pk95-ad:1.5.0}
ODJ_SOURCE=${ODJ_SOURCE:-endpoint}
MEMBER_IMAGE=pk95file-spike-member
NET=pk95spike
DC_IP=172.30.0.10 MEMBER_IP=172.30.0.20 FILES_IP=172.30.0.53 CLIENT_IP=172.30.0.100
REALM=ci.example.test REALM_UP=CI.EXAMPLE.TEST WG=CIEXAMPLE
API=http://127.0.0.1:18389
TOKEN=$(openssl rand -hex 24)
ADMIN_PW='Spike-Admin-2026!'
USER_PW='Spike-User-2026!'
MACHINE_PW=$(openssl rand -base64 64 | tr -d '\n/+=' | cut -c1-100)
TMP=$(mktemp -d)

RESULTS=()
FAILED=0
pass() { RESULTS+=("PASS  $1"); echo "== PASS: $1"; }
fail() { RESULTS+=("FAIL  $1"); echo "== FAIL: $1"; FAILED=1; }
info() { RESULTS+=("INFO  $1"); echo "== INFO: $1"; }
logs() {
	echo "----- member logs -----"
	docker exec spike-files sh -c 'tail -n 60 /var/log/samba/log.winbindd /var/log/samba/log.smbd 2>/dev/null' || true
	echo "----- DC container log (tail) -----"
	docker logs spike-dc 2>&1 | tail -n 60 || true
}
finish() {
	[ "$FAILED" = 1 ] && logs
	rm -rf "$TMP"
	echo
	echo "===== ODJ spike results ====="
	printf '%s\n' "${RESULTS[@]}"
	if [ "${KEEP:-0}" != 1 ]; then
		docker rm -f spike-dc spike-files spike-client >/dev/null 2>&1
		docker network rm "$NET" >/dev/null 2>&1
	fi
}
trap finish EXIT
die() { fail "$1"; exit 1; }

api() { # METHOD PATH [JSON]
	if [ $# -ge 3 ]; then
		curl -fsS -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$3" "$API$2"
	else
		curl -fsS -X "$1" -H "Authorization: Bearer $TOKEN" "$API$2"
	fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

KRB5_CONF="[libdefaults]
    default_realm = $REALM_UP
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
[realms]
    $REALM_UP = {
        kdc = $DC_IP
    }
[domain_realm]
    .$REALM = $REALM_UP
    $REALM = $REALM_UP"
HOSTS=(--add-host "dc1.$REALM:$DC_IP" --add-host "dc1:$DC_IP" --add-host "files.$REALM:$FILES_IP")

# --- 0. network and images --------------------------------------------------------------------------------------
docker rm -f spike-dc spike-files spike-client >/dev/null 2>&1
docker network rm "$NET" >/dev/null 2>&1
docker network create --subnet 172.30.0.0/24 "$NET" >/dev/null || die "docker network create"
docker build -q -t "$MEMBER_IMAGE" -f member.Dockerfile . >/dev/null || die "build member image"
docker pull -q "$AD_IMAGE" >/dev/null || die "pull $AD_IMAGE"

# --- 1. DC: provision a domain through the PK95 AD API --------------------------------------------------------------
docker run -d --name spike-dc --hostname dc1 --network "$NET" --ip "$DC_IP" -p 127.0.0.1:18389:8389 \
	-e PK95AD_TOKEN="$TOKEN" -e TZ=Europe/Berlin "$AD_IMAGE" >/dev/null || die "start DC"
for _ in $(seq 60); do curl -fsS "$API/core/health" >/dev/null 2>&1 && break; sleep 2; done
api POST /api/setup "{\"realm\":\"$REALM\",\"netbios_domain\":\"$WG\",\"hostname\":\"dc1\",\"host_ip\":\"$DC_IP\",\"dns_forwarder\":\"127.0.0.1\",\"admin_password\":\"$ADMIN_PW\"}" >/dev/null \
	|| die "POST /api/setup on the DC"
state=""
for _ in $(seq 150); do
	state=$(api GET /api/setup | json 'd["state"]')
	if [ "$state" = ready ] || [ "$state" = failed ]; then break; fi
	sleep 2
done
if [ "$state" != ready ]; then
	api GET /api/setup | json '"\n".join(d["log"][-40:]) + "\n" + d["error"]'
	die "DC provisioning (state $state)"
fi
pass "DC provisioned $REALM with $AD_IMAGE"
info "DC: $(docker exec spike-dc samba --version)"

SAM=/var/lib/samba/private/sam.ldb
docker exec spike-dc samba-tool user create alice "$USER_PW" -H "$SAM" >/dev/null || die "create user alice"
docker exec spike-dc samba-tool group add SpikeGroup -H "$SAM" >/dev/null || die "create group"
docker exec spike-dc samba-tool group addmembers SpikeGroup alice -H "$SAM" >/dev/null || die "add member"
docker exec spike-dc samba-tool user create bob "$USER_PW" -H "$SAM" >/dev/null || die "create user bob (not in the group)"
ALICE_SID=$(docker exec spike-dc samba-tool user show alice -H "$SAM" --attributes=objectSid | sed -n 's/^objectSid: //p')
ALICE_RID=${ALICE_SID##*-}
info "alice $ALICE_SID → expected Unix ID $((10000 + ALICE_RID)) (rid backend)"

DOM_SID=${ALICE_SID%-*}
ODJ_REQ="{\"name\":\"files\",\"dns_hostname\":\"files.$REALM\",\"description\":\"PK95 File ODJ spike\""

if [ "$ODJ_SOURCE" = endpoint ]; then
# --- 2+3. POST /api/computers/odj (PK95 AD >= 1.5.0): account in-process + composeodj on the DC -------------------
	ODJ=$(curl -sS -D "$TMP/odj.headers" -o - -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
		-d "$ODJ_REQ,\"reset\":false}" "$API/api/computers/odj")
	if ! echo "$ODJ" | json 'd["odj"]' >/dev/null 2>&1; then
		die "POST /api/computers/odj: $ODJ"
	fi
	BLOB=$(echo "$ODJ" | json 'd["odj"]')
	pass "POST /api/computers/odj: created=$(echo "$ODJ" | json 'd["created"]'), account $(echo "$ODJ" | json 'd["computer"]["name"]'), domain $(echo "$ODJ" | json 'd["domain"]["netbios_domain"] + " / " + d["domain"]["realm"] + ", DC " + d["domain"]["dc"]["hostname"] + " " + d["domain"]["dc"]["ip"]')"
	if grep -qi '^cache-control: no-store' "$TMP/odj.headers"; then pass "odj answer has Cache-Control: no-store"
	else fail "odj answer without Cache-Control: no-store"; fi
	if echo "$BLOB" | base64 -d >/dev/null 2>&1; then pass "blob is valid base64 (${#BLOB} chars)"
	else die "blob is not base64"; fi
	if docker logs spike-dc 2>&1 | grep -qF "$BLOB"; then fail "the blob appears in the DC log"
	else pass "the blob does not appear in the DC log"; fi
	code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
		-d "$ODJ_REQ,\"reset\":false}" "$API/api/computers/odj")
	if [ "$code" = 409 ]; then pass "second POST without reset → 409"
	else fail "second POST without reset → $code (expected 409)"; fi
else
	# --- 2. computer account in-process, as POST /api/computers/odj would create it ---------------------------------------
	DOM=$(docker exec -i -e MACHINE_PASSWORD="$MACHINE_PW" spike-dc python3 - files "$REALM" < create_account.py) \
		|| die "create computer account in-process (sam.ldb as system)"
	pass "computer account FILES\$ created in-process: $(echo "$DOM" | json 'd["account_dn"]')"
	DOM_SID=$(echo "$DOM" | json 'd["domain_sid"]')
	DOM_GUID=$(echo "$DOM" | json 'd["domain_guid"]')
	FOREST=$(echo "$DOM" | json 'd["forest_name"]')

	# --- 3. composeodj on the DC (no DC contact, machine password known) --------------------------------------------------
	COMPOSE=(net offlinejoin composeodj --realm="$REALM_UP" --workgroup="$WG" domain_sid="$DOM_SID" domain_guid="$DOM_GUID"
		forest_name="$FOREST" -S "dc1.$REALM" -I "$DC_IP" -U 'FILES$')
	BLOB=$(docker exec -e PASSWD="$MACHINE_PW" spike-dc timeout 30 "${COMPOSE[@]}" printblob </dev/null 2>"$TMP/compose.err" | tail -n 1)
	if [ -n "$BLOB" ] && echo "$BLOB" | base64 -d >/dev/null 2>&1; then
		pass "composeodj printblob with the password from \$PASSWD (not on the command line)"
	else
		info "composeodj with \$PASSWD failed: $(tr '\n' ' ' <"$TMP/compose.err")"
		BLOB=$(docker exec spike-dc timeout 30 "${COMPOSE[@]}" --password="$MACHINE_PW" printblob </dev/null 2>"$TMP/compose.err" | tail -n 1)
		if [ -n "$BLOB" ] && echo "$BLOB" | base64 -d >/dev/null 2>&1; then
			pass "composeodj printblob with --password"
		else
			die "composeodj: $(tr '\n' ' ' <"$TMP/compose.err")"
		fi
	fi
	info "blob: ${#BLOB} chars of base64"
	if docker exec spike-dc timeout 30 "${COMPOSE[@]}" --password="$MACHINE_PW" savefile=/tmp/files.odj </dev/null >/dev/null 2>&1 \
		&& docker cp spike-dc:/tmp/files.odj "$TMP/files.odj" >/dev/null 2>&1; then
		pass "composeodj savefile (UTF-16 file, Windows format) for the loadfile variant"
	else
		info "composeodj savefile not available"
	fi
	docker exec spike-dc rm -f /tmp/files.odj

fi

# --- 4. member: own secondary IP (option A), config, requestodj ------------------------------------------------------
docker run -d --name spike-files --hostname files --network "$NET" --ip "$MEMBER_IP" --cap-add NET_ADMIN \
	"${HOSTS[@]}" "$MEMBER_IMAGE" >/dev/null || die "start member"
info "member: $(docker exec spike-files smbd --version)"
if docker exec spike-files arping -D -q -c 2 -w 3 -I eth0 "$FILES_IP"; then
	pass "arping -D: $FILES_IP is free"
else
	fail "arping -D reports $FILES_IP as taken"
fi
docker exec spike-files ip addr add "$FILES_IP/24" dev eth0 || die "ip addr add $FILES_IP (NET_ADMIN)"
docker exec spike-files arping -U -q -c 2 -I eth0 "$FILES_IP" || info "gratuitous ARP failed (NET_RAW?)"
pass "secondary address $FILES_IP added to eth0 inside the container"

docker cp member-smb.conf spike-files:/etc/samba/smb.conf >/dev/null
docker exec spike-files sh -c "printf '%s\n' '$KRB5_CONF' > /etc/krb5.conf
	mkdir -p /srv/files/shares/spike && chmod 1777 /srv/files/shares/spike
	testparm -s >/dev/null 2>&1" || die "member config (testparm)"

joined=""
if printf '%s' "$BLOB" | docker exec -i spike-files net offlinejoin requestodj -i; then
	joined="printblob text via stdin (-i)"
elif [ -f "$TMP/files.odj" ]; then
	info "requestodj -i with the printblob text failed, trying loadfile with the UTF-16 file"
	docker cp "$TMP/files.odj" spike-files:/tmp/files.odj >/dev/null
	docker exec spike-files net offlinejoin requestodj loadfile=/tmp/files.odj && joined="loadfile (UTF-16 file)"
	docker exec spike-files rm -f /tmp/files.odj
fi
[ -n "$joined" ] || die "net offlinejoin requestodj"
pass "requestodj: $joined (no credentials, no network)"

# --- 5. winbind: trust, secure channel, rid mapping -------------------------------------------------------------------
docker exec spike-files winbindd -D || die "start winbindd"
ok=""
for _ in $(seq 20); do docker exec spike-files wbinfo -t >/dev/null 2>&1 && ok=1 && break; sleep 2; done
if [ -n "$ok" ]; then pass "wbinfo -t (trust secret valid)"
else fail "wbinfo -t: $(docker exec spike-files wbinfo -t 2>&1 | tr '\n' ' ')"; fi
if docker exec spike-files wbinfo -P >/dev/null 2>&1; then pass "wbinfo -P (netlogon secure channel)"
else fail "wbinfo -P: $(docker exec spike-files wbinfo -P 2>&1 | tr '\n' ' ')"; fi
if docker exec spike-files net ads testjoin >/dev/null 2>&1; then pass "net ads testjoin (Kerberos with the machine account)"
else fail "net ads testjoin: $(docker exec spike-files net ads testjoin 2>&1 | tr '\n' ' ')"; fi
uid=$(docker exec spike-files wbinfo --sid-to-uid="$ALICE_SID" 2>/dev/null)
if [ "$uid" = "$((10000 + ALICE_RID))" ]; then pass "rid mapping: alice → $uid"
else fail "rid mapping: alice → '$uid', expected $((10000 + ALICE_RID))"; fi
gid=$(docker exec spike-files wbinfo --sid-to-gid="$DOM_SID-513" 2>/dev/null)
if [ "$gid" = 10513 ]; then pass "rid mapping: Domain Users → 10513"
else fail "rid mapping: Domain Users → '$gid'"; fi
if docker exec spike-files getent passwd "$WG\\alice" >/dev/null; then pass "NSS: getent passwd $WG\\alice"
else fail "NSS lookup of alice"; fi

# --- 6. smbd bound to the secondary address only ----------------------------------------------------------------------
docker exec spike-files smbd -D || die "start smbd"
sleep 2
listen=$(docker exec spike-files ss -Hltn 'sport = :445' | awk '{print $4}' | tr '\n' ' ')
if [ "$listen" = "$FILES_IP:445 " ]; then pass "smbd listens on $FILES_IP:445 only"
else fail "smbd listens on: $listen"; fi

# --- 7. client: NTLM and Kerberos as a domain user --------------------------------------------------------------------
docker run -d --name spike-client --network "$NET" --ip "$CLIENT_IP" "${HOSTS[@]}" "$MEMBER_IMAGE" >/dev/null || die "start client"
docker exec spike-client sh -c "printf '%s\n' '$KRB5_CONF' > /etc/krb5.conf"
docker exec spike-client sh -c "printf '[global]\\n    workgroup = $WG\\n    realm = $REALM_UP\\n' > /etc/samba/smb.conf"
# Share root ACL as PK95 File will set it (docs/design.md §9): in-process with samba.ntacls on the member,
# SpikeGroup change, Domain Admins + SYSTEM full.
GROUP_SID=$(docker exec spike-files wbinfo -n "$WG\\SpikeGroup" | awk '{print $1}')
SDDL="O:S-1-22-1-0G:S-1-22-2-0D:PAI(A;OICI;FA;;;DA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;$GROUP_SID)"
if docker exec spike-files python3 -c "
import sys
from samba.param import LoadParm
from samba.ntacls import setntacl
from samba.auth_util import system_session_unix
lp = LoadParm(); lp.load('/etc/samba/smb.conf')
setntacl(lp, '/srv/files/shares/spike', sys.argv[1], sys.argv[2], system_session_unix(), use_ntvfs=False)
" "$SDDL" "$DOM_SID" >"$TMP/setntacl.out" 2>&1; then
	pass "root ACL set in-process (samba.ntacls.setntacl): $SDDL"
else
	fail "setntacl: $(tail -n 3 "$TMP/setntacl.out" | tr '\n' ' ')"
fi
# Administrator without username map: a normal domain user (rid uid 10500) with Full Control through Domain Admins.
if docker exec spike-files net sam rights grant "$WG\\Domain Admins" SeDiskOperatorPrivilege >/dev/null 2>&1; then
	pass "SeDiskOperatorPrivilege granted to Domain Admins"
else
	info "net sam rights grant SeDiskOperatorPrivilege failed"
fi
if docker exec spike-client smbcacls "//$FILES_IP/spike" / -U "$WG\\Administrator%$ADMIN_PW" >"$TMP/cacls.out" 2>&1 \
	&& grep -q 'Domain Admins:ALLOWED/OI|CI/FULL' "$TMP/cacls.out"; then
	pass "Administrator (Domain Admins, no username map) reads the root ACL over SMB"
else
	fail "Administrator over SMB: $(tail -n 3 "$TMP/cacls.out" | tr '\n' ' ')"
fi
if docker exec spike-client smbclient "//$FILES_IP/spike" -U "$WG\\Administrator%$ADMIN_PW" -m SMB3 -c 'put /etc/hostname admin.txt' >/dev/null 2>&1; then
	pass "Administrator writes through Domain Admins Full Control"
else
	fail "Administrator cannot write"
fi
if docker exec spike-files getfattr -n user.NTACL /srv/files/shares/spike >/dev/null 2>&1; then pass "share root NT ACL stored in user.NTACL"
else fail "no user.NTACL on the share root"; fi
if docker exec spike-client smbclient "//$FILES_IP/spike" -U "$WG\\alice%$USER_PW" -m SMB3 -c 'put /etc/hostname ntlm.txt; ls' >/dev/null 2>&1; then
	pass "NTLM: alice writes to //$FILES_IP/spike"
else
	fail "NTLM: $(docker exec spike-client smbclient "//$FILES_IP/spike" -U "$WG\\alice%$USER_PW" -m SMB3 -c ls 2>&1 | tail -n 2 | tr '\n' ' ')"
fi
if docker exec spike-client sh -c "echo '$USER_PW' | kinit alice@$REALM_UP >/dev/null"; then
	if docker exec spike-client smbclient "//files.$REALM/spike" --use-kerberos=required -m SMB3 -c 'put /etc/hostname krb.txt; ls' >/dev/null 2>&1; then
		pass "Kerberos: alice writes to //files.$REALM/spike"
	else
		fail "Kerberos: $(docker exec spike-client smbclient "//files.$REALM/spike" --use-kerberos=required -m SMB3 -c ls 2>&1 | tail -n 2 | tr '\n' ' ')"
	fi
	info "client service ticket: $(docker exec spike-client klist 2>/dev/null | grep -o 'cifs/[^ ]*' | head -n 1)"
else
	fail "kinit alice"
fi
owner=$(docker exec spike-files stat -c %u /srv/files/shares/spike/ntlm.txt 2>/dev/null)
if [ "$owner" = "$((10000 + ALICE_RID))" ]; then pass "file owner on disk = alice's rid Unix ID ($owner)"
else fail "file owner on disk: '$owner'"; fi
if docker exec spike-files getfattr -n user.NTACL /srv/files/shares/spike/ntlm.txt >/dev/null 2>&1; then pass "inherited NT ACL stored in user.NTACL on the new file"
else fail "no user.NTACL on the written file"; fi
out=$(docker exec spike-client smbclient "//$FILES_IP/spike" -U "$WG\\bob%$USER_PW" -m SMB3 -c 'put /etc/hostname bob.txt' 2>&1)
if echo "$out" | grep -q 'NT_STATUS_ACCESS_DENIED'; then pass "bob (not in SpikeGroup) cannot write: NT ACL enforced"
else fail "bob write was not denied: $(echo "$out" | tail -n 2 | tr '\n' ' ')"; fi

# --- 8. rejoin: reset the account, new blob, requestodj again (POST /api/join later) ------------------------------------
if [ "$ODJ_SOURCE" = endpoint ]; then
	ODJ=$(api POST /api/computers/odj "$ODJ_REQ,\"reset\":true}") || fail "POST /api/computers/odj with reset"
	BLOB2=$(echo "$ODJ" | json 'd["odj"]' 2>/dev/null)
	if [ -n "$BLOB2" ] && [ "$BLOB2" != "$BLOB" ]; then pass "reset: new blob, created=$(echo "$ODJ" | json 'd["created"]')"
	else fail "reset did not return a new blob"; fi
	sleep 2
	if docker exec spike-files wbinfo -t >/dev/null 2>&1; then info "old trust still accepted right after the reset (cached)"
	else pass "old trust fails after the reset (expected)"; fi
	docker exec spike-files sh -c 'pkill -x smbd; pkill -x winbindd; sleep 1'
	if printf '%s' "$BLOB2" | docker exec -i spike-files net offlinejoin requestodj -i >/dev/null; then
		docker exec spike-files sh -c 'winbindd -D && smbd -D'
		ok=""
		for _ in $(seq 20); do docker exec spike-files wbinfo -t >/dev/null 2>&1 && ok=1 && break; sleep 2; done
		if [ -n "$ok" ]; then pass "rejoin: requestodj with the new blob, wbinfo -t ok"
		else fail "rejoin: wbinfo -t: $(docker exec spike-files wbinfo -t 2>&1 | tr '\n' ' ')"; fi
		if docker exec spike-client smbclient "//files.$REALM/spike" --use-kerberos=required -m SMB3 -c ls >/dev/null 2>&1; then
			pass "rejoin: Kerberos SMB works with the new machine password"
		else
			info "rejoin: Kerberos SMB failed with the old service ticket; retrying with a fresh one"
			docker exec spike-client sh -c "kdestroy; echo '$USER_PW' | kinit alice@$REALM_UP >/dev/null"
			if docker exec spike-client smbclient "//files.$REALM/spike" --use-kerberos=required -m SMB3 -c ls >/dev/null 2>&1; then
				pass "rejoin: Kerberos SMB works after a new ticket"
			else
				fail "rejoin: Kerberos SMB: $(docker exec spike-client smbclient "//files.$REALM/spike" --use-kerberos=required -m SMB3 -c ls 2>&1 | tail -n 2 | tr '\n' ' ')"
			fi
		fi
	else
		fail "rejoin: requestodj with the new blob"
	fi
fi

exit "$FAILED"
