"""ODJ spike, runs INSIDE the PK95 AD container: create a computer account the way the planned
POST /api/computers/odj would – in-process on sam.ldb as system, with a random password – and print the
domain data composeodj needs as JSON. The password comes from the environment (MACHINE_PASSWORD).

Usage: docker exec -i -e MACHINE_PASSWORD=… <dc> python3 - <name> <realm> < create_account.py
"""

import json
import os
import sys

import ldb
from samba.auth import system_session
from samba.dcerpc import misc
from samba.ndr import ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

name, realm = sys.argv[1].lower(), sys.argv[2].lower()
password = os.environ["MACHINE_PASSWORD"]

lp = LoadParm()
lp.load_default()
db = SamDB(url="/var/lib/samba/private/sam.ldb", session_info=system_session(), lp=lp)

domain_dn = db.domain_dn()
fqdn = f"{name}.{realm}"
dn = f"CN={name.upper()},CN=Computers,{domain_dn}"

for msg in db.search(base=domain_dn, scope=ldb.SCOPE_SUBTREE,
                     expression=f"(sAMAccountName={name.upper()}$)", attrs=["dn"]):
    db.delete(msg.dn)

db.add({
    "dn": dn,
    "objectClass": "computer",
    "sAMAccountName": f"{name.upper()}$",
    "userAccountControl": "4096",  # WORKSTATION_TRUST_ACCOUNT
    "dNSHostName": fqdn,
    "servicePrincipalName": [f"HOST/{name}", f"HOST/{fqdn}",
                             f"RestrictedKrbHost/{name}", f"RestrictedKrbHost/{fqdn}"],
    "msDS-SupportedEncryptionTypes": "24",  # AES128 + AES256
    "unicodePwd": f'"{password}"'.encode("utf-16-le"),
    "description": "PK95 File ODJ spike",
})

root = db.search(base=domain_dn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])[0]
guid = str(ndr_unpack(misc.GUID, root["objectGUID"][0]))
rootdse = db.search(base="", scope=ldb.SCOPE_BASE, attrs=["rootDomainNamingContext"])[0]
forest_name = str(rootdse["rootDomainNamingContext"][0]).replace("DC=", "").replace(",", ".").lower()

print(json.dumps({
    "account_dn": dn,
    "domain_sid": str(db.get_domain_sid()),
    "domain_guid": guid,
    "forest_name": forest_name,
    "netbios_domain": lp.get("workgroup"),
    "realm": lp.get("realm"),
}))
