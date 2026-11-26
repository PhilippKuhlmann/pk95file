"""Pure parts without Samba: validation, SDDL, inheritance, smb.conf, IP suggestion, preflight, share fields."""

import base64
import os
import tempfile
import unittest

from pk95file import acl, acl_helper, config, netinfo, setup, smbconf, storage, validate
from pk95file.errors import ApiError
from pk95file.monitor import rid_warning

DSID = "S-1-5-21-1-2-3"
SETTINGS = {"hostname": "files", "ip": "192.168.1.20", "prefix": 24, "iface": "eth0", "ip_mode": "managed",
            "realm": "ad.example.com", "workgroup": "EXAMPLE", "dc": {"hostname": "dc1", "ip": "192.168.1.10"},
            "domain_sid": DSID, "joined_at": 1}


class ValidateTest(unittest.TestCase):
    def test_share_names(self):
        self.assertIsNone(validate.share_name("Buchhaltung"))
        self.assertIsNone(validate.share_name("Projekte$"))
        self.assertIsNone(validate.share_name("Geschäftsführung 2026"))
        for bad in ("", " x", "a/b", "a\\b", "x:y", "homes", "IPC$", ".", "a" * 81, "a\tb"):
            self.assertIsNotNone(validate.share_name(bad), bad)

    def test_hostname_realm_workgroup(self):
        self.assertIsNone(validate.hostname("files"))
        self.assertIsNotNone(validate.hostname("Files"))
        self.assertIsNotNone(validate.hostname("123"))
        self.assertIsNotNone(validate.hostname("a" * 16))
        self.assertIsNone(validate.realm("ad.example.com"))
        self.assertIsNotNone(validate.realm("local"))
        self.assertIsNone(validate.workgroup("EXAMPLE"))
        self.assertIsNotNone(validate.workgroup("example"))

    def test_ip_in_subnet(self):
        self.assertIsNone(validate.ip_in_subnet("192.168.1.20", "192.168.1.0/24"))
        self.assertIn("nicht im Netz", validate.ip_in_subnet("10.0.0.1", "192.168.1.0/24"))
        self.assertIsNotNone(validate.ip_in_subnet("192.168.1.255", "192.168.1.0/24"))


class AclTest(unittest.TestCase):
    def test_share_root_sddl(self):
        sddl = acl.share_root_sddl(DSID, [{"sid": DSID + "-1104", "access": "change"},
                                          {"sid": DSID + "-1107", "access": "read"}])
        self.assertTrue(sddl.startswith("O:S-1-22-1-0G:S-1-22-2-0D:PAI"))
        self.assertIn(f"(A;OICI;0x001f01ff;;;{DSID}-512)", sddl)
        self.assertIn("(A;OICI;0x001f01ff;;;S-1-5-18)", sddl)
        self.assertIn(f"(A;OICI;0x001301bf;;;{DSID}-1104)", sddl)
        self.assertIn(f"(A;OICI;0x001200a9;;;{DSID}-1107)", sddl)

    def test_recycle_sddl(self):
        sddl = acl.recycle_sddl(DSID, [{"sid": "S-1-5-21-9-1", "access": "change"},
                                      {"sid": "S-1-5-21-9-2", "access": "full"},
                                      {"sid": "S-1-5-21-9-3", "access": "read"}])
        self.assertIn("(A;;0x001000a4;;;S-1-5-21-9-1)", sddl)       # change: create own folder only
        self.assertIn("(A;OICI;0x001f01ff;;;S-1-5-21-9-2)", sddl)   # full: everything
        self.assertNotIn("S-1-5-21-9-3", sddl)                       # read: nothing
        self.assertIn("(A;OICIIO;0x001f01ff;;;S-1-3-0)", sddl)      # CREATOR OWNER

    def test_parse_permissions(self):
        entries = [{"sid": DSID + "-512", "type": 0, "flags": 3, "mask": 0x1F01FF, "inherited": False},
                   {"sid": DSID + "-1104", "type": 0, "flags": 3, "mask": 0x1301BF, "inherited": False},
                   {"sid": DSID + "-1105", "type": 0, "flags": 19, "mask": 0x1200A9, "inherited": True},
                   {"sid": DSID + "-1106", "type": 1, "flags": 3, "mask": 0x1200A9, "inherited": False}]
        self.assertEqual(acl.parse_permissions(entries, DSID), [{"sid": DSID + "-1104", "access": "change"}])

    def test_share_acl_entries(self):
        from pk95file import samba
        self.assertEqual(samba.share_acl_entries(DSID, [DSID + "-1104", "S-1-5-18"]),
                         f"{DSID}-512:ALLOWED/0/FULL,S-1-5-18:ALLOWED/0/FULL,{DSID}-1104:ALLOWED/0/FULL")

    def test_child_flags(self):
        OI, CI, NP, IO, ID = acl_helper.OI, acl_helper.CI, acl_helper.NP, acl_helper.IO, acl_helper.ID
        self.assertEqual(acl_helper.child_flags(OI | CI, True), OI | CI | ID)
        self.assertEqual(acl_helper.child_flags(OI | CI, False), ID)
        self.assertEqual(acl_helper.child_flags(OI | CI | IO, True), OI | CI | ID)
        self.assertEqual(acl_helper.child_flags(OI, True), OI | IO | ID)
        self.assertEqual(acl_helper.child_flags(CI, False), None)
        self.assertEqual(acl_helper.child_flags(CI | NP, True), ID)
        self.assertEqual(acl_helper.child_flags(0, True), None)


class SmbConfTest(unittest.TestCase):
    def test_render(self):
        share = {"name": "Buchhaltung", "description": "Belege", "enabled": True, "abe": True, "locked": False,
                 "recycle": {"enabled": True, "keep_days": 30, "max_file_mb": 10, "exclude": ["*.tmp", "~$*"]}}
        text = smbconf.render(SETTINGS, [share], "/srv/files/shares")
        self.assertIn("interfaces = 192.168.1.20/24", text)
        self.assertIn("bind interfaces only = yes", text)
        self.assertIn("idmap config EXAMPLE : backend = rid", text)
        self.assertIn("idmap config EXAMPLE : range = 10000-64999", text)
        self.assertIn("acl_xattr:security_acl_name = user.NTACL", text)
        self.assertNotIn("username map", text)
        self.assertIn("[Buchhaltung]", text)
        self.assertIn("vfs objects = acl_xattr recycle", text)
        self.assertIn("recycle:exclude = *.tmp|~$*", text)
        self.assertIn("recycle:maxsize = 10485760", text)
        self.assertIn("password server = dc1.ad.example.com", text)

    def test_disabled_and_locked(self):
        share = {"name": "Alt", "enabled": False, "abe": False, "locked": True, "recycle": {"enabled": False}}
        text = smbconf.render(SETTINGS, [share], "/srv/files/shares")
        self.assertIn("available = no", text)
        self.assertIn("read only = yes", text)
        self.assertIn("hide unreadable = no", text)
        self.assertIn("    vfs objects = acl_xattr\n", text)

    def test_hosts(self):
        out = smbconf.hosts("127.0.0.1 localhost\n1.2.3.4 old\t# pk95file\n", SETTINGS)
        self.assertIn("192.168.1.10\tdc1.ad.example.com dc1\t# pk95file", out)
        self.assertIn("192.168.1.20\tfiles.ad.example.com files\t# pk95file", out)
        self.assertNotIn("old", out)


class NetSetupTest(unittest.TestCase):
    def test_candidates(self):
        self.assertEqual(netinfo.candidates("192.168.1.10", 24, {"192.168.1.11"}, 3),
                         ["192.168.1.12", "192.168.1.13", "192.168.1.14"])
        self.assertEqual(netinfo.candidates("192.168.1.253", 24, set(), 5), ["192.168.1.254"])

    def test_check_ip(self):
        hosts = ["192.168.1.10"]
        self.assertIsNone(setup.check_ip("192.168.1.20", "managed", "192.168.1.0/24", hosts, dad=lambda ip: (True, "")))
        self.assertIn("vergeben", setup.check_ip("192.168.1.20", "managed", "192.168.1.0/24", hosts,
                                                 dad=lambda ip: (False, "aa:bb:cc:dd:ee:ff")))
        self.assertIn("gehört schon", setup.check_ip("192.168.1.10", "managed", "192.168.1.0/24", hosts))
        self.assertIn("nicht vorhanden", setup.check_ip("192.168.1.20", "existing", "192.168.1.0/24", hosts))
        self.assertIsNone(setup.check_ip("192.168.1.10", "existing", "192.168.1.0/24", hosts))
        self.assertIn("Domänencontroller", setup.check_ip("192.168.1.10", "existing", "", hosts, "192.168.1.10"))

    def test_odj_matches(self):
        blob = base64.b64encode(b"\x01\x00" + "FILES$".encode("utf-16-le") + b"\x00\x00").decode()
        self.assertTrue(setup.odj_matches(blob, "files"))
        self.assertFalse(setup.odj_matches(blob, "other"))
        self.assertFalse(setup.odj_matches("not base64!", "files"))

    def test_rid_warning(self):
        self.assertEqual(rid_warning(1500), "")
        self.assertIn("55 000", rid_warning(50000))


class StorageTest(unittest.TestCase):
    def test_evaluate(self):
        base = {"path": "/srv/files", "fs_type": "zfs", "total_bytes": 50 * storage.GIB,
                "free_bytes": 40 * storage.GIB, "on_system_disk": False, "xattr": True, "hardlinks": True,
                "reflink": False, "exists": True, "writable": True}
        self.assertEqual(storage.evaluate(base)["problems"], [])
        self.assertEqual(storage.evaluate(base)["warnings"], [])
        low = storage.evaluate({**base, "free_bytes": 8 * storage.GIB})
        self.assertEqual(len(low["warnings"]), 1)
        bad = storage.evaluate({**base, "fs_type": "overlay", "xattr": False, "on_system_disk": True})
        self.assertEqual(len(bad["problems"]), 3)

    def test_fs_type(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("22 1 0:21 / / rw - overlay overlay rw\n"
                     "30 22 0:40 / /srv/files rw,relatime - zfs rpool/data/subvol-1-disk-1 rw,xattr\n")
        try:
            self.assertEqual(storage.fs_type("/srv/files/shares", fh.name), "zfs")
            self.assertEqual(storage.fs_type("/etc", fh.name), "overlay")
        finally:
            os.unlink(fh.name)


class FakeResolver:
    NAMES = {DSID + "-1104": ("EXAMPLE\\Buchhaltung", 2), DSID + "-1105": ("EXAMPLE\\max", 1),
             DSID + "-512": ("EXAMPLE\\Domain Admins", 2), "S-1-5-18": ("NT AUTHORITY\\SYSTEM", 5)}

    def sid_to_name(self, sid):
        return self.NAMES.get(sid)

    def name_to_sid(self, name):
        for sid, (n, t) in self.NAMES.items():
            if n.lower() == name.lower():
                return sid, t
        return None


class SharesValidationTest(unittest.TestCase):
    def setUp(self):
        from pk95file.app import App
        self.tmp = tempfile.TemporaryDirectory()
        cfg = config.Config(data_dir=self.tmp.name + "/data", data_root=self.tmp.name + "/root",
                            smb_conf=self.tmp.name + "/smb.conf", manage_processes=False)
        self.app = App(cfg, resolver=FakeResolver())
        self.app.settings.update(SETTINGS)

    def tearDown(self):
        self.tmp.cleanup()

    def test_permissions(self):
        from pk95file.errors import Fields
        f = Fields()
        out = self.app.shares._permissions([{"sid": DSID + "-1104", "access": "change"},
                                            {"name": "example\\max", "access": "read"}], f)
        self.assertEqual(dict(f), {})
        self.assertEqual(out, [{"sid": DSID + "-1104", "access": "change"}, {"sid": DSID + "-1105", "access": "read"}])
        f = Fields()
        self.app.shares._permissions([{"sid": DSID + "-512", "access": "full"},
                                      {"sid": DSID + "-9999", "access": "read"},
                                      {"sid": DSID + "-1104", "access": "write"}], f)
        self.assertIn("permissions.0.sid", f)
        self.assertIn("permissions.1.sid", f)
        self.assertIn("permissions.2.access", f)

    def test_not_ready(self):
        with self.assertRaises(ApiError) as cm:
            self.app.shares.create({"name": "X"})
        self.assertEqual(cm.exception.status, 409)

    def test_fields(self):
        from pk95file.errors import Fields
        from pk95file.shares import DEFAULT_RECYCLE, DEFAULT_SNAPSHOTS, DEFAULT_SOFT_QUOTA
        cur = {"description": "", "enabled": True, "abe": True, "recycle": dict(DEFAULT_RECYCLE),
               "snapshots": {"enabled": True, "schedule": {"times": ["07:00"], "weekdays": [1]},
                             "keep": dict(DEFAULT_SNAPSHOTS["keep"])},
               "soft_quota": dict(DEFAULT_SOFT_QUOTA)}
        f = Fields()
        out = self.app.shares._fields({"recycle": {"keep_days": 7}, "soft_quota": {"size_bytes": 2 * 1024 ** 3},
                                       "snapshots": {"schedule": {"times": ["17:00", "07:00"]},
                                                     "estimate_bytes": 5}}, cur, f)
        self.assertEqual(dict(f), {})
        self.assertEqual(out["recycle"]["keep_days"], 7)
        self.assertEqual(out["snapshots"]["schedule"]["times"], ["07:00", "17:00"])
        f = Fields()
        self.app.shares._fields({"recycle": {"keep_days": 0}, "soft_quota": {"size_bytes": 5},
                                 "snapshots": {"schedule": {"weekdays": [8]}}, "abe": "yes"}, cur, f)
        self.assertEqual(set(f), {"recycle.keep_days", "soft_quota.size_bytes", "snapshots.schedule.weekdays", "abe"})

    def test_public(self):
        share = {"name": "Projekte$", "description": "", "enabled": True, "abe": True,
                 "permissions": [{"sid": DSID + "-1104", "access": "full"}, {"sid": DSID + "-4444", "access": "read"}],
                 "recycle": {"enabled": True}, "snapshots": {"enabled": False}, "locked": False,
                 "soft_quota": {"size_bytes": 0, "warn_percent": 90, "lock_when_exceeded": False}}
        pub = self.app.shares.public(share)
        self.assertTrue(pub["hidden"])
        self.assertEqual(pub["unc"], "\\\\files.ad.example.com\\Projekte$")
        self.assertEqual(pub["unc_short"], "\\\\FILES\\Projekte$")
        self.assertEqual(pub["permissions"][0]["type"], "group")
        self.assertTrue(pub["permissions"][1]["unresolved"])
        self.assertEqual([p["access"] for p in pub["fixed_permissions"]], ["full", "full"])
        self.assertEqual(pub["status"], "ok")


class RecycleSchedulerTest(unittest.TestCase):
    def test_safe_rel(self):
        from pk95file.recycle import safe_rel
        self.assertEqual(safe_rel("alice/Ordner/a.txt"), "alice/Ordner/a.txt")
        self.assertEqual(safe_rel("alice\\b.txt"), "alice/b.txt")
        for bad in ("", "/etc/passwd", "alice/../../x", "..", None, "a\x00b"):
            self.assertIsNone(safe_rel(bad), bad)

    def test_purge_and_free_name(self):
        from pk95file import recycle
        with tempfile.TemporaryDirectory() as share:
            base = os.path.join(share, ".recycle", "alice", "Ordner")
            os.makedirs(base)
            old, new = os.path.join(base, "old.txt"), os.path.join(base, "new.txt")
            for path in (old, new):
                open(path, "w").close()
            now = 1_800_000_000
            os.utime(old, (now - 40 * 86400, now - 40 * 86400))
            os.utime(new, (now - 86400, now - 86400))
            listing = recycle.listing(share)
            self.assertEqual(listing["total"], 2)
            self.assertEqual({e["user"] for e in listing["items"]}, {"alice"})
            self.assertEqual(recycle.purge(share, 30, now=now), 1)
            self.assertFalse(os.path.exists(old))
            self.assertTrue(os.path.exists(new))
            self.assertEqual(recycle.purge(share, 0, now=now), 1)
            self.assertFalse(os.path.exists(os.path.join(share, ".recycle", "alice")))
            target = os.path.join(share, "a.txt")
            open(target, "w").close()
            self.assertEqual(recycle.free_name(target), os.path.join(share, "a (Wiederhergestellt).txt"))
            open(os.path.join(share, "a (Wiederhergestellt).txt"), "w").close()
            self.assertEqual(recycle.free_name(target), os.path.join(share, "a (Wiederhergestellt 2).txt"))

    def test_due_and_next_slot(self):
        from datetime import datetime
        from pk95file.scheduler import due_slot, next_slot
        wed = datetime(2026, 11, 25, 12, 10)  # a Wednesday
        times, days = ["07:00", "12:00", "17:00"], [1, 2, 3, 4, 5]
        self.assertEqual(due_slot(times, days, wed, set()), "2026-11-25 12:00")
        self.assertIsNone(due_slot(times, days, wed, {"2026-11-25 12:00"}))
        self.assertIsNone(due_slot(times, days, datetime(2026, 11, 25, 14, 0), set()))   # missed by > 1 h
        self.assertIsNone(due_slot(times, days, datetime(2026, 11, 28, 12, 5), set()))   # Saturday
        self.assertEqual(next_slot(times, days, wed), datetime(2026, 11, 25, 17, 0))
        self.assertEqual(next_slot(times, days, datetime(2026, 11, 27, 18, 0)), datetime(2026, 11, 30, 7, 0))


if __name__ == "__main__":
    unittest.main()
