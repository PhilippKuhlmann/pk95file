"""HTTP layer against an unconfigured app (no Samba, no network changes)."""

import http.client
import json
import tempfile
import threading
import unittest

from pk95file import VERSION, config, events, httpapi, routes
from pk95file.app import App

TOKEN = "t" * 48


class HttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = config.Config(listen_host="127.0.0.1", listen_port=0, data_dir=cls.tmp.name + "/data",
                            data_root=cls.tmp.name + "/root", smb_conf=cls.tmp.name + "/smb.conf",
                            core_mode=True, token=TOKEN, manage_processes=False)
        cls.app = App(cfg)
        cls.server = httpapi.serve("127.0.0.1", 0, routes.build(cls.app), TOKEN, True)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def call(self, method, path, body=None, token=TOKEN):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Authorization": "Bearer " + token} if token else {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, (json.loads(raw) if raw else None)

    def test_health_without_token(self):
        self.assertEqual(self.call("GET", "/core/health", token=None),
                         (200, {"ok": True, "version": VERSION, "state": "unconfigured"}))

    def test_manifest(self):
        self.assertEqual(self.call("GET", "/core/manifest", token=None)[0], 401)
        status, body = self.call("GET", "/core/manifest")
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], "file")
        self.assertEqual([m["key"] for m in body["menu"]], ["server", "shares", "sessions"])
        self.assertEqual(body["events"], events.ALL)
        self.assertEqual(len(body["events"]), 13)

    def test_not_ready(self):
        status, body = self.call("GET", "/api/shares")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "Der Dateiserver ist noch nicht eingerichtet.")
        self.assertEqual(self.call("POST", "/api/shares", {"name": "X"})[0], 409)

    def test_setup_info(self):
        status, body = self.call("GET", "/api/setup")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "unconfigured")
        self.assertEqual(set(body["defaults"]), {"hostname", "ip", "ip_source", "interface", "subnet", "host_ips"})
        self.assertEqual(set(body["storage"]), {"path", "fs_type", "total_bytes", "free_bytes", "on_system_disk",
                                                "xattr", "hardlinks", "reflink", "problems", "warnings"})
        self.assertIsNone(body["server"])

    def test_setup_validation(self):
        status, body = self.call("POST", "/api/setup", {"hostname": "X!", "realm": "x", "workgroup": "e x",
                                                        "dc": {"hostname": "dc1", "ip": "nope"}, "ip": "1.2.3"})
        self.assertEqual(status, 422)
        for field in ("hostname", "realm", "workgroup", "dc.ip", "ip", "odj"):
            self.assertIn(field, body["fields"])

    def test_rejoin_before_setup(self):
        self.assertEqual(self.call("POST", "/api/join", {"odj": "AAAA"})[0], 409)

    def test_status_and_dashboard(self):
        status, body = self.call("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(body["idmap"]["range"], [10000, 64999])
        self.assertEqual(body["idmap"]["max_rid"], 54999)
        self.assertEqual(set(body), {"version", "core_mode", "state", "started_at", "smbd", "winbindd", "trust",
                                     "ip", "idmap", "server"})
        status, body = self.call("GET", "/api/dashboard")
        self.assertEqual(status, 200)
        self.assertEqual(set(body["storage"]), {"total_bytes", "used_bytes", "free_bytes", "free_percent",
                                                "share_bytes", "snapshot_bytes", "recycle_bytes", "scanned_at"})

    def test_settings(self):
        status, body = self.call("PUT", "/api/settings", {"disk_warn_percent": 5, "disk_critical_percent": 10})
        self.assertEqual(status, 422)
        status, body = self.call("PUT", "/api/settings", {"disk_warn_percent": 25})
        self.assertEqual((status, body["disk_warn_percent"]), (200, 25))
        self.assertEqual(body["notice"], "")
        self.assertEqual(self.call("PUT", "/api/settings", {"macos": "yes"})[0], 422)
        status, body = self.call("PUT", "/api/settings", {"macos": True})
        self.assertEqual((status, body["macos"]), (200, True))
        self.assertIn("neu verbinden", body["notice"])
        self.assertTrue(self.call("GET", "/api/settings")[1]["macos"])
        self.call("PUT", "/api/settings", {"macos": False})


if __name__ == "__main__":
    unittest.main()
