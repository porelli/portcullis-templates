#!/usr/bin/env python3
"""Unit tests for headscale/vpn/glue.py against a fake Headscale REST API
(stdlib only, no container; lint runs them).

    python3 -m unittest discover -s tests/vpn -p 'test_*.py'
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
GLUE = os.path.join(HERE, "..", "..", "headscale", "vpn", "glue.py")
ISSUER = "https://auth.example.org/realms/portcullis"
API_KEY = "hskey-api-secret-value"
PREAUTH = "hskey-auth-minted-secret"
SUB = "0b5a1c2e-1111-4222-8333-444455556666"


def node(id_: int, name: str, ip: str, *, pid: str = "", tags: Optional[List[str]] = None, online: bool = True,
         expiry: Any = None, last_seen: Any = "2026-11-13T10:00:00.123456789Z") -> Dict[str, Any]:
    return {"id": str(id_), "name": name, "givenName": name, "ipAddresses": [ip, "fd7a:115c:a1e0::9"] if ip else ["fd7a::1"],
            "user": {"id": "1", "name": "u", "providerId": pid}, "tags": tags or [], "online": online,
            "lastSeen": last_seen, "expiry": expiry}


GW = node(1, "portcullis-gateway", "100.64.0.1", tags=["tag:portcullis-gateway"])


class FakeAPI:
    def __init__(self) -> None:
        self.nodes: List[Dict[str, Any]] = [GW]
        self.status = 200
        self.created: List[Dict[str, Any]] = []
        api = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def reply(self, code: int, body: Dict[str, Any]) -> None:
                b = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def authorised(self) -> bool:
                if api.status != 200 or self.headers.get("Authorization") != "Bearer " + API_KEY:
                    self.reply(api.status if api.status != 200 else 401, {"message": "Unauthorized " + API_KEY})
                    return False
                return True

            def do_GET(self) -> None:
                if self.authorised() and self.path == "/api/v1/node":
                    self.reply(200, {"nodes": api.nodes})

            def do_POST(self) -> None:
                if self.authorised() and self.path == "/api/v1/preauthkey":
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    api.created.append(body)
                    self.reply(200, {"preAuthKey": {"key": PREAUTH, **body}})

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class GlueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = FakeAPI()
        self.addCleanup(self.api.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        spec = importlib.util.spec_from_file_location("glue", GLUE)
        self.glue = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.glue)
        self.glue.RECORDS_PATH = os.path.join(self.tmp.name, "extra-records.json")
        self.glue.AUTHKEY_PATH = os.path.join(self.tmp.name, "authkey")
        env = {"HEADSCALE_API_KEY": API_KEY, "HEADSCALE_URL": self.api.url, "OIDC_ISSUER": ISSUER}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        self.addCleanup(lambda: [os.environ.pop(k) if v is None else os.environ.__setitem__(k, v) for k, v in old.items()])

    def run_glue(self, stdin: Any, *args: str) -> Tuple[int, str, str]:
        raw = stdin if isinstance(stdin, bytes) else json.dumps(stdin).encode()
        out, err = io.StringIO(), io.StringIO()
        code = 0
        old_stdin = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(raw))
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.glue.main(["glue.py", *args])
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
        finally:
            sys.stdin = old_stdin
        self.assertNotIn(API_KEY, out.getvalue() + err.getvalue())
        self.assertNotIn(PREAUTH, out.getvalue() + err.getvalue())
        return code, out.getvalue(), err.getvalue()

    def devices(self) -> Tuple[int, Dict[str, Any], str]:
        code, out, err = self.run_glue({"version": 1, "trigger": "vpn", "instance": "headscale", "op": "devices",
                                        "ranges": ["100.64.0.0/10"]})
        return code, (json.loads(out) if code == 0 else {}), err

    # devices

    def test_only_portcullis_users_nodes_are_devices(self) -> None:
        self.api.nodes += [
            node(2, "laptop", "100.64.0.2", pid=f"{ISSUER}/{SUB}", expiry="2027-01-01T00:00:00Z"),
            node(3, "local", "100.64.0.3"),                                          # a local Headscale user
            node(4, "other", "100.64.0.4", pid=f"https://evil.example/realms/portcullis/{SUB}"),
            node(5, "prefix", "100.64.0.5", pid=f"{ISSUER}x/{SUB}"),                 # issuer look-alike
            node(6, "tagged", "100.64.0.6", pid=f"{ISSUER}/{SUB}", tags=["tag:server"]),
            node(7, "nested", "100.64.0.7", pid=f"{ISSUER}/a/b"),
            node(8, "v6only", "", pid=f"{ISSUER}/{SUB}"),
            node(9, "zero", "100.64.0.9", pid=f"{ISSUER}/{SUB}", expiry="0001-01-01T00:00:00Z", last_seen=None),
        ]
        code, doc, err = self.devices()
        self.assertEqual(code, 0, err)
        self.assertEqual(doc["version"], 1)
        self.assertEqual(doc["gateway"], "100.64.0.1")
        self.assertEqual([d["id"] for d in doc["devices"]], ["2", "9"])
        d = doc["devices"][0]
        self.assertEqual(d, {"id": "2", "name": "laptop", "address": "100.64.0.2", "owner": SUB, "online": True,
                             "last_seen": "2026-11-13T10:00:00Z", "expires": "2027-01-01T00:00:00Z"})
        self.assertEqual((doc["devices"][1]["expires"], doc["devices"][1]["last_seen"]), (None, None))

    def test_expired_node_passes_its_expiry_through(self) -> None:
        self.api.nodes.append(node(2, "old", "100.64.0.2", pid=f"{ISSUER}/{SUB}", expiry="2020-01-01T00:00:00Z"))
        code, doc, _ = self.devices()
        self.assertEqual(code, 0)
        self.assertEqual(doc["devices"][0]["expires"], "2020-01-01T00:00:00Z")   # the Hub drops it

    def test_unreadable_times_leave_the_node_out(self) -> None:
        for bad in ("soon", "2026-11-13T10:00:00", 12):
            with self.subTest(bad=bad):
                self.api.nodes = [GW, node(2, "laptop", "100.64.0.2", pid=f"{ISSUER}/{SUB}", expiry=bad)]
                code, doc, err = self.devices()
                self.assertEqual((code, doc["devices"]), (0, []))
                self.assertIn("unreadable expiry", err)

    def test_no_gateway_fails(self) -> None:
        self.api.nodes = [node(2, "laptop", "100.64.0.2", pid=f"{ISSUER}/{SUB}")]
        code, _, err = self.devices()
        self.assertEqual(code, 1)
        self.assertIn("no gateway node", err)

    def test_two_online_gateways_fail(self) -> None:
        self.api.nodes.append(node(5, "gw2", "100.64.0.5", tags=["tag:portcullis-gateway"]))
        code, _, err = self.devices()
        self.assertEqual(code, 1)
        self.assertIn("ids 1, 5", err)

    def test_an_offline_old_gateway_is_ignored(self) -> None:
        self.api.nodes.append(node(5, "gw-old", "100.64.0.5", tags=["tag:portcullis-gateway"], online=False))
        code, doc, _ = self.devices()
        self.assertEqual((code, doc["gateway"]), (0, "100.64.0.1"))

    def test_missing_key_and_issuer(self) -> None:
        os.environ["HEADSCALE_API_KEY"] = ""
        code, _, err = self.devices()
        self.assertEqual(code, 1)
        self.assertIn("set the Headscale API key setting", err)
        os.environ["HEADSCALE_API_KEY"] = API_KEY
        os.environ["OIDC_ISSUER"] = ""
        self.assertEqual(self.devices()[0], 1)

    def test_rejected_key_names_the_fix_without_the_body(self) -> None:
        for status in (401, 403):
            with self.subTest(status=status):
                self.api.status = status
                code, _, err = self.devices()
                self.assertEqual(code, 1)
                self.assertIn("invalid or expired", err)
                self.assertNotIn("Unauthorized", err)

    def test_bad_stdin(self) -> None:
        for raw in (b"not json", b"[]", json.dumps({"version": True, "trigger": "vpn", "op": "devices"}).encode(),
                    json.dumps({"version": 1, "trigger": "start", "op": "devices"}).encode(),
                    json.dumps({"version": 1, "trigger": "vpn", "op": "nope"}).encode(), b"x" * (2 << 20)):
            with self.subTest(raw=raw[:40]):
                self.assertEqual(self.run_glue(raw)[0], 1)

    # dns

    def dns(self, records: Any) -> int:
        return self.run_glue({"version": 1, "trigger": "vpn", "instance": "headscale", "op": "dns", "records": records})[0]

    def test_dns_writes_exactly_the_records(self) -> None:
        recs = [{"name": "app.example.org", "type": "A", "value": "100.64.0.1"}, {"name": "example.org", "type": "A", "value": "100.64.0.1"}]
        self.assertEqual(self.dns(recs), 0)
        with open(self.glue.RECORDS_PATH, encoding="utf-8") as f:
            self.assertEqual(json.load(f), recs)
        self.assertEqual(oct(os.stat(self.glue.RECORDS_PATH).st_mode & 0o777), "0o644")
        self.assertEqual(sorted(os.listdir(self.tmp.name)), ["extra-records.json"])

    def test_dns_refuses_bad_records_and_keeps_the_file(self) -> None:
        good = [{"name": "app.example.org", "type": "A", "value": "100.64.0.1"}]
        self.assertEqual(self.dns(good), 0)
        for bad in ([{"name": "App.example.org", "type": "A", "value": "100.64.0.1"}],
                    [{"name": "app.example.org.", "type": "A", "value": "100.64.0.1"}],
                    [{"name": "app.example.org", "type": "A", "value": "100.064.0.1"}],
                    [{"name": "app.example.org", "type": "AAAA", "value": "::1"}],
                    [{"name": "app.example.org", "type": "A", "value": "100.64.0.1", "ttl": 5}],
                    [{"name": "app.example.org", "type": "A"}], "x", good + [None]):
            with self.subTest(bad=bad):
                self.assertEqual(self.dns(bad), 1)
                with open(self.glue.RECORDS_PATH, encoding="utf-8") as f:
                    self.assertEqual(json.load(f), good)

    # gateway-key

    def test_gateway_key_mints_a_tag_only_single_use_key(self) -> None:
        self.api.nodes = [dict(GW, online=False)]
        code, out, err = self.run_glue({"version": 1, "trigger": "start"}, "gateway-key")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.api.created), 1)
        body = self.api.created[0]
        self.assertEqual({k: body[k] for k in ("reusable", "ephemeral", "aclTags")},
                         {"reusable": False, "ephemeral": False, "aclTags": ["tag:portcullis-gateway"]})
        self.assertNotIn("user", body)
        import datetime
        exp = datetime.datetime.fromisoformat(body["expiration"].replace("Z", "+00:00"))
        left = exp - datetime.datetime.now(datetime.timezone.utc)
        self.assertTrue(datetime.timedelta(minutes=55) < left <= datetime.timedelta(hours=1), left)
        with open(self.glue.AUTHKEY_PATH, encoding="utf-8") as f:
            self.assertEqual(f.read(), PREAUTH)
        self.assertEqual(oct(os.stat(self.glue.AUTHKEY_PATH).st_mode & 0o777), "0o600")

    def test_gateway_key_while_online_mints_nothing_and_removes_the_file(self) -> None:
        with open(self.glue.AUTHKEY_PATH, "w", encoding="utf-8") as f:
            f.write("old")
        code, _, _ = self.run_glue({"version": 1, "trigger": "start"}, "gateway-key")
        self.assertEqual((code, self.api.created), (0, []))
        self.assertFalse(os.path.exists(self.glue.AUTHKEY_PATH))

    def test_gateway_key_without_the_api_key_waits(self) -> None:
        os.environ["HEADSCALE_API_KEY"] = ""
        code, _, err = self.run_glue({"version": 1, "trigger": "start"}, "gateway-key")
        self.assertEqual((code, self.api.created), (0, []))
        self.assertIn("first start after the Headscale API key", err)


if __name__ == "__main__":
    unittest.main()
