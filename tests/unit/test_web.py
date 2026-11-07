import argparse
from unittest import IsolatedAsyncioTestCase
import socket
import tempfile
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

from mdns_relay.__main__ import check_web_security
from mdns_relay.interfaces import InterfaceInfo
from mdns_relay.relay import Relay
from mdns_relay.rules import RuleStore
from mdns_relay.web import WebApi

TOKEN = "correct-horse-battery-staple"
INTERFACES = [
    InterfaceInfo("prov", 1, True, False, True, ("10.0.1.1",)),
    InterfaceInfo("cli", 2, True, False, True, ("10.0.2.1",)),
]
RULE = {"service_type": "_http._tcp", "provider_iface": "prov", "client_iface": "cli"}


class FakeTransport:
    def join(self, ifindex):
        pass

    def leave(self, ifindex):
        pass

    def send(self, ifindex, data):
        pass


class WebCase(IsolatedAsyncioTestCase):
    auth_token = None
    allowed_hosts = None

    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "rules.json"
        self.store = RuleStore(self.path)
        self.relay = Relay(self.store, browse=False, interface_lister=lambda: INTERFACES)
        self.relay.add_transport(socket.AF_INET, FakeTransport())
        self.relay.sync_interfaces()
        api = WebApi(
            self.relay, self.store, auth_token=self.auth_token, allowed_hosts=self.allowed_hosts
        )
        self.client = TestClient(TestServer(api.build()))
        await self.client.start_server()
        self.addAsyncCleanup(self.client.close)


class TestRulesApi(WebCase):
    async def test_rule_lifecycle(self):
        response = await self.client.post("/api/rules", json=RULE)
        self.assertEqual(response.status, 201)
        created = await response.json()
        self.assertEqual(created["problems"], [])

        response = await self.client.patch(f"/api/rules/{created['id']}", json={"enabled": False})
        self.assertEqual(response.status, 200)
        self.assertFalse(self.store.rules[0].enabled)

        response = await self.client.delete(f"/api/rules/{created['id']}")
        self.assertEqual(response.status, 204)
        self.assertEqual(self.store.rules, ())

    async def test_validation_errors(self):
        response = await self.client.post("/api/rules", json={**RULE, "service_type": "bad"})
        self.assertEqual(response.status, 400)
        self.assertIn("service_type", (await response.json())["error"])
        self.assertEqual(self.store.rules, ())

        response = await self.client.post(
            "/api/rules", data="not json", headers={"Content-Type": "application/json"}
        )
        self.assertEqual(response.status, 400)
        response = await self.client.post("/api/rules", json=[1])
        self.assertEqual(response.status, 400)

    async def test_unknown_rule(self):
        self.assertEqual((await self.client.delete("/api/rules/none")).status, 404)
        response = await self.client.patch("/api/rules/none", json={"enabled": False})
        self.assertEqual(response.status, 404)

    async def test_problems_shown_for_missing_interface(self):
        response = await self.client.post("/api/rules", json={**RULE, "client_iface": "gone"})
        self.assertEqual(
            (await response.json())["problems"], ["Client interface gone does not exist"]
        )


class TestInterfacesApi(WebCase):
    async def test_toggle_interface(self):
        response = await self.client.patch("/api/interfaces/prov", json={"enabled": False})
        self.assertEqual(response.status, 200)
        self.assertEqual(self.relay.active_names(), ["cli"])
        data = await (await self.client.get("/api/interfaces")).json()
        states = {item["name"]: item["active"] for item in data["interfaces"]}
        self.assertEqual(states, {"prov": False, "cli": True})

    async def test_bad_requests(self):
        response = await self.client.patch("/api/interfaces/none", json={"enabled": False})
        self.assertEqual(response.status, 404)
        response = await self.client.patch("/api/interfaces/prov", json={"enabled": "no"})
        self.assertEqual(response.status, 400)

    async def test_pinned_interfaces_cannot_change(self):
        self.relay.pinned = frozenset({"prov", "cli"})
        response = await self.client.patch("/api/interfaces/prov", json={"enabled": False})
        self.assertEqual(response.status, 409)


class TestRequestChecks(WebCase):
    async def test_cross_origin_change_is_rejected(self):
        response = await self.client.post(
            "/api/rules", json=RULE, headers={"Origin": "http://evil.example"}
        )
        self.assertEqual(response.status, 403)
        self.assertEqual(self.store.rules, ())

    async def test_cross_site_fetch_metadata_is_rejected(self):
        for value in ("cross-site", "same-site"):
            response = await self.client.post(
                "/api/rules", json=RULE, headers={"Sec-Fetch-Site": value}
            )
            self.assertEqual(response.status, 403)
        self.assertEqual(self.store.rules, ())

    async def test_form_post_is_rejected(self):
        response = await self.client.post(
            "/api/rules",
            data="a=1",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(response.status, 415)
        response = await self.client.post(
            "/api/rules", data='{"a":1}', headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(response.status, 415)

    async def test_same_origin_change_is_accepted(self):
        origin = f"http://{self.client.host}:{self.client.port}"
        response = await self.client.post("/api/rules", json=RULE, headers={"Origin": origin})
        self.assertEqual(response.status, 201)

    async def test_page_and_security_headers(self):
        response = await self.client.get("/")
        self.assertEqual(response.status, 200)
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual((await self.client.get("/static/app.js")).status, 200)


class TestHostCheck(WebCase):
    allowed_hosts = {"localhost", "127.0.0.1", "::1"}

    async def test_rebound_host_is_rejected_for_reads_and_writes(self):
        headers = {"Host": "evil.example"}
        self.assertEqual((await self.client.get("/", headers=headers)).status, 403)
        self.assertEqual((await self.client.get("/api/rules", headers=headers)).status, 403)
        response = await self.client.post("/api/rules", json=RULE, headers=headers)
        self.assertEqual(response.status, 403)

    async def test_loopback_host_is_accepted(self):
        for host in ("localhost:8080", "127.0.0.1:8080", "[::1]:8080"):
            response = await self.client.get("/api/rules", headers={"Host": host})
            self.assertEqual(response.status, 200, host)


class TestAuth(WebCase):
    auth_token = TOKEN

    async def test_api_requires_token(self):
        for path in ("/api/rules", "/api/services", "/api/status", "/api/events", "/api/activity"):
            self.assertEqual((await self.client.get(path)).status, 401, path)
        self.assertEqual((await self.client.post("/api/rules", json=RULE)).status, 401)
        self.assertEqual(self.store.rules, ())

    async def test_static_page_loads_for_sign_in(self):
        self.assertEqual((await self.client.get("/")).status, 200)

    async def test_bearer_token(self):
        headers = {"Authorization": f"Bearer {TOKEN}"}
        self.assertEqual((await self.client.get("/api/rules", headers=headers)).status, 200)
        headers = {"Authorization": "Bearer wrong"}
        self.assertEqual((await self.client.get("/api/rules", headers=headers)).status, 401)

    async def test_login_sets_cookie(self):
        response = await self.client.post("/api/login", json={"token": "wrong"})
        self.assertEqual(response.status, 401)
        self.assertEqual((await self.client.get("/api/rules")).status, 401)

        response = await self.client.post("/api/login", json={"token": TOKEN})
        self.assertEqual(response.status, 200)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn(TOKEN, cookie)
        self.assertEqual((await self.client.get("/api/rules")).status, 200)


class TestStartupChecks(IsolatedAsyncioTestCase):
    def check(self, host, token=None, insecure=False):
        args = argparse.Namespace(http_host=host, auth_token=token, insecure_no_auth=insecure)
        return check_web_security(args)

    async def test_startup_checks(self):
        self.assertIsNone(self.check("127.0.0.1"))
        self.assertIsNone(self.check("localhost"))
        self.assertIsNone(self.check("::1"))
        self.assertIsNotNone(self.check("0.0.0.0"))
        self.assertIsNotNone(self.check("192.0.2.1"))
        self.assertIsNone(self.check("0.0.0.0", insecure=True))
        self.assertIsNone(self.check("0.0.0.0", token=TOKEN))
        self.assertIsNotNone(self.check("0.0.0.0", token="short"))
