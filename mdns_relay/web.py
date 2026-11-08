"""REST API, server-sent events and static web interface."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import web

from .relay import Relay
from .rules import RuleError, RuleStore

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
COOKIE_NAME = "mdns_relay_session"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
EVENT_POLL_SECONDS = 1.0
EVENT_HEARTBEAT_SECONDS = 15.0
_MUTATING = {"POST", "PATCH", "PUT", "DELETE"}


def _error(status: int, message: str) -> web.Response:
    return web.json_response({"error": message}, status=status)


def _session_value(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _hostname(host_header: str) -> str:
    return (urlsplit(f"//{host_header}").hostname or "").lower()


class WebApi:
    def __init__(
        self,
        relay: Relay,
        store: RuleStore,
        *,
        auth_token: str | None = None,
        allowed_hosts: set[str] | None = LOOPBACK_HOSTS,
    ) -> None:
        self.relay = relay
        self.store = store
        self.auth_token = auth_token
        # None allows any Host header. Requiring an auth token, or an explicit
        # opt-out, is how non-loopback binds are protected instead.
        self.allowed_hosts = allowed_hosts

    def _authorized(self, request: web.Request) -> bool:
        if self.auth_token is None:
            return True
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer ") and hmac.compare_digest(
            header[7:].encode(), self.auth_token.encode()
        ):
            return True
        cookie = request.cookies.get(COOKIE_NAME, "")
        return hmac.compare_digest(cookie.encode(), _session_value(self.auth_token).encode())

    @web.middleware
    async def security_middleware(self, request: web.Request, handler) -> web.StreamResponse:
        # A Host check stops DNS rebinding from reaching a loopback-only server.
        if (
            self.allowed_hosts is not None
            and _hostname(request.host) not in self.allowed_hosts
        ):
            return _error(403, "Host not allowed")

        if request.method in _MUTATING:
            fetch_site = request.headers.get("Sec-Fetch-Site")
            if fetch_site not in (None, "same-origin", "none"):
                return _error(403, "Cross-site request rejected")
            origin = request.headers.get("Origin")
            if origin is not None and urlsplit(origin).netloc.lower() != request.host.lower():
                return _error(403, "Cross-origin request rejected")
            if request.method != "DELETE" and request.content_type != "application/json":
                return _error(415, "Content-Type must be application/json")

        path = request.path
        if path.startswith("/api/") and path != "/api/login" and not self._authorized(request):
            return _error(401, "Authentication required")

        response = await handler(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        if path == "/" or path.startswith("/static/"):
            # Revalidate, so an upgrade can't leave an old script talking to a new server.
            response.headers["Cache-Control"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    async def _json_object(self, request: web.Request) -> dict:
        try:
            data = await request.json()
        except json.JSONDecodeError as exc:
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Body is not valid JSON"}),
                content_type="application/json",
            ) from exc
        if not isinstance(data, dict):
            raise web.HTTPBadRequest(
                text=json.dumps({"error": "Body must be a JSON object"}),
                content_type="application/json",
            )
        return data

    async def index(self, request: web.Request) -> web.FileResponse:
        return web.FileResponse(STATIC_DIR / "index.html")

    async def login(self, request: web.Request) -> web.Response:
        if self.auth_token is None:
            return web.json_response({"ok": True})
        data = await self._json_object(request)
        token = data.get("token")
        if not isinstance(token, str) or not hmac.compare_digest(
            token.encode(), self.auth_token.encode()
        ):
            return _error(401, "Incorrect token")
        response = web.json_response({"ok": True})
        response.set_cookie(
            COOKIE_NAME,
            _session_value(self.auth_token),
            httponly=True,
            samesite="Strict",
            path="/",
        )
        return response

    def _rule_json(self, rule) -> dict:
        return {**rule.to_dict(), "problems": self.relay.rule_status(rule)}

    async def status(self, request: web.Request) -> web.Response:
        relay = self.relay
        return web.json_response(
            {
                "uptime": round(relay.clock() - relay.started),
                "browse": relay.browse,
                "interfaces_pinned": relay.pinned is not None,
                "active_interfaces": relay.active_names(),
                "rule_count": len(self.store.rules),
                "ssdp": relay.ssdp is not None,
                "service_count": len(relay.service_snapshot()),
                "counters": dict(relay.counters),
            }
        )

    async def services(self, request: web.Request) -> web.Response:
        relay = self.relay
        items = relay.service_snapshot()
        for item in items:
            item["relayed_to"] = relay.relay_targets(item)
        return web.json_response({"services": items})

    async def activity(self, request: web.Request) -> web.Response:
        return web.json_response({"activity": list(reversed(self.relay.activity))})

    async def interfaces(self, request: web.Request) -> web.Response:
        relay = self.relay
        active = set(relay.active_names())
        items = []
        for info in sorted(relay.interfaces.values(), key=lambda i: i.name):
            eligible = info.up and info.multicast and not info.loopback
            items.append(
                {
                    "name": info.name,
                    "up": info.up,
                    "loopback": info.loopback,
                    "multicast": info.multicast,
                    "ipv4": list(info.ipv4),
                    "ipv6": list(info.ipv6),
                    "eligible": eligible,
                    "active": info.name in active,
                    "counters": dict(relay.interface_counters.get(info.name, {})),
                }
            )
        return web.json_response({"interfaces": items, "pinned": relay.pinned is not None})

    async def patch_interface(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if self.relay.pinned is not None:
            return _error(409, "Interfaces are fixed by the --interface option")
        if name not in self.relay.interfaces:
            return _error(404, "Unknown interface")
        data = await self._json_object(request)
        enabled = data.get("enabled")
        if set(data) != {"enabled"} or not isinstance(enabled, bool):
            return _error(400, "Body must be {\"enabled\": true|false}")
        self.store.set_interface_enabled(name, enabled)
        self.relay.sync_interfaces()
        return web.json_response({"name": name, "enabled": enabled})

    async def list_rules(self, request: web.Request) -> web.Response:
        return web.json_response({"rules": [self._rule_json(r) for r in self.store.rules]})

    async def create_rule(self, request: web.Request) -> web.Response:
        data = await self._json_object(request)
        try:
            rule = self.store.add(data)
        except RuleError as exc:
            return _error(400, str(exc))
        log.info("rule added: %s", rule)
        return web.json_response(self._rule_json(rule), status=201)

    async def update_rule(self, request: web.Request) -> web.Response:
        data = await self._json_object(request)
        try:
            rule = self.store.update(request.match_info["id"], data)
        except RuleError as exc:
            return _error(400, str(exc))
        if rule is None:
            return _error(404, "Unknown rule")
        log.info("rule updated: %s", rule)
        return web.json_response(self._rule_json(rule))

    async def delete_rule(self, request: web.Request) -> web.Response:
        rule_id = request.match_info["id"]
        if not self.store.delete(rule_id):
            return _error(404, "Unknown rule")
        log.info("rule deleted: %s", rule_id)
        return web.Response(status=204)

    async def events(self, request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse(
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
            }
        )
        await response.prepare(request)
        last_version = None
        idle = 0.0
        try:
            while True:
                version = self.relay.state_version
                if version != last_version:
                    last_version = version
                    idle = 0.0
                    await response.write(b"event: update\ndata: {}\n\n")
                elif idle >= EVENT_HEARTBEAT_SECONDS:
                    idle = 0.0
                    await response.write(b": heartbeat\n\n")
                await asyncio.sleep(EVENT_POLL_SECONDS)
                idle += EVENT_POLL_SECONDS
        except ConnectionResetError:
            pass
        return response

    def build(self) -> web.Application:
        app = web.Application(middlewares=[self.security_middleware], client_max_size=64 * 1024)
        app.add_routes(
            [
                web.get("/", self.index),
                web.static("/static", STATIC_DIR),
                web.post("/api/login", self.login),
                web.get("/api/status", self.status),
                web.get("/api/services", self.services),
                web.get("/api/activity", self.activity),
                web.get("/api/events", self.events),
                web.get("/api/interfaces", self.interfaces),
                web.patch("/api/interfaces/{name}", self.patch_interface),
                web.get("/api/rules", self.list_rules),
                web.post("/api/rules", self.create_rule),
                web.patch("/api/rules/{id}", self.update_rule),
                web.delete("/api/rules/{id}", self.delete_rule),
            ]
        )
        return app
