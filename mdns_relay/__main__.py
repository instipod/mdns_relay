"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import signal
import socket
import sys

from aiohttp import web

from . import __version__
from .relay import Relay
from .rules import RuleFileError, RuleStore
from .transport import FAMILY_NAMES, MulticastTransport
from .web import LOOPBACK_HOSTS, WebApi

log = logging.getLogger("mdns_relay")

MIN_TOKEN_LENGTH = 16


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="mdns-relay",
        description="Relay mDNS between interfaces, only where a rule allows it.",
    )
    parser.add_argument("--rules-file", default="mdns-relay.json", help="where rules are stored")
    parser.add_argument(
        "--interface",
        action="append",
        dest="interfaces",
        metavar="NAME",
        help="use only this interface (repeatable); default is all eligible interfaces",
    )
    parser.add_argument("--http-host", default="127.0.0.1", help="web interface bind address")
    parser.add_argument("--http-port", type=int, default=8080, help="web interface port")
    parser.add_argument(
        "--auth-token",
        default=os.environ.get("MDNS_RELAY_AUTH_TOKEN"),
        help="web interface token, or set MDNS_RELAY_AUTH_TOKEN",
    )
    parser.add_argument(
        "--insecure-no-auth",
        action="store_true",
        help="allow a non-loopback web interface with no authentication",
    )
    parser.add_argument(
        "--no-browse",
        action="store_true",
        help="don't send this app's own discovery queries; only listen",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser.parse_args(argv)


def _is_loopback(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_web_security(args: argparse.Namespace) -> str | None:
    """Return an error message if the web settings would be unsafe."""
    if args.auth_token is not None and len(args.auth_token) < MIN_TOKEN_LENGTH:
        return f"--auth-token must be at least {MIN_TOKEN_LENGTH} characters"
    if (
        not _is_loopback(args.http_host)
        and args.auth_token is None
        and not args.insecure_no_auth
    ):
        return (
            f"--http-host {args.http_host} is not loopback: "
            "set --auth-token, or pass --insecure-no-auth to run without authentication"
        )
    return None


async def run(args: argparse.Namespace, store: RuleStore) -> int:
    relay = Relay(store, pinned_interfaces=args.interfaces, browse=not args.no_browse)
    loop = asyncio.get_running_loop()

    transports = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            transport = MulticastTransport(family, relay.handle_packet)
        except OSError as exc:
            log.warning("%s disabled: %s", FAMILY_NAMES[family], exc)
            continue
        transport.start(loop)
        relay.add_transport(family, transport)
        transports.append(transport)
    if not transports:
        log.error("could not open an mDNS socket for any IP family")
        return 1

    relay.sync_interfaces()
    log.info("active interfaces: %s", ", ".join(relay.active_names()) or "(none)")
    log.info("%d rule(s) loaded from %s", len(store.rules), store.path)

    allowed_hosts = LOOPBACK_HOSTS if _is_loopback(args.http_host) else None
    api = WebApi(relay, store, auth_token=args.auth_token, allowed_hosts=allowed_hosts)
    runner = web.AppRunner(api.build(), access_log=None, shutdown_timeout=1.0)
    await runner.setup()
    site = web.TCPSite(runner, args.http_host, args.http_port)
    try:
        await site.start()
    except OSError as exc:
        log.error("cannot start web interface on %s:%d: %s", args.http_host, args.http_port, exc)
        await runner.cleanup()
        for transport in transports:
            transport.close()
        return 1
    log.info("web interface: http://%s:%d/", args.http_host, args.http_port)

    stop = asyncio.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)

    relay_task = asyncio.create_task(relay.run())
    stop_task = asyncio.create_task(stop.wait())
    await asyncio.wait({relay_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
    exit_code = 0
    if relay_task.done() and not relay_task.cancelled() and relay_task.exception():
        log.error("relay stopped unexpectedly", exc_info=relay_task.exception())
        exit_code = 1
    relay_task.cancel()
    stop_task.cancel()
    await asyncio.gather(relay_task, stop_task, return_exceptions=True)
    await runner.cleanup()
    for transport in transports:
        transport.close()
    log.info("stopped")
    return exit_code


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not sys.platform.startswith("linux"):
        log.error("mdns-relay runs only on Linux")
        return 1
    problem = check_web_security(args)
    if problem:
        log.error("%s", problem)
        return 2

    store = RuleStore(args.rules_file)
    try:
        store.load()
    except RuleFileError as exc:
        # Starting anyway could silently change what is relayed, or overwrite
        # rules that might be recoverable.
        log.error("%s", exc)
        return 2

    return asyncio.run(run(args, store))


if __name__ == "__main__":
    sys.exit(main())
