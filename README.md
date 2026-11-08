# mDNS Relay

Relays mDNS and SSDP between Linux network interfaces, but only where you've created a rule. It includes a web interface for seeing the services on each network and managing those rules.

With no rules, nothing is relayed.

## Install and run

Requires Linux and Python 3.11 or newer.

```sh
pip install .
mdns-relay --rules-file /var/lib/mdns-relay/rules.json
```

Then open <http://127.0.0.1:8080/>.

| Option | Default | Purpose |
|---|---|---|
| `--rules-file PATH` | `mdns-relay.json` | Where rules and interface settings are stored |
| `--interface NAME` | All eligible | Use only this interface. Repeat for more. Fixes the set of interfaces, so the web interface can't change it |
| `--http-host HOST` | `127.0.0.1` | Web interface bind address |
| `--http-port PORT` | `8080` | Web interface port |
| `--auth-token TOKEN` | None | Web interface token of 16 or more characters. Can also be set with `MDNS_RELAY_AUTH_TOKEN` |
| `--insecure-no-auth` | Off | Allow a non-loopback web interface with no authentication |
| `--no-browse` | Off | Don't send discovery queries; only listen |
| `--no-ssdp` | Off | Handle only mDNS, and don't open the SSDP port |
| `--log-level LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |

Root isn't required. A systemd unit is in `deploy/mdns-relay.service`.

On Alpine, install the OpenRC service instead:

```sh
addgroup -S mdns-relay
adduser -S -D -H -h /var/lib/mdns-relay -s /sbin/nologin -G mdns-relay mdns-relay
install -m 0755 deploy/mdns-relay.openrc /etc/init.d/mdns-relay
install -m 0600 deploy/mdns-relay.confd /etc/conf.d/mdns-relay
rc-update add mdns-relay default
rc-service mdns-relay start
```

Logs go to syslog. Set options and the auth token in `/etc/conf.d/mdns-relay`.

To run it in Docker, use `--network host`, or the relay will only see the container's own interface.

## How rules work

A rule makes a service on a **provider** interface discoverable by devices on a **client** interface:

```
Service type: _airplay._tcp
Instance:     Living*        (a pattern, or * for all)
Provider:     eth0
Client:       eth1
```

That rule relays queries from `eth1` to `eth0`, and responses from `eth0` to `eth1`. Devices on `eth1` can find the matching AirPlay devices. Services on `eth1` stay hidden from `eth0`. To share in both directions, add a second rule with the interfaces swapped.

Filtering applies to each record, not each packet. Anything a rule doesn't permit is removed from the relayed copy, and if nothing is left, nothing is sent.

Rule changes apply to the next packet, with no restart.

### What is never relayed

- Link-local addresses (`169.254.0.0/16`, `fe80::/10`), which don't work on another network
- Reverse-lookup records and names outside `.local`
- Name probes, so that devices on separate networks don't trigger name conflicts on each other
- Malformed packets, packets not sent to the mDNS multicast group, and packets with a source port other than 5353

When a query asks for a unicast reply, the relayed copy asks for a multicast reply instead, so the reply also passes through the rules.

## SSDP

SSDP rules work the same way, for UPnP and DLNA devices. Set `protocol` to `ssdp`. The service type is a search target, and the instance is a pattern matched against the device's USN:

```
Protocol:     ssdp
Service type: urn:schemas-upnp-org:device:MediaServer:1
Instance:     *
Provider:     eth0
Client:       eth1
```

Announcements (`NOTIFY`) go from the provider to the client network if a rule matches their NT and USN. Searches (`M-SEARCH`) go from the client to the provider network if a rule matches their search target; a search for `ssdp:all` needs any SSDP rule for that pair of interfaces. The relay sends each search from a short-lived socket of its own, checks each unicast reply against the rules, and forwards permitted replies to the client that searched.

A device advertises itself under several types, each with its own message. A rule for one device type doesn't pass the same device's `upnp:rootdevice` or `uuid:` messages, so use `*` if a client looks for those.

Also never relayed over SSDP:

- A message whose `LOCATION`, `AL` or `SECURELOCATION.UPNP.ORG` URL isn't an IP address, is link-local, or names a different host from the packet's source address. IPv6 devices that send from a link-local address are therefore not relayed
- Malformed messages, and messages not sent to the SSDP multicast group
- Replies arriving on a different interface from the one the search went out on

## What it sends without a rule

The app sends its own discovery queries on active interfaces, so the Services list fills in without waiting for devices to announce themselves. They start frequently and settle at one round per minute. It does the same with an SSDP `ssdp:all` search. These queries stay on the interface they're sent on and are never relayed. Use `--no-browse` to turn them off.

## Limitations

- **Discovery only.** The relay makes a service discoverable but doesn't carry its traffic. Clients still need a route and firewall access to the service's IP address and port.
- **No relaying to programs on the same host.** Relayed packets are sent with multicast loopback off, so Avahi running on the relay host won't see them.
- **Legacy unicast clients aren't supported.** Their queries come from a port other than 5353, and replies couldn't get back through the relay.
- **SSDP event callbacks aren't carried.** Clients need a route to the device's `LOCATION` address and port, and UPnP eventing also needs the device to be able to reach the client.
- **Firewalls and SSDP.** A firewall on the relay host must allow replies to the relay's search sockets, which use ephemeral ports.
- **Sharing a host with a UPnP daemon.** Both programs can listen on port 1900 and both receive multicast. A unicast packet sent to the host on that port reaches only one of them.
- **Downgrading.** Rules files written by this version contain `protocol`, which older versions reject.
- **Sharing a host with Avahi.** Both programs can listen on port 5353 and both receive multicast. A unicast packet sent to the host on that port reaches only one of them.

## Web interface security

Rule changes affect your network, so the web interface is restricted by default:

- It binds to loopback unless you choose another address, and on loopback it rejects requests with any other `Host` header. This blocks DNS rebinding attacks.
- A non-loopback address requires `--auth-token`, or an explicit `--insecure-no-auth`.
- Changes must be JSON and same-origin.

The token and session cookie travel unencrypted over plain HTTP. To reach the interface across an untrusted network, put it behind an HTTPS reverse proxy.

## Rules file

A missing file means no rules. A file that can't be read or validated stops startup with an error and is left untouched, rather than starting with different rules from those you expect.

## Development

Unit tests can run on any OS:

```sh
pip install ".[dev]"
pytest tests/unit
```

Integration tests use real packets across network namespaces, so they need a privileged Linux container:

```sh
docker build -t mdns-relay-test .
docker run --rm --privileged mdns-relay-test python -m pytest tests/integration -v
docker run --rm --privileged mdns-relay-test sh tests/integration/avahi_check.sh
```

`tests/integration/demo.sh` runs the app with simulated networks and services for trying out the web interface:

```sh
docker run --rm --privileged -p 8080:8080 mdns-relay-test sh tests/integration/demo.sh
```
