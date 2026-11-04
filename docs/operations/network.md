# Network features

## Pausing blocking

**Pause blocking** in the dashboard's header lets every device reach blocked domains for a set time,
up to a day. Blocking then comes back on its own, or as soon as you choose **Resume**.

- Emergency rules stay on during a pause, because they're for active incidents.
- A pause only lives in memory, so restarting the node ends it. It can't be left on by accident.
- Devices may keep a block they've already received for up to the block's cache time, which is 60
  seconds by default, under **Settings**.
- This also works when policy comes from a file, because a pause doesn't change the policy.

The API is `POST /api/v1/blocking/pause` with `{"seconds": 300}`, and `POST /api/v1/blocking/resume`.

## Identifying devices

A client can be identified by IP address or network, MAC address, or host name. When several match,
the narrowest wins, in this order: exact IP address, MAC address, host name, longest matching network.

```toml
[[clients]]
id = "tablet"
macs = ["aa:bb:cc:dd:ee:ff"]
groups = ["kids"]

[[clients]]
id = "laptop"
hostnames = ["laptop"]        # no dots, so it matches laptop.lan or laptop.home.arpa
```

**MAC addresses** come from the kernel's neighbor table, so they only work for devices on the same
network segment as this node. A device behind a router or VPN shows the router's MAC address, or
none. In a container, this needs host networking. Many phones use a private MAC address for each
network, and some change it over time, so turn that off for a device you want to identify this way.

**Host names** come from reverse lookups, so they need one of these:

- A [forward zone](#conditional-forwarding) for your network, so your router can answer. This is
  usually the easiest, and it's how most devices get a name.
- A local record. A local A or AAAA record for a private address also answers its reverse lookup.

Private addresses are never looked up through your public upstreams.

A device's first query waits up to 200 ms to find out who it is, but only if a client uses a MAC
address or host name. Later queries read from memory. MAC addresses refresh every 30 seconds and host
names every 5 minutes, so a change can take that long to apply. If the router can't answer for a
moment, a device keeps the host name it had.

**This isn't authentication.** A device can change its MAC address, and usually chooses the host name
it gives your router, so it could claim another device's identity and get its rules. Use these to
organize devices you trust, not to contain ones you don't.

## The network overview

**Network** lists devices the node can see in the neighbor table, whether or not they use it for
DNS, and any others that have sent it a query. Addresses that share a MAC address appear as one
device. **Name client** creates a client from a device, using its MAC address if it's known.

Devices with a MAC address are saved every minute, and are remembered for 90 days. Nothing is saved
when the query log mode is anything but **Full history**. Device history isn't included in backups.

## Conditional forwarding

A forward zone sends some names to specific servers instead of your upstreams. This is how local
names from a router or AD DNS keep working.

```toml
[[forward_zones]]
id = "router"
zones = ["lan", "192.168.1.0/24"]
servers = ["192.168.1.1"]
```

- A network sends its reverse lookups to these servers. It needs to be between /8 and /24 for IPv4, or
  /4 and /124 for IPv6.
- The most specific zone wins, and local zones this node manages always come first.
- A forward zone can take over names that are otherwise answered locally, such as private reverse
  lookups and `home.arpa`, but not `localhost`.
- Rules and lists still apply to forwarded names, and answers are cached.
- If the servers fail, the query fails. It's never retried with your upstreams, because that would
  send private names to them.
- With `--dnssec-validate`, forwarded names aren't validated, because private zones usually can't be.
- Servers use the same format as `--upstream`, so encrypted ones work. Don't point one at this node,
  which would make a loop.

## Load balancing

Servers are tried in order by default, so the later ones are only used if the earlier ones fail.
Turn on **Load balance** to share queries between them. It's a separate choice for each forward zone,
and for the upstreams under **Settings → DNS**.

```toml
[[forward_zones]]
id = "office"
zones = ["example.org"]
servers = ["10.0.0.5", "10.0.0.6"]
load_balance = true
```

- Each query that isn't answered from the cache starts on the next server, so servers get about the
  same number of queries, not the same amount of work.
- If a server doesn't respond, the query moves on to the next one. After two failures in a row it's set
  aside for 30 seconds, then tried again. A server that's set aside is still used if nothing else
  answers.
- All the servers need to give the same answers, or a name's answer will depend on which one was asked.

## Query limits

Each client address may send a limited number of queries per minute, 3,000 by default, and that's
also the largest burst. Past that, it's refused with `REFUSED` until it slows down, so that one
misbehaving device can't overload the node.

```toml
[rate_limit]
queries_per_minute = 3000     # 0 turns this off
exempt = ["127.0.0.0/8", "::1/128", "192.168.1.1"]
```

Loopback is exempt by default. If a router forwards a whole network's queries, every device looks
like one client, so add the router's address to `exempt`, or the whole network shares one limit.

Limits apply to each IP address, so a device with several IPv6 addresses has several allowances. Only
the first refused query from a client each minute is recorded in the query log, so a flood can't push
out real history. **System** shows the full count.

## NTP

`--ntp-listen`, or `FERRIXDNS_NTP_LISTEN`, shares this machine's clock with your network. It's off by
default, because port 123 is usually taken on machines that run a time server.

```sh
ferrixdns serve --ntp-listen 192.168.1.10:123 ...
```

- This doesn't set the clock. Keep a time service running to do that, such as `systemd-timesyncd`, which
  is only a client and doesn't use port 123. For chrony, set `port 0` so it doesn't serve NTP itself.
- When the kernel says nothing is keeping the clock accurate, replies say so too, and devices ignore
  them rather than follow a clock that may be wrong. **System** shows this state.
- It answers the same source networks as DNS, which is `--allow` or the default private networks.
- It tells any address sending over 120 requests a minute to slow down.
- This is for keeping devices' clocks right. It doesn't timestamp packets in the kernel, so don't use it
  for measurement or anything else that needs precise time.
