# vpnmgr

A WireGuard VPN manager for AirVPN that keeps you on a *good* server instead of
a fixed one. It measures the fleet, ranks it, and re-checks every 30 minutes —
asking before it moves you, unless you tell it not to.

Written for machines you leave running: the daemon idles at a few megabytes of
RSS and does nothing between scheduled passes.

```
$ vpnmgr status
connected to Kornephoros (Toronto, Ontario, ca)
  interface : vpnmgr0
  endpoint  : 184.75.221.171:1637 (entry 3)
  handshake : 34s ago (healthy)
  transfer  : 1.2 GiB up, 8.4 GiB down

without VPN: 840 Mbps (measured 12m)

last sweep: 31/31 reachable in 4.2s, 380s ago
next tune: in 24m
```

## How it picks a server

Throughput-testing 257 servers would mean bringing up 257 tunnels, so the work
is done as a funnel where only the last stage is disruptive:

| Tier | What it does | Cost |
|---|---|---|
| 0 | Metadata filter — health, country/server lists, `max_load` | free |
| 1 | Real WireGuard handshake to every survivor, timed | ~4s for the fleet, no disconnect |
| 2 | Actual throughput on the top few candidates | seconds each, only on connect |

Tier 1 is the interesting one. It sends a genuine handshake initiation from an
ephemeral socket carrying the tunnel's own fwmark, so the packets take the
physical path while an existing tunnel stays up. That measures the true
WireGuard round trip, proves UDP/1637 is open, and proves your credentials are
accepted — without touching the connection you are using.

It also answers *"is it the VPN or my ISP?"* for free: because those probes
travel outside the tunnel, if every server is slow at once the problem is your
link, and the tuner deliberately does nothing rather than churning servers.

Ranking combines three terms, weighted 0.6 / 0.3 / 0.1 by default:

- **latency**, on a log curve — 5ms against 10ms matters, 200ms against 400ms
  does not, and a linear scale disagrees
- **headroom**, absolute spare capacity, judged against your own measured line
  rate rather than a constant
- **load**, the provider's own percentage

Headroom is absolute rather than fractional on purpose: AirVPN's `currentload`
*is* `bw / bw_max` — across the whole fleet the two never differ by more than a
percentage point — so scoring the fraction counted load twice under two names.
Two servers at 27% and 62% load can have 14.4 Gbps and 756 Mbps of room.

## Requirements

- Linux with the `wireguard` kernel module and systemd
- An AirVPN account
- glibc 2.35 or newer for the release binaries; any Rust 1.85+ toolchain to
  build from source

Windows support is designed for but not implemented — the tunnel backend is
behind a trait with a WireGuard-NT implementation still to come.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ac615223s5/vpnmgr/master/packaging/vpnmgr-update.sh \
  | sudo bash -s -- --conf /path/to/AirVPN.conf
```

Then add yourself to the `vpnmgr` group and log out and back in:

```bash
sudo usermod -aG vpnmgr $USER
```

The log out matters — group membership is fixed at login, and until then every
client, including the tray, is refused by the socket.

### Where the `.conf` comes from

AirVPN's Config Generator, WireGuard, UDP port **1637**. Pick any single
server; the file is only read once, to extract your keys.

That works because **every AirVPN server shares one WireGuard peer public
key**, and your client key is account-wide. So one config is enough to reach
the whole fleet: switching servers is a local endpoint change, with no API
call, no login, and no rate limit. The installer copies the private and
preshared keys into root-owned `0600` files under `/etc/vpnmgr` and never puts
them on a command line, where `ps` would show them.

### From source

```bash
git clone https://github.com/ac615223s5/vpnmgr
cd vpnmgr
sudo ./packaging/install.sh /path/to/AirVPN.conf
```

## Update

```bash
sudo vpnmgr-update            # fetch and install the newest release
vpnmgr-update --check         # report what is available, change nothing
sudo vpnmgr-update --version v0.1.0
```

Your config and keys are left alone. The tarball's SHA256 is checked against
the published checksum, and nothing is installed if they disagree.

The daemon restarts, which drops the tunnel. It is not brought back
automatically — reconnecting silently under a build you have not seen run is
worse than a connection you re-make deliberately.

## Usage

```
vpnmgr status                     current connection, line rate, next pass
vpnmgr connect [server]           best available, or one you name
vpnmgr connect --measure          measure the line first, then verify candidates
vpnmgr disconnect
vpnmgr test [--country ca]        probe and rank without connecting
vpnmgr ranking                    the last ranking, no probing
vpnmgr servers [--all]            what the filters allow, or the whole fleet
vpnmgr speedtest                  measure the current path
vpnmgr baseline --yes             VPN vs. no-VPN, back to back
vpnmgr killswitch on|off
vpnmgr reload                     re-read the config
```

There is also a tray (`vpnmgr-tray`, started at login) with the same controls,
a server picker showing latency, load and headroom, and somewhere for the
tuner to ask before it moves you.

## Configuration

`/etc/vpnmgr/config.toml`, root-owned. `vpnmgr reload` applies changes without
a restart, and keeps the old config if the new one does not parse.

```toml
[filters]
country_whitelist = ["ca"]      # empty = everywhere
country_blacklist = []
server_blacklist  = []
max_load = 85

[autotune]
interval_minutes      = 30
max_latency_ms        = 80
min_mbps              = 50.0
switch_policy         = "ask"   # ask | auto | never
improvement_threshold = 0.25
measure_before_connect = true
verify_candidates      = 5      # try the top N, take the first that clears the bar
# target_mbps  = 500.0          # unset = learned from your measured line rate
accept_fraction = 0.6           # a candidate must deliver this much of target

[autotune.weights]
rtt = 0.6
headroom = 0.3
load = 0.1

[killswitch]
enabled = false                 # fails closed: a dead daemon leaves you offline
allow_lan = true

[bypass]
cidrs = []                      # destinations that keep using the real link
hosts = []
other_vpns = true               # do not capture Tailscale, corporate tunnels, ...
```

The bypass list matters more than it looks. A default route through the tunnel
otherwise captures every other VPN on the machine — Tailscale installs its
route at a lower priority and simply stops working, silently.

## Safety properties

- **Keys never cross the socket.** The daemon runs as root and reads them from
  `0600` files itself. Nothing in the IPC protocol can carry key material, and
  no code path logs it.
- **The kill switch is nftables in its own table**, so it can be inspected and
  removed without touching your other rules. It fails closed.
- **Switching servers rotates the listen port.** Because the fleet shares one
  peer key, the kernel sees it as a single peer, and a displaced server can
  open a handshake indistinguishable from the intended one — which silently
  hijacks the endpoint back. Rotating the port on switch closes that.
- **Probes cannot leak.** They carry the tunnel's fwmark and are matched by a
  dedicated policy rule, so they leave on the physical interface whether or not
  a tunnel is up.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

Releases are cut by pushing a tag matching the workspace version:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The workflow refuses to publish if the tag and `Cargo.toml` disagree, runs the
tests and lints, unpacks the tarball it just built and checks it is installable
before creating the release.

## License

MIT. See [LICENSE](LICENSE).
