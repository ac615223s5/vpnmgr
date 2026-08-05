# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings   # release gate: warnings fail
cargo fmt --all --check                                  # release gate

cargo test -p vpnmgr-tunnel bypass          # one crate, filtered by name
cargo test -p vpnmgr-core a_country_whitelist_restricts_to_those_countries
cargo test -- --ignored                     # network tests: live AirVPN API, 25MB transfer
```

Install locally after changing daemon code — the running daemon is a *binary*, not the
source tree, so edits do nothing until installed and restarted:

```bash
cargo build --release
sudo install -m 0755 target/release/{vpnmgrd,vpnmgr,vpnmgr-tray} /usr/local/bin/
sudo systemctl restart vpnmgrd
```

The tray is a separate long-lived process and keeps running the *old* binary across an
install. It must be quit and relaunched to pick up UI changes.

### Examples are the debugging tools

Each does one thing against the live system without needing a tunnel up, which makes them
the fastest way to check behaviour that is otherwise only observable while connected:

```bash
cargo run -p vpnmgr-tunnel --example bypass_plan -- --lan --reserve 10.128.0.1
cargo run -p vpnmgr-probe --example live_sweep
cargo run -p vpnmgr-core --example inspect /path/to/airvpn.conf
```

### Releasing

Bump `version` in the root `Cargo.toml`, **rebuild so `Cargo.lock` updates** (it records
workspace crate versions; CI builds `--locked` and will fail otherwise), then tag:

```bash
git tag -a v0.1.2 -m "..." && git push origin master v0.1.2
```

The workflow refuses to publish if the tag and `Cargo.toml` disagree, and unpacks the
tarball it built to check it is installable before creating the release.

## Architecture

### Process model

`vpnmgrd` (root, systemd) owns the tunnel and *all* state. `vpnmgr` (CLI) and `vpnmgr-tray`
are unprivileged and stateless — every command is a round trip over a Unix socket at
`/run/vpnmgr/sock`, group `vpnmgr`, mode 0660. Access control is the socket's group
ownership; there is no other authentication.

**All privileged work lives in `crates/vpnmgrd/src/state.rs`.** If a feature needs root, it
belongs there and gets exposed through a new `Request` variant. Clients must never do
privileged work themselves.

Crate graph: `core` (no internal deps) ← `probe`, `tunnel` ← `vpnmgrd`. `ipc` is depended on
by `vpnmgrd`, `vpnmgr` and `vpnmgr-tray` and depends on nothing internal — it is the wire
contract and deliberately has no logic.

### The one fact the whole design rests on

**Every AirVPN server shares a single WireGuard peer public key**, and the client key is
account-wide. So one imported `.conf` reaches the entire fleet, and switching servers is a
local endpoint change — no API call, no auth, no rate limit.

Two consequences that are not obvious and have each caused a bug:

- The kernel sees the fleet as **one peer**. A server you just left can open a handshake
  indistinguishable from the intended one and silently take the endpoint back. `retarget()`
  in `linux.rs` rotates the listen port on every switch to close this.
- Roaming is self-correcting in the other direction: WireGuard updates a peer's endpoint
  from any authenticated packet, and `PersistentKeepalive = 15` bounds the window.

### The probe funnel

Testing throughput on 257 servers would mean 257 tunnels, so `state.rs` narrows first:
metadata filter (`core/filter.rs`, free) → real WireGuard handshake RTT to every survivor
(`probe`, no disconnect) → actual throughput on the top few (`verify_candidates`, only on
connect).

Tier 1 works because probe sockets carry the tunnel's own fwmark (`DEFAULT_FWMARK = 51820`)
and a policy rule sends marked traffic out the physical interface. This is why probes cannot
leak and why the tuner can tell "the VPN is slow" from "your link is slow" — if every server
is slow at once, the problem is local and it deliberately does nothing.

### Routing model

`defguard_wireguard_rs`'s `configure_peer_routing` installs two rules: `not fwmark 51820
lookup 51820`, and `table main suppress_prefixlength 0` ("use main, but ignore its default
route"). The tunnel's default route lives in table 51820.

Everything about bypassing the tunnel follows from that suppression rule: **anything with a
specific route in `main` wins outright**. A bypass is just such a route.

- Your *attached* subnet survives free — its interface installed a link route.
- Anything *routed* through your gateway does not. It travels by the default route, which is
  exactly what gets suppressed. This is why `bypass.lan` mirrors the private ranges, minus
  any range the tunnel itself occupies (AirVPN's nameserver is `10.128.0.1`, so `10.0.0.0/8`
  is normally withheld).
- Other VPNs keep their routes in private tables consulted *after* ours (Tailscale: table 52
  at priority 5270 vs. ours at 5205), so they are mirrored into `main` rather than reordering
  another tool's rules.

`configure_peer_routing` *adds* its rules unconditionally and only prunes on interface
removal — which a switch avoids — so `prune_duplicate_policy_rules` must run after any
retarget or the rule list grows without bound in a daemon that re-tunes every 30 minutes.

The kill switch (`killswitch.rs`, its own `inet vpnmgr` nftables table) and the bypass must
agree on what "LAN" means. They once did not, and the symptom was a destination that was
permitted by the firewall and unreachable anyway.

### State and its lifetime

`State` holds the ranking, per-server measured throughput, the measured no-VPN baseline and
the pending switch proposal **in memory only**. A daemon restart loses all of it — that is
intentional, but it means any feature reading those fields must handle their absence, and it
is why an update tells the user to reconnect rather than reconnecting itself.

Anything cached and later shown to the user must be re-filtered on `reload`, or a config
change appears to be ignored until the next sweep.

### Tuner

`crates/vpnmgrd/src/tuner.rs` is deliberately pure: `decide(&Assessment, &Autotune) ->
Decision`, no I/O. All the policy tests live there. `state.rs` gathers the facts and executes
the decision. Keep new policy in `decide`.

## Conventions that bite

- **Keys never cross the socket.** The daemon reads them from root-owned 0600 files itself.
  Nothing in `ipc` may carry key material, and no code path may log it.
- `Response` is **adjacently tagged** (`tag = "response", content = "data"`). Internal tagging
  silently cannot serialise sequence-valued variants, which rules out every list reply.
- Config structs use `deny_unknown_fields`, so renaming a key breaks existing installs —
  add `#[serde(alias = "old_name")]`. New fields need `#[serde(default)]` or a `default_*`
  function, and new `Request` fields need `#[serde(default)]` so an older client still works.
- `vpnmgr connect <name>` takes a named server at face value and bypasses the filters. That
  is deliberate: naming one is the user's explicit decision.
- Don't `pkill -f` a pattern that also appears in the command you are typing — it matches the
  shell running it and kills the session (exit 144). Use `pgrep -x` or bracket the pattern.
- Commit messages here explain *why* and state how the change was verified. Match that.

## Testing things that need a tunnel

Bringing the tunnel up affects the machine you are running on, including the network path
this session uses. Ask before connecting. When testing connected behaviour, run the test
detached with a `setsid` watchdog that disconnects unconditionally after a timeout, so a
dropped session cannot leave the tunnel up.

`packaging/` and the release workflow are exercised end to end by building the tarball the
way `.github/workflows/release.yml` does and installing from it — `install.sh` detects an
existing install and switches to update mode, keeping `/etc/vpnmgr`.

## Windows

Builds and runs. `PlatformTunnel` aliases the backend for the target, so `state.rs` names one
type; everything platform-specific is behind it.

The Windows backend does **not** use `defguard_wireguard_rs`. That crate's Windows path loads
`wireguard.dll` from a path relative to the working directory and `expect()`s it — a missing
DLL is a panic inside a `LazyLock` — and its `configure_peer`, `remove_peer` and
`configure_peer_routing` are all no-ops there. It drives the official `wireguard.exe` instead:

| | Windows |
|---|---|
| up | render a `.conf`, `wireguard.exe /installtunnelservice` |
| switch | `wg.exe set <if> peer <key> endpoint <addr>`, which retargets in place |
| down | `wireguard.exe /uninstalltunnelservice` |
| status | `wg.exe show <if> <field>` |

`wg show <if> dump` would answer everything in one call, but its **first field is the
interface private key**. The narrower per-field subcommands are used so the key never enters
a buffer this process owns.

The daemon is a service (`--install-service`, needs elevation) running as LocalSystem. The
SCM's control handler cannot await, so it notifies a `tokio::sync::Notify` that
`shutdown_signal` selects on — the same shutdown path as SIGTERM.

Access control is the named pipe's DACL, applied at creation in `ipc/transport.rs`:
`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)` — SYSTEM and Administrators full, interactive
users read/write. That last ACE is the counterpart of the `vpnmgr` group; without it a
LocalSystem service produces a pipe no ordinary user can open. `reject_remote_clients` is on.

A service runs in Session 0 and has no desktop, so it cannot raise a notification at all.
`notify::desktop` is therefore a no-op on Windows and the **tray** is what surfaces a pending
switch — it already polls.

The bypass and kill switch both exist on Windows, with the same API and different mechanics.

The bypass shares its planning with Linux — which ranges, which the tunnel occupies, which
other VPNs to mirror — and swaps only the commands: `netsh`/`Get-NetRoute` for `ip`. There is
no `suppress_prefixlength`; Windows simply takes the longest prefix, so a specific route beats
the tunnel's default for the same reason.

Two Windows-only hazards, both of which produced a working routing table and dead traffic:

- WireGuard for Windows enables **its own** WFP kill switch whenever a peer's `AllowedIPs` is
  exactly a default route, and those filters ignore the routing table. `split_default_routes`
  in `windows.rs` expresses the same coverage as `0.0.0.0/1` + `128.0.0.0/1` so they are not
  installed, but only when there is something to bypass.
- Windows Firewall evaluates **Block before Allow**, so our kill switch cannot be a blocking
  rule with exceptions. It sets the profile's default outbound action to Block and adds Allow
  rules, which is machine-wide state — hence the previous value is saved to disk, not memory.

`route print` is never parsed: it is localised, and its headings change with system language.

Reading the daemon's log on Windows means `--log-file`; a service has no console, so without
it every diagnostic goes to a handle nobody holds.

### Building on Windows

Needs MSVC Build Tools with the C++ workload. Note that Git Bash ships a GNU coreutils
`link.exe` that shadows MSVC's on `PATH`; if linking fails with "unexpected error", that is
usually why. `cargo check --target x86_64-unknown-linux-gnu` cross-checks most of the Linux
build from Windows, but not the crates pulling `ring` in through reqwest, which need a Linux
C compiler.
