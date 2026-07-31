//! Destinations that must not travel through the tunnel.
//!
//! A full tunnel captures everything, which is usually the point and
//! occasionally a problem: it also captures the connection you are using to
//! work, and any other VPN you rely on.
//!
//! # How a bypass is expressed
//!
//! The tunnel's default route lives in its own policy table, reached by a rule
//! that first consults `main` with `suppress_prefixlength 0` — "use main, but
//! ignore its default route". Anything with a *specific* route in `main`
//! therefore wins outright. A bypass is just such a route.
//!
//! That is also why loopback needs no help: it is served by the `local` table
//! at rule priority 0, ahead of everything.
//!
//! # The local network needs more help than it looks
//!
//! Your own subnet survives on its own — the link route its interface installed
//! is specific, so the suppression leaves it alone. It is easy to conclude from
//! that the local network is fine, and wrong.
//!
//! Anything *routed* rather than *attached* has no such route. A machine on
//! `192.168.4.0/22` reaching a printer on `192.168.2.0/24` goes through the
//! gateway, which is to say via the default route — exactly the route the
//! tunnel suppresses. The printer becomes unreachable the moment you connect,
//! with nothing in the routing table to hint at why.
//!
//! So the private ranges are bypassed as a whole, minus any range the tunnel
//! itself occupies. That exception is not hypothetical: AirVPN hands out client
//! addresses in `10.128.0.0/9` and a nameserver at `10.128.0.1`, so bypassing
//! `10.0.0.0/8` outright would route the tunnel's own DNS at the local gateway
//! and break name resolution for everything.
//!
//! # Other VPNs do need help
//!
//! They are the case that looks like it should work and does not. Tailscale
//! keeps its routes in its own table (52 here) reached by a rule at priority
//! 5270, while the tunnel's rule sits at 5205. Lower number wins, so with the
//! tunnel up, traffic to a Tailscale peer is claimed by the tunnel before
//! Tailscale's rule is ever consulted, and the peer becomes unreachable.
//!
//! Rather than reorder another tool's rules, their destinations are copied into
//! `main`, where the suppression rule lets them through.
//!
//! # Hosts
//!
//! Names are resolved once, when the tunnel comes up. That is a real
//! limitation: a host behind a CDN answers with a rotating subset of a much
//! larger pool, so bypassing it by name catches only the addresses seen at that
//! moment. Bypass a CIDR when the destination's addresses move.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::process::{Command, Stdio};

/// Interface name prefixes treated as "another VPN".
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const VPN_INTERFACES: [&str; 6] = ["tailscale", "tun", "tap", "wg", "ppp", "zt"];

/// Prefixes that must never be mirrored into `main`.
///
/// Link-local and multicast are per-interface by definition: every interface
/// has an `fe80::/64`, and copying one interface's into the shared table would
/// send *every* interface's link-local traffic there, breaking IPv6 neighbour
/// discovery on the rest of the machine. They are already handled by the
/// `local` table, which is consulted first.
const NEVER_MIRROR: [&str; 4] = ["fe80:", "ff00:", "169.254.", "224.0.0."];

/// The private address space, as the ranges a bypass would install.
///
/// Deliberately the same set the kill switch calls "LAN". The two used to
/// disagree — the firewall accepted all of RFC1918 while the routing table sent
/// most of it into the tunnel — which is a contradiction that presents as a
/// destination that is allowed and still unreachable.
const PRIVATE_V4: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const PRIVATE_V6: [&str; 1] = ["fc00::/7"];

/// One route installed to keep a destination out of the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Prefix or single address, as `ip` spells it.
    pub destination: String,
    /// How to reach it.
    pub via: Via,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// Out of a specific interface, for point-to-point links like Tailscale.
    Device(String),
    /// Through the physical gateway, for ordinary internet destinations.
    Gateway { gateway: String, device: String },
}

impl Route {
    fn is_v6(&self) -> bool {
        self.destination.contains(':')
    }

    /// The destination as a prefix. A bare address from a resolved host has no
    /// length, and every tool that takes a route wants one.
    fn prefix(&self) -> String {
        if self.destination.contains('/') {
            self.destination.clone()
        } else if self.is_v6() {
            format!("{}/128", self.destination)
        } else {
            format!("{}/32", self.destination)
        }
    }

    #[cfg(target_os = "linux")]
    fn add_args(&self) -> Vec<String> {
        let mut args = vec!["route".into(), "add".into(), self.destination.clone()];
        match &self.via {
            Via::Device(dev) => {
                args.push("dev".into());
                args.push(dev.clone());
            }
            Via::Gateway { gateway, device } => {
                args.push("via".into());
                args.push(gateway.clone());
                args.push("dev".into());
                args.push(device.clone());
            }
        }
        args
    }
}

/// What to keep out of the tunnel.
///
/// A struct rather than a parameter list because two of these are adjacent
/// booleans, and `plan(cidrs, hosts, true, false, ...)` is a call nobody can
/// read or get right twice.
#[derive(Debug, Default, Clone, Copy)]
pub struct Request<'a> {
    /// Networks named in configuration.
    pub cidrs: &'a [String],
    /// Hostnames named in configuration, resolved when the tunnel comes up.
    pub hosts: &'a [String],
    /// Mirror the destinations served by other VPNs on this machine.
    pub other_vpns: bool,
    /// Keep the private address space on the physical link.
    pub lan: bool,
    /// Addresses the tunnel itself uses — its own interface addresses and its
    /// nameservers. Any private range containing one of these is left in the
    /// tunnel, where it belongs.
    pub tunnel_addresses: &'a [IpAddr],
    /// Our own interface, so it is never mistaken for another VPN to preserve.
    pub our_interface: &'a str,
}

/// The private ranges safe to bypass, given what the tunnel occupies.
///
/// A range is dropped whole rather than split around the conflict. Splitting
/// `10.0.0.0/8` around a nameserver would mean synthesising a dozen prefixes
/// whose only purpose is to look thorough; leaving the range alone is honest
/// about the fact that this tunnel lives there, and the `cidrs` list is the
/// place to name a specific subnet that still needs to escape.
fn lan_ranges(tunnel_addresses: &[IpAddr]) -> Vec<&'static str> {
    PRIVATE_V4
        .iter()
        .chain(PRIVATE_V6.iter())
        .copied()
        .filter(|range| {
            let conflict = tunnel_addresses
                .iter()
                .find(|addr| cidr_contains(range, **addr));
            if let Some(addr) = conflict {
                tracing::info!(
                    range,
                    %addr,
                    "not bypassing this private range: the tunnel itself uses an address in it"
                );
            }
            conflict.is_none()
        })
        .collect()
}

/// Whether `cidr` contains `addr`. Non-parsing input contains nothing, which
/// keeps a malformed constant from silently widening a bypass.
fn cidr_contains(cidr: &str, addr: IpAddr) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    match (network.parse::<IpAddr>(), addr) {
        (Ok(IpAddr::V4(net)), IpAddr::V4(addr)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(net) & mask == u32::from(addr) & mask
        }
        (Ok(IpAddr::V6(net)), IpAddr::V6(addr)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(net) & mask == u128::from(addr) & mask
        }
        _ => false,
    }
}

/// Tracks the routes installed for this tunnel, so they can be withdrawn.
#[derive(Debug, Default)]
pub struct Bypass {
    installed: Vec<Route>,
}

impl Bypass {
    pub fn new() -> Self {
        Self::default()
    }

    /// Work out what should bypass the tunnel.
    pub fn plan(request: &Request<'_>) -> Vec<Route> {
        let mut routes = Vec::new();

        if request.other_vpns {
            routes.extend(other_vpn_routes(request.our_interface));
        }

        // Explicit destinations need the physical gateway, which is whatever
        // `main` currently uses by default — the tunnel does not replace it,
        // it is only suppressed by a rule, so this stays correct while
        // connected.
        let gateways = default_gateways();

        if request.lan {
            for range in lan_ranges(request.tunnel_addresses) {
                if let Some(route) = via_gateway(range, &gateways) {
                    routes.push(route);
                }
            }
        }

        for cidr in request.cidrs {
            if let Some(route) = via_gateway(cidr, &gateways) {
                routes.push(route);
            }
        }
        for host in request.hosts {
            for addr in resolve(host) {
                let dest = match addr {
                    IpAddr::V4(a) => a.to_string(),
                    IpAddr::V6(a) => a.to_string(),
                };
                if let Some(route) = via_gateway(&dest, &gateways) {
                    routes.push(route);
                }
            }
        }

        routes.sort_by(|a, b| a.destination.cmp(&b.destination));
        routes.dedup();
        routes
    }

    /// Install `routes` into the main table.
    ///
    /// Routes that already exist are left alone and not recorded, so removing
    /// the bypass later cannot delete something the system set up itself.
    pub fn install(&mut self, routes: Vec<Route>) {
        for route in routes {
            if route_exists(&route) {
                tracing::debug!(
                    destination = %route.destination,
                    "already routed outside the tunnel; leaving it alone"
                );
                continue;
            }
            if sys_add(&route) {
                tracing::info!(destination = %route.destination, "bypassing the tunnel");
                self.installed.push(route);
            } else {
                tracing::warn!(
                    destination = %route.destination,
                    "could not install a bypass route; that destination will use the tunnel"
                );
            }
        }
    }

    /// Withdraw every route we installed. Safe to call more than once.
    pub fn remove(&mut self) {
        for route in self.installed.drain(..) {
            if !sys_del(&route) {
                tracing::debug!(
                    destination = %route.destination,
                    "bypass route was already gone"
                );
            }
        }
    }

    /// Destinations currently bypassing the tunnel.
    ///
    /// The kill switch needs these: it drops anything not leaving through the
    /// tunnel, which would otherwise include exactly the traffic we just went
    /// to the trouble of routing around it.
    pub fn destinations(&self) -> Vec<String> {
        self.installed
            .iter()
            .map(|r| r.destination.clone())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.installed.is_empty()
    }
}

impl Drop for Bypass {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Build a route to `destination` through whichever gateway suits its family.
fn via_gateway(destination: &str, gateways: &[(String, String, bool)]) -> Option<Route> {
    let want_v6 = destination.contains(':');
    let (gateway, device, _) = gateways.iter().find(|(_, _, v6)| *v6 == want_v6)?;
    Some(Route {
        destination: destination.to_owned(),
        via: Via::Gateway {
            gateway: gateway.clone(),
            device: device.clone(),
        },
    })
}

/// `(gateway, device, is_v6)` for each default route in the main table.
#[cfg(target_os = "linux")]
fn default_gateways() -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    for (flag, v6) in [("-4", false), ("-6", true)] {
        let Some(text) = ip_output(&[flag, "route", "show", "default"]) else {
            continue;
        };
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let (mut gateway, mut device) = (None, None);
            while let Some(token) = parts.next() {
                match token {
                    "via" => gateway = parts.next(),
                    "dev" => device = parts.next(),
                    _ => {}
                }
            }
            if let (Some(gateway), Some(device)) = (gateway, device) {
                out.push((gateway.to_owned(), device.to_owned(), v6));
                break;
            }
        }
    }
    out
}

/// Destinations served by other VPN interfaces, wherever their routes live.
///
/// Searches every routing table, not just `main`, because the tools that own
/// these interfaces generally keep their routes in a private table — which is
/// precisely why the tunnel preempts them.
#[cfg(target_os = "linux")]
fn other_vpn_routes(our_interface: &str) -> Vec<Route> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for flag in ["-4", "-6"] {
        let Some(text) = ip_output(&[flag, "route", "show", "table", "all"]) else {
            continue;
        };
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(destination) = parts.next() else {
                continue;
            };
            // A default route from another VPN would swallow everything and
            // defeat the tunnel entirely, so those are never mirrored.
            if destination == "default" || destination == "multicast" {
                continue;
            }
            // Skip the kernel's own local/broadcast bookkeeping.
            if matches!(
                destination,
                "local" | "broadcast" | "unreachable" | "prohibit"
            ) {
                continue;
            }
            if NEVER_MIRROR.iter().any(|p| destination.starts_with(p)) {
                continue;
            }

            let mut device = None;
            let mut parts = line.split_whitespace();
            while let Some(token) = parts.next() {
                if token == "dev" {
                    device = parts.next();
                }
            }
            let Some(device) = device else { continue };

            if device == our_interface || !is_vpn_interface(device) {
                continue;
            }
            if !seen.insert(destination.to_owned()) {
                continue;
            }
            out.push(Route {
                destination: destination.to_owned(),
                via: Via::Device(device.to_owned()),
            });
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn is_vpn_interface(name: &str) -> bool {
    VPN_INTERFACES.iter().any(|prefix| name.starts_with(prefix))
}

/// Whether `main` already routes this destination somewhere specific.
#[cfg(target_os = "linux")]
fn route_exists(route: &Route) -> bool {
    let flag = if route.is_v6() { "-6" } else { "-4" };
    ip_output(&[flag, "route", "show", &route.destination, "table", "main"])
        .is_some_and(|text| !text.trim().is_empty())
}

/// Resolve a hostname to every address it currently answers with.
fn resolve(host: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let found: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if found.is_empty() {
                tracing::warn!(host, "resolved to nothing; not bypassing it");
            }
            found
        }
        Err(e) => {
            tracing::warn!(host, "could not resolve for bypass: {e}");
            Vec::new()
        }
    }
}

#[cfg(target_os = "linux")]
fn ip_output(args: &[&str]) -> Option<String> {
    let output = Command::new("ip").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Install one route. Linux edits the `main` table directly.
#[cfg(target_os = "linux")]
fn sys_add(route: &Route) -> bool {
    run_ip(route.is_v6(), &route.add_args())
}

#[cfg(target_os = "linux")]
fn sys_del(route: &Route) -> bool {
    let args = vec![
        "route".to_owned(),
        "del".to_owned(),
        route.destination.clone(),
    ];
    run_ip(route.is_v6(), &args)
}

#[cfg(target_os = "linux")]
fn run_ip(v6: bool, args: &[String]) -> bool {
    Command::new("ip")
        .arg(if v6 { "-6" } else { "-4" })
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Asserts on `ip` argument construction, which only exists on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_gateway_route_names_both_gateway_and_device() {
        let gateways = vec![("192.168.1.1".into(), "eth0".into(), false)];
        let route = via_gateway("1.2.3.4", &gateways).expect("should build a route");
        assert_eq!(
            route.add_args(),
            vec![
                "route",
                "add",
                "1.2.3.4",
                "via",
                "192.168.1.1",
                "dev",
                "eth0"
            ]
        );
    }

    /// A v6 destination must not be sent through a v4 gateway, which `ip` would
    /// reject and which would silently leave the destination in the tunnel.
    // Asserts on `ip` argument construction, which only exists on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn address_families_are_not_mixed() {
        let v4_only = vec![("192.168.1.1".into(), "eth0".into(), false)];
        assert!(via_gateway("2001:db8::1", &v4_only).is_none());

        let v6 = vec![("fe80::1".into(), "eth0".into(), true)];
        let route = via_gateway("2001:db8::1", &v6).expect("should build a v6 route");
        assert!(route.is_v6());
    }

    // Asserts on `ip` argument construction, which only exists on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_device_route_omits_the_gateway() {
        let route = Route {
            destination: "100.64.0.0/10".into(),
            via: Via::Device("tailscale0".into()),
        };
        assert_eq!(
            route.add_args(),
            vec!["route", "add", "100.64.0.0/10", "dev", "tailscale0"]
        );
    }

    // Asserts on `ip` argument construction, which only exists on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn vpn_interfaces_are_recognised_by_name() {
        for name in ["tailscale0", "tun0", "wg0", "ppp0", "zt7x", "tap5"] {
            assert!(is_vpn_interface(name), "{name} should count as a VPN");
        }
        for name in ["eth0", "enx50a0300bcd0e", "wlp0s20f3", "lo", "docker0"] {
            assert!(!is_vpn_interface(name), "{name} should not count as a VPN");
        }
    }

    /// Our own interface starts with `wg`-like naming in some configurations,
    /// so it must be excluded explicitly rather than by pattern alone.
    #[test]
    fn our_own_interface_is_never_treated_as_another_vpn() {
        let routes = other_vpn_routes("vpnmgr0");
        assert!(
            routes.iter().all(|r| match &r.via {
                Via::Device(dev) => dev != "vpnmgr0",
                _ => true,
            }),
            "planned a bypass through the tunnel we are trying to escape"
        );
    }

    /// Every interface has its own `fe80::/64`. Copying one into the shared
    /// table would divert all link-local traffic to that interface and break
    /// neighbour discovery everywhere else.
    #[test]
    fn link_local_and_multicast_are_never_mirrored() {
        let routes = other_vpn_routes("vpnmgr0");
        for route in &routes {
            assert!(
                !NEVER_MIRROR
                    .iter()
                    .any(|p| route.destination.starts_with(p)),
                "{} should not be mirrored into main",
                route.destination
            );
        }
    }

    #[test]
    fn planning_is_deduplicated_and_ordered() {
        let cidrs = ["10.1.0.0/16".to_owned(), "10.1.0.0/16".to_owned()];
        let routes = Bypass::plan(&Request {
            cidrs: &cidrs,
            our_interface: "vpnmgr0",
            ..Default::default()
        });
        // Either the machine has no default route in a test environment, or the
        // duplicate collapsed; both are acceptable, a duplicate is not.
        assert!(
            routes.len() <= 1,
            "duplicate destinations were not collapsed"
        );
    }

    /// The bug this exists for: a private subnet reached through the gateway
    /// has no route of its own to survive the suppression, so without a LAN
    /// bypass it vanishes the moment the tunnel comes up.
    #[test]
    fn the_lan_bypass_covers_a_subnet_that_is_routed_rather_than_attached() {
        let ranges = lan_ranges(&[]);
        assert!(
            ranges.contains(&"192.168.0.0/16"),
            "a host on 192.168.2.0/24 would be swallowed by the tunnel"
        );
        assert_eq!(ranges.len(), PRIVATE_V4.len() + PRIVATE_V6.len());
    }

    /// AirVPN's nameserver is 10.128.0.1. Bypassing 10/8 would send the
    /// tunnel's own DNS to the local gateway, which answers for none of it.
    #[test]
    fn a_private_range_the_tunnel_lives_in_is_left_alone() {
        let dns: IpAddr = "10.128.0.1".parse().unwrap();
        let ranges = lan_ranges(&[dns]);
        assert!(
            !ranges.contains(&"10.0.0.0/8"),
            "would strand the tunnel DNS"
        );
        assert!(
            ranges.contains(&"192.168.0.0/16"),
            "unrelated ranges still apply"
        );
        assert!(ranges.contains(&"172.16.0.0/12"));
    }

    /// The client address is inside the tunnel too, and is the other way a
    /// range can turn out to be occupied.
    #[test]
    fn the_tunnels_own_address_also_reserves_its_range() {
        let addr: IpAddr = "10.129.64.12".parse().unwrap();
        assert!(!lan_ranges(&[addr]).contains(&"10.0.0.0/8"));
    }

    #[test]
    fn containment_respects_prefix_length_and_family() {
        assert!(cidr_contains(
            "192.168.0.0/16",
            "192.168.2.200".parse().unwrap()
        ));
        assert!(!cidr_contains(
            "192.168.0.0/16",
            "192.169.0.1".parse().unwrap()
        ));
        assert!(cidr_contains("10.0.0.0/8", "10.128.0.1".parse().unwrap()));
        assert!(!cidr_contains(
            "172.16.0.0/12",
            "172.32.0.1".parse().unwrap()
        ));
        assert!(cidr_contains(
            "172.16.0.0/12",
            "172.31.255.255".parse().unwrap()
        ));
        assert!(cidr_contains(
            "fc00::/7",
            "fd7a:115c:a1e0::1".parse().unwrap()
        ));
        // A v4 address is not inside a v6 range, however the bits line up.
        assert!(!cidr_contains("fc00::/7", "10.0.0.1".parse().unwrap()));
        // Malformed input must not widen anything.
        assert!(!cidr_contains("not-a-cidr", "10.0.0.1".parse().unwrap()));
        assert!(!cidr_contains(
            "10.0.0.0/notanumber",
            "10.0.0.1".parse().unwrap()
        ));
    }

    /// Tailscale's own range is inside `fc00::/7` and `100.64/10`; the LAN
    /// bypass must not claim its v6 ULA out from under it when Tailscale is
    /// the thing being preserved.
    #[test]
    fn lan_ranges_can_be_reserved_by_a_tunnel_ula() {
        let ula: IpAddr = "fd7a:115c:a1e0::cc35:213c".parse().unwrap();
        assert!(!lan_ranges(&[ula]).contains(&"fc00::/7"));
    }

    #[test]
    fn an_unresolvable_host_is_skipped_rather_than_failing_the_connect() {
        assert!(resolve("definitely-not-a-real-host.invalid").is_empty());
    }

    #[test]
    fn nothing_is_recorded_before_anything_is_installed() {
        let bypass = Bypass::new();
        assert!(bypass.is_empty());
        assert!(bypass.destinations().is_empty());
    }
}

// ---- Windows -------------------------------------------------------------
//
// The mechanism differs but the conclusion is the same. Windows has no policy
// rules and no `suppress_prefixlength`: it picks the route with the longest
// matching prefix, and breaks ties on metric. The tunnel's own route is a
// default, so *any* more specific route beats it outright — which is exactly
// what a bypass is, just as on Linux.
//
// Routes are added with `store=active`, so they live in memory only. A reboot
// clears them, which is right: the tunnel they were installed around will not
// have survived either, and a persistent bypass for a tunnel that is down is
// just a routing table nobody asked for.
//
// PowerShell rather than `route print`, because `route print` is localised --
// its column headings and the word "Gateway" change with the system language,
// and parsing them would work on this machine and fail on a German one.

#[cfg(target_os = "windows")]
mod win {
    use super::*;

    /// Interface alias fragments that mean "another VPN".
    ///
    /// Matched against the adapter's friendly name, which is what Windows
    /// exposes; there is no equivalent of Linux's `tun`/`wg` device naming.
    const VPN_ALIASES: [&str; 6] = [
        "tailscale",
        "wireguard",
        "wintun",
        "openvpn",
        "tap-",
        "zerotier",
    ];

    /// Run PowerShell and return stdout, or None if it failed.
    ///
    /// `-NoProfile` matters: a user profile that prints anything would end up
    /// parsed as route data.
    pub(super) fn ps(script: &str) -> Option<String> {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .stderr(Stdio::null())
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// `(gateway, interface index, is_v6)` for each usable default route.
    ///
    /// Excludes the tunnel's own default, which has no next hop -- WireGuard
    /// installs its default on-link. Picking that would route the bypass back
    /// into the tunnel it is meant to escape, which is the one outcome worth
    /// guarding against here.
    pub(super) fn default_gateways() -> Vec<(String, String, bool)> {
        let mut out = Vec::new();
        for (family, v6) in [("0.0.0.0/0", false), ("::/0", true)] {
            let script = format!(
                "Get-NetRoute -DestinationPrefix '{family}' -ErrorAction SilentlyContinue | \
                 Where-Object {{ $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' }} | \
                 Sort-Object RouteMetric | Select-Object -First 1 | \
                 ForEach-Object {{ \"$($_.NextHop)`t$($_.ifIndex)\" }}"
            );
            let Some(text) = ps(&script) else { continue };
            if let Some(line) = text.lines().next() {
                let mut parts = line.split('\t');
                if let (Some(gateway), Some(index)) = (parts.next(), parts.next()) {
                    let (gateway, index) = (gateway.trim(), index.trim());
                    if !gateway.is_empty() && !index.is_empty() {
                        out.push((gateway.to_owned(), index.to_owned(), v6));
                    }
                }
            }
        }
        out
    }

    /// Destinations served by other VPN adapters on this machine.
    pub(super) fn other_vpn_routes(our_interface: &str) -> Vec<Route> {
        let script = "Get-NetRoute -ErrorAction SilentlyContinue | \
                      ForEach-Object { \"$($_.DestinationPrefix)`t$($_.ifIndex)`t$($_.InterfaceAlias)\" }";
        let Some(text) = ps(script) else {
            return Vec::new();
        };

        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for line in text.lines() {
            let mut parts = line.split('\t');
            let (Some(destination), Some(index), Some(alias)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let (destination, index, alias) = (destination.trim(), index.trim(), alias.trim());

            // A default route from another VPN would swallow everything and
            // defeat the tunnel entirely.
            if destination == "0.0.0.0/0" || destination == "::/0" {
                continue;
            }
            if NEVER_MIRROR.iter().any(|p| destination.starts_with(p)) {
                continue;
            }
            let lower = alias.to_ascii_lowercase();
            if lower.contains(&our_interface.to_ascii_lowercase()) {
                continue;
            }
            if !VPN_ALIASES.iter().any(|p| lower.contains(p)) {
                continue;
            }
            if !seen.insert(destination.to_owned()) {
                continue;
            }
            out.push(Route {
                destination: destination.to_owned(),
                via: Via::Device(index.to_owned()),
            });
        }
        out
    }

    /// Whether this exact prefix is already routed.
    pub(super) fn route_exists(route: &Route) -> bool {
        let script = format!(
            "Get-NetRoute -DestinationPrefix '{}' -ErrorAction SilentlyContinue | \
             Select-Object -First 1 | ForEach-Object {{ 'yes' }}",
            route.prefix()
        );
        ps(&script).is_some_and(|s| s.trim() == "yes")
    }

    fn netsh(route: &Route, verb: &str, extra: &[String]) -> bool {
        let family = if route.is_v6() { "ipv6" } else { "ipv4" };
        let index = match &route.via {
            Via::Device(index) => index.clone(),
            Via::Gateway { device, .. } => device.clone(),
        };
        let mut args = vec![
            "interface".to_owned(),
            family.to_owned(),
            verb.to_owned(),
            "route".to_owned(),
            format!("prefix={}", route.prefix()),
            format!("interface={index}"),
        ];
        args.extend_from_slice(extra);
        match Command::new("netsh").args(&args).output() {
            Ok(out) if out.status.success() => true,
            Ok(out) => {
                // netsh reports "requires elevation" on stdout, not stderr, and
                // discarding it turns a fixable permission problem into an
                // unexplained "could not install a bypass route".
                let reason: String = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .chain(String::from_utf8_lossy(&out.stderr).lines())
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .unwrap_or("no output")
                    .to_owned();
                tracing::warn!(destination = %route.destination, "netsh {verb} route: {reason}");
                false
            }
            Err(e) => {
                tracing::warn!(destination = %route.destination, "could not run netsh: {e}");
                false
            }
        }
    }

    pub(super) fn add(route: &Route) -> bool {
        let mut extra = vec!["store=active".to_owned()];
        if let Via::Gateway { gateway, .. } = &route.via {
            extra.insert(0, format!("nexthop={gateway}"));
        }
        netsh(route, "add", &extra)
    }

    pub(super) fn del(route: &Route) -> bool {
        netsh(route, "delete", &["store=active".to_owned()])
    }
}

#[cfg(target_os = "windows")]
fn default_gateways() -> Vec<(String, String, bool)> {
    win::default_gateways()
}

#[cfg(target_os = "windows")]
fn other_vpn_routes(our_interface: &str) -> Vec<Route> {
    win::other_vpn_routes(our_interface)
}

#[cfg(target_os = "windows")]
fn route_exists(route: &Route) -> bool {
    win::route_exists(route)
}

#[cfg(target_os = "windows")]
fn sys_add(route: &Route) -> bool {
    win::add(route)
}

#[cfg(target_os = "windows")]
fn sys_del(route: &Route) -> bool {
    win::del(route)
}
