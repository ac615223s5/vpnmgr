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
//! That is also why some things need no help:
//!
//! * **Loopback** is served by the `local` table at rule priority 0, ahead of
//!   everything.
//! * **The local network** already has a specific route in `main` — the link
//!   route its interface installed — so it survives the suppression untouched.
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
const VPN_INTERFACES: [&str; 6] = ["tailscale", "tun", "tap", "wg", "ppp", "zt"];

/// Prefixes that must never be mirrored into `main`.
///
/// Link-local and multicast are per-interface by definition: every interface
/// has an `fe80::/64`, and copying one interface's into the shared table would
/// send *every* interface's link-local traffic there, breaking IPv6 neighbour
/// discovery on the rest of the machine. They are already handled by the
/// `local` table, which is consulted first.
const NEVER_MIRROR: [&str; 4] = ["fe80:", "ff00:", "169.254.", "224.0.0."];

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
    ///
    /// `cidrs` and `hosts` come from configuration; `include_other_vpns` adds
    /// the destinations served by any other VPN interface on the machine.
    pub fn plan(
        cidrs: &[String],
        hosts: &[String],
        include_other_vpns: bool,
        our_interface: &str,
    ) -> Vec<Route> {
        let mut routes = Vec::new();

        if include_other_vpns {
            routes.extend(other_vpn_routes(our_interface));
        }

        // Explicit destinations need the physical gateway, which is whatever
        // `main` currently uses by default — the tunnel does not replace it,
        // it is only suppressed by a rule, so this stays correct while
        // connected.
        let gateways = default_gateways();
        for cidr in cidrs {
            if let Some(route) = via_gateway(cidr, &gateways) {
                routes.push(route);
            }
        }
        for host in hosts {
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
            if run_ip(route.is_v6(), &route.add_args()) {
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
            let args = vec![
                "route".to_owned(),
                "del".to_owned(),
                route.destination.clone(),
            ];
            if !run_ip(route.is_v6(), &args) {
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

fn is_vpn_interface(name: &str) -> bool {
    VPN_INTERFACES.iter().any(|prefix| name.starts_with(prefix))
}

/// Whether `main` already routes this destination somewhere specific.
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

fn ip_output(args: &[&str]) -> Option<String> {
    let output = Command::new("ip").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

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
    #[test]
    fn address_families_are_not_mixed() {
        let v4_only = vec![("192.168.1.1".into(), "eth0".into(), false)];
        assert!(via_gateway("2001:db8::1", &v4_only).is_none());

        let v6 = vec![("fe80::1".into(), "eth0".into(), true)];
        let route = via_gateway("2001:db8::1", &v6).expect("should build a v6 route");
        assert!(route.is_v6());
    }

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
        let routes = Bypass::plan(
            &["10.1.0.0/16".into(), "10.1.0.0/16".into()],
            &[],
            false,
            "vpnmgr0",
        );
        // Either the machine has no default route in a test environment, or the
        // duplicate collapsed; both are acceptable, a duplicate is not.
        assert!(
            routes.len() <= 1,
            "duplicate destinations were not collapsed"
        );
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
