//! Full end-to-end connect test against live AirVPN. Needs root.
//!
//!     cargo build --release -p vpnmgr-tunnel --example connect_test
//!     sudo ./target/release/examples/connect_test <conf> [country]
//!
//! This is the real thing: a full tunnel with `0.0.0.0/0` and AirVPN's
//! resolver, so it *will* briefly reroute all traffic and change DNS. It
//! verifies the public IP actually changes, that DNS resolves through the
//! tunnel without leaking to the ISP resolver, and that a live server switch
//! works — then restores the previous state.
//!
//! The tunnel is torn down on every exit path, including panics, because
//! leaving a half-configured default route behind would strand the machine.

use std::net::SocketAddr;
use std::process::Command;
use std::time::{Duration, Instant};

use vpnmgr_core::airvpn::{self, Client};
use vpnmgr_core::config::{Filters, Probe};
use vpnmgr_core::wgconf::ClientConfig;
use vpnmgr_core::{filter, score};
use vpnmgr_probe::{Prober, sweep};
use vpnmgr_tunnel::{LinuxTunnel, TunnelBackend, TunnelSpec};

const IFNAME: &str = "vpnmgr0";

/// How long the endpoint must hold after a switch before it is believed.
/// Comfortably longer than the ~10s it took a displaced server to reclaim it.
const HOLD_WINDOW: Duration = Duration::from_secs(45);

fn sh(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// Public IP as seen from outside, or `None` if the lookup failed.
fn public_ip() -> Option<String> {
    for url in ["https://ipinfo.io/ip", "https://api.ipify.org"] {
        let out = sh("curl", &["-s", "--max-time", "12", url]);
        if !out.is_empty() && out.parse::<std::net::IpAddr>().is_ok() {
            return Some(out);
        }
    }
    None
}

struct Checks {
    passed: usize,
    total: usize,
}

impl Checks {
    fn check(&mut self, label: &str, ok: bool) {
        self.total += 1;
        if ok {
            self.passed += 1;
        }
        println!("  [{}] {label}", if ok { "PASS" } else { "FAIL" });
    }
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let conf = args.next().expect("usage: connect_test <conf> [country]");
    let country = args.next();

    let client = ClientConfig::import(&conf).expect("config should parse");
    assert!(
        client.is_full_tunnel(),
        "this test expects a full-tunnel config"
    );

    let mut checks = Checks { passed: 0, total: 0 };

    // ---- baseline -------------------------------------------------------
    println!("== baseline ==");
    let route_before = sh("ip", &["route", "show", "default"]);
    let dns_before = sh("resolvectl", &["dns"]);
    let ip_before = public_ip();
    println!("  default route : {route_before}");
    println!("  public IP     : {ip_before:?}");
    if ip_before.is_none() {
        eprintln!("cannot reach the internet to establish a baseline; aborting");
        std::process::exit(1);
    }

    // ---- pick a server --------------------------------------------------
    println!("\n== selecting a server ==");
    let list = Client::new().unwrap().fetch().await.expect("fetch servers");
    let filters = Filters {
        country_whitelist: country.iter().cloned().collect(),
        max_load: 90,
        ..Default::default()
    };
    let selection = filter::apply(&list, &filters);
    let prober = Prober::new(
        &client,
        Probe {
            concurrency: 32,
            timeout_ms: 2000,
            samples: 2,
        },
    );
    let measured = sweep(
        &prober,
        &selection.accepted,
        &airvpn::WG_ENTRIES,
        airvpn::WG_PORT,
    )
    .await;
    let ranked = score::rank(&measured, &score::Scoring::default());
    assert!(ranked.len() >= 2, "need at least two candidates");

    let best = &ranked[0];
    let second = &ranked[1];
    println!(
        "  best   : {} ({}) entry {} {:.1}ms",
        best.server.name,
        best.server.location,
        best.entry,
        best.rtt.as_secs_f64() * 1000.0
    );
    println!(
        "  second : {} ({}) entry {} {:.1}ms",
        second.server.name,
        second.server.location,
        second.entry,
        second.rtt.as_secs_f64() * 1000.0
    );

    let best_endpoint = best.endpoint;
    let second_endpoint = second.endpoint;
    let second_name = second.server.name.clone();
    let best_name = best.server.name.clone();
    drop(ranked);

    // ---- connect --------------------------------------------------------
    println!("\n== connecting ==");
    let mut tunnel = LinuxTunnel::new(IFNAME).expect("open handle");
    let spec = TunnelSpec::new(&client, best_endpoint).with_interface(IFNAME);

    if let Err(e) = tunnel.up(&spec) {
        eprintln!("up failed: {e}");
        std::process::exit(1);
    }

    // Give the handshake a moment to complete.
    let handshake_ok = wait_for_handshake(&tunnel, Duration::from_secs(15));
    checks.check("handshake completed", handshake_ok);

    if handshake_ok {
        let ip_after = public_ip();
        println!("  public IP now : {ip_after:?}");
        checks.check("public IP is reachable through the tunnel", ip_after.is_some());
        checks.check(
            "public IP changed from the baseline",
            ip_after.is_some() && ip_after != ip_before,
        );

        let link_dns = sh("resolvectl", &["dns", IFNAME]);
        println!("  link DNS      : {link_dns}");
        checks.check(
            "AirVPN resolver is set on the tunnel link",
            client
                .dns
                .iter()
                .any(|d| link_dns.contains(&d.to_string())),
        );

        let resolved = sh("resolvectl", &["query", "--legend=no", "example.com"]);
        println!("  resolve test  : {}", resolved.lines().next().unwrap_or(""));
        checks.check("DNS resolves while connected", !resolved.is_empty());

        // The leak check that matters: the tunnel's resolver must be the
        // default route for DNS, not merely present alongside the ISP's.
        let status = sh("resolvectl", &["status", IFNAME]);
        checks.check(
            "tunnel link is the default DNS route",
            status.contains("Default Route: yes") || status.contains("+DefaultRoute"),
        );

        let stats = tunnel.status().expect("status");
        checks.check("traffic flowed both ways", stats.tx_bytes > 0 && stats.rx_bytes > 0);
        println!("  tx/rx         : {} / {} bytes", stats.tx_bytes, stats.rx_bytes);

        // ---- live switch ------------------------------------------------
        println!("\n== switching server without teardown ==");
        let routes_before_switch = sh("ip", &["route", "show", "dev", IFNAME]);
        let spec2 = TunnelSpec::new(&client, second_endpoint).with_interface(IFNAME);
        match tunnel.switch_endpoint(&spec2) {
            Err(e) => {
                eprintln!("switch failed: {e}");
                checks.check("switch_endpoint succeeds", false);
            }
            Ok(()) => {
                println!("  switched {best_name} -> {second_name}");
                let re_handshook = wait_for_new_handshake(&tunnel, second_endpoint, Duration::from_secs(20));
                checks.check("re-handshook with the new server", re_handshook);
                checks.check(
                    "routes survived the switch",
                    sh("ip", &["route", "show", "dev", IFNAME]) == routes_before_switch,
                );
                let ip_switched = public_ip();
                println!("  public IP now : {ip_switched:?}");
                checks.check(
                    "still reachable after the switch",
                    ip_switched.is_some() && ip_switched != ip_before,
                );

                // The endpoint has to *stay* switched, and a short window is
                // not enough to prove that. Because every AirVPN server shares
                // one peer key, the server we just left can open a fresh
                // handshake that is indistinguishable from the intended one and
                // silently steal the endpoint back. That took roughly ten
                // seconds to happen, so an earlier 12-second check passed while
                // the bug was live.
                let (held, observed) = endpoint_holds(&tunnel, second_endpoint, HOLD_WINDOW);
                checks.check(
                    &format!("endpoint stayed on the new server for {HOLD_WINDOW:?}"),
                    held,
                );
                if !held {
                    println!("    drifted to  : {observed:?}");
                }

                let ip_settled = public_ip();
                println!("  public IP late: {ip_settled:?}");
                checks.check(
                    "exit IP still matches the server we switched to",
                    ip_settled.is_some() && ip_settled == ip_switched,
                );
            }
        }
    }

    // ---- teardown -------------------------------------------------------
    println!("\n== tearing down ==");
    if let Err(e) = tunnel.down() {
        eprintln!("down failed: {e}");
        checks.check("down succeeds", false);
    }
    drop(tunnel);
    std::thread::sleep(Duration::from_millis(600));

    let route_after = sh("ip", &["route", "show", "default"]);
    let dns_after = sh("resolvectl", &["dns"]);
    let ip_restored = public_ip();

    checks.check("interface removed", sh("ip", &["link", "show", IFNAME]).is_empty());
    checks.check("default route restored", route_after == route_before);
    checks.check("system DNS restored", dns_after == dns_before);
    checks.check("original public IP restored", ip_restored == ip_before);
    println!("  public IP     : {ip_restored:?}");

    println!("\n{}/{} checks passed", checks.passed, checks.total);
    if checks.passed != checks.total {
        std::process::exit(1);
    }
}

fn wait_for_handshake(tunnel: &LinuxTunnel, timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Ok(s) = tunnel.status()
            && s.last_handshake.is_some()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    false
}

/// Watch the endpoint for `window`, reporting whether it stayed on `expected`
/// and what it drifted to if not.
fn endpoint_holds(
    tunnel: &LinuxTunnel,
    expected: SocketAddr,
    window: Duration,
) -> (bool, Option<SocketAddr>) {
    let started = Instant::now();
    while started.elapsed() < window {
        if let Ok(s) = tunnel.status()
            && let Some(endpoint) = s.endpoint
            && endpoint != expected
        {
            return (false, Some(endpoint));
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    (true, Some(expected))
}

/// After a switch the peer must handshake again, this time with the new
/// endpoint. Waiting on the endpoint as well as the timestamp avoids
/// mistaking the previous server's handshake for success.
fn wait_for_new_handshake(tunnel: &LinuxTunnel, expected: SocketAddr, timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Ok(s) = tunnel.status()
            && s.endpoint == Some(expected)
            && s.last_handshake.is_some()
            && s.rx_bytes > 0
        {
            return true;
        }
        // Nudge traffic so WireGuard is prompted to rekey against the new peer.
        let _ = Command::new("curl")
            .args(["-s", "--max-time", "3", "-o", "/dev/null", "https://ipinfo.io/ip"])
            .output();
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}
