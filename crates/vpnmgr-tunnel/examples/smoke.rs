//! Throwaway-interface smoke test for the Linux tunnel backend. Needs root.
//!
//! Deliberately low blast radius: the interface is named `vpnmgrsmoke`, its
//! AllowedIPs cover only 10.99.99.0/24, and no DNS is configured. That means
//! the default route and the system resolver are never touched — this proves
//! interface lifecycle, peer configuration, stats and teardown, nothing more.
//!
//!     cargo build -p vpnmgr-tunnel --example smoke
//!     sudo ./target/debug/examples/smoke
//!
//! It removes the interface on every exit path, including failure.

use std::net::SocketAddr;
use std::process::Command;

use vpnmgr_core::key::{PublicKey, SecretKey};
use vpnmgr_core::wgconf::ClientConfig;
use vpnmgr_tunnel::{LinuxTunnel, TunnelBackend, TunnelSpec};

const IFNAME: &str = "vpnmgrsmoke";

/// TEST-NET-3. Routable nowhere, so no packets escape.
const ENDPOINT_A: &str = "203.0.113.10:1637";
const ENDPOINT_B: &str = "203.0.113.20:1637";

fn kernel_sees_interface() -> bool {
    Command::new("ip")
        .args(["link", "show", IFNAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn check(label: &str, ok: bool) -> bool {
    println!("  [{}] {label}", if ok { "PASS" } else { "FAIL" });
    ok
}

fn main() {
    let client = ClientConfig {
        private_key: SecretKey::from_base64("SPrivateKeyFixturexxxxxxxxxxxxxxxxxxxxxxxxA=").unwrap(),
        addresses: vec!["10.99.99.2/32".parse().unwrap()],
        // No DNS: leaves systemd-resolved alone.
        dns: vec![],
        search_domains: vec![],
        mtu: Some(1320),
        peer_public_key: PublicKey::from_base64("PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk=")
            .unwrap(),
        preshared_key: None,
        // Not 0.0.0.0/0: the default route stays exactly as it is.
        allowed_ips: vec!["10.99.99.0/24".parse().unwrap()],
        persistent_keepalive: Some(15),
    };

    let endpoint_a: SocketAddr = ENDPOINT_A.parse().unwrap();
    let endpoint_b: SocketAddr = ENDPOINT_B.parse().unwrap();

    println!("interface {IFNAME} present before: {}", kernel_sees_interface());

    let mut tunnel = match LinuxTunnel::new(IFNAME) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("could not open a handle: {e}");
            std::process::exit(1);
        }
    };

    let mut passed = 0;
    let mut total = 0;
    let mut assert_that = |label: &str, ok: bool| {
        total += 1;
        if check(label, ok) {
            passed += 1;
        }
    };

    println!("\nbringing the tunnel up");
    let spec = TunnelSpec::new(&client, endpoint_a).with_interface(IFNAME);
    if let Err(e) = tunnel.up(&spec) {
        eprintln!("up failed: {e}");
        std::process::exit(1);
    }

    assert_that("kernel reports the interface exists", kernel_sees_interface());

    match tunnel.status() {
        Err(e) => {
            eprintln!("status failed: {e}");
            assert_that("status is readable", false);
        }
        Ok(s) => {
            println!("  status: {s:?}");
            assert_that("endpoint matches what we configured", s.endpoint == Some(endpoint_a));
            assert_that("fwmark was applied", s.fwmark == Some(spec.fwmark));
            assert_that("a listen port was allocated", s.listen_port != 0);
            assert_that(
                "no handshake yet, so the tunnel is not healthy",
                !s.is_healthy(std::time::SystemTime::now(), std::time::Duration::from_secs(180)),
            );
            // PersistentKeepalive makes the kernel attempt a handshake as soon
            // as the peer is configured, so tx is one 148-byte initiation --
            // the same packet the prober sends. The endpoint is a black hole,
            // so nothing comes back.
            assert_that(
                "tx is a handshake initiation attempt",
                s.tx_bytes > 0 && s.tx_bytes % 148 == 0,
            );
            assert_that("nothing was received from a black-holed endpoint", s.rx_bytes == 0);
        }
    }

    println!("\nswitching servers without a teardown");
    let route_before = routes_for(IFNAME);
    let spec_b = TunnelSpec::new(&client, endpoint_b).with_interface(IFNAME);
    if let Err(e) = tunnel.switch_endpoint(&spec_b) {
        eprintln!("switch failed: {e}");
        assert_that("switch_endpoint succeeds", false);
    } else {
        match tunnel.status() {
            Err(e) => {
                eprintln!("status after switch failed: {e}");
                assert_that("status readable after switch", false);
            }
            Ok(s) => {
                assert_that("endpoint moved to the new server", s.endpoint == Some(endpoint_b));
                assert_that("the interface was not recreated", kernel_sees_interface());
                assert_that(
                    "routes survived the switch",
                    routes_for(IFNAME) == route_before,
                );
            }
        }
    }

    println!("\ntearing down");
    if let Err(e) = tunnel.down() {
        eprintln!("down failed: {e}");
        assert_that("down succeeds", false);
    }
    assert_that("interface is gone", !kernel_sees_interface());

    println!("\n{passed}/{total} checks passed");
    if passed != total {
        std::process::exit(1);
    }
}

/// Routes bound to the interface, for confirming a switch leaves them alone.
fn routes_for(ifname: &str) -> String {
    Command::new("ip")
        .args(["route", "show", "dev", ifname])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}
