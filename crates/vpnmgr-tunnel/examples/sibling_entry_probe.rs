//! Does probing a server we are connected to break the live tunnel?
//!
//!     cargo build --release -p vpnmgr-tunnel --example sibling_entry_probe
//!     sudo ./target/release/examples/sibling_entry_probe <conf> [country] [self|sibling]
//!
//! # Why this matters
//!
//! `Prober::excluding` guards a single `SocketAddr`, but AirVPN servers answer
//! WireGuard on two addresses (entry 1 and entry 3), and a sweep probes both.
//! So while connected to server X on entry 1, a sweep still fires a handshake
//! initiation at X entry 3. The worry: that initiation carries our account's
//! static key, so the server could match it to the peer holding the live
//! session and roam that peer onto the ephemeral probe socket, black-holing
//! the tunnel.
//!
//! # What this measured
//!
//! Neither target disrupted traffic: 5 rounds against the sibling entry and 5
//! against the connected endpoint itself both left the kernel endpoint and the
//! exit IP unchanged, with traffic flowing throughout.
//!
//! The reason is that roaming is self-correcting. WireGuard updates a peer's
//! endpoint from *any* authenticated packet, so the tunnel re-asserts its own
//! endpoint constantly — a TCP ACK within milliseconds under load, or the
//! config's `PersistentKeepalive = 15` when idle. A probe can only displace
//! the endpoint until the next outbound packet, and a tunnel idle enough for
//! that window to stay open has no inbound traffic to lose.
//!
//! Note the limit of this result: it shows the tunnel was not *disrupted*, not
//! that no roam occurred. The two cases are indistinguishable from outside
//! precisely because the correction is faster than the observation.
//!
//! Needs root; brings up a full tunnel and tears it down on every exit path.

// Linux-only: this example drives a Linux tunnel and checks routes with ip(8), so on other
// platforms it compiles to a message instead of failing the build.
#[cfg(target_os = "linux")]
mod imp {
    use std::net::SocketAddr;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use vpnmgr_core::airvpn::{self, Client, Server};
    use vpnmgr_core::config::{Filters, Probe};
    use vpnmgr_core::wgconf::ClientConfig;
    use vpnmgr_core::{filter, score};
    use vpnmgr_probe::{Prober, sweep};
    use vpnmgr_tunnel::{DEFAULT_FWMARK, LinuxTunnel, TunnelBackend, TunnelSpec};

    const IFNAME: &str = "vpnmgr0";
    /// How many probe rounds to fire at the sibling entry.
    const ROUNDS: usize = 5;

    fn sh(cmd: &str, args: &[&str]) -> String {
        Command::new(cmd)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default()
    }

    /// Whether traffic still flows through the tunnel, and the observed exit IP.
    fn traffic_flows() -> Option<String> {
        let out = sh("curl", &["-s", "--max-time", "8", "https://ipinfo.io/ip"]);
        (!out.is_empty() && out.parse::<std::net::IpAddr>().is_ok()).then_some(out)
    }

    #[tokio::main]
    pub async fn main() {
        let mut args = std::env::args().skip(1);
        let conf = args
            .next()
            .expect("usage: sibling_entry_probe <conf> [country] [self|sibling]");
        let country = args.next();
        // `self` aims the probes at the connected endpoint itself, to check whether
        // the exclusion guard is defending against a real hazard.
        let target_self = args.next().is_some_and(|m| m == "self");

        let client = ClientConfig::import(&conf).expect("config should parse");
        let ip_before = traffic_flows().expect("need working internet for a baseline");
        println!("baseline public IP: {ip_before}");

        // ---- pick a server that actually answers on BOTH entries ------------
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

        // Re-probe the top few on each entry individually: we need a server that
        // answers on entry 1 *and* entry 3, otherwise there is nothing to test.
        let mut chosen: Option<(Server, SocketAddr, SocketAddr)> = None;
        for scored in ranked.iter().take(8) {
            let s = scored.server;
            let (Some(e1), Some(e3)) = (
                s.wg_endpoint_for_entry(1, airvpn::WG_PORT),
                s.wg_endpoint_for_entry(3, airvpn::WG_PORT),
            ) else {
                continue;
            };
            let both = prober.probe_many(&[e1, e3]).await;
            if both.iter().all(|r| r.rtt.is_some()) {
                println!("using {} ({}): entry1={e1} entry3={e3}", s.name, s.location);
                chosen = Some((s.clone(), e1, e3));
                break;
            }
        }
        drop(ranked);
        let (server, entry1, entry3) = chosen.expect("no server answered on both entries");

        // ---- connect on entry 1 ---------------------------------------------
        let mut tunnel = LinuxTunnel::new(IFNAME).expect("open handle");
        let spec = TunnelSpec::new(&client, entry1)
            .with_interface(IFNAME)
            .with_fwmark(DEFAULT_FWMARK);
        tunnel.up(&spec).expect("tunnel up");

        let mut verdict = "INCONCLUSIVE";
        let started = Instant::now();
        let mut connected = false;
        while started.elapsed() < Duration::from_secs(20) {
            if let Ok(s) = tunnel.status()
                && s.last_handshake.is_some()
                && s.rx_bytes > 0
            {
                connected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(400));
        }

        if !connected {
            eprintln!("never established a working tunnel; aborting");
        } else {
            let ip_tunnelled = traffic_flows();
            println!("connected via entry 1, exit IP: {ip_tunnelled:?}");

            // A prober that escapes the tunnel exactly the way a real sweep does,
            // excluding only the connected endpoint — which is precisely the gap
            // being tested.
            let sweeper = Prober::new(
                &client,
                Probe {
                    concurrency: 32,
                    timeout_ms: 2000,
                    samples: 2,
                },
            )
            .with_fwmark(DEFAULT_FWMARK);
            let target = if target_self { entry1 } else { entry3 };
            println!(
                "probing {} ({target})",
                if target_self {
                    "the CONNECTED endpoint"
                } else {
                    "the sibling entry"
                }
            );

            let mut broke_at = None;
            for round in 1..=ROUNDS {
                let result = sweeper.probe(target).await;
                let status = tunnel.status().expect("status");
                let flows = traffic_flows();
                println!(
                    "  round {round}: probe -> {:?}, kernel endpoint {:?}, traffic {}",
                    result
                        .rtt
                        .map(|r| format!("{:.1}ms", r.as_secs_f64() * 1000.0)),
                    status.endpoint,
                    flows.as_deref().unwrap_or("DEAD")
                );
                if flows.is_none() && broke_at.is_none() {
                    broke_at = Some(round);
                }
                std::thread::sleep(Duration::from_millis(800));
            }

            // Give the tunnel a grace period: WireGuard recovers from a roam on
            // the next rekey, so a transient break still counts as a break but a
            // recovery is worth reporting.
            let recovered = traffic_flows();

            verdict = match (broke_at, recovered) {
                (None, Some(_)) => {
                    // Deliberately narrow: this shows the tunnel was not disrupted,
                    // not that no roam occurred. An active tunnel re-asserts its own
                    // endpoint with every outbound packet, so a roam would be undone
                    // before it could be observed from up here.
                    println!(
                        "\nVERDICT: SAFE — {} kept carrying traffic through {ROUNDS} probes \
                     of {}. Any roaming was corrected faster than it could disrupt traffic.",
                        server.name,
                        if target_self {
                            "the connected endpoint itself"
                        } else {
                            "its sibling entry"
                        }
                    );
                    "SAFE"
                }
                (Some(round), Some(_)) => {
                    println!(
                        "\nVERDICT: TRANSIENT BREAK at round {round}, recovered by the end. \
                     The sibling entry does disturb the live session."
                    );
                    "BROKE"
                }
                (Some(round), None) => {
                    println!(
                        "\nVERDICT: BROKEN at round {round} and still dead. \
                     Probing the sibling entry black-holes the tunnel."
                    );
                    "BROKE"
                }
                (None, None) => {
                    println!("\nVERDICT: died only after the last probe; treat as BROKEN.");
                    "BROKE"
                }
            };
        }

        let _ = tunnel.down();
        drop(tunnel);
        std::thread::sleep(Duration::from_millis(600));
        println!("restored public IP: {:?}", traffic_flows());
        println!("result: {verdict}");
    }
}

#[cfg(target_os = "linux")]
fn main() {
    imp::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "sibling_entry_probe is a Linux-only tool: it drives a Linux tunnel and checks routes with ip(8)."
    );
}
