//! Probe explicit endpoints with credentials from a `.conf`.
//!
//!     cargo run -p vpnmgr-probe --example probe_endpoints -- <conf> <ip:port>...
//!
//! Useful for answering "does this entry IP actually speak WireGuard?" without
//! bringing up a tunnel.

use std::net::SocketAddr;

use vpnmgr_core::config;
use vpnmgr_core::wgconf::ClientConfig;
use vpnmgr_probe::Prober;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let conf = args
        .next()
        .expect("usage: probe_endpoints <conf> <ip:port>...");
    let endpoints: Vec<SocketAddr> = args
        .map(|a| {
            a.parse()
                .unwrap_or_else(|e| panic!("bad endpoint {a:?}: {e}"))
        })
        .collect();
    assert!(!endpoints.is_empty(), "give at least one endpoint");

    let client = ClientConfig::import(&conf).expect("config should parse");
    println!(
        "peer key {} (known AirVPN fleet key: {})\n",
        client.peer_public_key,
        client.matches_known_airvpn_key()
    );

    let settings = config::Probe {
        concurrency: 8,
        timeout_ms: 2500,
        samples: 3,
    };
    let results = Prober::new(&client, settings).probe_many(&endpoints).await;

    for r in &results {
        match r.rtt {
            Some(rtt) => println!(
                "{:<22} {:>7.1} ms  {:?}  ({} samples)",
                r.endpoint.to_string(),
                rtt.as_secs_f64() * 1000.0,
                r.outcome,
                r.samples.len()
            ),
            None => println!(
                "{:<22} {:>10}  {:?}",
                r.endpoint.to_string(),
                "-",
                r.outcome
            ),
        }
    }
}
