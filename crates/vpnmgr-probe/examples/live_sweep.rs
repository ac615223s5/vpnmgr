//! Full Tier-0 + Tier-1 sweep against the live AirVPN fleet.
//!
//!     cargo run --release -p vpnmgr-probe --example live_sweep -- <conf> [country]
//!
//! This is the auto-tuner's measurement path end to end: fetch the server list,
//! filter it, handshake-probe every survivor concurrently, and rank the
//! results. Nothing is connected and no interface is created.

use std::time::Instant;

use vpnmgr_core::airvpn::{self, Client};
use vpnmgr_core::config::{Filters, Probe};
use vpnmgr_core::wgconf::ClientConfig;
use vpnmgr_core::{filter, score};
use vpnmgr_probe::{Prober, sweep};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let conf = args.next().expect("usage: live_sweep <conf> [country_code]");
    let country = args.next();

    let client = ClientConfig::import(&conf).expect("config should parse");
    println!("fleet key matches: {}", client.matches_known_airvpn_key());

    let list = Client::new().unwrap().fetch().await.expect("fetch servers");
    println!("fetched {} servers ({} healthy)", list.servers.len(), list.healthy_count());

    let filters = Filters {
        country_whitelist: country.iter().cloned().collect(),
        max_load: 95,
        ..Default::default()
    };
    let selection = filter::apply(&list, &filters);
    println!(
        "tier 0: {} candidates after filtering ({} rejected)",
        selection.accepted.len(),
        selection.rejected.len()
    );
    if selection.is_empty() {
        println!("rejections: {:?}", selection.rejection_summary());
        return;
    }

    let settings = Probe {
        concurrency: 32,
        timeout_ms: 2000,
        samples: 2,
    };
    println!(
        "tier 1: probing {} servers x {} entries (concurrency {}, {} samples each)...",
        selection.accepted.len(),
        airvpn::WG_ENTRIES.len(),
        settings.concurrency,
        settings.samples
    );

    let started = Instant::now();
    let prober = Prober::new(&client, settings);
    let measured = sweep(
        &prober,
        &selection.accepted,
        &airvpn::WG_ENTRIES,
        airvpn::WG_PORT,
    )
    .await;
    let elapsed = started.elapsed();

    let reachable = measured.iter().filter(|m| m.rtt.is_some()).count();
    println!(
        "swept {} servers in {:.2}s -- {reachable} reachable, {} not",
        measured.len(),
        elapsed.as_secs_f64(),
        measured.len() - reachable
    );

    // How often each entry won, now that both are probed.
    let mut wins = std::collections::BTreeMap::<u8, usize>::new();
    for m in measured.iter().filter(|m| m.rtt.is_some()) {
        *wins.entry(m.entry).or_default() += 1;
    }
    println!("fastest entry per server: {wins:?}");

    let ranked = score::rank(&measured, &score::Scoring::default());

    println!("\ntop 15 by score:");
    println!(
        "  {:<16} {:<16} {:>7}  {:>5}  {:>6}  {:>5}  entry",
        "server", "location", "rtt", "load", "score", "cc"
    );
    for s in ranked.iter().take(15) {
        println!(
            "  {:<16} {:<16} {:>6.1}ms  {:>4}%  {:>6.3}  {:>5}  {}",
            s.server.name,
            s.server.location.chars().take(16).collect::<String>(),
            s.rtt.as_secs_f64() * 1000.0,
            s.server.load,
            s.score,
            s.server.country_code,
            s.entry
        );
    }

    if let Some(best) = ranked.first() {
        println!(
            "\nwould connect to: {} ({}, {}) at {:.1}ms",
            best.server.name,
            best.server.location,
            best.server.country_name,
            best.rtt.as_secs_f64() * 1000.0
        );
    }

    // The "is it me or the exit server?" signal the auto-tuner depends on.
    let fastest = ranked.first().map(|s| s.rtt.as_secs_f64() * 1000.0);
    if let Some(f) = fastest {
        println!(
            "diagnosis: fastest server is {f:.1}ms -- {}",
            if f > 250.0 {
                "every server is slow, so this looks like a local/ISP problem"
            } else {
                "the network path looks healthy"
            }
        );
    }
}
