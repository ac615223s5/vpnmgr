//! End-to-end checks against the real AirVPN API.
//!
//! Ignored by default because they need network access and depend on live
//! data. Run them with:
//!
//! ```sh
//! cargo test -p vpnmgr-core -- --ignored --nocapture
//! ```
//!
//! Their job is to catch AirVPN changing the API shape out from under the
//! fixture — the unit tests would keep passing in that case.

use std::time::Duration;

use vpnmgr_core::airvpn::{self, Client};
use vpnmgr_core::config::{Filters, Weights};
use vpnmgr_core::{filter, render, score};

#[tokio::test]
#[ignore = "requires network access to airvpn.org"]
async fn live_api_still_matches_the_shape_we_parse() {
    let list = Client::new()
        .expect("client builds")
        .fetch()
        .await
        .expect("AirVPN status API should respond");

    assert!(
        list.servers.len() > 100,
        "expected a substantial fleet, got {}",
        list.servers.len()
    );
    assert!(list.healthy_count() > 0, "no healthy servers reported");

    // The fields the rest of the pipeline depends on must be populated.
    for s in list.healthy() {
        assert!(!s.name.is_empty(), "server with no public_name");
        assert!(!s.country_code.is_empty(), "{} has no country_code", s.name);
        assert!(s.bw_max > 0, "{} reports zero capacity", s.name);
        assert!(!s.wg_ipv4.is_unspecified(), "{} has no WireGuard entry IP", s.name);
    }

    let countries: std::collections::BTreeSet<_> =
        list.healthy().map(|s| s.country_code.as_str()).collect();
    println!(
        "live: {} servers, {} healthy, {} countries",
        list.servers.len(),
        list.healthy_count(),
        countries.len()
    );
}

#[tokio::test]
#[ignore = "requires network access to airvpn.org"]
async fn the_full_pipeline_produces_a_ranked_swedish_shortlist() {
    let list = Client::new().unwrap().fetch().await.unwrap();

    let filters = Filters {
        country_whitelist: vec!["se".into()],
        max_load: 95,
        ..Default::default()
    };
    let selection = filter::apply(&list, &filters);
    assert!(
        !selection.is_empty(),
        "no Swedish servers survived filtering: {:?}",
        selection.rejection_summary()
    );
    assert!(selection.accepted.iter().all(|s| s.country_code == "se"));

    // Stand in for Tier 1 with synthetic RTTs; the real prober lands in M2.
    let measured: Vec<_> = selection
        .accepted
        .iter()
        .enumerate()
        .map(|(i, server)| score::Measured {
            server,
            endpoint: server.wg_endpoint(airvpn::WG_PORT),
            entry: 1,
            rtt: Some(Duration::from_millis(20 + i as u64)),
        })
        .collect();

    let ranked = score::rank(&measured, &Weights::default());
    assert_eq!(ranked.len(), selection.accepted.len());
    // rank() must return best-first.
    assert!(ranked.windows(2).all(|w| w[0].score >= w[1].score));

    println!("top Swedish candidates:");
    for s in ranked.iter().take(5) {
        println!(
            "  {:<14} load {:>3}%  rtt {:>4}ms  score {:.3}",
            s.server.name,
            s.server.load,
            s.rtt.as_millis(),
            s.score
        );
    }
}

#[tokio::test]
#[ignore = "requires network access to airvpn.org"]
async fn every_live_server_yields_a_wireguard_endpoint_on_1637() {
    let list = Client::new().unwrap().fetch().await.unwrap();
    for s in list.healthy() {
        let endpoint = s.wg_endpoint(airvpn::WG_PORT);
        assert_eq!(endpoint.port(), airvpn::WG_PORT);
        assert!(endpoint.is_ipv4());
    }
}

#[test]
fn a_rendered_config_differs_only_in_its_endpoint_across_the_whole_fleet() {
    // No network: this is the property the design rests on, checked against
    // the committed fixture so it runs in CI too.
    let list = airvpn::ServerList::from_json(include_str!("fixtures/airvpn_status.json")).unwrap();
    let client = vpnmgr_core::ClientConfig::parse(
        include_str!("fixtures/airvpn_sample.conf"),
        "sample.conf",
    )
    .unwrap();

    let baseline = render::for_server(&client, list.healthy().next().unwrap(), airvpn::WG_PORT);
    let baseline_without_endpoint: Vec<_> = baseline
        .lines()
        .filter(|l| !l.starts_with("Endpoint = "))
        .collect();

    for server in list.healthy() {
        let conf = render::for_server(&client, server, airvpn::WG_PORT);
        let without_endpoint: Vec<_> = conf
            .lines()
            .filter(|l| !l.starts_with("Endpoint = "))
            .collect();
        assert_eq!(
            without_endpoint, baseline_without_endpoint,
            "{} rendered a config differing outside its Endpoint",
            server.name
        );
        assert!(conf.contains(&format!("Endpoint = {}:1637", server.wg_ipv4)));
    }
}
