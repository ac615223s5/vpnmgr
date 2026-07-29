//! Ranking of probed servers.
//!
//! Combines measured handshake RTT with the load and spare bandwidth AirVPN
//! reports, into a score in `0.0..=1.0` where **higher is better**.
//!
//! RTT is scored *relative to the fastest candidate* rather than against an
//! absolute scale, because what counts as a good RTT depends entirely on where
//! the user is. It is a ratio (`fastest / rtt`) and not a min-max
//! normalisation, which matters more than it sounds:
//!
//! A min-max normalisation spreads scores over the whole range present in the
//! set, so with a fleet reaching 350ms the gap between a 6ms server and a 28ms
//! one is 6% of the range — while a 20-point load difference is 20% of *its*
//! range. Load then decides, and the tuner picks a server four times further
//! away because it reports a lighter load. A ratio keeps "twice as slow" worth
//! the same whether that is 5ms to 10ms or 100ms to 200ms, which is also how
//! latency is actually experienced.

use std::net::SocketAddr;
use std::time::Duration;

use crate::airvpn::Server;
use crate::config::Weights;

/// A server together with its probe result.
///
/// `rtt: None` means the handshake never came back — the server is treated as
/// unreachable and is dropped before ranking rather than scored badly.
#[derive(Debug, Clone)]
pub struct Measured<'a> {
    pub server: &'a Server,
    /// The endpoint this timing belongs to. A server exposes more than one
    /// WireGuard entry, and they differ in latency, so the winning endpoint
    /// has to travel with the measurement rather than being re-derived.
    pub endpoint: SocketAddr,
    /// Which AirVPN entry index `endpoint` is.
    pub entry: u8,
    pub rtt: Option<Duration>,
}

/// A ranked candidate.
#[derive(Debug, Clone)]
pub struct Scored<'a> {
    pub server: &'a Server,
    /// Connect to exactly this endpoint — it is the fastest entry measured.
    pub endpoint: SocketAddr,
    pub entry: u8,
    pub rtt: Duration,
    /// Overall score, higher is better.
    pub score: f64,
    /// Component scores, for `vpnmgr servers --explain`.
    pub rtt_score: f64,
    pub load_score: f64,
    pub bandwidth_score: f64,
}

/// Rank measured servers best-first.
///
/// Unreachable servers are omitted. Ties break on RTT, then on name, so the
/// ordering is deterministic and the tuner does not flap between equals.
pub fn rank<'a>(measured: &[Measured<'a>], weights: &Weights) -> Vec<Scored<'a>> {
    let reachable: Vec<(&Server, SocketAddr, u8, Duration)> = measured
        .iter()
        .filter_map(|m| m.rtt.map(|rtt| (m.server, m.endpoint, m.entry, rtt)))
        .collect();

    if reachable.is_empty() {
        return Vec::new();
    }

    let micros = |d: Duration| d.as_secs_f64() * 1e6;
    let fastest = reachable
        .iter()
        .map(|(_, _, _, d)| micros(*d))
        .fold(f64::INFINITY, f64::min);

    let total_weight = weights.rtt + weights.load + weights.bandwidth;

    let mut out: Vec<Scored<'a>> = reachable
        .into_iter()
        .map(|(server, endpoint, entry, rtt)| {
            // Ratio to the fastest candidate: 1.0 for the quickest, 0.5 for
            // one twice as slow, and so on. Depends only on this server and
            // the leader, so adding a distant outlier to the set cannot
            // compress the fast servers together.
            let us = micros(rtt);
            let rtt_score = if us <= f64::EPSILON { 1.0 } else { fastest / us };
            let load_score = 1.0 - server.load_fraction();
            let bandwidth_score = server.spare_bandwidth();

            let score = (weights.rtt * rtt_score
                + weights.load * load_score
                + weights.bandwidth * bandwidth_score)
                / total_weight;

            Scored {
                server,
                endpoint,
                entry,
                rtt,
                score,
                rtt_score,
                load_score,
                bandwidth_score,
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.rtt.cmp(&b.rtt))
            .then_with(|| a.server.name.cmp(&b.server.name))
    });
    out
}

/// Fractional improvement of `candidate` over `current`, as used against
/// `autotune.improvement_threshold`.
///
/// Returns 0.0 when the candidate is no better. A current score of zero is
/// treated as "any improvement is total", avoiding a division by zero.
pub fn relative_improvement(current: f64, candidate: f64) -> f64 {
    if candidate <= current {
        return 0.0;
    }
    if current <= f64::EPSILON {
        return 1.0;
    }
    (candidate - current) / current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airvpn::ServerList;

    const FIXTURE: &str = include_str!("../tests/fixtures/airvpn_status.json");

    fn list() -> ServerList {
        ServerList::from_json(FIXTURE).unwrap()
    }

    fn ms(n: u64) -> Option<Duration> {
        Some(Duration::from_millis(n))
    }

    /// Most tests do not care which entry a timing came from.
    fn measured(server: &Server, rtt: Option<Duration>) -> Measured<'_> {
        Measured {
            server,
            endpoint: server.wg_endpoint(crate::airvpn::WG_PORT),
            entry: 1,
            rtt,
        }
    }

    #[test]
    fn faster_servers_rank_higher_when_load_matches() {
        let list = list();
        // Two servers with identical load, differing only in RTT.
        let pair: Vec<_> = {
            let mut by_load = std::collections::HashMap::<u32, Vec<&crate::airvpn::Server>>::new();
            for s in list.healthy() {
                by_load.entry(s.load).or_default().push(s);
            }
            by_load
                .into_values()
                .find(|v| v.len() >= 2)
                .expect("some load value is shared")
                .into_iter()
                .take(2)
                .collect()
        };
        let measured = vec![
            measured(pair[0], ms(90)),
            measured(pair[1], ms(12)),
        ];
        let ranked = rank(&measured, &Weights::default());
        assert_eq!(ranked[0].server.name, pair[1].name);
    }

    #[test]
    fn unreachable_servers_are_dropped_not_ranked_last() {
        let list = list();
        let servers: Vec<_> = list.healthy().take(3).collect();
        let measured = vec![
            measured(servers[0], ms(30)),
            measured(servers[1], None),
            measured(servers[2], ms(40)),
        ];
        let ranked = rank(&measured, &Weights::default());
        assert_eq!(ranked.len(), 2);
        assert!(ranked.iter().all(|s| s.server.name != servers[1].name));
    }

    #[test]
    fn returns_nothing_when_every_probe_failed() {
        let list = list();
        let measured: Vec<_> = list
            .healthy()
            .take(5)
            .map(|server| measured(server, None))
            .collect();
        assert!(rank(&measured, &Weights::default()).is_empty());
    }

    #[test]
    fn scores_stay_within_the_unit_range() {
        let list = list();
        let measured: Vec<_> = list
            .healthy()
            .enumerate()
            .map(|(i, server)| measured(server, ms(10 + i as u64)))
            .collect();
        let ranked = rank(&measured, &Weights::default());
        assert_eq!(ranked.len(), 243);
        assert!(ranked.iter().all(|s| (0.0..=1.0).contains(&s.score)));
    }

    #[test]
    fn a_single_candidate_is_not_penalised_for_having_no_peers() {
        let list = list();
        let server = list.healthy().next().unwrap();
        let ranked = rank(&[measured(server, ms(200))], &Weights::default());
        // A lone candidate has no spread to compare against, so RTT is neutral.
        assert_eq!(ranked[0].rtt_score, 1.0);
    }

    /// Regression, caught against the live fleet: ranking put Muliphein (New
    /// York, 27.9ms, 17% load) above Kornephoros (Toronto, 6.1ms, 37% load),
    /// and scored Sarin (Los Angeles, 69.3ms) within 0.005 of the 6.1ms server.
    ///
    /// A min-max normalisation was to blame — across a fleet reaching ~350ms,
    /// the 22ms gap was 6% of the RTT range while the 20-point load gap was 20%
    /// of the load range, so a reported load figure outvoted a 4.5x measured
    /// latency difference.
    #[test]
    fn a_four_times_closer_server_beats_a_lightly_loaded_distant_one() {
        let list = list();
        let mut healthy: Vec<_> = list.healthy().collect();
        healthy.sort_by_key(|s| s.load);
        // The extremes of the fleet, so load pulls as hard as it possibly can.
        let (lightest, heaviest) = (healthy[0], healthy[healthy.len() - 1]);
        assert!(lightest.load + 15 < heaviest.load, "fixture needs a real load spread");

        let measured = vec![
            measured(lightest, ms(28)),
            measured(heaviest, ms(6)),
        ];
        let ranked = rank(&measured, &Weights::default());
        assert_eq!(
            ranked[0].server.name, heaviest.name,
            "a 4.5x latency advantage must outweigh even the widest load gap"
        );
    }

    /// The property that fixes the above: a server's RTT score depends only on
    /// itself and the fastest candidate, so a distant outlier joining the set
    /// cannot squeeze the fast servers together.
    #[test]
    fn rtt_scores_are_unaffected_by_a_distant_outlier() {
        let list = list();
        let servers: Vec<_> = list.healthy().take(3).collect();

        let pair = rank(
            &[measured(servers[0], ms(10)), measured(servers[1], ms(20))],
            &Weights::default(),
        );
        let with_outlier = rank(
            &[
                measured(servers[0], ms(10)),
                measured(servers[1], ms(20)),
                measured(servers[2], ms(500)),
            ],
            &Weights::default(),
        );

        let score_of = |ranked: &[Scored], name: &str| {
            ranked
                .iter()
                .find(|s| s.server.name == name)
                .expect("server should be ranked")
                .rtt_score
        };
        for server in [servers[0], servers[1]] {
            assert!(
                (score_of(&pair, &server.name) - score_of(&with_outlier, &server.name)).abs() < 1e-12,
                "{} moved when an unrelated slow server joined the set",
                server.name
            );
        }
        // And the shape is the ratio we intend: 20ms scores half of 10ms.
        assert!((score_of(&pair, &servers[1].name) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn load_decides_when_latency_is_identical() {
        let list = list();
        let mut healthy: Vec<_> = list.healthy().collect();
        healthy.sort_by_key(|s| s.load);
        let (light, heavy) = (healthy[0], healthy[healthy.len() - 1]);
        assert!(light.load < heavy.load);
        let measured = vec![
            measured(heavy, ms(25)),
            measured(light, ms(25)),
        ];
        let ranked = rank(&measured, &Weights::default());
        assert_eq!(ranked[0].server.name, light.name);
    }

    #[test]
    fn weights_can_be_retargeted_at_a_single_signal() {
        let list = list();
        let mut healthy: Vec<_> = list.healthy().collect();
        healthy.sort_by_key(|s| s.load);
        let (light, heavy) = (healthy[0], healthy[healthy.len() - 1]);
        // Ignore load entirely: the slower-but-lighter server should lose.
        let rtt_only = Weights { rtt: 1.0, load: 0.0, bandwidth: 0.0 };
        let measured = vec![
            measured(light, ms(200)),
            measured(heavy, ms(10)),
        ];
        let ranked = rank(&measured, &rtt_only);
        assert_eq!(ranked[0].server.name, heavy.name);
    }

    #[test]
    fn ranking_is_deterministic_for_identical_inputs() {
        let list = list();
        let servers: Vec<_> = list.healthy().take(20).collect();
        let measured: Vec<_> = servers
            .iter()
            .map(|server| measured(server, ms(50)))
            .collect();
        let first = rank(&measured, &Weights::default());
        let second = rank(&measured, &Weights::default());
        let names = |v: &[Scored]| v.iter().map(|s| s.server.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&first), names(&second));
    }

    #[test]
    fn improvement_is_zero_when_the_candidate_is_no_better() {
        assert_eq!(relative_improvement(0.8, 0.8), 0.0);
        assert_eq!(relative_improvement(0.8, 0.5), 0.0);
    }

    #[test]
    fn improvement_is_relative_to_the_current_score() {
        // 0.5 -> 0.75 is a 50% improvement, clearing a 0.25 threshold.
        assert!((relative_improvement(0.5, 0.75) - 0.5).abs() < 1e-9);
        // 0.70 -> 0.77 is only 10%, and should not trigger a switch.
        assert!(relative_improvement(0.70, 0.77) < 0.25);
    }

    #[test]
    fn improvement_from_zero_does_not_divide_by_zero() {
        assert_eq!(relative_improvement(0.0, 0.4), 1.0);
        assert_eq!(relative_improvement(0.0, 0.0), 0.0);
    }
}
