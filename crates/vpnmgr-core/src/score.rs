//! Ranking of probed servers.
//!
//! Combines measured handshake RTT with the load and spare capacity AirVPN
//! reports, into a score in `0.0..=1.0` where **higher is better**.
//!
//! Capacity is scored as *absolute* headroom rather than as the spare-bandwidth
//! fraction. The fraction was redundant: AirVPN's `currentload` is itself
//! `bw / bw_max`, so weighting both counted utilisation twice under two names,
//! and the nominal 0.6/0.3/0.1 split was really 0.6/0.4.
//!
//! Headroom is measured against what the *user* can actually use — their target
//! throughput times a safety margin — rather than an absolute figure, and is
//! scored on a log curve for the same reason latency is: the first few hundred
//! Mbit/s of spare capacity matter far more than the next few thousand.
//!
//! RTT is scored *relative to the fastest candidate* rather than against an
//! absolute scale, because what counts as a good RTT depends entirely on where
//! the user is. It is scored on the logarithm of that ratio, which took two
//! attempts to get right.
//!
//! A min-max normalisation spreads scores over the whole range present in the
//! set, so with a fleet reaching 350ms the gap between a 6ms server and a 28ms
//! one is 6% of the range — while a 20-point load difference is 20% of *its*
//! range. Load then decides, and the tuner picks a server four times further
//! away because it reports a lighter load.
//!
//! A plain ratio (`fastest / rtt`) fixes that but is badly shaped: it spends
//! almost all its range on the first doubling. Going from 1x to 2x the best
//! costs 0.5, while 10x to 20x costs 0.05 — the same multiplicative
//! degradation priced ten times apart, and everything past ~10x squashed into
//! a band too narrow to rank.
//!
//! Taking the log makes equal ratios cost equal score: 1x to 2x and 10x to 20x
//! are both worth the same drop. That matches how latency is experienced —
//! "twice as slow" means the same thing whether it is 5ms to 10ms or 100ms to
//! 200ms — and keeps resolution across the whole usable range.

use std::net::SocketAddr;
use std::time::Duration;

use crate::airvpn::Server;
use crate::config::Weights;

/// A server this many times slower than the fastest scores zero on latency.
///
/// Not a claim that such a server is unusable, only that once something is
/// twenty times further away than the best available, ranking it against other
/// equally distant servers is meaningless — load and headroom should decide.
const RTT_RATIO_FLOOR: f64 = 20.0;

/// Everything the ranking needs beyond the measurements themselves.
///
/// Bundled rather than passed loose because the capacity term is anchored to
/// the user's own connection speed, so it is not a constant the way it looks.
#[derive(Debug, Clone)]
pub struct Scoring {
    /// Relative importance of each signal.
    pub weights: Weights,
    /// Spare capacity at which a server scores full marks on capacity, in
    /// Mbit/s. Derived from `autotune.target_mbps * autotune.headroom_margin`.
    pub headroom_target_mbps: f64,
}

impl Default for Scoring {
    fn default() -> Self {
        Self {
            weights: Weights::default(),
            headroom_target_mbps: crate::config::DEFAULT_TARGET_MBPS * 2.0,
        }
    }
}

impl Scoring {
    pub fn new(weights: Weights, headroom_target_mbps: f64) -> Self {
        Self {
            weights,
            headroom_target_mbps,
        }
    }
}

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
    pub headroom_score: f64,
}

/// Rank measured servers best-first.
///
/// Unreachable servers are omitted. Ties break on RTT, then on name, so the
/// ordering is deterministic and the tuner does not flap between equals.
pub fn rank<'a>(measured: &[Measured<'a>], scoring: &Scoring) -> Vec<Scored<'a>> {
    let weights = &scoring.weights;
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

    let total_weight = weights.rtt + weights.load + weights.headroom;

    let mut out: Vec<Scored<'a>> = reachable
        .into_iter()
        .map(|(server, endpoint, entry, rtt)| {
            // Log of the ratio to the fastest candidate. Depends only on this
            // server and the leader, so adding a distant outlier to the set
            // cannot compress the fast servers together.
            let us = micros(rtt);
            let rtt_score = if us <= f64::EPSILON || fastest <= f64::EPSILON {
                1.0
            } else {
                let ratio = (us / fastest).max(1.0);
                (1.0 - ratio.ln() / RTT_RATIO_FLOOR.ln()).clamp(0.0, 1.0)
            };
            let load_score = 1.0 - server.load_fraction();
            // Log for the same reason as latency: the first few hundred Mbit/s
            // of spare capacity matter far more than the next few thousand, and
            // a linear ramp prices them the same. Full marks at the target,
            // and nothing beyond it, because capacity you cannot use is not an
            // advantage.
            let headroom_score = if scoring.headroom_target_mbps <= 0.0 {
                1.0
            } else {
                let ratio = server.headroom_mbps() as f64 / scoring.headroom_target_mbps;
                ((1.0 + ratio).ln() / std::f64::consts::LN_2).clamp(0.0, 1.0)
            };

            let score = (weights.rtt * rtt_score
                + weights.load * load_score
                + weights.headroom * headroom_score)
                / total_weight;

            Scored {
                server,
                endpoint,
                entry,
                rtt,
                score,
                rtt_score,
                load_score,
                headroom_score,
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
        let ranked = rank(&measured, &Scoring::default());
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
        let ranked = rank(&measured, &Scoring::default());
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
        assert!(rank(&measured, &Scoring::default()).is_empty());
    }

    #[test]
    fn scores_stay_within_the_unit_range() {
        let list = list();
        let measured: Vec<_> = list
            .healthy()
            .enumerate()
            .map(|(i, server)| measured(server, ms(10 + i as u64)))
            .collect();
        let ranked = rank(&measured, &Scoring::default());
        assert_eq!(ranked.len(), 243);
        assert!(ranked.iter().all(|s| (0.0..=1.0).contains(&s.score)));
    }

    #[test]
    fn a_single_candidate_is_not_penalised_for_having_no_peers() {
        let list = list();
        let server = list.healthy().next().unwrap();
        let ranked = rank(&[measured(server, ms(200))], &Scoring::default());
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
    fn a_four_times_closer_server_wins_despite_a_heavier_load() {
        let list = list();
        // A realistic pairing rather than the fleet's extremes: a meaningful
        // load gap, and enough headroom on both that capacity is not what
        // decides it.
        let mut candidates: Vec<_> = list
            .healthy()
            .filter(|s| s.headroom_mbps() >= 1000)
            .collect();
        candidates.sort_by_key(|s| s.load);
        let light = candidates.first().copied().expect("fixture has servers");
        let heavy = candidates
            .iter()
            .copied()
            .find(|s| s.load >= light.load + 15)
            .expect("fixture should span at least a 15-point load range");

        // The heavier server is 4.5x closer, which is what should decide it.
        let measured = vec![measured(light, ms(28)), measured(heavy, ms(6))];
        let ranked = rank(&measured, &Scoring::default());
        assert_eq!(
            ranked[0].server.name, heavy.name,
            "a 4.5x latency advantage should beat a {}-point load gap",
            heavy.load - light.load
        );
    }

    /// The deliberate limit of the above: latency does not win unconditionally.
    /// A server with no capacity left is a bad destination however close it is,
    /// and the score is expected to say so.
    #[test]
    fn a_saturated_server_loses_to_an_idle_one_even_when_much_closer() {
        let list = list();
        let saturated = list
            .servers
            .iter()
            .max_by_key(|s| s.load)
            .expect("fixture has servers");
        let idle = list
            .servers
            .iter()
            .min_by_key(|s| s.load)
            .expect("fixture has servers");
        assert!(saturated.load >= 100, "expected an oversubscribed server");
        assert_eq!(saturated.headroom_mbps(), 0, "expected no capacity left");

        let measured = vec![measured(idle, ms(28)), measured(saturated, ms(6))];
        let ranked = rank(&measured, &Scoring::default());
        assert_eq!(
            ranked[0].server.name, idle.name,
            "a fully saturated server should not win on proximity alone"
        );
    }

    /// The property that fixes the original bug: a server's RTT score depends
    /// only on itself and the fastest candidate, so a distant outlier joining
    /// the set cannot squeeze the fast servers together.
    #[test]
    fn rtt_scores_are_unaffected_by_a_distant_outlier() {
        let list = list();
        let servers: Vec<_> = list.healthy().take(3).collect();

        let pair = rank(
            &[measured(servers[0], ms(10)), measured(servers[1], ms(20))],
            &Scoring::default(),
        );
        let with_outlier = rank(
            &[
                measured(servers[0], ms(10)),
                measured(servers[1], ms(20)),
                measured(servers[2], ms(500)),
            ],
            &Scoring::default(),
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
    }

    /// The shape the log curve exists to provide: the same *multiplicative*
    /// degradation costs the same score wherever it happens. Under the previous
    /// `fastest / rtt` ratio, 1x->2x cost 0.5 while 10x->20x cost 0.05.
    #[test]
    fn equal_latency_ratios_cost_equal_score() {
        let list = list();
        let servers: Vec<_> = list.healthy().take(4).collect();
        let ranked = rank(
            &[
                measured(servers[0], ms(10)),
                measured(servers[1], ms(20)),
                measured(servers[2], ms(100)),
                measured(servers[3], ms(200)),
            ],
            &Scoring::default(),
        );
        let rtt_of = |name: &str| {
            ranked
                .iter()
                .find(|s| s.server.name == name)
                .expect("ranked")
                .rtt_score
        };
        let first_doubling = rtt_of(&servers[0].name) - rtt_of(&servers[1].name);
        let later_doubling = rtt_of(&servers[2].name) - rtt_of(&servers[3].name);
        assert!(
            (first_doubling - later_doubling).abs() < 1e-9,
            "1x->2x cost {first_doubling:.4} but 10x->20x cost {later_doubling:.4}"
        );
        assert!(first_doubling > 0.2, "a doubling should be clearly penalised");
    }

    /// Capacity is scored as absolute headroom, and deliberately capped: past
    /// the point where a server has more spare bandwidth than any domestic link
    /// can pull, extra capacity is not worth anything. Two well-provisioned
    /// servers should therefore tie, however different their size.
    #[test]
    fn ample_headroom_ties_at_the_cap() {
        let list = list();
        let mut ample: Vec<_> = list
            .servers
            .iter()
            .filter(|s| s.headroom_mbps() >= 2000)
            .collect();
        ample.sort_by_key(|s| s.bw_max);
        let (small, large) = (ample[0], ample[ample.len() - 1]);
        assert!(large.bw_max > small.bw_max, "need different capacities");

        let ranked = rank(
            &[measured(small, ms(10)), measured(large, ms(10))],
            &Scoring::default(),
        );
        let of = |name: &str| {
            ranked
                .iter()
                .find(|s| s.server.name == name)
                .expect("ranked")
                .headroom_score
        };
        assert_eq!(
            of(&small.name),
            of(&large.name),
            "headroom is a penalty for scarcity, not a bonus for size"
        );
    }

    /// Where the term earns its place: a server running out of room scores
    /// below one with plenty, which is information `load` alone does not carry
    /// once capacity differs.
    #[test]
    fn scarce_headroom_scores_below_ample_headroom() {
        let list = list();
        let scarce = list
            .servers
            .iter()
            .filter(|s| s.bw_max > 0)
            .min_by_key(|s| s.headroom_mbps())
            .expect("fixture has servers");
        let ample = list
            .servers
            .iter()
            .max_by_key(|s| s.headroom_mbps())
            .expect("fixture has servers");
        assert!(scarce.headroom_mbps() < 1000, "expected a server short of room");

        let ranked = rank(
            &[measured(scarce, ms(10)), measured(ample, ms(10))],
            &Scoring::default(),
        );
        let of = |name: &str| {
            ranked
                .iter()
                .find(|s| s.server.name == name)
                .expect("ranked")
                .headroom_score
        };
        assert!(
            of(&scarce.name) < of(&ample.name),
            "a server with no room left should be penalised"
        );
    }

    /// The capacity curve is anchored to what the user can actually use, so
    /// the same server scores differently for a gigabit line and a slow one.
    #[test]
    fn the_headroom_target_moves_the_capacity_score() {
        let list = list();
        let server = list
            .servers
            .iter()
            .find(|s| s.headroom_mbps() > 500 && s.headroom_mbps() < 1500)
            .expect("fixture has a mid-headroom server");

        let head = |target: f64| {
            rank(
                &[measured(server, ms(10))],
                &Scoring::new(Weights::default(), target),
            )[0]
                .headroom_score
        };
        // A modest target is easily satisfied; a demanding one is not.
        assert!(
            head(200.0) > head(4000.0),
            "a server should look better to someone who needs less from it"
        );
        assert!(head(200.0) >= 0.99, "well past the target should be full marks");
    }

    /// Log-shaped like latency: the first slice of spare capacity is worth more
    /// than the last, so a linear ramp would undervalue partial headroom.
    #[test]
    fn capacity_has_diminishing_returns() {
        let list = list();
        let server = list
            .servers
            .iter()
            .max_by_key(|s| s.headroom_mbps())
            .expect("fixture has servers");
        let h = server.headroom_mbps() as f64;

        let head = |target: f64| {
            rank(
                &[measured(server, ms(10))],
                &Scoring::new(Weights::default(), target),
            )[0]
                .headroom_score
        };
        // Headroom at a quarter of target already earns well over a quarter of
        // the score; that concavity is the whole point of the log.
        let quarter = head(h * 4.0);
        assert!(
            quarter > 0.25,
            "a quarter of the target scored {quarter:.3}, no better than linear"
        );
        assert!(quarter < 1.0);
        // And the target itself is exactly full marks, not merely close.
        assert!((head(h) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn no_capacity_left_scores_zero_however_the_target_is_set() {
        let list = list();
        let full = list
            .servers
            .iter()
            .find(|s| s.headroom_mbps() == 0)
            .expect("fixture has a saturated server");
        for target in [100.0, 1000.0, 10_000.0] {
            let score = rank(
                &[measured(full, ms(10))],
                &Scoring::new(Weights::default(), target),
            )[0]
                .headroom_score;
            assert_eq!(score, 0.0, "target {target} gave {score}");
        }
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
        let ranked = rank(&measured, &Scoring::default());
        assert_eq!(ranked[0].server.name, light.name);
    }

    #[test]
    fn weights_can_be_retargeted_at_a_single_signal() {
        let list = list();
        let mut healthy: Vec<_> = list.healthy().collect();
        healthy.sort_by_key(|s| s.load);
        let (light, heavy) = (healthy[0], healthy[healthy.len() - 1]);
        // Ignore load entirely: the slower-but-lighter server should lose.
        let rtt_only = Scoring::new(
            Weights { rtt: 1.0, load: 0.0, headroom: 0.0 },
            Scoring::default().headroom_target_mbps,
        );
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
        let first = rank(&measured, &Scoring::default());
        let second = rank(&measured, &Scoring::default());
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
