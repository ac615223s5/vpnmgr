//! The auto-tuner's decision logic.
//!
//! Deliberately free of I/O: [`decide`] is a pure function over an
//! [`Assessment`], so every branch — including the ones that are awkward to
//! reproduce against a live network, like "the current server went silent" —
//! is reachable from a unit test.
//!
//! The policy the daemon enforces around it:
//!
//! * A healthy server is never disturbed, and costs one probe to confirm.
//! * A switch has to *earn* it, by `improvement_threshold`, so the tuner does
//!   not flap between servers that are within noise of each other.
//! * When nothing is meaningfully better, that is reported rather than acted
//!   on — the interesting sub-case being "everything is slow", which points at
//!   the local link rather than at the server and must not cause churn.

use vpnmgr_core::config::{Autotune, SwitchPolicy};
use vpnmgr_core::score::relative_improvement;
use vpnmgr_ipc::RankedServer;

/// What a tuning pass observed.
#[derive(Debug, Clone)]
pub struct Assessment {
    /// `None` when the daemon is not connected.
    pub current: Option<Current>,
    /// Best candidate from the sweep, or `None` if nothing answered.
    pub best: Option<RankedServer>,
    pub probed: usize,
    /// The server the user chose to stay on when they last dismissed a
    /// proposal. While still on it, equivalent proposals are suppressed instead
    /// of re-raised every cycle.
    ///
    /// Keyed on where the user *is* rather than on the server that was
    /// suggested: several servers are usually within noise of each other, so
    /// the top candidate alternates between passes, and keying on the target
    /// would let the same suggestion return under a different name.
    pub declined_from: Option<String>,
}

/// The server we are on, as measured this pass.
#[derive(Debug, Clone)]
pub struct Current {
    pub name: String,
    /// `None` means it stopped answering probes entirely.
    pub rtt_ms: Option<f64>,
    /// Its score from the ranking. `None` when the current server was excluded
    /// by the filters and so never got ranked.
    pub score: Option<f64>,
}

/// Why a move is being suggested.
#[derive(Debug, Clone, PartialEq)]
pub enum Reason {
    /// The current server stopped answering. Always worth leaving, regardless
    /// of how good the alternative is.
    CurrentWentSilent,
    /// Still reachable, but slower than `max_latency_ms`, and something beat
    /// it by more than the threshold.
    Degraded {
        rtt_ms: f64,
        threshold_ms: u32,
        improvement: f64,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Nothing to tune.
    NotConnected,
    /// Current server is within `max_latency_ms`. The common path.
    Healthy { server: String, rtt_ms: f64 },
    /// Degraded, but already the best of the eligible servers.
    AlreadyBest { server: String, rtt_ms: f64 },
    /// Degraded, and something is better — but not by enough to be worth the
    /// interruption.
    NoBetterAvailable {
        server: String,
        rtt_ms: f64,
        best: String,
        best_rtt_ms: f64,
        improvement: f64,
        /// Set when even the best candidate is above `max_latency_ms`, which
        /// implicates the local link rather than any server.
        local_link_suspect: bool,
    },
    /// Moving now, because policy is `auto`.
    Switch {
        to: Box<RankedServer>,
        reason: Reason,
    },
    /// Waiting for the user to approve, because policy is `ask`.
    Propose {
        to: Box<RankedServer>,
        reason: Reason,
    },
    /// Would have moved, but policy is `never`.
    Blocked {
        to: Box<RankedServer>,
        reason: Reason,
    },
    /// Would have proposed, but the user already said no to this server.
    Suppressed {
        to: Box<RankedServer>,
        reason: Reason,
    },
    /// Every probed server was silent. Never a reason to switch.
    NothingReachable { probed: usize },
}

impl Decision {
    /// Whether this pass wants the tunnel moved right now.
    pub fn is_actionable(&self) -> bool {
        matches!(self, Decision::Switch { .. })
    }

    /// The server this decision points at, if any.
    pub fn target(&self) -> Option<&RankedServer> {
        match self {
            Decision::Switch { to, .. }
            | Decision::Propose { to, .. }
            | Decision::Blocked { to, .. }
            | Decision::Suppressed { to, .. } => Some(to),
            _ => None,
        }
    }

    /// One line for the log and for the desktop notification.
    pub fn describe(&self) -> String {
        match self {
            Decision::NotConnected => "not connected; nothing to tune".into(),
            Decision::Healthy { server, rtt_ms } => {
                format!("{server} is healthy at {rtt_ms:.1}ms")
            }
            Decision::AlreadyBest { server, rtt_ms } => format!(
                "{server} is slow at {rtt_ms:.1}ms, but it is still the best available; \
                 staying put"
            ),
            Decision::NoBetterAvailable {
                server,
                rtt_ms,
                best,
                best_rtt_ms,
                improvement,
                local_link_suspect,
            } => {
                if *local_link_suspect {
                    format!(
                        "{server} is slow at {rtt_ms:.1}ms, but so is every alternative \
                         (best {best} at {best_rtt_ms:.1}ms). That points at this machine's \
                         connection rather than the VPN, so nothing was changed."
                    )
                } else {
                    format!(
                        "{server} at {rtt_ms:.1}ms; best alternative {best} at \
                         {best_rtt_ms:.1}ms is only {:.0}% better, below the threshold",
                        improvement * 100.0
                    )
                }
            }
            Decision::Switch { to, reason } => {
                format!("switching to {} ({}): {}", to.name, to.location, reason.describe())
            }
            Decision::Propose { to, reason } => format!(
                "{} ({}) looks better: {}. Run `vpnmgr approve` to move.",
                to.name,
                to.location,
                reason.describe()
            ),
            Decision::Blocked { to, reason } => format!(
                "{} would be better ({}), but autotune.switch_policy is \"never\"",
                to.name,
                reason.describe()
            ),
            Decision::Suppressed { to, reason } => format!(
                "{} still looks better ({}), but you dismissed that move recently, \
                 so it will not be raised again for now",
                to.name,
                reason.describe()
            ),
            Decision::NothingReachable { probed } => format!(
                "none of the {probed} probed servers answered; treating this as a local \
                 connectivity problem rather than a reason to switch"
            ),
        }
    }
}

impl Reason {
    pub fn describe(&self) -> String {
        match self {
            Reason::CurrentWentSilent => "the current server stopped answering probes".into(),
            Reason::Degraded {
                rtt_ms,
                threshold_ms,
                improvement,
            } => format!(
                "{rtt_ms:.1}ms is over the {threshold_ms}ms limit and this is {:.0}% better",
                improvement * 100.0
            ),
        }
    }
}

/// Turn an assessment into a decision. Pure.
pub fn decide(assessment: &Assessment, autotune: &Autotune) -> Decision {
    let Some(current) = &assessment.current else {
        return Decision::NotConnected;
    };

    let Some(best) = &assessment.best else {
        return Decision::NothingReachable {
            probed: assessment.probed,
        };
    };

    // A server that has gone silent is worth leaving even for a mediocre
    // alternative, so this is checked before the latency threshold.
    let Some(rtt_ms) = current.rtt_ms else {
        // A dismissal covers a merely-slow server. A silent one is a worse
        // situation than the one declined, so it is always worth re-asking.
        return act(
            autotune.switch_policy,
            best.clone(),
            Reason::CurrentWentSilent,
            false,
        );
    };

    if rtt_ms <= f64::from(autotune.max_latency_ms) {
        return Decision::Healthy {
            server: current.name.clone(),
            rtt_ms,
        };
    }

    // Degraded from here down.
    if best.name == current.name {
        return Decision::AlreadyBest {
            server: current.name.clone(),
            rtt_ms,
        };
    }

    // Prefer comparing scores, which fold in load and spare bandwidth. Falls
    // back to raw latency when the current server was filtered out of the
    // ranking and therefore has no score to compare against.
    let improvement = match current.score {
        Some(score) => relative_improvement(score, best.score),
        None => {
            if rtt_ms <= f64::EPSILON {
                0.0
            } else {
                ((rtt_ms - best.rtt_ms) / rtt_ms).max(0.0)
            }
        }
    };

    if improvement < autotune.improvement_threshold {
        return Decision::NoBetterAvailable {
            server: current.name.clone(),
            rtt_ms,
            best: best.name.clone(),
            best_rtt_ms: best.rtt_ms,
            improvement,
            // Everything being slow at once implicates the path out of this
            // machine, not the exit server.
            local_link_suspect: best.rtt_ms > f64::from(autotune.max_latency_ms),
        };
    }

    act(
        autotune.switch_policy,
        best.clone(),
        Reason::Degraded {
            rtt_ms,
            threshold_ms: autotune.max_latency_ms,
            improvement,
        },
        assessment.declined_from.as_deref() == Some(current.name.as_str()),
    )
}

/// Apply the switch policy. `already_declined` suppresses a repeat prompt.
fn act(policy: SwitchPolicy, to: RankedServer, reason: Reason, already_declined: bool) -> Decision {
    let to = Box::new(to);
    match policy {
        // `auto` was told to act without consulting anyone, so a dismissal —
        // which exists only to quiet a prompt — does not apply to it.
        SwitchPolicy::Auto => Decision::Switch { to, reason },
        SwitchPolicy::Ask if already_declined => Decision::Suppressed { to, reason },
        SwitchPolicy::Ask => Decision::Propose { to, reason },
        SwitchPolicy::Never => Decision::Blocked { to, reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str, rtt_ms: f64, score: f64) -> RankedServer {
        RankedServer {
            name: name.into(),
            country_code: "ca".into(),
            country_name: "Canada".into(),
            location: "Toronto, Ontario".into(),
            load: 20,
            rtt_ms,
            score,
            entry: 1,
            endpoint: "1.2.3.4:1637".parse().unwrap(),
            mbps: None,
            mbps_age_secs: None,
        }
    }

    fn tune(policy: SwitchPolicy) -> Autotune {
        Autotune {
            max_latency_ms: 80,
            improvement_threshold: 0.25,
            switch_policy: policy,
            ..Default::default()
        }
    }

    #[test]
    fn a_disconnected_daemon_has_nothing_to_tune() {
        let a = Assessment {
            current: None,
            best: Some(server("Chamukuy", 5.0, 0.9)),
            probed: 10,
            declined_from: None,
        };
        assert_eq!(decide(&a, &tune(SwitchPolicy::Auto)), Decision::NotConnected);
    }

    #[test]
    fn a_fast_server_is_left_alone() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: Some(26.0),
                score: Some(0.5),
            }),
            // Something far better exists, but the current server is fine, so
            // it must not be disturbed.
            best: Some(server("Chamukuy", 5.0, 0.99)),
            probed: 200,
            declined_from: None,
        };
        assert!(matches!(
            decide(&a, &tune(SwitchPolicy::Auto)),
            Decision::Healthy { .. }
        ));
    }

    #[test]
    fn a_silent_current_server_is_abandoned_even_for_a_mediocre_alternative() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: None,
                score: None,
            }),
            best: Some(server("Chamukuy", 250.0, 0.1)),
            probed: 200,
            declined_from: None,
        };
        let d = decide(&a, &tune(SwitchPolicy::Auto));
        assert!(matches!(
            d,
            Decision::Switch {
                reason: Reason::CurrentWentSilent,
                ..
            }
        ));
    }

    #[test]
    fn a_slow_server_that_is_still_the_best_stays_put() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: Some(300.0),
                score: Some(0.4),
            }),
            best: Some(server("Muliphein", 300.0, 0.4)),
            probed: 200,
            declined_from: None,
        };
        assert!(matches!(
            decide(&a, &tune(SwitchPolicy::Auto)),
            Decision::AlreadyBest { .. }
        ));
    }

    /// The case the plan calls out: when the whole fleet is slow the problem is
    /// local, and churning servers would only make things worse.
    #[test]
    fn everything_being_slow_is_blamed_on_the_local_link_not_the_server() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: Some(400.0),
                score: Some(0.40),
            }),
            best: Some(server("Chamukuy", 390.0, 0.42)),
            probed: 200,
            declined_from: None,
        };
        let d = decide(&a, &tune(SwitchPolicy::Auto));
        match d {
            Decision::NoBetterAvailable {
                local_link_suspect, ..
            } => assert!(local_link_suspect, "should implicate the local link"),
            other => panic!("expected NoBetterAvailable, got {other:?}"),
        }
    }

    #[test]
    fn a_marginal_gain_does_not_justify_a_switch() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: Some(100.0),
                score: Some(0.80),
            }),
            // 5% better: real, but well under the 25% threshold.
            best: Some(server("Chamukuy", 95.0, 0.84)),
            probed: 200,
            declined_from: None,
        };
        match decide(&a, &tune(SwitchPolicy::Auto)) {
            Decision::NoBetterAvailable {
                improvement,
                local_link_suspect,
                ..
            } => {
                assert!(improvement < 0.25);
                // Not a local-link case: the alternative is over the limit too,
                // so this asserts the flag tracks the threshold, not the gap.
                assert!(local_link_suspect);
            }
            other => panic!("expected NoBetterAvailable, got {other:?}"),
        }
    }

    #[test]
    fn a_clear_win_switches_under_auto() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: Some(200.0),
                score: Some(0.40),
            }),
            best: Some(server("Chamukuy", 6.0, 0.95)),
            probed: 200,
            declined_from: None,
        };
        let d = decide(&a, &tune(SwitchPolicy::Auto));
        assert!(d.is_actionable());
        assert_eq!(d.target().unwrap().name, "Chamukuy");
    }

    /// The user chose "ask before switching", so the same input that would move
    /// the tunnel under `auto` must only ever produce a proposal.
    #[test]
    fn the_same_win_only_proposes_under_ask() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: Some(200.0),
                score: Some(0.40),
            }),
            best: Some(server("Chamukuy", 6.0, 0.95)),
            probed: 200,
            declined_from: None,
        };
        let d = decide(&a, &tune(SwitchPolicy::Ask));
        assert!(!d.is_actionable(), "ask must never move the tunnel itself");
        assert!(matches!(d, Decision::Propose { .. }));
    }

    /// Without this, "ask" would re-raise the identical proposal every cycle
    /// for as long as the condition held, which is nagging rather than asking.
    #[test]
    fn a_dismissed_proposal_is_not_raised_again() {
        let a = Assessment {
            current: Some(Current {
                name: "Azmidiske".into(),
                rtt_ms: Some(137.0),
                score: Some(0.41),
            }),
            best: Some(server("Kornephoros", 5.4, 0.84)),
            probed: 200,
            declined_from: Some("Azmidiske".into()),
        };
        let d = decide(&a, &tune(SwitchPolicy::Ask));
        assert!(matches!(d, Decision::Suppressed { .. }), "got {d:?}");
        assert!(!d.is_actionable());
    }

    /// The suppression is scoped to the server the user chose to stay on, so
    /// moving elsewhere and hitting the same condition asks again.
    #[test]
    fn a_dismissal_does_not_carry_over_to_a_different_current_server() {
        let a = Assessment {
            current: Some(Current {
                name: "Azmidiske".into(),
                rtt_ms: Some(137.0),
                score: Some(0.41),
            }),
            best: Some(server("Castula", 5.4, 0.84)),
            probed: 200,
            declined_from: Some("Benetnasch".into()),
        };
        assert!(matches!(
            decide(&a, &tune(SwitchPolicy::Ask)),
            Decision::Propose { .. }
        ));
    }

    /// A dismissal is about a merely-slow server. If the current server stops
    /// answering altogether that is a worse situation than the one declined,
    /// and the user should be asked again.
    #[test]
    fn a_dismissal_does_not_silence_a_server_going_silent() {
        let a = Assessment {
            current: Some(Current {
                name: "Azmidiske".into(),
                rtt_ms: None,
                score: None,
            }),
            best: Some(server("Kornephoros", 5.4, 0.84)),
            probed: 200,
            declined_from: Some("Azmidiske".into()),
        };
        assert!(matches!(
            decide(&a, &tune(SwitchPolicy::Ask)),
            Decision::Propose { .. }
        ));
    }

    /// `auto` was told to act without consulting anyone, so a dismissal — which
    /// only exists to quiet a prompt — must not stop it.
    #[test]
    fn a_dismissal_does_not_block_the_auto_policy() {
        let a = Assessment {
            current: Some(Current {
                name: "Azmidiske".into(),
                rtt_ms: Some(137.0),
                score: Some(0.41),
            }),
            best: Some(server("Kornephoros", 5.4, 0.84)),
            probed: 200,
            declined_from: Some("Azmidiske".into()),
        };
        assert!(decide(&a, &tune(SwitchPolicy::Auto)).is_actionable());
    }

    #[test]
    fn never_reports_but_does_not_move() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: Some(200.0),
                score: Some(0.40),
            }),
            best: Some(server("Chamukuy", 6.0, 0.95)),
            probed: 200,
            declined_from: None,
        };
        let d = decide(&a, &tune(SwitchPolicy::Never));
        assert!(!d.is_actionable());
        assert!(matches!(d, Decision::Blocked { .. }));
    }

    #[test]
    fn a_totally_unreachable_sweep_never_switches() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: None,
                score: None,
            }),
            best: None,
            probed: 231,
            declined_from: None,
        };
        let d = decide(&a, &tune(SwitchPolicy::Auto));
        assert!(!d.is_actionable());
        assert_eq!(d, Decision::NothingReachable { probed: 231 });
    }

    /// A current server dropped by the filters has no score, so the comparison
    /// has to fall back to latency instead of silently treating it as zero —
    /// which would make every candidate look infinitely better.
    #[test]
    fn a_current_server_without_a_score_is_compared_on_latency() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: Some(200.0),
                score: None,
            }),
            best: Some(server("Chamukuy", 20.0, 0.95)),
            probed: 200,
            declined_from: None,
        };
        match decide(&a, &tune(SwitchPolicy::Auto)) {
            Decision::Switch {
                reason: Reason::Degraded { improvement, .. },
                ..
            } => assert!((improvement - 0.9).abs() < 1e-9, "got {improvement}"),
            other => panic!("expected a switch, got {other:?}"),
        }
    }

    #[test]
    fn a_scoreless_current_server_with_a_marginal_alternative_stays() {
        let a = Assessment {
            current: Some(Current {
                name: "Muliphein".into(),
                rtt_ms: Some(100.0),
                score: None,
            }),
            best: Some(server("Chamukuy", 95.0, 0.95)),
            probed: 200,
            declined_from: None,
        };
        assert!(matches!(
            decide(&a, &tune(SwitchPolicy::Auto)),
            Decision::NoBetterAvailable { .. }
        ));
    }

    #[test]
    fn every_decision_describes_itself_without_panicking() {
        let to = Box::new(server("Chamukuy", 6.0, 0.95));
        let reason = Reason::CurrentWentSilent;
        for d in [
            Decision::NotConnected,
            Decision::Healthy {
                server: "M".into(),
                rtt_ms: 5.0,
            },
            Decision::AlreadyBest {
                server: "M".into(),
                rtt_ms: 500.0,
            },
            Decision::NoBetterAvailable {
                server: "M".into(),
                rtt_ms: 500.0,
                best: "C".into(),
                best_rtt_ms: 480.0,
                improvement: 0.04,
                local_link_suspect: true,
            },
            Decision::Switch {
                to: to.clone(),
                reason: reason.clone(),
            },
            Decision::Propose {
                to: to.clone(),
                reason: reason.clone(),
            },
            Decision::Blocked {
                to: to.clone(),
                reason: reason.clone(),
            },
            Decision::Suppressed { to, reason },
            Decision::NothingReachable { probed: 231 },
        ] {
            assert!(!d.describe().is_empty());
        }
    }
}
