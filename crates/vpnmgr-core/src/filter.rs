//! Tier 0 of the probe funnel: narrow the fleet using only API metadata.
//!
//! This is free — no packets — and typically cuts 257 servers to 50–150 before
//! any handshake is sent. Rejections are returned with a reason so the CLI can
//! explain an empty result instead of just reporting "no candidates".

use crate::airvpn::{Server, ServerList};
use crate::config::Filters;

/// Why a server was excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// AirVPN reports a problem; `warning` carries its text.
    Unhealthy(Option<String>),
    CountryNotWhitelisted,
    CountryBlacklisted,
    ServerNotWhitelisted,
    ServerBlacklisted,
    /// Reported load exceeded `filters.max_load`.
    LoadTooHigh { load: u32, max: u32 },
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unhealthy(Some(w)) => write!(f, "unhealthy ({w})"),
            Self::Unhealthy(None) => f.write_str("unhealthy"),
            Self::CountryNotWhitelisted => f.write_str("country not in whitelist"),
            Self::CountryBlacklisted => f.write_str("country blacklisted"),
            Self::ServerNotWhitelisted => f.write_str("server not in whitelist"),
            Self::ServerBlacklisted => f.write_str("server blacklisted"),
            Self::LoadTooHigh { load, max } => write!(f, "load {load}% exceeds max_load {max}%"),
        }
    }
}

/// Outcome of applying [`Filters`] to a server list.
#[derive(Debug)]
pub struct Selection<'a> {
    pub accepted: Vec<&'a Server>,
    pub rejected: Vec<(&'a Server, Rejection)>,
}

impl<'a> Selection<'a> {
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }

    /// Rejection reasons with counts, most common first — the useful summary
    /// when a filter set matches nothing.
    pub fn rejection_summary(&self) -> Vec<(String, usize)> {
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (_, reason) in &self.rejected {
            // Collapse the parameterised variants so the summary stays short.
            let label = match reason {
                Rejection::Unhealthy(_) => "unhealthy".to_owned(),
                Rejection::LoadTooHigh { max, .. } => format!("load above max_load {max}%"),
                other => other.to_string(),
            };
            *counts.entry(label).or_default() += 1;
        }
        let mut out: Vec<_> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }
}

/// Apply `filters` to `list`.
///
/// Order matters for the reported reason: health first, then blacklists (an
/// explicit exclusion is the most useful thing to report), then whitelists,
/// then load.
pub fn apply<'a>(list: &'a ServerList, filters: &Filters) -> Selection<'a> {
    let country_white = normalised(&filters.country_whitelist);
    let country_black = normalised(&filters.country_blacklist);
    let server_white = normalised(&filters.server_whitelist);
    let server_black = normalised(&filters.server_blacklist);

    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    for server in &list.servers {
        let name = server.name.to_ascii_lowercase();
        let country = server.country_code.to_ascii_lowercase();

        let reason = if !server.is_healthy() {
            Some(Rejection::Unhealthy(server.warning.clone()))
        } else if server_black.contains(&name) {
            Some(Rejection::ServerBlacklisted)
        } else if country_black.contains(&country) {
            Some(Rejection::CountryBlacklisted)
        } else if !server_white.is_empty() && !server_white.contains(&name) {
            Some(Rejection::ServerNotWhitelisted)
        } else if !country_white.is_empty() && !country_white.contains(&country) {
            Some(Rejection::CountryNotWhitelisted)
        } else if server.load > filters.max_load {
            Some(Rejection::LoadTooHigh {
                load: server.load,
                max: filters.max_load,
            })
        } else {
            None
        };

        match reason {
            Some(r) => rejected.push((server, r)),
            None => accepted.push(server),
        }
    }

    Selection { accepted, rejected }
}

fn normalised(values: &[String]) -> std::collections::HashSet<String> {
    values
        .iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airvpn::ServerList;

    const FIXTURE: &str = include_str!("../tests/fixtures/airvpn_status.json");

    fn list() -> ServerList {
        ServerList::from_json(FIXTURE).unwrap()
    }

    fn filters() -> Filters {
        Filters {
            max_load: 100,
            ..Default::default()
        }
    }

    #[test]
    fn empty_filters_accept_every_healthy_server() {
        let list = list();
        let sel = apply(&list, &filters());
        // 243 healthy, minus the one server reporting load above 100.
        assert_eq!(sel.accepted.len(), 242);
        assert!(sel.accepted.iter().all(|s| s.is_healthy()));
    }

    #[test]
    fn unhealthy_servers_are_always_excluded() {
        let list = list();
        let sel = apply(&list, &filters());
        assert_eq!(
            sel.rejected
                .iter()
                .filter(|(_, r)| matches!(r, Rejection::Unhealthy(_)))
                .count(),
            14
        );
    }

    #[test]
    fn a_country_whitelist_restricts_to_those_countries() {
        let list = list();
        let f = Filters {
            country_whitelist: vec!["se".into(), "CH".into()],
            ..filters()
        };
        let sel = apply(&list, &f);
        assert!(!sel.is_empty());
        assert!(
            sel.accepted
                .iter()
                .all(|s| matches!(s.country_code.as_str(), "se" | "ch"))
        );
    }

    #[test]
    fn a_country_blacklist_removes_those_countries() {
        let list = list();
        let f = Filters {
            country_blacklist: vec!["nl".into()],
            ..filters()
        };
        let sel = apply(&list, &f);
        assert!(sel.accepted.iter().all(|s| s.country_code != "nl"));
        // The fixture has 73 Netherlands servers, so this must remove some.
        assert!(!sel.rejected.is_empty());
    }

    #[test]
    fn a_server_blacklist_beats_a_country_whitelist() {
        let list = list();
        let named = list
            .healthy()
            .find(|s| s.country_code == "se")
            .unwrap()
            .name
            .clone();
        let f = Filters {
            country_whitelist: vec!["se".into()],
            server_blacklist: vec![named.to_ascii_uppercase()],
            ..filters()
        };
        let sel = apply(&list, &f);
        assert!(sel.accepted.iter().all(|s| s.name != named));
        assert_eq!(
            sel.rejected
                .iter()
                .find(|(s, _)| s.name == named)
                .map(|(_, r)| r.clone()),
            Some(Rejection::ServerBlacklisted)
        );
    }

    #[test]
    fn max_load_excludes_busy_servers() {
        let list = list();
        let f = Filters {
            max_load: 20,
            ..Default::default()
        };
        let sel = apply(&list, &f);
        assert!(!sel.accepted.is_empty());
        assert!(sel.accepted.iter().all(|s| s.load <= 20));
    }

    #[test]
    fn an_impossible_filter_explains_itself() {
        let list = list();
        let f = Filters {
            country_whitelist: vec!["zz".into()],
            ..filters()
        };
        let sel = apply(&list, &f);
        assert!(sel.is_empty());
        let summary = sel.rejection_summary();
        assert_eq!(summary[0].0, "country not in whitelist");
        assert!(summary[0].1 > 200);
    }

    #[test]
    fn filters_ignore_case_and_surrounding_whitespace() {
        let list = list();
        let f = Filters {
            country_whitelist: vec!["  SE  ".into()],
            ..filters()
        };
        assert!(!apply(&list, &f).is_empty());
    }

    #[test]
    fn every_server_lands_in_exactly_one_bucket() {
        let list = list();
        let sel = apply(&list, &filters());
        assert_eq!(sel.accepted.len() + sel.rejected.len(), list.servers.len());
    }
}
