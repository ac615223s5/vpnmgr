//! AirVPN server-list client.
//!
//! AirVPN publishes its full server list at an unauthenticated endpoint, so no
//! API key or login is needed. The response carries live `currentload`,
//! bandwidth and health per server, which is what the scorer ranks on.
//!
//! The property this whole project leans on: **every AirVPN server shares one
//! WireGuard peer public key**, and WireGuard listens on `ip_v4_in1:1637`. A
//! single client keypair (imported once from the Config Generator) is therefore
//! valid against every server, so switching servers only means rewriting the
//! peer endpoint. See [`WG_PUBLIC_KEY_FALLBACK`] for the caveat on that key.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::Deserialize;

use crate::error::{Error, Result};

/// Unauthenticated endpoint returning the full server list.
pub const STATUS_URL: &str = "https://airvpn.org/api/status/";

/// Port AirVPN's WireGuard instances listen on.
pub const WG_PORT: u16 = 1637;

/// Entry indices that actually run WireGuard.
///
/// AirVPN gives each server four entry addresses. Probing all four of a Toronto
/// server with real credentials showed entries **1 and 3** complete handshakes
/// (18.7 ms and 33.4 ms respectively) while 2 and 4 never answer — those carry
/// OpenVPN only. The two live entries can differ substantially in latency, so
/// both are worth probing and the faster one wins.
pub const WG_ENTRIES: [u8; 2] = [1, 3];

/// The peer public key shared by all AirVPN servers.
///
/// This is only a **fallback and sanity check**. The authoritative key is the
/// one in the user's imported `.conf`
/// ([`crate::wgconf::ClientConfig::peer_public_key`]), so a key rotation by
/// AirVPN cannot break an existing install. [`crate::wgconf::ClientConfig`]
/// warns when the imported key differs from this value.
pub const WG_PUBLIC_KEY_FALLBACK: &str = "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk=";

/// Server health as reported by AirVPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    Ok,
    Error,
    /// Any value AirVPN adds later. Treated as unusable.
    #[serde(other)]
    Unknown,
}

/// One AirVPN server.
///
/// Only the fields relevant to WireGuard are kept: `ip_v4_in1` / `ip_v6_in1`
/// are the WireGuard entry addresses, while `in2`–`in4` are OpenVPN-only and
/// are deliberately discarded.
#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    #[serde(rename = "public_name")]
    pub name: String,
    pub country_name: String,
    /// Lowercase ISO 3166-1 alpha-2, e.g. `se`.
    pub country_code: String,
    pub location: String,
    pub continent: String,
    /// Current throughput in Mbit/s.
    pub bw: u64,
    /// Provisioned capacity in Mbit/s.
    pub bw_max: u64,
    pub users: u32,
    /// Percentage load. Observed to exceed 100 on oversubscribed servers.
    #[serde(rename = "currentload")]
    pub load: u32,
    pub health: Health,
    /// Present only when `health` is `Error`, e.g. `"*Line problems"`.
    #[serde(default)]
    pub warning: Option<String>,
    /// Entry 1: a WireGuard entry address.
    #[serde(rename = "ip_v4_in1")]
    pub wg_ipv4: Ipv4Addr,
    /// Entry 3: the other WireGuard entry address. See [`WG_ENTRIES`].
    #[serde(rename = "ip_v4_in3", default)]
    pub wg_ipv4_alt: Option<Ipv4Addr>,
    #[serde(rename = "ip_v6_in1", default)]
    pub wg_ipv6: Option<Ipv6Addr>,
}

impl Server {
    pub fn is_healthy(&self) -> bool {
        self.health == Health::Ok
    }

    /// Primary WireGuard endpoint (entry 1).
    pub fn wg_endpoint(&self, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.wg_ipv4), port)
    }

    /// Endpoint for a specific entry index, if this server exposes it.
    pub fn wg_endpoint_for_entry(&self, entry: u8, port: u16) -> Option<SocketAddr> {
        let ip = match entry {
            1 => Some(self.wg_ipv4),
            3 => self.wg_ipv4_alt,
            // 2 and 4 are OpenVPN-only; asking for them is a caller mistake
            // rather than something to silently fall back from.
            _ => None,
        }?;
        Some(SocketAddr::new(IpAddr::V4(ip), port))
    }

    /// Every WireGuard endpoint worth probing, paired with its entry index.
    pub fn wg_endpoints(&self, entries: &[u8], port: u16) -> Vec<(u8, SocketAddr)> {
        entries
            .iter()
            .filter_map(|&e| self.wg_endpoint_for_entry(e, port).map(|a| (e, a)))
            .collect()
    }

    /// Load as a 0.0–1.0 fraction, saturating above 100%.
    pub fn load_fraction(&self) -> f64 {
        f64::from(self.load).min(100.0) / 100.0
    }

    /// Spare capacity in Mbit/s: provisioned minus what is in use.
    ///
    /// Absolute rather than fractional, because the fraction is not independent
    /// information. AirVPN's `currentload` *is* `bw / bw_max` — across all 257
    /// servers the two never differ by more than one percentage point — so
    /// scoring on the fraction counted load twice under two names. Absolute
    /// headroom is genuinely different: two servers at 40% utilisation have the
    /// same load but 1.2 Gbit/s and 12 Gbit/s of room respectively.
    ///
    /// Returns 0 when capacity is unknown, so a server with missing data is
    /// never preferred over one with measured headroom.
    pub fn headroom_mbps(&self) -> u64 {
        if self.bw_max == 0 {
            return 0;
        }
        self.bw_max.saturating_sub(self.bw)
    }

    /// Stable identifier used in configs, CLI arguments and blacklists.
    pub fn id(&self) -> &str {
        &self.name
    }
}

/// A decoded `/api/status/` response.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerList {
    pub servers: Vec<Server>,
    #[serde(default)]
    result: Option<String>,
}

impl ServerList {
    /// Decode and validate an `/api/status/` body.
    pub fn from_json(body: &str) -> Result<Self> {
        let list: ServerList = serde_json::from_str(body).map_err(Error::Decode)?;
        match list.result.as_deref() {
            // Older responses omit `result` entirely; absence is not an error.
            Some("ok") | None => Ok(list),
            Some(other) => Err(Error::ApiResult(other.to_owned())),
        }
    }

    pub fn healthy(&self) -> impl Iterator<Item = &Server> {
        self.servers.iter().filter(|s| s.is_healthy())
    }

    pub fn healthy_count(&self) -> usize {
        self.healthy().count()
    }

    pub fn get(&self, name: &str) -> Option<&Server> {
        self.servers
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }
}

/// HTTP client for the AirVPN status API.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    url: String,
}

impl Client {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("vpnmgr/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        Ok(Self {
            http,
            url: STATUS_URL.to_owned(),
        })
    }

    /// Point the client at a different URL. Used by tests.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    pub async fn fetch(&self) -> Result<ServerList> {
        let body = self
            .http
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        ServerList::from_json(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/airvpn_status.json");

    fn fixture() -> ServerList {
        ServerList::from_json(FIXTURE).expect("fixture should decode")
    }

    #[test]
    fn decodes_the_live_response_shape() {
        let list = fixture();
        assert_eq!(list.servers.len(), 257);
        assert_eq!(list.healthy_count(), 243);
    }

    #[test]
    fn keeps_the_wireguard_entry_address_not_the_openvpn_ones() {
        let list = fixture();
        let s = list.get("Achernar").expect("Achernar present");
        // ip_v4_in1 is the WireGuard entry; in2..in4 are OpenVPN and dropped.
        assert_eq!(s.wg_ipv4, Ipv4Addr::new(185, 156, 175, 170));
        assert_eq!(s.wg_endpoint(WG_PORT).to_string(), "185.156.175.170:1637");
    }

    #[test]
    fn unhealthy_servers_carry_a_warning() {
        let list = fixture();
        let sick: Vec<_> = list.servers.iter().filter(|s| !s.is_healthy()).collect();
        assert_eq!(sick.len(), 14);
        assert!(sick.iter().all(|s| s.warning.is_some()));
    }

    #[test]
    fn load_above_100_percent_saturates() {
        // At least one live server reports currentload > 100.
        let list = fixture();
        assert!(list.servers.iter().any(|s| s.load > 100));
        assert!(
            list.servers
                .iter()
                .all(|s| (0.0..=1.0).contains(&s.load_fraction()))
        );
    }

    #[test]
    fn headroom_is_never_more_than_the_provisioned_capacity() {
        let list = fixture();
        assert!(list.servers.iter().all(|s| s.headroom_mbps() <= s.bw_max));
    }

    /// The reason headroom replaced the spare-bandwidth *fraction*: servers at
    /// the same utilisation can have wildly different absolute room, and the
    /// fraction threw that away while duplicating `load`.
    #[test]
    fn equal_utilisation_can_mean_very_different_headroom() {
        let list = fixture();
        let same_util: Vec<_> = list
            .servers
            .iter()
            .filter(|s| s.bw_max > 0 && (38..=42).contains(&(s.bw * 100 / s.bw_max)))
            .collect();
        let min = same_util.iter().map(|s| s.headroom_mbps()).min().unwrap();
        let max = same_util.iter().map(|s| s.headroom_mbps()).max().unwrap();
        assert!(
            max >= min * 5,
            "expected a wide headroom spread at equal utilisation, got {min}..{max}"
        );
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let list = fixture();
        assert!(list.get("achernar").is_some());
    }

    #[test]
    fn rejects_a_non_ok_result() {
        let err = ServerList::from_json(r#"{"servers":[],"result":"error"}"#).unwrap_err();
        assert!(matches!(err, Error::ApiResult(r) if r == "error"));
    }

    #[test]
    fn accepts_a_response_without_a_result_field() {
        assert!(ServerList::from_json(r#"{"servers":[]}"#).is_ok());
    }

    #[test]
    fn unknown_health_values_are_not_healthy() {
        let json = r#"{"servers":[{"public_name":"X","country_name":"Sweden",
            "country_code":"se","location":"L","continent":"Europe","bw":1,"bw_max":2,
            "users":1,"currentload":1,"health":"maintenance","ip_v4_in1":"1.2.3.4"}]}"#;
        let list = ServerList::from_json(json).unwrap();
        assert_eq!(list.servers[0].health, Health::Unknown);
        assert_eq!(list.healthy_count(), 0);
    }
}
