//! `config.toml` — the daemon's on-disk settings.
//!
//! Key material is referenced by path, never inlined, so the config file can
//! stay world-readable while the keys sit in root-owned `0600` files.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::airvpn;
use crate::error::{Error, Result};
use crate::key::{PublicKey, SecretKey};
use crate::wgconf::{Cidr, ClientConfig};

/// Default config location on Linux.
pub const DEFAULT_PATH: &str = "/etc/vpnmgr/config.toml";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub provider: Provider,
    #[serde(default)]
    pub filters: Filters,
    #[serde(default)]
    pub autotune: Autotune,
    #[serde(default)]
    pub probe: Probe,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub airvpn: AirvpnProvider,
}

/// Credentials imported once from the AirVPN Config Generator.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AirvpnProvider {
    /// Path to a `0600` file holding the base64 private key.
    pub private_key_file: PathBuf,
    /// Path to a `0600` file holding the base64 preshared key, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key_file: Option<PathBuf>,
    /// Tunnel-local addresses assigned by AirVPN.
    pub address: Vec<Cidr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
    /// The fleet-wide peer key, taken from the imported config rather than
    /// hardcoded, so an AirVPN key rotation cannot brick an install.
    pub peer_public_key: PublicKey,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: Option<u16>,
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: Vec<Cidr>,
}

/// Which servers are eligible. Applied before any network probing.
///
/// `Default` is hand-written rather than derived: a derived one would set
/// `max_load` to 0 and silently reject every server whenever the `[filters]`
/// section is omitted.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Filters {
    /// Lowercase ISO country codes. Empty means every country.
    #[serde(default)]
    pub country_whitelist: Vec<String>,
    #[serde(default)]
    pub country_blacklist: Vec<String>,
    /// Server names, e.g. `Benetnasch`. Empty means every server.
    #[serde(default)]
    pub server_whitelist: Vec<String>,
    #[serde(default)]
    pub server_blacklist: Vec<String>,
    /// Reject servers reporting a load above this percentage.
    #[serde(default = "default_max_load")]
    pub max_load: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SwitchPolicy {
    /// Notify and wait for confirmation before moving. The default.
    Ask,
    /// Switch without asking.
    Auto,
    /// Only ever report; never move.
    Never,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Autotune {
    #[serde(default = "default_interval")]
    pub interval_minutes: u64,
    /// Above this round-trip time the current server counts as degraded.
    #[serde(default = "default_max_latency")]
    pub max_latency_ms: u32,
    /// Throughput floor for the opt-in Tier-2 test.
    #[serde(default = "default_min_mbps")]
    pub min_mbps: f64,
    #[serde(default = "default_switch_policy")]
    pub switch_policy: SwitchPolicy,
    /// Fractional score improvement required to justify a switch, 0.0–1.0.
    /// Keeps the tuner from flapping between near-identical servers.
    #[serde(default = "default_improvement")]
    pub improvement_threshold: f64,
    #[serde(default)]
    pub weights: Weights,
}

/// Relative importance of each ranking signal. Normalised before use, so only
/// the ratios matter.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    /// Measured handshake round-trip time.
    #[serde(default = "default_w_rtt")]
    pub rtt: f64,
    /// Load reported by the API.
    #[serde(default = "default_w_load")]
    pub load: f64,
    /// Spare bandwidth reported by the API.
    #[serde(default = "default_w_bandwidth")]
    pub bandwidth: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    /// Handshakes in flight at once. Bounded to stay well clear of the
    /// rate limiting a WireGuard endpoint applies under load.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Handshakes per server; the median is used.
    #[serde(default = "default_samples")]
    pub samples: usize,
}

fn default_port() -> u16 {
    airvpn::WG_PORT
}
fn default_keepalive() -> Option<u16> {
    Some(15)
}
fn default_allowed_ips() -> Vec<Cidr> {
    vec![
        "0.0.0.0/0".parse().expect("literal is valid"),
        "::/0".parse().expect("literal is valid"),
    ]
}
fn default_max_load() -> u32 {
    85
}
fn default_interval() -> u64 {
    30
}
fn default_max_latency() -> u32 {
    80
}
fn default_min_mbps() -> f64 {
    50.0
}
fn default_switch_policy() -> SwitchPolicy {
    SwitchPolicy::Ask
}
fn default_improvement() -> f64 {
    0.25
}
fn default_concurrency() -> usize {
    32
}
fn default_timeout() -> u64 {
    1500
}
fn default_samples() -> usize {
    3
}
fn default_w_rtt() -> f64 {
    0.6
}
fn default_w_load() -> f64 {
    0.3
}
fn default_w_bandwidth() -> f64 {
    0.1
}

impl Default for Filters {
    fn default() -> Self {
        Self {
            country_whitelist: Vec::new(),
            country_blacklist: Vec::new(),
            server_whitelist: Vec::new(),
            server_blacklist: Vec::new(),
            max_load: default_max_load(),
        }
    }
}

impl Default for Autotune {
    fn default() -> Self {
        Self {
            interval_minutes: default_interval(),
            max_latency_ms: default_max_latency(),
            min_mbps: default_min_mbps(),
            switch_policy: default_switch_policy(),
            improvement_threshold: default_improvement(),
            weights: Weights::default(),
        }
    }
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            rtt: default_w_rtt(),
            load: default_w_load(),
            bandwidth: default_w_bandwidth(),
        }
    }
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            concurrency: default_concurrency(),
            timeout_ms: default_timeout(),
            samples: default_samples(),
        }
    }
}

impl Autotune {
    pub fn interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_minutes * 60)
    }
}

impl Probe {
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.timeout_ms)
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text, path)
    }

    pub fn parse(text: &str, path: impl AsRef<Path>) -> Result<Self> {
        let config: Config = toml::from_str(text).map_err(|source| Error::ConfigParse {
            path: path.as_ref().to_owned(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Render back to TOML, for `vpnmgr import`.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("serialising the config: {e}")))
    }

    /// Reject settings that parse but cannot work, with an actionable message.
    pub fn validate(&self) -> Result<()> {
        let f = &self.filters;

        if f.max_load > 200 {
            return Err(Error::Config(format!(
                "filters.max_load = {} is meaningless; AirVPN reports load as a percentage",
                f.max_load
            )));
        }

        // A country in both lists selects nothing, which would otherwise show
        // up much later as a confusing "no candidates".
        let white: BTreeSet<_> = f.country_whitelist.iter().map(lower).collect();
        let black: BTreeSet<_> = f.country_blacklist.iter().map(lower).collect();
        let both: Vec<_> = white.intersection(&black).cloned().collect();
        if !both.is_empty() {
            return Err(Error::Config(format!(
                "these countries are in both filters.country_whitelist and \
                 country_blacklist, so nothing can match: {}",
                both.join(", ")
            )));
        }

        let swhite: BTreeSet<_> = f.server_whitelist.iter().map(lower).collect();
        let sblack: BTreeSet<_> = f.server_blacklist.iter().map(lower).collect();
        let both: Vec<_> = swhite.intersection(&sblack).cloned().collect();
        if !both.is_empty() {
            return Err(Error::Config(format!(
                "these servers are in both filters.server_whitelist and \
                 server_blacklist, so nothing can match: {}",
                both.join(", ")
            )));
        }

        if self.probe.concurrency == 0 {
            return Err(Error::Config("probe.concurrency must be at least 1".into()));
        }
        if self.probe.samples == 0 {
            return Err(Error::Config("probe.samples must be at least 1".into()));
        }
        if self.probe.timeout_ms == 0 {
            return Err(Error::Config("probe.timeout_ms must be greater than 0".into()));
        }
        if self.autotune.interval_minutes == 0 {
            return Err(Error::Config(
                "autotune.interval_minutes must be greater than 0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.autotune.improvement_threshold) {
            return Err(Error::Config(format!(
                "autotune.improvement_threshold = {} must be between 0.0 and 1.0",
                self.autotune.improvement_threshold
            )));
        }

        let w = &self.autotune.weights;
        if w.rtt < 0.0 || w.load < 0.0 || w.bandwidth < 0.0 {
            return Err(Error::Config("autotune.weights must not be negative".into()));
        }
        if w.rtt + w.load + w.bandwidth <= 0.0 {
            return Err(Error::Config(
                "at least one autotune.weights entry must be greater than 0".into(),
            ));
        }

        if self.provider.airvpn.address.is_empty() {
            return Err(Error::Config(
                "provider.airvpn.address must list at least one tunnel address".into(),
            ));
        }

        Ok(())
    }

    /// Read the key files and assemble the credentials used to build tunnels.
    ///
    /// Kept separate from [`Config::load`] so unprivileged clients can read the
    /// config without touching the keys.
    pub fn load_client_config(&self) -> Result<ClientConfig> {
        let p = &self.provider.airvpn;
        let private_key = read_key(&p.private_key_file)?;
        let preshared_key = match &p.preshared_key_file {
            Some(path) => Some(read_key(path)?),
            None => None,
        };
        Ok(ClientConfig {
            private_key,
            addresses: p.address.clone(),
            dns: p.dns.clone(),
            search_domains: p.search_domains.clone(),
            mtu: p.mtu,
            peer_public_key: p.peer_public_key.clone(),
            preshared_key,
            allowed_ips: p.allowed_ips.clone(),
            persistent_keepalive: p.persistent_keepalive,
        })
    }

    /// Build a config from a freshly imported `.conf`, given where the secrets
    /// will be written. The caller is responsible for writing those files
    /// with `0600` permissions.
    pub fn from_imported(client: &ClientConfig, private_key_file: PathBuf, preshared_key_file: PathBuf) -> Self {
        Self {
            provider: Provider {
                airvpn: AirvpnProvider {
                    private_key_file,
                    preshared_key_file: client.preshared_key.as_ref().map(|_| preshared_key_file),
                    address: client.addresses.clone(),
                    dns: client.dns.clone(),
                    search_domains: client.search_domains.clone(),
                    peer_public_key: client.peer_public_key.clone(),
                    port: airvpn::WG_PORT,
                    mtu: client.mtu,
                    persistent_keepalive: client.persistent_keepalive,
                    allowed_ips: client.allowed_ips.clone(),
                },
            },
            filters: Filters::default(),
            autotune: Autotune::default(),
            probe: Probe::default(),
        }
    }
}

fn lower(s: impl AsRef<str>) -> String {
    s.as_ref().trim().to_ascii_lowercase()
}

fn read_key(path: &Path) -> Result<SecretKey> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.to_owned(),
        source,
    })?;
    SecretKey::from_base64(text.trim()).map_err(|e| {
        // Names the file and the failure mode, never the contents.
        Error::Config(format!("{}: {e}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[provider.airvpn]
private_key_file = "/etc/vpnmgr/wg.key"
address = ["10.176.14.22/32"]
peer_public_key = "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk="
"#;

    fn parse(text: &str) -> Result<Config> {
        Config::parse(text, "config.toml")
    }

    #[test]
    fn a_minimal_config_gets_sensible_defaults() {
        let c = parse(MINIMAL).unwrap();
        assert_eq!(c.provider.airvpn.port, airvpn::WG_PORT);
        assert_eq!(c.filters.max_load, 85);
        assert_eq!(c.autotune.interval_minutes, 30);
        assert_eq!(c.autotune.switch_policy, SwitchPolicy::Ask);
        assert_eq!(c.probe.concurrency, 32);
        // Defaults to a full tunnel rather than leaking traffic.
        assert_eq!(c.provider.airvpn.allowed_ips.len(), 2);
        assert!(c.provider.airvpn.allowed_ips.iter().any(Cidr::is_default_route));
    }

    #[test]
    fn round_trips_through_toml() {
        let original = parse(MINIMAL).unwrap();
        let text = toml::to_string(&original).unwrap();
        let again = parse(&text).unwrap();
        assert_eq!(
            again.provider.airvpn.peer_public_key.to_base64(),
            original.provider.airvpn.peer_public_key.to_base64()
        );
    }

    #[test]
    fn rejects_a_typo_in_a_key_name() {
        // deny_unknown_fields turns a silently-ignored setting into an error.
        let text = format!("{MINIMAL}\n[autotune]\ninterval_minute = 5\n");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn rejects_a_country_in_both_lists() {
        let text = format!(
            "{MINIMAL}\n[filters]\ncountry_whitelist = [\"se\", \"ch\"]\ncountry_blacklist = [\"SE\"]\n"
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("both"), "{err}");
        assert!(err.contains("se"), "{err}");
    }

    #[test]
    fn rejects_a_server_in_both_lists() {
        let text = format!(
            "{MINIMAL}\n[filters]\nserver_whitelist = [\"Benetnasch\"]\nserver_blacklist = [\"benetnasch\"]\n"
        );
        assert!(parse(&text).unwrap_err().to_string().contains("both"));
    }

    #[test]
    fn rejects_a_zero_probe_concurrency() {
        let text = format!("{MINIMAL}\n[probe]\nconcurrency = 0\n");
        assert!(parse(&text).unwrap_err().to_string().contains("at least 1"));
    }

    #[test]
    fn rejects_an_out_of_range_improvement_threshold() {
        let text = format!("{MINIMAL}\n[autotune]\nimprovement_threshold = 1.5\n");
        assert!(parse(&text).unwrap_err().to_string().contains("between 0.0 and 1.0"));
    }

    #[test]
    fn rejects_all_zero_weights() {
        let text = format!(
            "{MINIMAL}\n[autotune.weights]\nrtt = 0.0\nload = 0.0\nbandwidth = 0.0\n"
        );
        assert!(parse(&text).unwrap_err().to_string().contains("greater than 0"));
    }

    #[test]
    fn rejects_a_malformed_peer_key() {
        let text = MINIMAL.replace(
            "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk=",
            "not-a-key",
        );
        assert!(parse(&text).is_err());
    }

    #[test]
    fn rejects_an_empty_address_list() {
        let text = MINIMAL.replace(r#"address = ["10.176.14.22/32"]"#, "address = []");
        assert!(parse(&text).unwrap_err().to_string().contains("at least one"));
    }

    #[test]
    fn serialised_config_never_contains_key_material() {
        // Only paths are stored, so a config file is safe to share.
        let text = toml::to_string(&parse(MINIMAL).unwrap()).unwrap();
        assert!(text.contains("private_key_file"));
        assert!(!text.contains("PrivateKey"));
    }
}
