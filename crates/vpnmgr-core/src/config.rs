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

/// Default config location.
///
/// `ProgramData` is the Windows counterpart of `/etc`: machine-wide state that
/// outlives any one user. It sits beside the key files, so the directory's
/// access control is what protects them and it must not be world-writable.
#[cfg(unix)]
pub const DEFAULT_PATH: &str = "/etc/vpnmgr/config.toml";
/// Default config location. See the Unix variant for the reasoning.
#[cfg(windows)]
pub const DEFAULT_PATH: &str = r"C:\ProgramData\vpnmgr\config.toml";

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
    #[serde(default)]
    pub killswitch: Killswitch,
    #[serde(default)]
    pub throughput: Throughput,
    #[serde(default)]
    pub bypass: Bypass,
}

/// Destinations that should not travel through the tunnel.
///
/// A full tunnel captures everything, including the connection you are working
/// over and any other VPN you depend on. Loopback and the local network are
/// already exempt by virtue of how policy routing works; these are the cases
/// that are not.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bypass {
    /// Networks or addresses to route around the tunnel.
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// Hostnames to route around the tunnel.
    ///
    /// Resolved once, when connecting. A host behind a CDN answers with a
    /// rotating subset of a larger pool, so prefer a CIDR when the addresses
    /// move.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Keep other VPNs on this machine working.
    ///
    /// On by default because it is otherwise a silent breakage: tools like
    /// Tailscale keep their routes in a private table consulted *after* ours,
    /// so connecting quietly makes their peers unreachable.
    #[serde(default = "default_true")]
    pub other_vpns: bool,
    /// Keep the private address space reachable on the physical link.
    ///
    /// On by default, for the same reason as `other_vpns`: without it a full
    /// tunnel silently swallows every private subnet that is *routed* rather
    /// than attached. Your own subnet keeps working — it has a link route —
    /// so the breakage looks arbitrary: the machine next to you answers and
    /// the printer one subnet over does not.
    ///
    /// Private ranges the tunnel itself uses are excluded automatically, so
    /// this cannot strand the tunnel's own nameservers.
    #[serde(default = "default_true")]
    pub lan: bool,
}

/// Settings for the Tier-2 throughput test.
///
/// Never runs as part of a sweep or the scheduled tuning pass: it moves tens of
/// megabytes, and doing that every 30 minutes would cost more than it is worth.
/// It runs when explicitly asked for, via `vpnmgr speedtest` or `vpnmgr
/// baseline`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Throughput {
    /// Where to pull the payload from. Must accept a byte count and return
    /// incompressible data.
    #[serde(default = "default_throughput_url")]
    pub url: String,
    #[serde(default = "default_throughput_bytes")]
    pub bytes: u64,
    #[serde(default = "default_throughput_timeout")]
    pub timeout_secs: u64,
    /// Payload for the measurements taken while choosing a server, in bytes.
    ///
    /// Smaller than `bytes` on purpose: picking between candidates needs a
    /// rough figure, not a precise one, and this may run several times in a row.
    /// Still large enough to clear TCP slow start, which the first couple of
    /// megabytes are spent on.
    #[serde(default = "default_select_bytes")]
    pub select_bytes: u64,
}

/// Refuse to let traffic leave outside the tunnel.
///
/// Off by default, and deliberately so: it is enforced with firewall rules that
/// outlive the daemon, so a crash leaves the machine with no direct internet
/// access until they are cleared. That is the correct behaviour for a kill
/// switch and the wrong surprise to hand someone who did not ask for it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Killswitch {
    #[serde(default)]
    pub enabled: bool,
    /// Keep the local network reachable. Without this, enabling the kill switch
    /// also cuts off printers, NAS boxes and inbound SSH.
    #[serde(default = "default_allow_lan")]
    pub allow_lan: bool,
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
    /// Absolute throughput floor, in Mbit/s.
    ///
    /// A server delivering less than this is rejected however modest the
    /// target is. It is a backstop, not the usual bar — see `accept_fraction`.
    #[serde(default = "default_min_mbps")]
    pub min_mbps: f64,
    /// Fraction of `target_mbps` a server must deliver to be accepted when
    /// choosing automatically.
    ///
    /// Below 1.0 deliberately. Demanding the full target would mean rejecting
    /// servers for the ordinary overhead of tunnelling and for any transient
    /// congestion, so a connect would work through every candidate and settle
    /// on whichever happened to be least bad.
    #[serde(default = "default_accept_fraction")]
    pub accept_fraction: f64,
    /// Measure the connection itself, with no tunnel up, before connecting.
    ///
    /// This is what calibrates `target_mbps` to the real line rate, so the
    /// acceptance bar means something on this machine rather than being a
    /// guess. It costs one short download and exposes nothing: the tunnel is
    /// already down at that point, which is exactly why it is a *direct*
    /// measurement.
    #[serde(default = "default_true")]
    pub measure_before_connect: bool,
    /// Throughput you want the VPN to be able to sustain, in Mbit/s.
    ///
    /// Set this a little below your line rate: it is what you expect to get,
    /// not the number on the bill. It anchors the capacity term in scoring —
    /// a server needs `target_mbps * headroom_margin` free to score full marks.
    ///
    /// Left unset, the daemon uses whatever `vpnmgr baseline` last measured
    /// directly on your own connection, shaded down slightly, and falls back to
    /// a conservative default until one has run.
    #[serde(default)]
    pub target_mbps: Option<f64>,
    /// How many times `target_mbps` a server should have spare before its
    /// capacity stops counting against it.
    ///
    /// Above 1.0 because the figure is a fleet-wide average that moves, you are
    /// not the only client arriving, and a server with exactly enough room for
    /// you has none for anyone else.
    #[serde(default = "default_headroom_margin")]
    pub headroom_margin: f64,
    /// How many of the best-ranked servers to actually connect to and measure
    /// before settling, when picking a server automatically.
    ///
    /// Ranking is a prediction from latency and reported capacity; this checks
    /// it against reality, because a server can be close and idle and still be
    /// slow. The first candidate to clear `min_mbps` wins, so the usual cost is
    /// one measurement, not this many. Set to 0 to trust the ranking and skip
    /// measuring entirely.
    #[serde(default = "default_verify_candidates")]
    pub verify_candidates: usize,
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
///
/// Capacity outweighs load because the two overlap and headroom is the better
/// of the pair: `load` is a raw utilisation percentage, while headroom is the
/// same utilisation expressed against what *this* machine needs, so it already
/// accounts for a server's size. Load is kept at a low weight as a tiebreaker
/// for servers whose headroom is comfortably past the target and therefore
/// tied at full marks.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    /// Measured handshake round-trip time.
    #[serde(default = "default_w_rtt")]
    pub rtt: f64,
    /// Load reported by the API.
    #[serde(default = "default_w_load")]
    pub load: f64,
    /// Absolute spare capacity reported by the API.
    ///
    /// Accepts the old `bandwidth` key: this used to weight the spare-bandwidth
    /// *fraction*, which turned out to be the same number as `load` and so
    /// counted it twice. Existing configs keep working.
    #[serde(default = "default_w_headroom", alias = "bandwidth")]
    pub headroom: f64,
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
fn default_accept_fraction() -> f64 {
    0.6
}
/// Used only until a baseline measurement exists. Deliberately conservative:
/// with the default margin it reproduces the 1 Gbit/s saturation point this
/// replaced, so an unconfigured install behaves as before.
pub const DEFAULT_TARGET_MBPS: f64 = 500.0;
/// What fraction of a measured direct throughput to treat as the target.
/// "A bit below the maximum" — the peak is not what you sustain.
pub const MEASURED_TARGET_FRACTION: f64 = 0.9;
fn default_headroom_margin() -> f64 {
    2.0
}
fn default_verify_candidates() -> usize {
    5
}
fn default_true() -> bool {
    true
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
    0.1
}
fn default_w_headroom() -> f64 {
    0.3
}
fn default_allow_lan() -> bool {
    true
}
fn default_throughput_url() -> String {
    "https://speed.cloudflare.com/__down?bytes=".into()
}
fn default_throughput_bytes() -> u64 {
    25_000_000
}
fn default_throughput_timeout() -> u64 {
    30
}
fn default_select_bytes() -> u64 {
    8_000_000
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
            accept_fraction: default_accept_fraction(),
            measure_before_connect: true,
            target_mbps: None,
            headroom_margin: default_headroom_margin(),
            verify_candidates: default_verify_candidates(),
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
            headroom: default_w_headroom(),
        }
    }
}

impl Default for Bypass {
    fn default() -> Self {
        Self {
            cidrs: Vec::new(),
            hosts: Vec::new(),
            other_vpns: true,
            lan: true,
        }
    }
}

impl Default for Killswitch {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_lan: default_allow_lan(),
        }
    }
}

impl Default for Throughput {
    fn default() -> Self {
        Self {
            url: default_throughput_url(),
            bytes: default_throughput_bytes(),
            timeout_secs: default_throughput_timeout(),
            select_bytes: default_select_bytes(),
        }
    }
}

impl Throughput {
    /// The full request URL. The byte count is appended when the configured
    /// URL ends in `=`, which is the shape the default endpoint takes.
    pub fn request_url(&self) -> String {
        self.request_url_for(self.bytes)
    }

    /// The same, for an arbitrary payload size.
    pub fn request_url_for(&self, bytes: u64) -> String {
        if self.url.ends_with('=') {
            format!("{}{bytes}", self.url)
        } else {
            self.url.clone()
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

    /// Throughput to aim for, in Mbit/s.
    ///
    /// `measured_direct_mbps` is what the connection itself managed with the
    /// tunnel down, if that has ever been measured. An explicit `target_mbps`
    /// always wins over it, so configuring it stays dependable.
    pub fn target_mbps(&self, measured_direct_mbps: Option<f64>) -> f64 {
        self.target_mbps
            .or_else(|| {
                measured_direct_mbps
                    .filter(|m| *m > 0.0)
                    .map(|m| m * MEASURED_TARGET_FRACTION)
            })
            .unwrap_or(DEFAULT_TARGET_MBPS)
    }

    /// Spare capacity at which a server scores full marks, in Mbit/s.
    pub fn headroom_target_mbps(&self, measured_direct_mbps: Option<f64>) -> f64 {
        // Never zero: it divides the headroom ratio.
        (self.target_mbps(measured_direct_mbps) * self.headroom_margin).max(1.0)
    }

    /// Throughput a server must actually deliver to be accepted.
    ///
    /// A fraction of the target, floored at `min_mbps`. The floor matters on a
    /// slow connection, where a fraction of an already-small target would
    /// accept almost anything.
    pub fn acceptance_mbps(&self, measured_direct_mbps: Option<f64>) -> f64 {
        (self.target_mbps(measured_direct_mbps) * self.accept_fraction).max(self.min_mbps)
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
            return Err(Error::Config(
                "probe.timeout_ms must be greater than 0".into(),
            ));
        }
        if self.autotune.interval_minutes == 0 {
            return Err(Error::Config(
                "autotune.interval_minutes must be greater than 0".into(),
            ));
        }
        if self.autotune.target_mbps.is_some_and(|t| t <= 0.0) {
            return Err(Error::Config(
                "autotune.target_mbps must be greater than 0 when set".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.autotune.accept_fraction) {
            return Err(Error::Config(format!(
                "autotune.accept_fraction = {} must be between 0.0 and 1.0",
                self.autotune.accept_fraction
            )));
        }
        if self.autotune.headroom_margin <= 0.0 {
            return Err(Error::Config(
                "autotune.headroom_margin must be greater than 0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.autotune.improvement_threshold) {
            return Err(Error::Config(format!(
                "autotune.improvement_threshold = {} must be between 0.0 and 1.0",
                self.autotune.improvement_threshold
            )));
        }

        let w = &self.autotune.weights;
        if w.rtt < 0.0 || w.load < 0.0 || w.headroom < 0.0 {
            return Err(Error::Config(
                "autotune.weights must not be negative".into(),
            ));
        }
        if w.rtt + w.load + w.headroom <= 0.0 {
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
    pub fn from_imported(
        client: &ClientConfig,
        private_key_file: PathBuf,
        preshared_key_file: PathBuf,
    ) -> Self {
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
            killswitch: Killswitch::default(),
            throughput: Throughput::default(),
            bypass: Bypass::default(),
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
        assert!(
            c.provider
                .airvpn
                .allowed_ips
                .iter()
                .any(Cidr::is_default_route)
        );
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

    /// Unset, the target comes from whatever the connection itself managed,
    /// shaded down — "a bit below the maximum" rather than the peak.
    #[test]
    fn the_headroom_target_follows_a_measured_connection() {
        let c = parse(MINIMAL).unwrap();
        let unmeasured = c.autotune.headroom_target_mbps(None);
        let measured = c.autotune.headroom_target_mbps(Some(1000.0));
        assert_eq!(unmeasured, DEFAULT_TARGET_MBPS * 2.0);
        assert_eq!(measured, 1000.0 * MEASURED_TARGET_FRACTION * 2.0);
        assert!(
            measured > unmeasured,
            "a gigabit line should demand more of a server than the default"
        );
    }

    /// The bar follows the line rate, so it means something on this machine
    /// rather than being a fixed guess.
    #[test]
    fn the_acceptance_bar_follows_the_measured_connection() {
        let c = parse(MINIMAL).unwrap();
        let uncalibrated = c.autotune.acceptance_mbps(None);
        let calibrated = c.autotune.acceptance_mbps(Some(1000.0));
        assert_eq!(uncalibrated, DEFAULT_TARGET_MBPS * 0.6);
        assert_eq!(calibrated, 1000.0 * MEASURED_TARGET_FRACTION * 0.6);
        assert!(calibrated > uncalibrated);
    }

    /// On a slow line a fraction of the target would accept nearly anything,
    /// so the absolute floor has to win there.
    #[test]
    fn the_absolute_floor_wins_on_a_slow_connection() {
        let c = parse(MINIMAL).unwrap();
        // 20 Mbit/s line: 0.9 * 20 * 0.6 = 10.8, below the 50 floor.
        assert_eq!(c.autotune.acceptance_mbps(Some(20.0)), c.autotune.min_mbps);
    }

    #[test]
    fn rejects_a_nonsensical_accept_fraction() {
        let text = format!("{MINIMAL}\n[autotune]\naccept_fraction = 1.5\n");
        assert!(
            parse(&text)
                .unwrap_err()
                .to_string()
                .contains("between 0.0 and 1.0")
        );
    }

    #[test]
    fn an_explicit_target_overrides_the_measurement() {
        let text = format!("{MINIMAL}\n[autotune]\ntarget_mbps = 100.0\n");
        let c = parse(&text).unwrap();
        // The measurement is ignored entirely once the user has said what they
        // want; otherwise configuring it would not be dependable.
        assert_eq!(c.autotune.headroom_target_mbps(Some(5000.0)), 200.0);
    }

    #[test]
    fn rejects_a_nonsensical_target() {
        let text = format!("{MINIMAL}\n[autotune]\ntarget_mbps = 0.0\n");
        assert!(
            parse(&text)
                .unwrap_err()
                .to_string()
                .contains("greater than 0")
        );
        let text = format!("{MINIMAL}\n[autotune]\nheadroom_margin = 0.0\n");
        assert!(
            parse(&text)
                .unwrap_err()
                .to_string()
                .contains("greater than 0")
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
        assert!(
            parse(&text)
                .unwrap_err()
                .to_string()
                .contains("between 0.0 and 1.0")
        );
    }

    #[test]
    fn rejects_all_zero_weights() {
        let text =
            format!("{MINIMAL}\n[autotune.weights]\nrtt = 0.0\nload = 0.0\nheadroom = 0.0\n");
        assert!(
            parse(&text)
                .unwrap_err()
                .to_string()
                .contains("greater than 0")
        );
    }

    #[test]
    fn rejects_a_malformed_peer_key() {
        let text = MINIMAL.replace("PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk=", "not-a-key");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn rejects_an_empty_address_list() {
        let text = MINIMAL.replace(r#"address = ["10.176.14.22/32"]"#, "address = []");
        assert!(
            parse(&text)
                .unwrap_err()
                .to_string()
                .contains("at least one")
        );
    }

    #[test]
    fn serialised_config_never_contains_key_material() {
        // Only paths are stored, so a config file is safe to share.
        let text = toml::to_string(&parse(MINIMAL).unwrap()).unwrap();
        assert!(text.contains("private_key_file"));
        assert!(!text.contains("PrivateKey"));
    }
}
