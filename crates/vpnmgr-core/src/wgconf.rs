//! Importer for a WireGuard `.conf` from the AirVPN Config Generator.
//!
//! The user downloads one config, once. Because every AirVPN server shares a
//! peer public key, the credentials in that file work against the entire fleet
//! — so everything here is server-independent, and the `Endpoint` line is
//! parsed only to be discarded. [`crate::render`] rewrites it per server.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::airvpn;
use crate::error::{Error, Result};
use crate::key::{PublicKey, SecretKey};

/// An address with a prefix length, e.g. `10.0.0.2/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// True when this covers the whole address space (`0.0.0.0/0` or `::/0`),
    /// i.e. a default route.
    pub fn is_default_route(&self) -> bool {
        self.prefix == 0
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_part
            .trim()
            .parse()
            .map_err(|_| format!("{addr_part:?} is not an IP address"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            None => max,
            Some(p) => {
                let p: u8 = p
                    .trim()
                    .parse()
                    .map_err(|_| format!("{p:?} is not a prefix length"))?;
                if p > max {
                    return Err(format!("/{p} exceeds the maximum /{max} for this address"));
                }
                p
            }
        };
        Ok(Cidr { addr, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl serde::Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Server-independent WireGuard credentials and interface settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub private_key: SecretKey,
    pub addresses: Vec<Cidr>,
    /// Nameserver addresses from the `DNS` key.
    pub dns: Vec<IpAddr>,
    /// Non-address entries of the `DNS` key. `wg-quick` allows search domains
    /// to be mixed in with nameservers, so a bare hostname there is a valid
    /// config rather than an error.
    pub search_domains: Vec<String>,
    pub mtu: Option<u32>,
    pub peer_public_key: PublicKey,
    pub preshared_key: Option<SecretKey>,
    pub allowed_ips: Vec<Cidr>,
    pub persistent_keepalive: Option<u16>,
}

impl ClientConfig {
    /// True when the peer key matches the AirVPN fleet key this build knows.
    ///
    /// A `false` here is not fatal — the imported key always wins — but it is
    /// worth surfacing, since it means either a key rotation or a config from
    /// a different provider.
    pub fn matches_known_airvpn_key(&self) -> bool {
        self.peer_public_key.to_base64() == airvpn::WG_PUBLIC_KEY_FALLBACK
    }

    /// True when this config routes all traffic through the tunnel.
    pub fn is_full_tunnel(&self) -> bool {
        self.allowed_ips.iter().any(Cidr::is_default_route)
    }

    pub fn import(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text, path)
    }

    pub fn parse(text: &str, path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bad = |reason: String| Error::WgConf {
            path: path.to_owned(),
            reason,
        };

        let mut interface = Section::default();
        let mut peers: Vec<Section> = Vec::new();
        let mut current: Option<&mut Section> = None;

        for (lineno, raw) in text.lines().enumerate() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }

            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                match name.trim().to_ascii_lowercase().as_str() {
                    "interface" => current = Some(&mut interface),
                    "peer" => {
                        peers.push(Section::default());
                        current = peers.last_mut();
                    }
                    other => {
                        return Err(bad(format!(
                            "line {}: unknown section [{other}]",
                            lineno + 1
                        )));
                    }
                }
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                return Err(bad(format!("line {}: expected `key = value`", lineno + 1)));
            };
            let Some(section) = current.as_deref_mut() else {
                return Err(bad(format!(
                    "line {}: `{}` appears before any [Interface] or [Peer] section",
                    lineno + 1,
                    key.trim()
                )));
            };
            section.set(key.trim(), value.trim(), lineno + 1);
        }

        let peer = match peers.len() {
            1 => &peers[0],
            0 => return Err(bad("no [Peer] section".into())),
            n => {
                return Err(bad(format!(
                    "{n} [Peer] sections; vpnmgr selects the peer itself and expects exactly one"
                )));
            }
        };

        let private_key = {
            let (raw, lineno) = interface
                .get("privatekey")
                .ok_or_else(|| bad("[Interface] has no PrivateKey".into()))?;
            SecretKey::from_base64(raw)
                .map_err(|e| bad(format!("line {lineno}: PrivateKey is {e}")))?
        };

        let peer_public_key = {
            let (raw, lineno) = peer
                .get("publickey")
                .ok_or_else(|| bad("[Peer] has no PublicKey".into()))?;
            PublicKey::from_base64(raw)
                .map_err(|e| bad(format!("line {lineno}: PublicKey is {e}")))?
        };

        let preshared_key = match peer.get("presharedkey") {
            None => None,
            Some((raw, lineno)) => Some(
                SecretKey::from_base64(raw)
                    .map_err(|e| bad(format!("line {lineno}: PresharedKey is {e}")))?,
            ),
        };

        let addresses = parse_list::<Cidr>(&interface, "address", "Address", &bad)?;
        if addresses.is_empty() {
            return Err(bad("[Interface] has no Address".into()));
        }

        let allowed_ips = {
            let parsed = parse_list::<Cidr>(peer, "allowedips", "AllowedIPs", &bad)?;
            if parsed.is_empty() {
                // wg's own default when the key is absent.
                vec![
                    "0.0.0.0/0".parse().expect("literal is valid"),
                    "::/0".parse().expect("literal is valid"),
                ]
            } else {
                parsed
            }
        };

        // wg-quick's DNS key mixes nameserver addresses and search domains.
        let (dns, search_domains) = {
            let (mut ips, mut domains) = (Vec::new(), Vec::new());
            for (value, _) in interface.get_all("dns") {
                for item in value.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                    match item.parse::<IpAddr>() {
                        Ok(ip) => ips.push(ip),
                        Err(_) => domains.push(item.to_owned()),
                    }
                }
            }
            (ips, domains)
        };
        let mtu = parse_scalar::<u32>(&interface, "mtu", "MTU", &bad)?;
        let persistent_keepalive =
            parse_scalar::<u16>(peer, "persistentkeepalive", "PersistentKeepalive", &bad)?;

        Ok(Self {
            private_key,
            addresses,
            dns,
            search_domains,
            mtu,
            peer_public_key,
            preshared_key,
            allowed_ips,
            persistent_keepalive,
        })
    }
}

/// Everything in a `.conf` except the parts we override per server.
#[derive(Default)]
struct Section {
    /// (lowercased key, raw value, line number)
    entries: Vec<(String, String, usize)>,
}

impl Section {
    fn set(&mut self, key: &str, value: &str, lineno: usize) {
        self.entries
            .push((key.to_ascii_lowercase(), value.to_owned(), lineno));
    }

    fn get(&self, key: &str) -> Option<(&str, usize)> {
        self.entries
            .iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, v, n)| (v.as_str(), *n))
    }

    /// All values for a key. WireGuard permits repeating a key instead of
    /// using a comma-separated list, and the two forms are equivalent.
    fn get_all(&self, key: &str) -> impl Iterator<Item = (&str, usize)> {
        self.entries
            .iter()
            .filter(move |(k, _, _)| k == key)
            .map(|(_, v, n)| (v.as_str(), *n))
    }
}

fn parse_list<T>(
    section: &Section,
    key: &str,
    display: &str,
    bad: &impl Fn(String) -> Error,
) -> Result<Vec<T>>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    let mut out = Vec::new();
    for (value, lineno) in section.get_all(key) {
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            out.push(
                item.parse::<T>()
                    .map_err(|e| bad(format!("line {lineno}: {display} entry {item:?}: {e}")))?,
            );
        }
    }
    Ok(out)
}

fn parse_scalar<T>(
    section: &Section,
    key: &str,
    display: &str,
    bad: &impl Fn(String) -> Error,
) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match section.get(key) {
        None => Ok(None),
        Some((value, lineno)) => value
            .parse::<T>()
            .map(Some)
            .map_err(|e| bad(format!("line {lineno}: {display} {value:?}: {e}"))),
    }
}

fn strip_comment(line: &str) -> &str {
    match line.split_once(['#', ';']) {
        Some((before, _)) => before,
        None => line,
    }
}

/// Split a `.conf` into the secret and non-secret parts of an install.
///
/// Returns the key material to be written to root-owned `0600` files, leaving
/// the caller to persist the rest in `config.toml`.
pub fn split_secrets(config: &ClientConfig) -> (SecretKey, Option<SecretKey>) {
    (config.private_key.clone(), config.preshared_key.clone())
}

/// Conventional on-disk locations for the secrets, alongside a config file.
pub fn secret_paths(config_dir: &Path) -> (PathBuf, PathBuf) {
    (config_dir.join("wg.key"), config_dir.join("wg.psk"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../tests/fixtures/airvpn_sample.conf");

    fn parse(text: &str) -> Result<ClientConfig> {
        ClientConfig::parse(text, "test.conf")
    }

    fn sample() -> ClientConfig {
        parse(SAMPLE).expect("sample should parse")
    }

    #[test]
    fn parses_a_real_airvpn_config() {
        let c = sample();
        assert_eq!(c.addresses.len(), 2);
        assert_eq!(c.addresses[0].to_string(), "10.176.14.22/32");
        assert_eq!(c.dns.len(), 2);
        assert_eq!(c.mtu, Some(1320));
        assert_eq!(c.persistent_keepalive, Some(15));
        assert!(c.preshared_key.is_some());
        assert!(c.is_full_tunnel());
    }

    #[test]
    fn recognises_the_known_airvpn_fleet_key() {
        assert!(sample().matches_known_airvpn_key());
    }

    #[test]
    fn flags_a_config_whose_peer_key_is_not_airvpns() {
        let other = "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gMTI=";
        let text = SAMPLE.replace(airvpn::WG_PUBLIC_KEY_FALLBACK, other);
        assert!(!parse(&text).unwrap().matches_known_airvpn_key());
    }

    /// A split-tunnel corporate config: no default route, and a search domain
    /// mixed into the DNS list. Modelled on a real-world file that the first
    /// version of this parser rejected outright.
    const SPLIT_TUNNEL: &str = "\
[Interface]
Address = 10.101.222.48/32
PrivateKey = SPrivateKeyFixturexxxxxxxxxxxxxxxxxxxxxxxxA=
DNS = 10.101.110.11,10.101.110.12,corp.internal

[Peer]
PublicKey = PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk=
Endpoint = 198.51.100.9:51820
AllowedIPs = 10.101.1.0/24,10.100.0.0/16,192.0.2.5/32
";

    #[test]
    fn accepts_a_search_domain_mixed_into_the_dns_list() {
        let c = parse(SPLIT_TUNNEL).expect("wg-quick permits this");
        assert_eq!(c.dns.len(), 2, "both nameservers should be addresses");
        assert_eq!(c.search_domains, vec!["corp.internal".to_owned()]);
    }

    #[test]
    fn recognises_a_split_tunnel_as_not_a_full_tunnel() {
        let c = parse(SPLIT_TUNNEL).unwrap();
        assert!(!c.is_full_tunnel());
        assert_eq!(c.allowed_ips.len(), 3);
    }

    #[test]
    fn a_config_may_have_no_preshared_key() {
        assert!(parse(SPLIT_TUNNEL).unwrap().preshared_key.is_none());
    }

    #[test]
    fn tolerates_comments_and_blank_lines() {
        let text = format!("# leading comment\n\n{SAMPLE}\n; trailing comment\n");
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn strips_inline_comments() {
        let text = SAMPLE.replace("MTU = 1320", "MTU = 1320 # AirVPN default");
        assert_eq!(parse(&text).unwrap().mtu, Some(1320));
    }

    #[test]
    fn section_and_key_names_are_case_insensitive() {
        let text = SAMPLE
            .replace("[Interface]", "[interface]")
            .replace("PrivateKey", "privatekey")
            .replace("[Peer]", "[PEER]");
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn accepts_repeated_keys_as_an_alternative_to_comma_lists() {
        let text = SAMPLE.replace(
            "AllowedIPs = 0.0.0.0/0, ::/0",
            "AllowedIPs = 0.0.0.0/0\nAllowedIPs = ::/0",
        );
        assert_eq!(parse(&text).unwrap().allowed_ips.len(), 2);
    }

    #[test]
    fn defaults_allowed_ips_to_a_full_tunnel_when_absent() {
        let text = SAMPLE.replace("AllowedIPs = 0.0.0.0/0, ::/0\n", "");
        assert!(parse(&text).unwrap().is_full_tunnel());
    }

    #[test]
    fn rejects_a_config_with_no_private_key() {
        let text = SAMPLE
            .lines()
            .filter(|l| !l.starts_with("PrivateKey"))
            .collect::<Vec<_>>()
            .join("\n");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("no PrivateKey"), "{err}");
    }

    #[test]
    fn rejects_a_config_with_no_peer() {
        let text = SAMPLE.split("[Peer]").next().unwrap().to_owned();
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("no [Peer]"), "{err}");
    }

    #[test]
    fn rejects_multiple_peers_rather_than_silently_picking_one() {
        let text = format!(
            "{SAMPLE}\n[Peer]\nPublicKey = {}\n",
            airvpn::WG_PUBLIC_KEY_FALLBACK
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("2 [Peer] sections"), "{err}");
    }

    #[test]
    fn reports_the_line_number_of_a_malformed_key() {
        let text = SAMPLE.replace(airvpn::WG_PUBLIC_KEY_FALLBACK, "obviously-not-base64!");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("PublicKey is not valid base64"), "{err}");
    }

    #[test]
    fn never_leaks_key_material_in_an_error_message() {
        let text = SAMPLE.replace("MTU = 1320", "MTU = banana");
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("MTU"), "{err}");
        // The private key from the fixture must not ride along in the error.
        assert!(!err.contains("SPrivate"), "{err}");
    }

    #[test]
    fn rejects_an_entry_outside_any_section() {
        let err = parse("PrivateKey = abc\n").unwrap_err().to_string();
        assert!(err.contains("before any [Interface]"), "{err}");
    }

    #[test]
    fn rejects_an_out_of_range_prefix() {
        let err = "10.0.0.1/33".parse::<Cidr>().unwrap_err();
        assert!(err.contains("exceeds the maximum /32"), "{err}");
    }

    #[test]
    fn a_bare_address_gets_a_host_prefix() {
        assert_eq!("10.0.0.1".parse::<Cidr>().unwrap().prefix, 32);
        assert_eq!("fd00::1".parse::<Cidr>().unwrap().prefix, 128);
    }

    #[test]
    fn debug_output_of_a_config_hides_the_secrets() {
        let rendered = format!("{:?}", sample());
        assert!(rendered.contains("SecretKey(<redacted>)"), "{rendered}");
        assert!(!rendered.contains("SPrivate"), "{rendered}");
    }
}
