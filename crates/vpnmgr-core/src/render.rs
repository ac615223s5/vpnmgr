//! Rendering a WireGuard `.conf` for a chosen server.
//!
//! This is the payoff of the shared-peer-key property: producing a config for
//! any of the 257 servers is a pure string operation on already-held
//! credentials — no request, no auth, no rate limit. Switching servers is
//! therefore just a re-render with a different `Endpoint`.

use std::fmt::Write as _;
use std::net::SocketAddr;

use crate::airvpn::Server;
use crate::wgconf::ClientConfig;

/// Render a complete `.conf` pointing at `endpoint`.
///
/// **The result contains the private key and preshared key.** Write it only to
/// a `0600` file, and never log it. Prefer configuring a tunnel backend
/// directly from [`ClientConfig`] where possible.
pub fn to_conf(client: &ClientConfig, endpoint: SocketAddr) -> String {
    let mut out = String::with_capacity(512);

    out.push_str("[Interface]\n");
    let addrs: Vec<String> = client.addresses.iter().map(|a| a.to_string()).collect();
    let _ = writeln!(out, "Address = {}", addrs.join(", "));
    let _ = writeln!(out, "PrivateKey = {}", client.private_key.expose_base64());
    // Nameservers and search domains share the DNS key, in that order.
    let dns: Vec<String> = client
        .dns
        .iter()
        .map(|d| d.to_string())
        .chain(client.search_domains.iter().cloned())
        .collect();
    if !dns.is_empty() {
        let _ = writeln!(out, "DNS = {}", dns.join(", "));
    }
    if let Some(mtu) = client.mtu {
        let _ = writeln!(out, "MTU = {mtu}");
    }

    out.push_str("\n[Peer]\n");
    let _ = writeln!(out, "PublicKey = {}", client.peer_public_key);
    if let Some(psk) = &client.preshared_key {
        let _ = writeln!(out, "PresharedKey = {}", psk.expose_base64());
    }
    let _ = writeln!(out, "Endpoint = {endpoint}");
    let allowed: Vec<String> = client.allowed_ips.iter().map(|a| a.to_string()).collect();
    let _ = writeln!(out, "AllowedIPs = {}", allowed.join(", "));
    if let Some(k) = client.persistent_keepalive {
        let _ = writeln!(out, "PersistentKeepalive = {k}");
    }

    out
}

/// Render a `.conf` for `server`, using the AirVPN WireGuard entry address.
pub fn for_server(client: &ClientConfig, server: &Server, port: u16) -> String {
    to_conf(client, server.wg_endpoint(port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airvpn::{self, ServerList};
    use crate::wgconf::ClientConfig;

    const STATUS: &str = include_str!("../tests/fixtures/airvpn_status.json");
    const SAMPLE: &str = include_str!("../tests/fixtures/airvpn_sample.conf");

    fn client() -> ClientConfig {
        ClientConfig::parse(SAMPLE, "sample.conf").unwrap()
    }

    #[test]
    fn rendered_config_reparses_to_the_same_credentials() {
        let original = client();
        let list = ServerList::from_json(STATUS).unwrap();
        let server = list.get("Achernar").unwrap();

        let text = for_server(&original, server, airvpn::WG_PORT);
        let again = ClientConfig::parse(&text, "rendered.conf").unwrap();

        assert_eq!(again.private_key, original.private_key);
        assert_eq!(again.preshared_key, original.preshared_key);
        assert_eq!(
            again.peer_public_key.to_base64(),
            original.peer_public_key.to_base64()
        );
        assert_eq!(again.addresses, original.addresses);
        assert_eq!(again.dns, original.dns);
        assert_eq!(again.mtu, original.mtu);
        assert_eq!(again.allowed_ips, original.allowed_ips);
        assert_eq!(again.persistent_keepalive, original.persistent_keepalive);
    }

    #[test]
    fn only_the_endpoint_changes_between_servers() {
        let client = client();
        let list = ServerList::from_json(STATUS).unwrap();
        let mut healthy = list.healthy();
        let (a, b) = (healthy.next().unwrap(), healthy.next().unwrap());

        let conf_a = for_server(&client, a, airvpn::WG_PORT);
        let conf_b = for_server(&client, b, airvpn::WG_PORT);

        let differing: Vec<_> = conf_a
            .lines()
            .zip(conf_b.lines())
            .filter(|(x, y)| x != y)
            .collect();
        assert_eq!(differing.len(), 1, "{differing:?}");
        assert!(differing[0].0.starts_with("Endpoint = "));
    }

    #[test]
    fn targets_the_wireguard_port_and_entry_address() {
        let list = ServerList::from_json(STATUS).unwrap();
        let server = list.get("Achernar").unwrap();
        let text = for_server(&client(), server, airvpn::WG_PORT);
        assert!(text.contains("Endpoint = 185.156.175.170:1637"), "{text}");
    }

    #[test]
    fn omits_optional_fields_that_are_absent() {
        let mut c = client();
        c.preshared_key = None;
        c.mtu = None;
        c.dns.clear();
        c.persistent_keepalive = None;
        let text = to_conf(&c, "1.2.3.4:1637".parse().unwrap());
        assert!(!text.contains("PresharedKey"));
        assert!(!text.contains("MTU"));
        assert!(!text.contains("DNS"));
        assert!(!text.contains("PersistentKeepalive"));
        // Still a valid config.
        assert!(ClientConfig::parse(&text, "x.conf").is_ok());
    }
}
