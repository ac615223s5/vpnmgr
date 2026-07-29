//! Parse a WireGuard .conf and print a redacted summary.
//! Usage: cargo run -p vpnmgr-core --example inspect -- <path>
fn main() {
    let path = std::env::args().nth(1).expect("usage: inspect <path.conf>");
    match vpnmgr_core::ClientConfig::import(&path) {
        Err(e) => println!("PARSE FAILED: {e}"),
        Ok(c) => {
            println!("addresses      : {:?}", c.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>());
            println!("dns servers    : {:?}", c.dns);
            println!("search domains : {:?}", c.search_domains);
            println!("mtu            : {:?}", c.mtu);
            println!("peer key       : {}", c.peer_public_key);
            println!("has psk        : {}", c.preshared_key.is_some());
            println!("allowed_ips    : {} entries", c.allowed_ips.len());
            println!("full tunnel    : {}", c.is_full_tunnel());
            println!("airvpn fleet   : {}", c.matches_known_airvpn_key());
            println!("keepalive      : {:?}", c.persistent_keepalive);
            println!("debug (secrets): {:?}", c.private_key);
        }
    }
}
