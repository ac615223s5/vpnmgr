//! Kill switch: refuse to let traffic leave unencrypted.
//!
//! Routing alone cannot guarantee this. The tunnel's default route lives in a
//! policy routing table, and there are windows where that table is empty while
//! the interface still exists — reconfiguring the interface during a server
//! switch flushes it, and a crashed daemon can leave it that way. In those
//! windows every lookup falls through to the physical default route and traffic
//! leaves in the clear. That is not hypothetical: it is exactly what happened
//! when the listen-port rotation was first added without reinstalling routes.
//!
//! So the guarantee is enforced where packets actually leave, with an nftables
//! output chain that drops anything not accounted for.
//!
//! # What is allowed out
//!
//! * Loopback, and the tunnel interface itself.
//! * Anything carrying the WireGuard fwmark. That covers the encrypted tunnel
//!   traffic *and* the prober's handshakes, which have to reach servers
//!   directly. Setting a socket mark needs `CAP_NET_ADMIN`, so an unprivileged
//!   process cannot use this to escape.
//! * Link-local and multicast, without which IPv6 neighbour discovery and DHCP
//!   stop working and the link itself falls over.
//! * Private ranges, when `allow_lan` is set — otherwise enabling the kill
//!   switch would also cut off printers, NAS boxes and inbound SSH.
//!
//! Everything else is dropped and counted.
//!
//! # Failure mode
//!
//! Deliberately fail-closed: if the daemon dies while connected, the rules
//! outlive it and the machine has no direct internet access until they are
//! removed. That is the point of a kill switch, but it does mean a crash is
//! recoverable only with `vpnmgr killswitch off` (or `nft delete table inet
//! vpnmgr`), which [`Killswitch::recovery_hint`] spells out.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::{Error, Result};

/// Name of the nftables table we own. Nothing else is touched, so an existing
/// firewall — ufw, docker, whatever — is left completely alone.
pub const TABLE: &str = "vpnmgr";

/// Private ranges treated as "the local network".
const LAN_V4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";
const LAN_V6: &str = "fc00::/7";

/// Ranges the link needs regardless of policy: link-local (including IPv6
/// neighbour discovery), multicast, and the broadcast address DHCP uses.
const LINK_V4: &str = "169.254.0.0/16, 224.0.0.0/4, 255.255.255.255";
const LINK_V6: &str = "fe80::/10, ff00::/8";

/// Controls the nftables table that enforces the kill switch.
#[derive(Debug, Clone)]
pub struct Killswitch {
    interface: String,
    fwmark: u32,
    allow_lan: bool,
    /// Destinations deliberately routed around the tunnel.
    ///
    /// Without these the two features would contradict each other: the bypass
    /// sends traffic out the physical interface, which is exactly what the
    /// kill switch exists to drop.
    bypass: Vec<String>,
}

impl Killswitch {
    pub fn new(interface: impl Into<String>, fwmark: u32, allow_lan: bool) -> Self {
        Self {
            interface: interface.into(),
            fwmark,
            allow_lan,
            bypass: Vec::new(),
        }
    }

    /// Permit traffic to destinations that bypass the tunnel by design.
    pub fn allowing(mut self, destinations: Vec<String>) -> Self {
        self.bypass = destinations;
        self
    }

    /// The nftables script this configuration produces.
    ///
    /// Separate from [`Self::engage`] so tests can assert on the actual ruleset
    /// without root and without touching the machine's firewall. A test that
    /// rebuilt the script itself could pass while this drifted.
    ///
    /// The `table`/`delete`/`table` idiom is nftables' way of saying "replace":
    /// the first line creates the table if it is missing so the delete cannot
    /// fail, and the whole script is applied as one transaction.
    pub fn script(&self) -> String {
        let mut script = String::new();
        script.push_str(&format!("table inet {TABLE} {{}}\n"));
        script.push_str(&format!("delete table inet {TABLE}\n"));
        script.push_str(&format!("table inet {TABLE} {{\n"));
        script.push_str("  chain output {\n");
        script.push_str("    type filter hook output priority filter; policy accept;\n");
        script.push_str("    oifname \"lo\" accept\n");
        script.push_str(&format!("    oifname \"{}\" accept\n", self.interface));
        // The tunnel's own encrypted traffic, and the prober's handshakes.
        script.push_str(&format!("    meta mark {} accept\n", self.fwmark));
        script.push_str(&format!("    ip daddr {{ {LINK_V4} }} accept\n"));
        script.push_str(&format!("    ip6 daddr {{ {LINK_V6} }} accept\n"));
        // DHCP renewals are sent before a lease exists, so they are not always
        // covered by the broadcast address above.
        script.push_str("    udp dport { 67, 68 } accept\n");
        if self.allow_lan {
            script.push_str(&format!("    ip daddr {{ {LAN_V4} }} accept\n"));
            script.push_str(&format!("    ip6 daddr {{ {LAN_V6} }} accept\n"));
        }
        let (v4, v6): (Vec<&String>, Vec<&String>) =
            self.bypass.iter().partition(|d| !d.contains(':'));
        if !v4.is_empty() {
            script.push_str(&format!(
                "    ip daddr {{ {} }} accept\n",
                v4.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        if !v6.is_empty() {
            script.push_str(&format!(
                "    ip6 daddr {{ {} }} accept\n",
                v6.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        script.push_str("    counter drop\n");
        script.push_str("  }\n}\n");
        script
    }

    /// Install the rules, replacing any previous copy atomically.
    pub fn engage(&self) -> Result<()> {
        nft(&self.script()).map_err(|e| Error::Killswitch {
            operation: "engaging",
            source: e,
        })
    }

    /// Remove the rules. Succeeds when they were not installed.
    pub fn release() -> Result<()> {
        // Same create-then-delete trick, so "not installed" is not an error.
        let script = format!("table inet {TABLE} {{}}\ndelete table inet {TABLE}\n");
        nft(&script).map_err(|e| Error::Killswitch {
            operation: "releasing",
            source: e,
        })
    }

    /// Whether our table is currently installed.
    pub fn is_engaged() -> bool {
        Command::new("nft")
            .args(["list", "table", "inet", TABLE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// How many packets the kill switch has dropped, if it can be read.
    ///
    /// Zero is the expected value in normal operation; a non-zero count is
    /// evidence that something genuinely tried to leave outside the tunnel.
    pub fn dropped() -> Option<u64> {
        let output = Command::new("nft")
            .args(["list", "table", "inet", TABLE])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        // The counter sits on the drop rule: `counter packets 12 bytes 900 drop`
        let line = text.lines().find(|l| l.contains("drop"))?;
        let after = line.split("packets").nth(1)?;
        after.split_whitespace().next()?.parse().ok()
    }

    /// What to tell a user whose machine is offline because of a stale table.
    pub fn recovery_hint() -> String {
        format!(
            "the vpnmgr kill switch is still active, so direct internet access is \
             blocked. Clear it with `vpnmgr killswitch off`, or if the daemon is not \
             running: sudo nft delete table inet {TABLE}"
        )
    }
}

/// Feed a script to `nft -f -`.
///
/// Passed on stdin rather than as arguments so the ruleset is applied as a
/// single transaction — a partially applied kill switch would be worse than
/// none, since it could block traffic while still leaking some.
fn nft(script: &str) -> std::io::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("could not run nft ({e}); the kill switch needs nftables installed"),
            )
        })?;

    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(script.as_bytes())?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "nft rejected the ruleset: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated ruleset is the whole security boundary, so its shape is
    /// worth pinning even without root to apply it.
    #[test]
    fn the_ruleset_permits_exactly_what_it_should() {
        let ks = Killswitch::new("vpnmgr0", 51820, true);
        // Rebuild the script the way `engage` does, without running nft.
        let script = ks.script();

        assert!(script.contains("oifname \"vpnmgr0\" accept"));
        assert!(script.contains("oifname \"lo\" accept"));
        assert!(script.contains("meta mark 51820 accept"));
        assert!(script.contains("counter drop"));
        // Without this the prober could not reach servers and sweeps would stop.
        assert!(
            script.find("meta mark").unwrap() < script.find("counter drop").unwrap(),
            "the fwmark exemption must precede the drop"
        );
    }

    #[test]
    fn lan_access_is_omitted_when_not_asked_for() {
        let script = Killswitch::new("vpnmgr0", 51820, false).script();
        assert!(!script.contains("192.168.0.0/16"));
        // Link-local and multicast are not optional; the link needs them.
        assert!(script.contains("fe80::/10"));
        assert!(script.contains("169.254.0.0/16"));
    }

    #[test]
    fn lan_access_is_included_when_asked_for() {
        let script = Killswitch::new("vpnmgr0", 51820, true).script();
        assert!(script.contains("192.168.0.0/16"));
        assert!(script.contains("fc00::/7"));
    }

    #[test]
    fn the_table_is_replaced_rather_than_appended_to() {
        let script = Killswitch::new("vpnmgr0", 51820, true).script();
        // Re-engaging must not stack duplicate chains.
        assert!(script.contains(&format!("delete table inet {TABLE}")));
        assert!(
            script.find("delete table").unwrap() < script.rfind("chain output").unwrap(),
            "the delete has to come before the new definition"
        );
    }

    /// The bypass and the kill switch would otherwise contradict each other:
    /// one routes traffic out the physical interface, the other drops exactly
    /// that.
    #[test]
    fn bypassed_destinations_are_permitted() {
        let script = Killswitch::new("vpnmgr0", 51820, false)
            .allowing(vec!["1.2.3.4".into(), "2001:db8::1".into()])
            .script();
        assert!(script.contains("ip daddr { 1.2.3.4 } accept"));
        assert!(script.contains("ip6 daddr { 2001:db8::1 } accept"));
        assert!(
            script.find("1.2.3.4").unwrap() < script.find("counter drop").unwrap(),
            "the exemption must precede the drop"
        );
    }

    #[test]
    fn the_recovery_hint_names_a_command_that_works_without_the_daemon() {
        let hint = Killswitch::recovery_hint();
        assert!(hint.contains("nft delete table inet vpnmgr"));
    }
}
