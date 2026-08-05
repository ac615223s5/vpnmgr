//! Kill switch on Windows: refuse to let traffic leave unencrypted.
//!
//! Same guarantee as the Linux implementation and a different mechanism,
//! because the two firewalls disagree about a fundamental point.
//!
//! # Why the default action, and not a block rule
//!
//! nftables evaluates rules in order, so Linux can drop everything at the end
//! of a chain and accept exceptions before it. Windows Firewall does not work
//! that way: an explicit **Block rule always beats an explicit Allow rule**,
//! whatever order they were added in. A "block all outbound" rule would
//! therefore also block the tunnel, the LAN and every bypass destination, and
//! no Allow rule could rescue them.
//!
//! The only way to express "deny by default, with exceptions" is to set the
//! profile's *default outbound action* to Block and let Allow rules carve out
//! what may pass. That is a machine-wide setting rather than a self-contained
//! table, which is why the previous value is written to disk before it is
//! changed — see [`Killswitch::release`].
//!
//! # What is allowed out
//!
//! * Everything on the tunnel adapter itself.
//! * UDP to the WireGuard port, on any adapter. This is what lets the handshake
//!   reach a server at all, and it is deliberately expressed as a port rather
//!   than the current server's address: the tuner changes servers every thirty
//!   minutes, and a rule naming one endpoint would have to be rewritten on each
//!   switch, with a window in between where the tunnel cannot re-establish.
//!   The exposure is one UDP port, and what leaves through it is encrypted.
//! * Link-local, multicast and DHCP, without which the link itself falls over.
//! * Private ranges, when `allow_lan` is set.
//! * Whatever the bypass is routing around the tunnel, which would otherwise be
//!   routed correctly and then dropped — the two must agree, and on Windows
//!   they disagreeing is how a destination ends up permitted and unreachable.
//!
//! # Failure mode
//!
//! Deliberately fail-closed: if the daemon dies while this is engaged, the
//! setting outlives it and the machine has no direct internet access until it
//! is removed. That is the point. It also means the recovery instructions have
//! to be findable without internet access, which is what
//! [`Killswitch::recovery_hint`] is for.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Error, Result};

/// Group every rule belongs to, so they can be removed as a unit — the nearest
/// equivalent of the Linux build's dedicated `inet vpnmgr` table.
pub const GROUP: &str = "vpnmgr";

/// Rule name prefix. Windows identifies rules by name, not by number.
const RULE_PREFIX: &str = "vpnmgr-allow";

const LAN_V4: &str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";
const LAN_V6: &str = "fc00::/7";

/// Link-local, multicast and broadcast. Blocking these breaks DHCP lease
/// renewal and IPv6 neighbour discovery, which takes the link down with it.
const LINK_V4: &str = "169.254.0.0/16,224.0.0.0/4,255.255.255.255";
const LINK_V6: &str = "fe80::/10,ff00::/8";

/// Where the previous default outbound action is recorded.
///
/// On disk rather than in memory because the daemon's state does not survive a
/// restart, and a kill switch that cannot be turned off after a crash is a
/// machine that needs its firewall repaired by hand.
fn restore_path() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_owned());
    Path::new(&base)
        .join("vpnmgr")
        .join("killswitch-restore.txt")
}

pub struct Killswitch {
    interface: String,
    /// The WireGuard port. Unlike Linux there is no fwmark to recognise the
    /// tunnel's own encrypted packets by, so the port stands in for it.
    port: u16,
    allow_lan: bool,
    allowed: Vec<String>,
}

impl Killswitch {
    /// `fwmark` is accepted for signature parity with the Linux build, which
    /// uses it to recognise the tunnel's own traffic. Windows has no equivalent
    /// and identifies that traffic by port instead.
    pub fn new(interface: impl Into<String>, _fwmark: u32, allow_lan: bool) -> Self {
        Self {
            interface: interface.into(),
            port: 1637,
            allow_lan,
            allowed: Vec::new(),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Destinations the bypass is keeping off the tunnel.
    pub fn allowing(mut self, destinations: Vec<String>) -> Self {
        self.allowed = destinations;
        self
    }

    /// The PowerShell this would run.
    ///
    /// Separated from [`Self::engage`] so the rules can be asserted on in tests
    /// without touching the firewall of the machine running them.
    pub fn script(&self) -> String {
        let mut s = String::with_capacity(2048);
        s.push_str("$ErrorActionPreference = 'Stop'\n");

        // Remove any leftovers first: re-engaging must not accumulate rules,
        // and a previous run that died mid-way may have left some behind.
        s.push_str(&format!(
            "Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue | \
             Remove-NetFirewallRule -ErrorAction SilentlyContinue\n"
        ));

        // Record what to go back to, before changing anything. Written only if
        // absent, so a second engage cannot overwrite the real previous value
        // with 'Block'.
        let restore = restore_path();
        s.push_str(&format!(
            "$restore = '{}'\n\
             New-Item -ItemType Directory -Force -Path (Split-Path -Parent $restore) | Out-Null\n\
             if (-not (Test-Path $restore)) {{\n\
             \x20 (Get-NetFirewallProfile -All | ForEach-Object {{ \"$($_.Name)=$($_.DefaultOutboundAction)\" }}) \
             -join ';' | Set-Content -Path $restore\n\
             }}\n",
            restore.display()
        ));

        let rule = |name: &str, extra: &str| {
            format!(
                "New-NetFirewallRule -DisplayName '{RULE_PREFIX}-{name}' -Group '{GROUP}' \
                 -Direction Outbound -Action Allow -Profile Any {extra} | Out-Null\n"
            )
        };

        // The tunnel adapter: everything that reaches it is already encrypted.
        s.push_str(&rule(
            "tunnel",
            &format!("-InterfaceAlias '{}'", self.interface),
        ));

        // The encrypted traffic itself, and the prober's handshakes.
        s.push_str(&rule(
            "wireguard",
            &format!("-Protocol UDP -RemotePort {}", self.port),
        ));

        s.push_str(&rule("link-v4", &format!("-RemoteAddress {LINK_V4}")));
        s.push_str(&rule("link-v6", &format!("-RemoteAddress {LINK_V6}")));
        // DHCP renewal is UDP 67/68 to the broadcast address, which the
        // link-local rule above covers, but a server on the LAN answers from
        // its own address.
        s.push_str(&rule("dhcp", "-Protocol UDP -RemotePort 67,68"));

        if self.allow_lan {
            s.push_str(&rule("lan-v4", &format!("-RemoteAddress {LAN_V4}")));
            s.push_str(&rule("lan-v6", &format!("-RemoteAddress {LAN_V6}")));
        }

        if !self.allowed.is_empty() {
            // Quoted individually: a destination is a prefix, and PowerShell
            // would otherwise split on the comma inside one.
            let list = self
                .allowed
                .iter()
                .map(|d| format!("'{d}'"))
                .collect::<Vec<_>>()
                .join(",");
            s.push_str(&rule("bypass", &format!("-RemoteAddress {list}")));
        }

        // Last, so a failure above leaves the machine connected rather than
        // cut off with no rules to let anything through.
        s.push_str("Set-NetFirewallProfile -All -DefaultOutboundAction Block\n");
        s
    }

    pub fn engage(&self) -> Result<()> {
        run(&self.script()).map_err(|source| Error::Killswitch {
            operation: "engaging",
            source,
        })?;
        tracing::info!(
            interface = %self.interface,
            allow_lan = self.allow_lan,
            bypassed = self.allowed.len(),
            "kill switch engaged: outbound traffic is blocked by default"
        );
        Ok(())
    }

    /// Remove the rules and put the default outbound action back.
    pub fn release() -> Result<()> {
        let restore = restore_path();
        let script = format!(
            "$ErrorActionPreference = 'Continue'\n\
             Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue | \
             Remove-NetFirewallRule -ErrorAction SilentlyContinue\n\
             $restore = '{}'\n\
             if (Test-Path $restore) {{\n\
             \x20 foreach ($entry in (Get-Content $restore) -split ';') {{\n\
             \x20   $parts = $entry -split '='\n\
             \x20   if ($parts.Count -eq 2) {{ Set-NetFirewallProfile -Name $parts[0] \
             -DefaultOutboundAction $parts[1] }}\n\
             \x20 }}\n\
             \x20 Remove-Item -Force $restore\n\
             }} else {{\n\
             \x20 # No record: Allow is the Windows default, and leaving the machine\n\
             \x20 # unable to reach anything would be worse than a wrong guess.\n\
             \x20 Set-NetFirewallProfile -All -DefaultOutboundAction Allow\n\
             }}\n",
            restore.display()
        );
        run(&script).map_err(|source| Error::Killswitch {
            operation: "releasing",
            source,
        })?;
        tracing::info!("kill switch released");
        Ok(())
    }

    /// Whether the rules are currently installed.
    pub fn is_engaged() -> bool {
        let script =
            format!("@(Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue).Count");
        run_output(&script)
            .and_then(|s| s.trim().parse::<u32>().ok())
            .is_some_and(|count| count > 0)
    }

    /// Windows Firewall keeps no per-rule counters that can be read back, so
    /// there is no honest number to report here. Reporting zero would suggest
    /// nothing had been blocked, which is a different claim entirely.
    pub fn dropped() -> Option<u64> {
        None
    }

    pub fn recovery_hint() -> String {
        format!(
            "outbound traffic is blocked by default. To restore it:\n    \
             vpnmgr killswitch off\n  \
             or, if the daemon is not running, from an elevated PowerShell:\n    \
             Get-NetFirewallRule -Group '{GROUP}' | Remove-NetFirewallRule\n    \
             Set-NetFirewallProfile -All -DefaultOutboundAction Allow"
        )
    }
}

fn run(script: &str) -> std::io::Result<()> {
    let output = powershell(script)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output");
    Err(std::io::Error::other(format!(
        "powershell exited {}: {reason}",
        output.status.code().unwrap_or(-1)
    )))
}

fn run_output(script: &str) -> Option<String> {
    let output = powershell(script).ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn powershell(script: &str) -> std::io::Result<std::process::Output> {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks() -> Killswitch {
        Killswitch::new("vpnmgr0", 51820, false)
    }

    /// The whole guarantee rests on this one line. Everything else is an
    /// exception to it.
    #[test]
    fn the_default_outbound_action_is_set_to_block() {
        assert!(
            ks().script()
                .contains("Set-NetFirewallProfile -All -DefaultOutboundAction Block")
        );
    }

    /// Ordering matters: the allow rules must exist before the default action
    /// changes, or there is a window with no way out at all.
    #[test]
    fn allow_rules_are_created_before_the_default_action_changes() {
        let script = ks().script();
        let block = script.find("-DefaultOutboundAction Block").unwrap();
        let tunnel = script.find("vpnmgr-allow-tunnel").unwrap();
        let wireguard = script.find("vpnmgr-allow-wireguard").unwrap();
        assert!(tunnel < block && wireguard < block);
    }

    /// Without this the tunnel could never handshake, and the kill switch would
    /// simply be an internet off switch.
    #[test]
    fn the_wireguard_port_is_always_allowed_out() {
        assert!(ks().script().contains("-Protocol UDP -RemotePort 1637"));
        assert!(
            ks().with_port(51820)
                .script()
                .contains("-Protocol UDP -RemotePort 51820")
        );
    }

    #[test]
    fn the_previous_default_action_is_recorded_before_being_changed() {
        let script = ks().script();
        let record = script.find("DefaultOutboundAction)").unwrap();
        let change = script.find("-DefaultOutboundAction Block").unwrap();
        assert!(record < change, "the old value must be saved first");
    }

    /// Re-engaging must not overwrite the saved value with the one this feature
    /// itself set, or releasing would restore Block and never let go.
    #[test]
    fn the_saved_value_is_not_overwritten_by_a_second_engage() {
        assert!(ks().script().contains("if (-not (Test-Path $restore))"));
    }

    #[test]
    fn the_lan_is_only_allowed_when_asked_for() {
        assert!(!ks().script().contains("192.168.0.0/16"));
        let permissive = Killswitch::new("vpnmgr0", 51820, true);
        assert!(permissive.script().contains("192.168.0.0/16"));
        assert!(permissive.script().contains("fc00::/7"));
    }

    /// The bypass routes traffic out of the physical adapter; without a
    /// matching rule the firewall drops exactly what the routing table just
    /// went to the trouble of letting out.
    #[test]
    fn bypass_destinations_are_allowed_through() {
        let script = ks().allowing(vec!["160.79.104.0/23".into()]).script();
        assert!(script.contains("160.79.104.0/23"));
    }

    /// Each destination is quoted separately: PowerShell splits an unquoted
    /// comma-separated argument, and a prefix contains no comma but the list
    /// between them does.
    #[test]
    fn several_bypass_destinations_are_quoted_individually() {
        let script = ks()
            .allowing(vec!["10.1.0.0/16".into(), "10.2.0.0/16".into()])
            .script();
        assert!(script.contains("'10.1.0.0/16','10.2.0.0/16'"));
    }

    /// Link-local and DHCP are not optional: without them the machine loses
    /// its lease and the link goes down, taking the tunnel with it.
    #[test]
    fn the_link_layer_keeps_working() {
        let script = ks().script();
        assert!(script.contains("169.254.0.0/16"));
        assert!(script.contains("fe80::/10"));
        assert!(script.contains("-RemotePort 67,68"));
    }

    /// Stale rules from a previous run must go, or engaging repeatedly would
    /// accumulate duplicates until the rule list is unreadable.
    #[test]
    fn existing_rules_are_cleared_first() {
        let script = ks().script();
        let remove = script.find("Remove-NetFirewallRule").unwrap();
        let create = script.find("New-NetFirewallRule").unwrap();
        assert!(remove < create);
    }

    #[test]
    fn the_recovery_hint_names_a_command_that_needs_no_internet() {
        let hint = Killswitch::recovery_hint();
        assert!(hint.contains("vpnmgr killswitch off"));
        assert!(hint.contains("Set-NetFirewallProfile"));
    }
}
