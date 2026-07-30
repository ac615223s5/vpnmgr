//! Linux backend, driving the in-kernel WireGuard module over netlink.
//!
//! The kernel datapath is used rather than a userspace implementation: it is
//! why the daemon can stay near-idle while carrying traffic, which is the whole
//! point of the background-footprint requirement.

use defguard_wireguard_rs::{
    InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi, key::Key, net::IpAddrMask,
    peer::Peer,
};
use vpnmgr_core::wgconf::Cidr;

use crate::{Error, Result, TunnelBackend, TunnelSpec, TunnelStatus};

/// Tunnel managed through the kernel WireGuard module.
pub struct LinuxTunnel {
    api: WGApi<Kernel>,
    interface: String,
    /// Tracks whether *we* created the interface, so `down` does not remove
    /// something another tool owns.
    created: bool,
    /// Firewall enforcement, when the user asked for it. Engaged as part of
    /// `up` and released by `down`, so the protected window is exactly the
    /// window in which traffic is supposed to be tunnelled.
    killswitch: Option<crate::Killswitch>,
}

impl LinuxTunnel {
    pub fn new(interface: impl Into<String>) -> Result<Self> {
        let interface = interface.into();
        let api = WGApi::<Kernel>::new(interface.clone()).map_err(|e| wg_err("open", &interface, e))?;
        Ok(Self {
            api,
            interface,
            created: false,
            killswitch: None,
        })
    }

    /// Enforce the kill switch for the lifetime of this tunnel.
    pub fn with_killswitch(mut self, killswitch: crate::Killswitch) -> Self {
        self.killswitch = Some(killswitch);
        self
    }

    /// Build the peer for `spec`. Identical for every server except the
    /// endpoint, which is exactly what makes switching cheap.
    fn peer(spec: &TunnelSpec<'_>) -> Peer {
        let mut peer = Peer::new(Key::new(*spec.client.peer_public_key.as_bytes()));
        peer.endpoint = Some(spec.endpoint);
        peer.preshared_key = spec
            .client
            .preshared_key
            .as_ref()
            .map(|k| Key::new(*k.expose()));
        peer.persistent_keepalive_interval = spec.client.persistent_keepalive;
        peer.allowed_ips = spec.client.allowed_ips.iter().map(to_mask).collect();
        peer
    }
}

impl LinuxTunnel {
    /// Collapse duplicated policy routing rules back down to one of each.
    ///
    /// `configure_peer_routing` unconditionally *adds* its two rules — the
    /// `not fwmark` lookup and the `suppress_prefixlength 0` override — and the
    /// library only prunes them when the interface is removed, which a switch
    /// deliberately avoids. Reinstalling routing on every switch would then grow
    /// the rule list without bound in a daemon that re-tunes every 30 minutes.
    ///
    /// Pruning happens *after* the reinstall rather than before, so there is
    /// never a moment with no rule directing traffic into the tunnel.
    ///
    /// Best-effort: a failure here leaves redundant but harmless duplicates, so
    /// it is logged rather than allowed to fail the switch.
    fn prune_duplicate_policy_rules(&self, fwmark: u32) {
        let table = fwmark.to_string();
        let lookup = format!("lookup {table}");
        for family in ["-4", "-6"] {
            self.prune_rule(
                family,
                &|line| line.contains("fwmark") && line.contains(&lookup),
                &["not", "fwmark", &table, "table", &table],
            );
            self.prune_rule(
                family,
                &|line| line.contains("suppress_prefixlength 0"),
                &["table", "main", "suppress_prefixlength", "0"],
            );
        }
    }

    /// Delete copies of one rule until a single instance remains.
    fn prune_rule(&self, family: &str, matches: &dyn Fn(&str) -> bool, delete_args: &[&str]) {
        while count_rules(family, matches) > 1 {
            let status = std::process::Command::new("ip")
                .arg(family)
                .args(["rule", "del"])
                .args(delete_args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            match status {
                Ok(s) if s.success() => {}
                other => {
                    tracing::debug!(
                        interface = %self.interface,
                        result = ?other,
                        "could not prune a duplicate policy rule; leaving it in place"
                    );
                    break;
                }
            }
        }
    }

    /// Rebind the interface to a different UDP source port.
    ///
    /// Deliberately re-applies the whole interface configuration minus the
    /// peers: `configure_interface` is the only way to set the listen port, and
    /// passing an empty peer list keeps it from re-adding the peer we are in
    /// the middle of replacing. Routes are not touched here, because
    /// `configure_peer_routing` is a separate call.
    fn rotate_listen_port(&mut self, spec: &TunnelSpec<'_>) -> Result<()> {
        let config = InterfaceConfiguration {
            name: self.interface.clone(),
            prvkey: spec.client.private_key.expose_base64(),
            addresses: spec.client.addresses.iter().map(to_mask).collect(),
            // 0 asks the kernel for a fresh ephemeral port.
            port: 0,
            peers: Vec::new(),
            mtu: spec.client.mtu,
            fwmark: Some(spec.fwmark),
        };
        self.api
            .configure_interface(&config)
            .map_err(|e| wg_err("rotating the listen port", &self.interface, e))
    }
}

/// How many policy rules in `family` satisfy `matches`.
fn count_rules(family: &str, matches: &dyn Fn(&str) -> bool) -> usize {
    let Ok(output) = std::process::Command::new("ip")
        .arg(family)
        .args(["rule", "show"])
        .output()
    else {
        // Without a way to count, report zero so the caller does not loop.
        return 0;
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| matches(line))
        .count()
}

fn to_mask(cidr: &Cidr) -> IpAddrMask {
    IpAddrMask::new(cidr.addr, cidr.prefix)
}

/// Map a backend error, promoting permission failures to their own variant so
/// the daemon can tell the user to run as root instead of dumping netlink noise.
fn wg_err(
    operation: &'static str,
    interface: &str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    let text = source.to_string();
    if text.contains("Operation not permitted")
        || text.contains("permission denied")
        || text.contains("Permission denied")
    {
        return Error::PermissionDenied {
            operation,
            interface: interface.to_owned(),
        };
    }
    Error::Wireguard {
        operation,
        interface: interface.to_owned(),
        source: Box::new(source),
    }
}

impl TunnelBackend for LinuxTunnel {
    fn up(&mut self, spec: &TunnelSpec<'_>) -> Result<()> {
        spec.validate()?;

        // Engaged before anything else, so there is no instant between "we
        // decided to tunnel" and "traffic is confined". `oifname` is matched by
        // name at runtime, so naming an interface that does not exist yet is
        // fine.
        if let Some(killswitch) = &self.killswitch {
            killswitch.engage()?;
            tracing::info!(interface = %self.interface, "kill switch engaged");
        }

        // From here on a failure must not strand the machine behind rules for a
        // tunnel that never came up.
        let result = self.bring_up(spec);
        if result.is_err()
            && let Some(_killswitch) = &self.killswitch
        {
            if let Err(e) = crate::Killswitch::release() {
                tracing::error!(
                    "could not release the kill switch after a failed connect: {e}. {}",
                    crate::Killswitch::recovery_hint()
                );
            } else {
                tracing::info!("kill switch released after a failed connect");
            }
        }
        result
    }

    fn switch_endpoint(&mut self, spec: &TunnelSpec<'_>) -> Result<()> {
        self.retarget(spec)
    }

    fn down(&mut self) -> Result<()> {
        let result = self
            .api
            .remove_interface()
            .map_err(|e| wg_err("removing the interface", &self.interface, e));
        self.created = false;

        // Released even if teardown failed: the interface state is unknown, and
        // leaving the machine with no route out is worse than a brief exposure
        // the user explicitly asked for by disconnecting.
        if self.killswitch.is_some() {
            crate::Killswitch::release()?;
            tracing::info!("kill switch released");
        }

        result?;
        tracing::info!(interface = %self.interface, "tunnel down");
        Ok(())
    }

    fn status(&self) -> Result<TunnelStatus> {
        self.read_status()
    }

    fn interface(&self) -> &str {
        &self.interface
    }
}

impl LinuxTunnel {
    fn bring_up(&mut self, spec: &TunnelSpec<'_>) -> Result<()> {
        self.api
            .create_interface()
            .map_err(|e| wg_err("creating the interface", &self.interface, e))?;
        self.created = true;

        let peer = Self::peer(spec);
        let config = InterfaceConfiguration {
            name: self.interface.clone(),
            prvkey: spec.client.private_key.expose_base64(),
            addresses: spec.client.addresses.iter().map(to_mask).collect(),
            // 0 lets the kernel pick a source port. Not pinning it means a
            // reconnect looks like a new source to the server, which is fine
            // and avoids clashing with anything already bound.
            port: 0,
            peers: vec![peer.clone()],
            mtu: spec.client.mtu,
            fwmark: Some(spec.fwmark),
        };

        self.api
            .configure_interface(&config)
            .map_err(|e| wg_err("configuring the interface", &self.interface, e))?;

        // Installs the wg-quick-equivalent routes, including the fwmark rule
        // that keeps encrypted traffic out of the tunnel it belongs to.
        self.api
            .configure_peer_routing(&[peer])
            .map_err(|e| wg_err("installing routes", &self.interface, e))?;

        if !spec.client.dns.is_empty() || !spec.client.search_domains.is_empty() {
            let domains: Vec<&str> = spec
                .client
                .search_domains
                .iter()
                .map(String::as_str)
                .collect();
            // With no search domains this sets resolved's "exclusive" flag,
            // making the tunnel's resolvers authoritative for every lookup —
            // which is what stops DNS from leaking to the ISP resolver.
            self.api
                .configure_dns(&spec.client.dns, &domains)
                .map_err(|e| wg_err("configuring DNS", &self.interface, e))?;
        }

        tracing::info!(
            interface = %self.interface,
            endpoint = %spec.endpoint,
            "tunnel up"
        );
        Ok(())
    }

    fn retarget(&mut self, spec: &TunnelSpec<'_>) -> Result<()> {
        // Switching servers on a shared-key fleet takes three steps, and all
        // three are load-bearing.
        //
        // Every AirVPN server presents the *same* peer public key, so the
        // kernel cannot tell them apart: it sees one peer, and WireGuard moves
        // a peer's endpoint to the source of any packet that authenticates
        // against it. That makes the server we are leaving able to drag us back.
        //
        // 1. `remove_peer` discards the old session keys, so the previous
        //    server's in-flight *data* packets no longer authenticate. Without
        //    this a rewritten endpoint reverted within two seconds.
        //
        // 2. The listen port is rotated. Step 1 is not enough on its own: the
        //    old server can open a *fresh handshake*, and because that
        //    initiation carries the fleet key it is indistinguishable from the
        //    intended server's, so the kernel completes it and roams. Measured:
        //    the endpoint held for ~10s after a switch and then silently moved
        //    to the previous server, exiting in the wrong country while the
        //    daemon still reported the new one.
        //
        //    Rotating the port fixes this because only a server we have
        //    *connected* to knows the port; servers we merely probed saw
        //    ephemeral probe sockets instead. Sending the old server's
        //    initiations to a port with no socket is enough to ignore them, and
        //    is far cheaper than the alternative of firewalling the listen port
        //    down to one source address.
        //
        // 3. `configure_peer` re-adds the peer, forcing a fresh handshake to
        //    the new endpoint, and the routing is reinstalled.
        //
        // Reinstalling routes is not optional. Setting the listen port means
        // re-applying the interface configuration, and that flushes the policy
        // routing table holding the tunnel's default route. Skipping the
        // reinstall leaves the `not fwmark` rule pointing at an empty table, so
        // every lookup falls through to the physical default route and traffic
        // leaves unencrypted — observed as the machine's real ISP address
        // reappearing while the tunnel looked healthy.
        //
        // DNS is left alone: `configure_interface` does not touch the resolver
        // configuration, so the settings applied by `up` still stand.
        let peer = Self::peer(spec);
        let key = Key::new(*spec.client.peer_public_key.as_bytes());

        self.api
            .remove_peer(&key)
            .map_err(|e| wg_err("clearing the previous session", &self.interface, e))?;

        let previous_port = self.api.read_interface_data().ok().map(|h| h.listen_port);
        self.rotate_listen_port(spec)?;

        self.api
            .configure_peer(&peer)
            .map_err(|e| wg_err("retargeting the peer", &self.interface, e))?;

        self.api
            .configure_peer_routing(&[peer])
            .map_err(|e| wg_err("reinstalling routes", &self.interface, e))?;
        self.prune_duplicate_policy_rules(spec.fwmark);

        tracing::info!(
            interface = %self.interface,
            endpoint = %spec.endpoint,
            previous_port = ?previous_port,
            listen_port = ?self.api.read_interface_data().ok().map(|h| h.listen_port),
            "switched server"
        );
        Ok(())
    }

    fn read_status(&self) -> Result<TunnelStatus> {
        let host = self
            .api
            .read_interface_data()
            .map_err(|e| wg_err("reading interface state", &self.interface, e))?;

        // We configure exactly one peer, so taking the first is unambiguous.
        let peer = host.peers.values().next();

        Ok(TunnelStatus {
            interface: self.interface.clone(),
            up: true,
            endpoint: peer.and_then(|p| p.endpoint),
            last_handshake: peer.and_then(|p| p.last_handshake).filter(|t| {
                // The kernel reports the zero instant for "never handshook";
                // surfacing that as a real timestamp would make a dead tunnel
                // look merely stale.
                *t != std::time::UNIX_EPOCH
            }),
            tx_bytes: peer.map(|p| p.tx_bytes).unwrap_or(0),
            rx_bytes: peer.map(|p| p.rx_bytes).unwrap_or(0),
            listen_port: host.listen_port,
            fwmark: host.fwmark,
        })
    }
}

impl Drop for LinuxTunnel {
    fn drop(&mut self) {
        // Leaving a live interface behind on a crash would strand the user's
        // routing table, so tear it down on the way out.
        if self.created
            && let Err(e) = self.api.remove_interface()
        {
            tracing::warn!(
                interface = %self.interface,
                error = %e,
                "failed to remove the interface while dropping the tunnel"
            );
        }

        // The interface is going away, so the rules can only block traffic that
        // now has nowhere to be tunnelled. Releasing here covers an orderly
        // shutdown; a hard kill still leaves them in place, which is the
        // intended fail-closed behaviour rather than an oversight.
        if self.killswitch.is_some()
            && let Err(e) = crate::Killswitch::release()
        {
            tracing::error!(
                error = %e,
                "failed to release the kill switch while dropping the tunnel. {}",
                crate::Killswitch::recovery_hint()
            );
        }
    }
}
