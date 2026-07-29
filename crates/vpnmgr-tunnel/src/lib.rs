//! Tunnel control: bringing a WireGuard interface up, switching which server
//! it points at, and tearing it down.
//!
//! Everything platform-specific lives behind [`TunnelBackend`], so the daemon
//! and auto-tuner never learn whether they are driving netlink on Linux or
//! WireGuard-NT on Windows.
//!
//! # Switching servers is cheap
//!
//! Because every AirVPN server shares a peer public key, moving to a different
//! server does not mean rebuilding the tunnel. The interface, its addresses,
//! its routes and its DNS all stay exactly as they are, and only the peer's
//! `Endpoint` is rewritten — see [`TunnelBackend::switch_endpoint`]. The
//! existing session keys belong to the old server, so WireGuard performs a
//! fresh handshake on the next outbound packet; nothing else is disturbed.
//!
//! # fwmark
//!
//! The interface is marked with [`DEFAULT_FWMARK`], which does double duty: it
//! stops WireGuard's own encrypted packets from being routed back into the
//! tunnel, and it is the mark `vpnmgr-probe` puts on its probe sockets so Tier
//! 1 measurements travel the physical path. Both sides must agree, so the
//! constant lives here and the prober is handed the value.

use std::net::SocketAddr;
use std::time::SystemTime;

use vpnmgr_core::ClientConfig;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxTunnel;

/// Firewall mark applied to the interface and to probe sockets.
///
/// 51820 is the value `wg-quick` uses by default; matching it keeps any
/// hand-written policy-routing rules working.
pub const DEFAULT_FWMARK: u32 = 51820;

/// Default interface name. Distinct from `wg0` so vpnmgr never collides with a
/// tunnel the user manages themselves.
pub const DEFAULT_INTERFACE: &str = "vpnmgr0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{operation} on interface {interface} failed: {source}")]
    Wireguard {
        operation: &'static str,
        interface: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error(
        "{operation} on interface {interface} needs root (CAP_NET_ADMIN); \
         run vpnmgrd as a system service rather than as your user"
    )]
    PermissionDenied {
        operation: &'static str,
        interface: String,
    },

    #[error("the tunnel is not up")]
    NotUp,

    #[error("interface name {0:?} is not usable: {1}")]
    BadInterfaceName(String, &'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Everything needed to bring up or retarget a tunnel.
#[derive(Debug, Clone)]
pub struct TunnelSpec<'a> {
    pub interface: &'a str,
    /// Credentials. Server-independent, so the same value is reused across
    /// every switch.
    pub client: &'a ClientConfig,
    /// The server to point at.
    pub endpoint: SocketAddr,
    pub fwmark: u32,
}

impl<'a> TunnelSpec<'a> {
    pub fn new(client: &'a ClientConfig, endpoint: SocketAddr) -> Self {
        Self {
            interface: DEFAULT_INTERFACE,
            client,
            endpoint,
            fwmark: DEFAULT_FWMARK,
        }
    }

    pub fn with_interface(mut self, interface: &'a str) -> Self {
        self.interface = interface;
        self
    }

    pub fn with_fwmark(mut self, fwmark: u32) -> Self {
        self.fwmark = fwmark;
        self
    }

    /// Reject names the kernel will not accept, before a confusing netlink
    /// error surfaces instead.
    pub fn validate(&self) -> Result<()> {
        let name = self.interface;
        if name.is_empty() {
            return Err(Error::BadInterfaceName(name.into(), "it is empty"));
        }
        if name.len() >= 16 {
            return Err(Error::BadInterfaceName(
                name.into(),
                "Linux limits interface names to 15 characters",
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::BadInterfaceName(
                name.into(),
                "only letters, digits, '-' and '_' are allowed",
            ));
        }
        Ok(())
    }
}

/// Live state of the tunnel, as reported by the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelStatus {
    pub interface: String,
    pub up: bool,
    /// Endpoint of the peer, i.e. the server currently in use.
    pub endpoint: Option<SocketAddr>,
    /// When the last handshake completed. `None` means the tunnel is
    /// configured but has never successfully connected.
    pub last_handshake: Option<SystemTime>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub listen_port: u16,
    pub fwmark: Option<u32>,
}

impl TunnelStatus {
    /// A tunnel is only *working* if a handshake has happened recently.
    /// WireGuard rekeys about every two minutes, so a gap much beyond that
    /// means traffic is not flowing even though the interface exists.
    pub fn is_healthy(&self, now: SystemTime, max_handshake_age: std::time::Duration) -> bool {
        match self.last_handshake {
            None => false,
            Some(at) => now
                .duration_since(at)
                .map(|age| age <= max_handshake_age)
                .unwrap_or(true), // a clock skew into the future is not a fault
        }
    }
}

/// Platform-independent tunnel control.
pub trait TunnelBackend: Send {
    /// Create the interface, configure the peer, install routes and DNS.
    fn up(&mut self, spec: &TunnelSpec<'_>) -> Result<()>;

    /// Point the existing tunnel at a different server.
    ///
    /// Must not disturb addresses, routes or DNS — that is the whole reason
    /// server switching is cheap.
    fn switch_endpoint(&mut self, spec: &TunnelSpec<'_>) -> Result<()>;

    /// Remove the interface and its routes.
    fn down(&mut self) -> Result<()>;

    /// Read live state from the kernel.
    fn status(&self) -> Result<TunnelStatus>;

    fn interface(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn spec_with(interface: &str) -> Result<()> {
        // The client config is irrelevant to name validation.
        let client = ClientConfig::parse(
            include_str!("../../vpnmgr-core/tests/fixtures/airvpn_sample.conf"),
            "sample.conf",
        )
        .unwrap();
        TunnelSpec::new(&client, "1.2.3.4:1637".parse().unwrap())
            .with_interface(interface)
            .validate()
    }

    #[test]
    fn accepts_the_default_interface_name() {
        assert!(spec_with(DEFAULT_INTERFACE).is_ok());
    }

    #[test]
    fn rejects_an_over_long_interface_name() {
        let err = spec_with("averyverylonginterfacename").unwrap_err();
        assert!(err.to_string().contains("15 characters"), "{err}");
    }

    #[test]
    fn rejects_an_empty_interface_name() {
        assert!(spec_with("").is_err());
    }

    #[test]
    fn rejects_shell_metacharacters_in_an_interface_name() {
        for name in ["wg0; rm -rf /", "wg 0", "wg/0", "wg$0"] {
            assert!(spec_with(name).is_err(), "{name:?} should be rejected");
        }
    }

    #[test]
    fn accepts_names_with_dashes_and_underscores() {
        assert!(spec_with("vpn-mgr_0").is_ok());
    }

    fn status(last_handshake: Option<SystemTime>) -> TunnelStatus {
        TunnelStatus {
            interface: DEFAULT_INTERFACE.into(),
            up: true,
            endpoint: Some("1.2.3.4:1637".parse().unwrap()),
            last_handshake,
            tx_bytes: 0,
            rx_bytes: 0,
            listen_port: 51820,
            fwmark: Some(DEFAULT_FWMARK),
        }
    }

    #[test]
    fn a_tunnel_that_never_handshook_is_not_healthy() {
        let now = SystemTime::now();
        assert!(!status(None).is_healthy(now, Duration::from_secs(180)));
    }

    #[test]
    fn a_recent_handshake_is_healthy() {
        let now = SystemTime::now();
        let recent = now - Duration::from_secs(30);
        assert!(status(Some(recent)).is_healthy(now, Duration::from_secs(180)));
    }

    #[test]
    fn a_stale_handshake_is_not_healthy() {
        // The interface can exist and look fine while carrying no traffic.
        let now = SystemTime::now();
        let stale = now - Duration::from_secs(600);
        assert!(!status(Some(stale)).is_healthy(now, Duration::from_secs(180)));
    }

    #[test]
    fn a_handshake_timestamped_in_the_future_is_tolerated() {
        // Clock skew or a suspend/resume must not be reported as a dead tunnel.
        let now = SystemTime::now();
        let future = now + Duration::from_secs(60);
        assert!(status(Some(future)).is_healthy(now, Duration::from_secs(180)));
    }
}
