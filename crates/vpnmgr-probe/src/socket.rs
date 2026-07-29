//! UDP sockets that can be steered around an active tunnel.
//!
//! When a tunnel is up, its `AllowedIPs` of `0.0.0.0/0` capture every packet —
//! including the probes. Marking the socket with the same fwmark WireGuard uses
//! for its own encrypted traffic makes the policy-routing rule send these
//! packets out the physical interface instead, so Tier 1 can measure the real
//! path to every server without disturbing the live connection.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::UdpSocket;

/// Bind an ephemeral UDP socket suitable for reaching `peer`.
///
/// `fwmark` is applied on Linux only; elsewhere it is ignored, since probing
/// from inside the tunnel still yields a usable (if tunnel-relative) RTT.
pub fn bind_for(peer: SocketAddr, fwmark: Option<u32>) -> io::Result<UdpSocket> {
    let bind_addr = match peer {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    bind_marked(bind_addr, fwmark)
}

#[cfg(target_os = "linux")]
fn bind_marked(bind_addr: SocketAddr, fwmark: Option<u32>) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = match bind_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    if let Some(mark) = fwmark {
        // Needs CAP_NET_ADMIN. The daemon has it; an unprivileged caller does
        // not, and gets a clear error rather than silently probing through the
        // tunnel and reporting misleading RTTs.
        socket.set_mark(mark).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("setting fwmark {mark} on the probe socket failed \
                         (needs CAP_NET_ADMIN): {e}"),
            )
        })?;
    }

    socket.set_nonblocking(true)?;
    socket.bind(&bind_addr.into())?;
    UdpSocket::from_std(socket.into())
}

#[cfg(not(target_os = "linux"))]
fn bind_marked(bind_addr: SocketAddr, fwmark: Option<u32>) -> io::Result<UdpSocket> {
    if fwmark.is_some() {
        tracing::debug!("fwmark is not supported on this platform; probing without it");
    }
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_an_ephemeral_ipv4_socket() {
        let s = bind_for("1.2.3.4:1637".parse().unwrap(), None).unwrap();
        let local = s.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn binds_an_ephemeral_ipv6_socket() {
        let s = bind_for("[2001:db8::1]:1637".parse().unwrap(), None).unwrap();
        assert!(s.local_addr().unwrap().is_ipv6());
    }

    #[tokio::test]
    async fn each_probe_gets_a_distinct_source_port() {
        let a = bind_for("1.2.3.4:1637".parse().unwrap(), None).unwrap();
        let b = bind_for("1.2.3.4:1637".parse().unwrap(), None).unwrap();
        assert_ne!(a.local_addr().unwrap().port(), b.local_addr().unwrap().port());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn setting_an_fwmark_without_privileges_fails_loudly() {
        // Running as root would legitimately succeed, so only assert the
        // message when we actually lack the capability.
        match bind_for("1.2.3.4:1637".parse().unwrap(), Some(0x1234)) {
            Ok(_) => {} // privileged test runner
            Err(e) => assert!(e.to_string().contains("CAP_NET_ADMIN"), "{e}"),
        }
    }
}
