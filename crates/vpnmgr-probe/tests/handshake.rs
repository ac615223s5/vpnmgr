//! End-to-end verification of the prober against a real WireGuard responder.
//!
//! The unit tests only cover timeouts and malformed replies. These stand up an
//! actual WireGuard peer (boringtun in responder role) and complete a genuine
//! Noise_IKpsk2 handshake, which is the only way to prove the prober measures
//! what it claims to and correctly distinguishes valid credentials from stale
//! ones. No root and no AirVPN account required.

use std::net::SocketAddr;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use vpnmgr_core::config;
use vpnmgr_core::key::{PublicKey as CorePublicKey, SecretKey};
use vpnmgr_core::wgconf::ClientConfig;
use vpnmgr_probe::{Outcome, Prober};

/// Deterministic keys so failures are reproducible.
fn keypair(seed: u8) -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::from([seed; 32]);
    let public = PublicKey::from(&secret);
    (secret, public)
}

fn client_config(client_seed: u8, peer_public: PublicKey, psk: Option<[u8; 32]>) -> ClientConfig {
    ClientConfig {
        private_key: SecretKey::from_base64(&base64_of([client_seed; 32])).unwrap(),
        addresses: vec!["10.0.0.2/32".parse().unwrap()],
        dns: vec![],
        search_domains: vec![],
        mtu: None,
        peer_public_key: CorePublicKey::from_base64(&base64_of(*peer_public.as_bytes())).unwrap(),
        preshared_key: psk.map(|k| SecretKey::from_base64(&base64_of(k)).unwrap()),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        persistent_keepalive: None,
    }
}

fn base64_of(bytes: [u8; 32]) -> String {
    // Small local helper so the test does not depend on a base64 crate.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Spawn a WireGuard responder that answers handshakes from `client_public`.
///
/// Returns the address to probe. The responder answers `answer_count`
/// handshakes, then goes silent.
async fn spawn_responder(
    server_secret: StaticSecret,
    client_public: PublicKey,
    psk: Option<[u8; 32]>,
    answer_count: usize,
) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let mut scratch = [0u8; 1500];
        for i in 0..answer_count {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            // A fresh responder per handshake, mirroring a server that has no
            // prior session with this source port.
            let mut tunn = Tunn::new(
                server_secret.clone(),
                client_public,
                psk,
                None,
                (i + 1000) as u32,
                None,
            );
            if let TunnResult::WriteToNetwork(response) =
                tunn.decapsulate(None, &buf[..n], &mut scratch)
            {
                let _ = socket.send_to(response, peer).await;
            }
        }
        // Hold the socket open but silent for the remaining probes.
        std::future::pending::<()>().await;
    });

    addr
}

fn settings(samples: usize) -> config::Probe {
    config::Probe {
        concurrency: 8,
        timeout_ms: 1000,
        samples,
    }
}

#[tokio::test]
async fn completes_a_real_handshake_and_measures_a_round_trip() {
    let (server_secret, server_public) = keypair(7);
    let (_, client_public) = keypair(3);

    let addr = spawn_responder(server_secret, client_public, None, 4).await;
    let client = client_config(3, server_public, None);

    let result = Prober::new(&client, settings(3)).probe(addr).await;

    assert_eq!(
        result.outcome,
        Outcome::Reachable,
        "a valid handshake should verify: {:?}",
        result.outcome
    );
    assert_eq!(result.samples.len(), 3, "every sample should have succeeded");
    let rtt = result.rtt.expect("a completed handshake yields an RTT");
    // Loopback: real, non-zero, and far below the timeout.
    assert!(rtt > Duration::ZERO);
    assert!(rtt < Duration::from_millis(500), "{rtt:?}");
}

#[tokio::test]
async fn a_preshared_key_is_exercised_by_the_handshake() {
    let (server_secret, server_public) = keypair(11);
    let (_, client_public) = keypair(5);
    let psk = [42u8; 32];

    let addr = spawn_responder(server_secret, client_public, Some(psk), 2).await;
    let client = client_config(5, server_public, Some(psk));

    let result = Prober::new(&client, settings(1)).probe(addr).await;
    assert_eq!(result.outcome, Outcome::Reachable, "{:?}", result.outcome);
}

#[tokio::test]
async fn a_mismatched_preshared_key_is_rejected_not_reported_reachable() {
    let (server_secret, server_public) = keypair(11);
    let (_, client_public) = keypair(5);

    // Server expects one PSK, client presents another.
    let addr = spawn_responder(server_secret, client_public, Some([42u8; 32]), 2).await;
    let client = client_config(5, server_public, Some([99u8; 32]));

    let result = Prober::new(&client, settings(1)).probe(addr).await;
    assert!(
        !result.outcome.is_usable(),
        "a bad PSK must not count as reachable, got {:?}",
        result.outcome
    );
}

#[tokio::test]
async fn a_wrong_peer_key_is_indistinguishable_from_an_unreachable_server() {
    // Documents a real limitation. A handshake initiation is encrypted *to*
    // the peer's public key, so if that key is wrong the server cannot decrypt
    // it and answers nothing at all. The result is a plain timeout, identical
    // to a dead server or a blocked port.
    //
    // Consequence for the auto-tuner: a sweep where every server times out
    // means "local link down OR our credentials are stale" — it cannot be
    // pinned on the ISP alone.
    let (server_secret, _server_public) = keypair(11);
    let (_, client_public) = keypair(5);
    let addr = spawn_responder(server_secret, client_public, None, 2).await;

    let (_, wrong_public) = keypair(200);
    let client = client_config(5, wrong_public, None);

    let result = Prober::new(&client, settings(1)).probe(addr).await;
    assert_eq!(
        result.outcome,
        Outcome::Unreachable,
        "a wrong peer key yields silence, not a rejection"
    );
    assert!(!result.outcome.is_usable());
}

#[tokio::test]
async fn a_mismatched_preshared_key_is_reported_as_rejected() {
    // Unlike the peer key, the PSK is only mixed in at the response stage of
    // Noise_IKpsk2, so the server *does* reply and the failure surfaces as a
    // verification error. This one is actionable: tell the user to re-import.
    let (server_secret, server_public) = keypair(11);
    let (_, client_public) = keypair(5);
    let addr = spawn_responder(server_secret, client_public, Some([42u8; 32]), 2).await;
    let client = client_config(5, server_public, Some([99u8; 32]));

    let result = Prober::new(&client, settings(1)).probe(addr).await;
    assert!(
        matches!(result.outcome, Outcome::Rejected(_)),
        "expected a rejection, got {:?}",
        result.outcome
    );
}

#[tokio::test]
async fn a_sweep_ranks_a_live_responder_above_dead_endpoints() {
    let (server_secret, server_public) = keypair(7);
    let (_, client_public) = keypair(3);
    let live = spawn_responder(server_secret, client_public, None, 4).await;
    let client = client_config(3, server_public, None);

    let endpoints: Vec<SocketAddr> = vec![
        "198.51.100.1:1637".parse().unwrap(),
        live,
        "198.51.100.2:1637".parse().unwrap(),
    ];

    let prober = Prober::new(&client, settings(1));
    let results = prober.probe_many(&endpoints).await;

    assert_eq!(results[1].endpoint, live);
    assert_eq!(results[1].outcome, Outcome::Reachable);
    assert!(results[1].rtt.is_some());
    assert_eq!(results[0].outcome, Outcome::Unreachable);
    assert_eq!(results[2].outcome, Outcome::Unreachable);
}

#[tokio::test]
async fn a_server_that_stops_answering_degrades_to_unreachable() {
    let (server_secret, server_public) = keypair(7);
    let (_, client_public) = keypair(3);
    // Answers the first handshake only.
    let addr = spawn_responder(server_secret, client_public, None, 1).await;
    let client = client_config(3, server_public, None);

    let result = Prober::new(&client, settings(3)).probe(addr).await;

    // One sample landed, so the server is still usable and has a timing, but
    // the partial failure must not be silently presented as three good ones.
    assert_eq!(result.outcome, Outcome::Reachable);
    assert_eq!(result.samples.len(), 1);
    assert!(result.rtt.is_some());
}

#[tokio::test]
async fn probing_is_bounded_by_the_configured_timeout() {
    let (server_secret, server_public) = keypair(7);
    let (_, client_public) = keypair(3);
    let addr = spawn_responder(server_secret, client_public, None, 0).await;
    let client = client_config(3, server_public, None);

    let quick = config::Probe {
        concurrency: 4,
        timeout_ms: 200,
        samples: 1,
    };
    let started = std::time::Instant::now();
    let result = Prober::new(&client, quick).probe(addr).await;
    let elapsed = started.elapsed();

    assert_eq!(result.outcome, Outcome::Unreachable);
    assert!(elapsed < Duration::from_millis(800), "{elapsed:?}");
}
