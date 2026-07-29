//! Tier 1 of the probe funnel: measure real WireGuard round-trip time to every
//! candidate server without disturbing the live tunnel.
//!
//! Each probe performs a genuine WireGuard handshake — an initiation is sent to
//! `endpoint`, and the time until the server's handshake response arrives is
//! the RTT. That single measurement proves four things at once: the server is
//! up, UDP/1637 is reachable from here, our credentials are accepted, and this
//! is what the path actually costs. An ICMP ping would prove none of them.
//!
//! # Why this can run while connected
//!
//! Probe sockets carry WireGuard's fwmark, so policy routing sends them out the
//! physical interface rather than into the tunnel (see [`socket`]). Because the
//! probes travel outside the tunnel, a sweep where *every* server is slow is
//! positive evidence that the local link — not the exit server — is the
//! problem, which is exactly the question the auto-tuner needs answered before
//! it starts switching servers.
//!
//! One caveat on that inference: a sweep where every server *times out* is
//! ambiguous, because stale credentials look exactly like a dead network (see
//! [`Outcome::Unreachable`]). Uniformly slow-but-answering is the unambiguous
//! ISP signal; uniformly silent is not.
//!
//! # The endpoint-roaming hazard
//!
//! A WireGuard peer is identified by its public key, and a server updates the
//! stored endpoint for a peer whenever it authenticates a packet from a new
//! source address. Our probes come from a fresh ephemeral port, so a successful
//! handshake **moves the server's idea of where we are**.
//!
//! For a server we are not using this is harmless — the session simply expires.
//! For the server we are *currently connected to* it would redirect the live
//! tunnel's return traffic at our short-lived probe socket and black-hole the
//! connection. [`Prober::excluding`] exists to make that unmissable, and
//! [`Prober::probe_many`] refuses to touch the excluded endpoint.

pub mod socket;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::sync::Semaphore;
use vpnmgr_core::ClientConfig;
use vpnmgr_core::config;

/// WireGuard message type byte for a handshake response.
const MSG_HANDSHAKE_RESPONSE: u8 = 2;
/// WireGuard message type byte for a cookie reply, sent when under load.
const MSG_COOKIE_REPLY: u8 = 3;

/// Gap between repeated handshakes to one server, to stay under the per-source
/// rate limiting a WireGuard endpoint applies.
const SAMPLE_GAP: Duration = Duration::from_millis(120);

/// What a probe established about a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Handshake completed: reachable and our credentials are accepted.
    Reachable,
    /// The server replied with a cookie, meaning it is up but rate limiting
    /// us. Reachability and RTT are still valid.
    RateLimited,
    /// No response within the timeout.
    ///
    /// Note this also covers a wrong *peer public key*: the initiation is
    /// encrypted to that key, so a server that cannot decrypt it stays silent.
    /// A stale fleet key is therefore indistinguishable from a dead server.
    Unreachable,
    /// The server answered but the handshake failed to verify. A preshared-key
    /// mismatch produces this, because the PSK is only mixed in at the response
    /// stage — so unlike a bad peer key, it is actionable: re-import the config.
    Rejected(String),
    /// A local failure, e.g. the socket could not be created.
    Failed(String),
    /// Deliberately not probed; see the endpoint-roaming note above.
    SkippedConnected,
}

impl Outcome {
    /// Whether this outcome should count towards ranking.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Reachable | Self::RateLimited)
    }
}

/// The result of probing one server.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub endpoint: SocketAddr,
    /// Median of the successful samples; `None` if none succeeded.
    pub rtt: Option<Duration>,
    /// Every successful sample, in the order measured.
    pub samples: Vec<Duration>,
    pub outcome: Outcome,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("building a probe socket: {0}")]
    Socket(#[from] std::io::Error),
    #[error("boringtun rejected our key material: {0}")]
    Key(String),
}

/// Sends WireGuard handshakes and times the responses.
#[derive(Clone)]
pub struct Prober {
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    settings: config::Probe,
    fwmark: Option<u32>,
    excluded: Option<SocketAddr>,
    index: Arc<AtomicU32>,
}

impl std::fmt::Debug for Prober {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key material.
        f.debug_struct("Prober")
            .field("settings", &self.settings)
            .field("fwmark", &self.fwmark)
            .field("excluded", &self.excluded)
            .finish_non_exhaustive()
    }
}

impl Prober {
    pub fn new(client: &ClientConfig, settings: config::Probe) -> Self {
        Self {
            private_key: *client.private_key.expose(),
            peer_public_key: *client.peer_public_key.as_bytes(),
            preshared_key: client.preshared_key.as_ref().map(|k| *k.expose()),
            settings,
            fwmark: None,
            excluded: None,
            index: Arc::new(AtomicU32::new(1)),
        }
    }

    /// Route probes around an active tunnel using WireGuard's fwmark.
    ///
    /// Without this, probes sent while connected travel *through* the tunnel
    /// and measure the wrong path entirely.
    pub fn with_fwmark(mut self, fwmark: u32) -> Self {
        self.fwmark = Some(fwmark);
        self
    }

    /// Refuse to probe `endpoint`, which must be the currently connected
    /// server. Probing it would roam the server's peer entry onto the probe
    /// socket and break the live tunnel.
    pub fn excluding(mut self, endpoint: SocketAddr) -> Self {
        self.excluded = Some(endpoint);
        self
    }

    /// Probe one server, taking `settings.samples` measurements.
    pub async fn probe(&self, endpoint: SocketAddr) -> ProbeResult {
        if self.excluded == Some(endpoint) {
            return ProbeResult {
                endpoint,
                rtt: None,
                samples: Vec::new(),
                outcome: Outcome::SkippedConnected,
            };
        }

        let mut samples = Vec::with_capacity(self.settings.samples);
        let mut outcome = Outcome::Unreachable;

        for i in 0..self.settings.samples {
            if i > 0 {
                tokio::time::sleep(SAMPLE_GAP).await;
            }
            match self.one_handshake(endpoint).await {
                Ok((rtt, o)) => {
                    samples.push(rtt);
                    // A later cookie reply shouldn't downgrade an earlier
                    // clean handshake.
                    if outcome != Outcome::Reachable {
                        outcome = o;
                    }
                }
                Err(o) => {
                    if samples.is_empty() {
                        outcome = o;
                    }
                }
            }
        }

        ProbeResult {
            endpoint,
            rtt: median(&samples),
            samples,
            outcome,
        }
    }

    /// Probe every endpoint, at most `settings.concurrency` at a time.
    ///
    /// Results come back in input order. The excluded endpoint is reported as
    /// [`Outcome::SkippedConnected`] rather than silently dropped, so callers
    /// can see it was considered.
    pub async fn probe_many(&self, endpoints: &[SocketAddr]) -> Vec<ProbeResult> {
        let permits = Arc::new(Semaphore::new(self.settings.concurrency));
        let mut handles = Vec::with_capacity(endpoints.len());

        for &endpoint in endpoints {
            let permits = Arc::clone(&permits);
            let prober = self.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permits
                    .acquire()
                    .await
                    .expect("semaphore is never closed while probes are in flight");
                prober.probe(endpoint).await
            }));
        }

        let mut out = Vec::with_capacity(handles.len());
        for (handle, &endpoint) in handles.into_iter().zip(endpoints) {
            out.push(handle.await.unwrap_or_else(|e| ProbeResult {
                endpoint,
                rtt: None,
                samples: Vec::new(),
                outcome: Outcome::Failed(format!("probe task panicked: {e}")),
            }));
        }
        out
    }

    /// One handshake. `Ok` carries the RTT, `Err` an outcome describing why
    /// no timing was obtained.
    async fn one_handshake(
        &self,
        endpoint: SocketAddr,
    ) -> Result<(Duration, Outcome), Outcome> {
        let socket = socket::bind_for(endpoint, self.fwmark)
            .map_err(|e| Outcome::Failed(e.to_string()))?;

        let index = self.index.fetch_add(1, Ordering::Relaxed);
        let mut tunn = Tunn::new(
            StaticSecret::from(self.private_key),
            PublicKey::from(self.peer_public_key),
            self.preshared_key,
            None,
            index,
            None,
        );

        // A handshake initiation is 148 bytes; the buffer is generous.
        let mut out = [0u8; 256];
        let initiation = match tunn.format_handshake_initiation(&mut out, true) {
            TunnResult::WriteToNetwork(packet) => packet,
            TunnResult::Err(e) => {
                return Err(Outcome::Rejected(format!("{e:?}")));
            }
            other => {
                return Err(Outcome::Failed(format!(
                    "expected a handshake initiation, got {}",
                    describe(&other)
                )));
            }
        };

        let started = Instant::now();
        socket
            .send_to(initiation, endpoint)
            .await
            .map_err(|e| Outcome::Failed(e.to_string()))?;

        let mut buf = [0u8; 1500];
        let received = tokio::time::timeout(self.settings.timeout(), socket.recv(&mut buf)).await;

        let n = match received {
            Err(_elapsed) => return Err(Outcome::Unreachable),
            Ok(Err(e)) => return Err(Outcome::Failed(e.to_string())),
            Ok(Ok(n)) => n,
        };
        let rtt = started.elapsed();

        if n == 0 {
            return Err(Outcome::Failed("empty datagram".into()));
        }

        match buf[0] {
            MSG_COOKIE_REPLY => {
                // The server is up but shedding load. Still a valid RTT.
                Ok((rtt, Outcome::RateLimited))
            }
            MSG_HANDSHAKE_RESPONSE => {
                // Verify cryptographically, which is what distinguishes
                // "something answered" from "our credentials work".
                let mut scratch = [0u8; 1500];
                match tunn.decapsulate(None, &buf[..n], &mut scratch) {
                    // Completing the handshake yields a keepalive to send. We
                    // deliberately drop it: the measurement is done and the
                    // session is left to expire.
                    TunnResult::WriteToNetwork(_) | TunnResult::Done => {
                        Ok((rtt, Outcome::Reachable))
                    }
                    TunnResult::Err(e) => Err(Outcome::Rejected(format!("{e:?}"))),
                    other => Err(Outcome::Failed(format!(
                        "unexpected handshake result: {}",
                        describe(&other)
                    ))),
                }
            }
            other => Err(Outcome::Failed(format!(
                "unexpected WireGuard message type {other}"
            ))),
        }
    }
}

fn describe(result: &TunnResult<'_>) -> &'static str {
    match result {
        TunnResult::Done => "done",
        TunnResult::Err(_) => "error",
        TunnResult::WriteToNetwork(_) => "write-to-network",
        TunnResult::WriteToTunnelV4(_, _) => "write-to-tunnel-v4",
        TunnResult::WriteToTunnelV6(_, _) => "write-to-tunnel-v6",
    }
}

/// Median of the samples. Even-sized sets take the lower middle, which biases
/// very slightly optimistic and keeps the result an actually-observed value.
fn median(samples: &[Duration]) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    Some(sorted[(sorted.len() - 1) / 2])
}

/// Probe every WireGuard entry of every server and keep the fastest per server.
///
/// AirVPN exposes two WireGuard entry addresses per server and they can differ
/// by tens of milliseconds, so the entry is treated as another dimension to
/// optimise. A server whose entries all fail is returned with `rtt: None` and
/// is dropped by [`vpnmgr_core::score::rank`].
pub async fn sweep<'a>(
    prober: &Prober,
    servers: &[&'a vpnmgr_core::airvpn::Server],
    entries: &[u8],
    port: u16,
) -> Vec<vpnmgr_core::Measured<'a>> {
    // Flatten to one probe per (server, entry), remembering which server each
    // belongs to so results can be regrouped afterwards.
    let mut owners = Vec::new();
    let mut endpoints = Vec::new();
    for (index, server) in servers.iter().enumerate() {
        for (entry, endpoint) in server.wg_endpoints(entries, port) {
            owners.push((index, entry));
            endpoints.push(endpoint);
        }
    }

    let results = prober.probe_many(&endpoints).await;

    // Best usable timing per server.
    let mut best: Vec<Option<(u8, SocketAddr, Duration)>> = vec![None; servers.len()];
    for ((index, entry), result) in owners.into_iter().zip(&results) {
        let Some(rtt) = result.rtt.filter(|_| result.outcome.is_usable()) else {
            continue;
        };
        let candidate = (entry, result.endpoint, rtt);
        match &best[index] {
            Some((_, _, current)) if *current <= rtt => {}
            _ => best[index] = Some(candidate),
        }
    }

    servers
        .iter()
        .zip(best)
        .map(|(server, best)| match best {
            Some((entry, endpoint, rtt)) => vpnmgr_core::Measured {
                server,
                endpoint,
                entry,
                rtt: Some(rtt),
            },
            // No entry answered. Keep a placeholder endpoint so the type stays
            // simple; rank() discards it because rtt is None.
            None => vpnmgr_core::Measured {
                server,
                endpoint: server.wg_endpoint(port),
                entry: entries.first().copied().unwrap_or(1),
                rtt: None,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpnmgr_core::airvpn::{self, ServerList};

    const SAMPLE_CONF: &str = include_str!(
        "../../vpnmgr-core/tests/fixtures/airvpn_sample.conf"
    );
    const STATUS: &str = include_str!(
        "../../vpnmgr-core/tests/fixtures/airvpn_status.json"
    );

    fn client() -> ClientConfig {
        ClientConfig::parse(SAMPLE_CONF, "sample.conf").unwrap()
    }

    fn fast_settings() -> config::Probe {
        config::Probe {
            concurrency: 8,
            timeout_ms: 150,
            samples: 1,
        }
    }

    fn prober() -> Prober {
        Prober::new(&client(), fast_settings())
    }

    #[test]
    fn median_of_one_sample_is_that_sample() {
        assert_eq!(median(&[Duration::from_millis(7)]), Some(Duration::from_millis(7)));
    }

    #[test]
    fn median_ignores_sample_order() {
        let ms = |n| Duration::from_millis(n);
        let ascending = [ms(10), ms(20), ms(90)];
        let shuffled = [ms(90), ms(10), ms(20)];
        assert_eq!(median(&ascending), median(&shuffled));
        assert_eq!(median(&ascending), Some(ms(20)));
    }

    #[test]
    fn median_discards_a_single_outlier() {
        let ms = |n| Duration::from_millis(n);
        // The point of sampling: one slow handshake must not pick the server.
        assert_eq!(median(&[ms(12), ms(13), ms(800)]), Some(ms(13)));
    }

    #[test]
    fn median_of_nothing_is_none() {
        assert_eq!(median(&[]), None);
    }

    #[test]
    fn debug_output_never_reveals_key_material() {
        let rendered = format!("{:?}", prober());
        assert!(!rendered.contains("SPrivate"), "{rendered}");
        assert!(!rendered.contains("private_key"), "{rendered}");
    }

    #[tokio::test]
    async fn an_unroutable_endpoint_times_out_cleanly() {
        // 198.51.100.0/24 is TEST-NET-2 and is guaranteed not to answer.
        let result = prober().probe("198.51.100.1:1637".parse().unwrap()).await;
        assert_eq!(result.outcome, Outcome::Unreachable);
        assert!(result.rtt.is_none());
        assert!(result.samples.is_empty());
    }

    #[tokio::test]
    async fn a_silent_local_socket_times_out_rather_than_hanging() {
        // Bind a socket that receives the initiation and never replies.
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sink.local_addr().unwrap();

        let started = Instant::now();
        let result = prober().probe(addr).await;
        assert_eq!(result.outcome, Outcome::Unreachable);
        // Must respect the configured timeout rather than blocking.
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_garbage_reply_is_reported_as_a_bad_message_type() {
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sink.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            if let Ok((_, peer)) = sink.recv_from(&mut buf).await {
                // Message type 9 is not a WireGuard message.
                let _ = sink.send_to(&[9, 0, 0, 0], peer).await;
            }
        });

        let result = prober().probe(addr).await;
        assert!(
            matches!(&result.outcome, Outcome::Failed(m) if m.contains("message type 9")),
            "{:?}",
            result.outcome
        );
    }

    #[tokio::test]
    async fn a_cookie_reply_still_yields_a_usable_timing() {
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sink.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            if let Ok((_, peer)) = sink.recv_from(&mut buf).await {
                let mut cookie = [0u8; 64];
                cookie[0] = MSG_COOKIE_REPLY;
                let _ = sink.send_to(&cookie, peer).await;
            }
        });

        let result = prober().probe(addr).await;
        assert_eq!(result.outcome, Outcome::RateLimited);
        assert!(result.outcome.is_usable());
        assert!(result.rtt.is_some());
    }

    #[tokio::test]
    async fn the_connected_server_is_never_probed() {
        let connected: SocketAddr = "198.51.100.7:1637".parse().unwrap();
        let result = prober().excluding(connected).probe(connected).await;
        // Not merely skipped in ranking — no packet may be sent at all.
        assert_eq!(result.outcome, Outcome::SkippedConnected);
        assert!(!result.outcome.is_usable());
    }

    #[tokio::test]
    async fn exclusion_applies_within_a_bulk_sweep() {
        let connected: SocketAddr = "198.51.100.7:1637".parse().unwrap();
        let others: Vec<SocketAddr> = vec![
            "198.51.100.5:1637".parse().unwrap(),
            connected,
            "198.51.100.6:1637".parse().unwrap(),
        ];
        let results = prober().excluding(connected).probe_many(&others).await;

        assert_eq!(results.len(), 3);
        // Order is preserved so callers can zip against their input.
        assert_eq!(results[1].endpoint, connected);
        assert_eq!(results[1].outcome, Outcome::SkippedConnected);
        assert_eq!(results[0].outcome, Outcome::Unreachable);
        assert_eq!(results[2].outcome, Outcome::Unreachable);
    }

    #[tokio::test]
    async fn a_bulk_sweep_returns_one_result_per_endpoint_in_order() {
        let endpoints: Vec<SocketAddr> = (1..=12)
            .map(|i| format!("198.51.100.{i}:1637").parse().unwrap())
            .collect();
        let results = prober().probe_many(&endpoints).await;
        assert_eq!(results.len(), endpoints.len());
        for (r, e) in results.iter().zip(&endpoints) {
            assert_eq!(r.endpoint, *e);
        }
    }

    #[tokio::test]
    async fn concurrency_makes_a_sweep_far_faster_than_running_serially() {
        let endpoints: Vec<SocketAddr> = (1..=16)
            .map(|i| format!("198.51.100.{i}:1637").parse().unwrap())
            .collect();
        let started = Instant::now();
        prober().probe_many(&endpoints).await;
        let elapsed = started.elapsed();
        // 16 endpoints x 150ms serially would be 2.4s; at concurrency 8 this
        // should take roughly two rounds.
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
    }

    #[test]
    fn a_measurement_that_did_not_verify_is_not_ranked() {
        // rank() must ignore a stray timing attached to an unusable outcome,
        // or a server with bad credentials could win on a fast rejection.
        let list = ServerList::from_json(STATUS).unwrap();
        let servers: Vec<_> = list.healthy().take(2).collect();
        let measured = vec![
            vpnmgr_core::Measured {
                server: servers[0],
                endpoint: servers[0].wg_endpoint(airvpn::WG_PORT),
                entry: 1,
                rtt: Some(Duration::from_millis(20)),
            },
            vpnmgr_core::Measured {
                server: servers[1],
                endpoint: servers[1].wg_endpoint(airvpn::WG_PORT),
                entry: 1,
                rtt: None,
            },
        ];
        let ranked = vpnmgr_core::score::rank(&measured, &config::Weights::default());
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].server.name, servers[0].name);
    }

    #[tokio::test]
    async fn a_sweep_returns_one_entry_per_server_even_when_all_entries_fail() {
        let list = ServerList::from_json(STATUS).unwrap();
        let servers: Vec<_> = list.healthy().take(3).collect();

        // Real AirVPN addresses, but with a port nothing listens on, so every
        // entry times out.
        let measured = sweep(&prober(), &servers, &airvpn::WG_ENTRIES, 9).await;

        assert_eq!(measured.len(), servers.len(), "one result per server");
        assert!(measured.iter().all(|m| m.rtt.is_none()));
        // An endpoint is still populated so callers never see a hole.
        assert!(measured.iter().all(|m| m.endpoint.port() == 9));
        assert!(vpnmgr_core::score::rank(&measured, &config::Weights::default()).is_empty());
    }

    #[test]
    fn servers_expose_both_wireguard_entries() {
        let list = ServerList::from_json(STATUS).unwrap();
        let server = list.healthy().next().unwrap();
        let endpoints = server.wg_endpoints(&airvpn::WG_ENTRIES, airvpn::WG_PORT);
        // Entries 1 and 3 answer WireGuard; 2 and 4 are OpenVPN-only.
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].0, 1);
        assert_eq!(endpoints[1].0, 3);
        assert_ne!(endpoints[0].1.ip(), endpoints[1].1.ip());
    }
}
