//! Daemon state and the operations clients can drive.
//!
//! All privileged work happens here. The socket layer is only responsible for
//! framing and for handing requests over.

use std::time::{Duration, Instant, SystemTime};

use vpnmgr_core::airvpn::{self, Server, ServerList};
use vpnmgr_core::config::Config;
use vpnmgr_core::{ClientConfig, filter, score};
use vpnmgr_ipc::{PendingSwitch, RankedServer, ServerSummary, StatusReport, SweepSummary, TuneReport};
use vpnmgr_probe::{Prober, sweep};
use vpnmgr_tunnel::{DEFAULT_FWMARK, LinuxTunnel, TunnelBackend, TunnelSpec};

use crate::tuner::{self, Assessment, Decision};

/// How long the AirVPN server list is reused before refetching. Load figures
/// move on the order of minutes, and this keeps a burst of CLI calls from
/// hammering the API.
const SERVER_CACHE_TTL: Duration = Duration::from_secs(300);

/// A handshake older than this means traffic is not flowing. WireGuard rekeys
/// roughly every two minutes, so three gives margin without being lax.
const MAX_HANDSHAKE_AGE: Duration = Duration::from_secs(360);

/// How long a dismissed proposal stays dismissed.
///
/// Turning down a switch is a statement about preference, not a one-off, so
/// re-asking on the next 30-minute cycle would be nagging. Four hours is long
/// enough to stop that while still letting the tuner revisit the question
/// within a working day.
const DISMISSAL_COOLDOWN: Duration = Duration::from_secs(4 * 60 * 60);

/// What the daemon is currently connected to.
#[derive(Debug, Clone)]
pub struct Connection {
    pub server: String,
    pub location: String,
    pub country_code: String,
    pub endpoint: std::net::SocketAddr,
    pub entry: u8,
}

pub struct State {
    config: Config,
    config_path: std::path::PathBuf,
    client: ClientConfig,
    servers: Option<(ServerList, Instant)>,
    tunnel: Option<LinuxTunnel>,
    current: Option<Connection>,
    last_sweep: Option<(SweepSummary, Instant)>,
    /// Ranking from the most recent sweep, latency-ordered. Served to clients
    /// that want good servers cheaply, without paying for a fresh sweep.
    last_ranking: Vec<RankedServer>,
    /// A switch awaiting approval under `switch_policy = "ask"`.
    pending: Option<(RankedServer, String, Instant)>,
    /// The server the user was on when they last turned down a proposal, and
    /// when. Kept so the tuner does not re-raise the suggestion every cycle.
    dismissed: Option<(String, Instant)>,
    /// Outcome of the most recent tuning pass, for `vpnmgr status`.
    last_tune: Option<String>,
    /// When the last pass ran; the schedule is measured from here so a manual
    /// `vpnmgr autotune` postpones the next automatic one rather than being
    /// followed by a redundant sweep.
    last_tune_at: Option<Instant>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] vpnmgr_core::Error),
    #[error(transparent)]
    Tunnel(#[from] vpnmgr_tunnel::Error),
    #[error("not connected")]
    NotConnected,
    #[error("already connected to {0}; disconnect first or use switch")]
    AlreadyConnected(String),
    #[error("no server named {0:?}; try `vpnmgr servers` to see the list")]
    UnknownServer(String),
    #[error(
        "{server} did not answer a handshake on any of its entry addresses; \
         it may be down even though the API reports it healthy"
    )]
    ServerUnreachable { server: String },
    #[error(
        "every one of the {probed} probed servers was unreachable. \
         That means either this machine has no working internet connection, \
         or the credentials in the config are no longer accepted by AirVPN \
         (a wrong peer key produces silence, not an error). \
         Check connectivity first, then re-import the config."
    )]
    AllUnreachable { probed: usize },
    #[error("no servers match the configured filters: {0}")]
    NoCandidates(String),
    #[error("nothing is waiting for approval")]
    NoPendingSwitch,
}

pub type Result<T> = std::result::Result<T, Error>;

impl State {
    pub fn load(config_path: std::path::PathBuf) -> Result<Self> {
        let config = Config::load(&config_path)?;
        let client = config.load_client_config()?;
        Ok(Self {
            config,
            config_path,
            client,
            servers: None,
            tunnel: None,
            current: None,
            last_sweep: None,
            last_ranking: Vec::new(),
            pending: None,
            dismissed: None,
            last_tune: None,
            last_tune_at: None,
        })
    }

    pub fn reload(&mut self) -> Result<()> {
        let config = Config::load(&self.config_path)?;
        let client = config.load_client_config()?;
        self.config = config;
        self.client = client;
        // Force a refetch so new filters are applied to fresh data.
        self.servers = None;
        Ok(())
    }

    /// The AirVPN server list, refetched when the cache has expired.
    ///
    /// A failed refetch falls back to the stale copy rather than failing the
    /// caller. The list is mostly static — which servers exist, and roughly how
    /// loaded they are — while the numbers that actually drive a switch come
    /// from probing, not from the API. Letting a transient API error take the
    /// tuner offline would be a far worse trade, and the request is retried on
    /// the next call because the cache timestamp is left untouched.
    async fn server_list(&mut self) -> Result<&ServerList> {
        let stale = self
            .servers
            .as_ref()
            .is_none_or(|(_, at)| at.elapsed() > SERVER_CACHE_TTL);

        if stale {
            match airvpn::Client::new()?.fetch().await {
                Ok(list) => self.servers = Some((list, Instant::now())),
                Err(e) => match &self.servers {
                    Some((_, at)) => tracing::warn!(
                        "could not refresh the AirVPN server list ({e}); \
                         continuing with the copy cached {}s ago",
                        at.elapsed().as_secs()
                    ),
                    // Nothing cached, so there is genuinely nothing to work with.
                    None => return Err(e.into()),
                },
            }
        }

        Ok(&self.servers.as_ref().expect("cached or just fetched").0)
    }

    /// A prober configured for the current connection state.
    ///
    /// Two things matter here. The fwmark keeps probes on the physical path
    /// while a tunnel is up, and excluding the connected endpoint prevents the
    /// server from roaming our peer onto the probe socket and black-holing the
    /// live tunnel.
    fn prober(&self) -> Prober {
        let mut prober = Prober::new(&self.client, self.config.probe.clone());
        if let Some(current) = &self.current {
            prober = prober.with_fwmark(DEFAULT_FWMARK).excluding(current.endpoint);
        }
        prober
    }

    /// Filter, probe and rank. The measurement path shared by connect and test.
    pub async fn sweep(&mut self, country: Option<String>) -> Result<Vec<RankedServer>> {
        let probe_settings = self.config.probe.clone();
        let weights = self.config.autotune.weights;
        let mut filters = self.config.filters.clone();
        if let Some(country) = country {
            filters.country_whitelist = vec![country];
        }
        let entries = airvpn::WG_ENTRIES;
        let port = self.config.provider.airvpn.port;
        let prober = self.prober();

        // Take owned copies of the candidates so the borrow of `self` ends
        // here; the sweep result is recorded on `self` further down.
        let candidates: Vec<Server> = {
            let list = self.server_list().await?;
            let selection = filter::apply(list, &filters);
            if selection.is_empty() {
                let summary = selection
                    .rejection_summary()
                    .into_iter()
                    .map(|(reason, count)| format!("{count} {reason}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::NoCandidates(summary));
            }
            selection.accepted.into_iter().cloned().collect()
        };
        let refs: Vec<&Server> = candidates.iter().collect();

        let started = Instant::now();
        let measured = sweep(&prober, &refs, &entries, port).await;
        let elapsed = started.elapsed();

        let probed = measured.len();
        let reachable = measured.iter().filter(|m| m.rtt.is_some()).count();
        let ranked = score::rank(&measured, &weights);

        let best = ranked.first().map(to_ranked);
        // Distinguishing "nothing reachable" from "nothing good" matters: the
        // former is never a reason to switch servers.
        let all_unreachable = reachable == 0;
        self.last_sweep = Some((
            SweepSummary {
                probed,
                reachable,
                elapsed_ms: elapsed.as_millis() as u64,
                age_secs: 0,
                best: best.clone(),
                all_unreachable,
            },
            Instant::now(),
        ));

        if all_unreachable {
            return Err(Error::AllUnreachable { probed });
        }

        let _ = probe_settings;
        let ranking: Vec<RankedServer> = ranked.iter().map(to_ranked).collect();
        self.last_ranking = ranking.clone();
        Ok(ranking)
    }

    pub async fn connect(&mut self, server: Option<String>) -> Result<RankedServer> {
        if let Some(current) = &self.current {
            return Err(Error::AlreadyConnected(current.server.clone()));
        }

        let chosen = match server {
            Some(name) => self.probe_named(&name).await?,
            None => self
                .sweep(None)
                .await?
                .into_iter()
                .next()
                .ok_or(Error::AllUnreachable { probed: 0 })?,
        };

        let spec = TunnelSpec::new(&self.client, chosen.endpoint)
            .with_interface(vpnmgr_tunnel::DEFAULT_INTERFACE)
            .with_fwmark(DEFAULT_FWMARK);

        let mut tunnel = LinuxTunnel::new(vpnmgr_tunnel::DEFAULT_INTERFACE)?;
        tunnel.up(&spec)?;

        self.tunnel = Some(tunnel);
        self.current = Some(Connection {
            server: chosen.name.clone(),
            location: chosen.location.clone(),
            country_code: chosen.country_code.clone(),
            endpoint: chosen.endpoint,
            entry: chosen.entry,
        });
        tracing::info!(server = %chosen.name, endpoint = %chosen.endpoint, "connected");
        Ok(chosen)
    }

    /// Probe one named server's entries and return the faster.
    async fn probe_named(&mut self, name: &str) -> Result<RankedServer> {
        let entries = airvpn::WG_ENTRIES;
        let port = self.config.provider.airvpn.port;
        let weights = self.config.autotune.weights;
        let prober = self.prober();

        let list = self.server_list().await?;
        let server = list
            .get(name)
            .ok_or_else(|| Error::UnknownServer(name.to_owned()))?;

        let measured = sweep(&prober, &[server], &entries, port).await;
        let ranked = score::rank(&measured, &weights);
        ranked
            .first()
            .map(to_ranked)
            .ok_or_else(|| Error::ServerUnreachable {
                server: name.to_owned(),
            })
    }

    pub async fn switch(&mut self, name: &str) -> Result<RankedServer> {
        if self.current.is_none() {
            return Err(Error::NotConnected);
        }
        let chosen = self.probe_named(name).await?;

        let spec = TunnelSpec::new(&self.client, chosen.endpoint)
            .with_interface(vpnmgr_tunnel::DEFAULT_INTERFACE)
            .with_fwmark(DEFAULT_FWMARK);

        let tunnel = self.tunnel.as_mut().ok_or(Error::NotConnected)?;
        tunnel.switch_endpoint(&spec)?;

        // Any deliberate move supersedes an earlier refusal: whatever the user
        // was declining, it is no longer the situation they are in.
        self.dismissed = None;

        self.current = Some(Connection {
            server: chosen.name.clone(),
            location: chosen.location.clone(),
            country_code: chosen.country_code.clone(),
            endpoint: chosen.endpoint,
            entry: chosen.entry,
        });
        tracing::info!(server = %chosen.name, "switched");
        Ok(chosen)
    }

    pub fn disconnect(&mut self) -> Result<()> {
        let mut tunnel = self.tunnel.take().ok_or(Error::NotConnected)?;
        let result = tunnel.down();
        // Drop the connection record regardless: if teardown failed, the state
        // is unknown, and claiming to still be connected would be worse.
        self.current = None;
        drop(tunnel);
        result?;
        tracing::info!("disconnected");
        Ok(())
    }

    pub fn status(&self) -> StatusReport {
        let interface = vpnmgr_tunnel::DEFAULT_INTERFACE.to_owned();
        let last_sweep = self.last_sweep.as_ref().map(|(summary, at)| {
            let mut summary = summary.clone();
            summary.age_secs = at.elapsed().as_secs();
            summary
        });

        let Some(current) = &self.current else {
            return StatusReport {
                connected: false,
                interface,
                server: None,
                location: None,
                country_code: None,
                endpoint: None,
                entry: None,
                last_handshake_secs: None,
                healthy: false,
                tx_bytes: 0,
                rx_bytes: 0,
                last_sweep,
                pending_switch: self.pending_switch(),
                last_tune: self.last_tune.clone(),
                next_tune_secs: Some(self.time_until_next_tune().as_secs()),
            };
        };

        let live = self.tunnel.as_ref().and_then(|t| t.status().ok());
        let now = SystemTime::now();
        let last_handshake_secs = live.as_ref().and_then(|s| {
            s.last_handshake
                .and_then(|at| now.duration_since(at).ok())
                .map(|d| d.as_secs())
        });

        StatusReport {
            connected: true,
            interface,
            server: Some(current.server.clone()),
            location: Some(current.location.clone()),
            country_code: Some(current.country_code.clone()),
            // Prefer what the kernel reports over what we believe.
            endpoint: live
                .as_ref()
                .and_then(|s| s.endpoint)
                .or(Some(current.endpoint)),
            entry: Some(current.entry),
            last_handshake_secs,
            healthy: live
                .as_ref()
                .is_some_and(|s| s.is_healthy(now, MAX_HANDSHAKE_AGE)),
            tx_bytes: live.as_ref().map(|s| s.tx_bytes).unwrap_or(0),
            rx_bytes: live.as_ref().map(|s| s.rx_bytes).unwrap_or(0),
            last_sweep,
            pending_switch: self.pending_switch(),
            last_tune: self.last_tune.clone(),
            next_tune_secs: Some(self.time_until_next_tune().as_secs()),
        }
    }

    pub async fn servers(
        &mut self,
        country: Option<String>,
        limit: Option<usize>,
    ) -> Result<Vec<ServerSummary>> {
        let list = self.server_list().await?;
        let wanted = country.map(|c| c.trim().to_ascii_lowercase());
        let mut out: Vec<ServerSummary> = list
            .servers
            .iter()
            .filter(|s| {
                wanted
                    .as_ref()
                    .is_none_or(|c| s.country_code.eq_ignore_ascii_case(c))
            })
            .map(|s| ServerSummary {
                name: s.name.clone(),
                country_code: s.country_code.clone(),
                country_name: s.country_name.clone(),
                location: s.location.clone(),
                load: s.load,
                users: s.users,
                healthy: s.is_healthy(),
            })
            .collect();
        out.sort_by(|a, b| a.load.cmp(&b.load).then_with(|| a.name.cmp(&b.name)));
        if let Some(limit) = limit {
            out.truncate(limit);
        }
        Ok(out)
    }

    /// The cached ranking from the last sweep, best first.
    pub fn last_ranking(&self, limit: Option<usize>) -> Vec<RankedServer> {
        let mut out = self.last_ranking.clone();
        if let Some(limit) = limit {
            out.truncate(limit);
        }
        out
    }

    pub fn is_connected(&self) -> bool {
        self.current.is_some()
    }

    // ---- auto-tuning ----------------------------------------------------

    pub fn tune_interval_minutes(&self) -> u64 {
        self.config.autotune.interval_minutes
    }

    /// How long until the next scheduled pass. Zero when one is due.
    pub fn time_until_next_tune(&self) -> Duration {
        let interval = self.config.autotune.interval();
        match self.last_tune_at {
            // Stagger the first pass rather than sweeping the moment the
            // daemon starts, which would collide with boot-time network churn.
            None => interval.min(Duration::from_secs(60)),
            Some(at) => interval.saturating_sub(at.elapsed()),
        }
    }

    /// Measure the server we are connected to.
    ///
    /// Unlike the bulk sweep this does *not* exclude the connected endpoint.
    /// It has to not: a server that answers on only one entry address would
    /// otherwise measure as silent and be abandoned for no reason. Probing the
    /// live endpoint was verified not to disturb the tunnel — WireGuard
    /// updates a peer's endpoint from any authenticated packet, so the
    /// tunnel's own traffic (or its 15-second keepalive) immediately undoes
    /// any roaming a probe causes.
    async fn probe_current(&mut self, server_name: &str) -> Option<f64> {
        let entries = airvpn::WG_ENTRIES;
        let port = self.config.provider.airvpn.port;
        let prober = Prober::new(&self.client, self.config.probe.clone()).with_fwmark(DEFAULT_FWMARK);

        let list = self.server_list().await.ok()?;
        let server = list.get(server_name)?;
        let measured = sweep(&prober, &[server], &entries, port).await;
        measured
            .first()
            .and_then(|m| m.rtt)
            .map(|d| d.as_secs_f64() * 1000.0)
    }

    /// One tuning pass: check the current server, and only sweep if it is
    /// struggling. Applies the result according to `switch_policy`.
    pub async fn autotune(&mut self) -> Result<TuneReport> {
        self.last_tune_at = Some(Instant::now());

        let Some(current) = self.current.clone() else {
            return Ok(self.record(Decision::NotConnected));
        };

        // The cheap path, and the one taken almost every time: a single
        // server's worth of probes rather than the whole fleet's.
        let current_rtt = self.probe_current(&current.server).await;
        if let Some(rtt_ms) = current_rtt
            && rtt_ms <= f64::from(self.config.autotune.max_latency_ms)
        {
            return Ok(self.record(Decision::Healthy {
                server: current.server.clone(),
                rtt_ms,
            }));
        }

        tracing::info!(
            server = %current.server,
            rtt_ms = ?current_rtt,
            "current server is degraded; sweeping for alternatives"
        );

        let ranked = match self.sweep(None).await {
            Ok(ranked) => ranked,
            // Everything silent means the local link, not the server. Reported,
            // never acted on.
            Err(Error::AllUnreachable { probed }) => {
                return Ok(self.record(Decision::NothingReachable { probed }));
            }
            Err(e) => return Err(e),
        };

        let assessment = Assessment {
            current: Some(tuner::Current {
                name: current.server.clone(),
                rtt_ms: current_rtt,
                score: ranked
                    .iter()
                    .find(|r| r.name == current.server)
                    .map(|r| r.score),
            }),
            best: ranked.first().cloned(),
            probed: self
                .last_sweep
                .as_ref()
                .map(|(s, _)| s.probed)
                .unwrap_or(ranked.len()),
            declined_from: self.active_dismissal(),
        };

        let decision = tuner::decide(&assessment, &self.config.autotune);

        // Only `auto` moves the tunnel here; `ask` parks a proposal instead.
        if decision.is_actionable()
            && let Some(target) = decision.target().map(|t| t.name.clone())
        {
            self.switch(&target).await?;
        }

        Ok(self.record(decision))
    }

    /// Fold a decision into the daemon's state and render it for the client.
    fn record(&mut self, decision: Decision) -> TuneReport {
        let summary = decision.describe();
        let switched = decision.is_actionable();

        match &decision {
            Decision::Propose { to, reason } => {
                self.pending = Some((to.as_ref().clone(), reason.describe(), Instant::now()));
            }
            // Any other outcome makes a previous proposal stale: the situation
            // that motivated it no longer holds.
            _ => self.pending = None,
        }

        self.last_tune = Some(summary.clone());
        match &decision {
            Decision::Healthy { .. } | Decision::NotConnected => {
                tracing::debug!("{summary}")
            }
            _ => tracing::info!("{summary}"),
        }

        TuneReport {
            summary,
            switched,
            nothing_reachable: matches!(decision, Decision::NothingReachable { .. }),
            pending: self.pending_switch(),
        }
    }

    fn pending_switch(&self) -> Option<PendingSwitch> {
        self.pending.as_ref().map(|(to, reason, at)| PendingSwitch {
            to: to.clone(),
            reason: reason.clone(),
            age_secs: at.elapsed().as_secs(),
        })
    }

    /// Carry out the pending proposal.
    pub async fn approve(&mut self) -> Result<RankedServer> {
        let (target, _, _) = self.pending.take().ok_or(Error::NoPendingSwitch)?;
        let moved = self.switch(&target.name).await?;
        self.last_tune = Some(format!("switched to {} on approval", moved.name));
        Ok(moved)
    }

    /// The server under an unexpired dismissal, if any.
    fn active_dismissal(&self) -> Option<String> {
        self.dismissed
            .as_ref()
            .filter(|(_, at)| at.elapsed() < DISMISSAL_COOLDOWN)
            .map(|(name, _)| name.clone())
    }

    /// Drop the pending proposal without moving.
    pub fn dismiss(&mut self) -> Result<String> {
        let (target, _, _) = self.pending.take().ok_or(Error::NoPendingSwitch)?;
        // Record where the user chose to stay, not what they turned down: the
        // top candidate shifts between near-identical servers, so keying on the
        // target would let the same suggestion return under another name.
        if let Some(current) = &self.current {
            self.dismissed = Some((current.server.clone(), Instant::now()));
        }
        self.last_tune = Some(format!("dismissed the proposal to move to {}", target.name));
        Ok(target.name)
    }
}

fn to_ranked(s: &score::Scored<'_>) -> RankedServer {
    RankedServer {
        name: s.server.name.clone(),
        country_code: s.server.country_code.clone(),
        country_name: s.server.country_name.clone(),
        location: s.server.location.clone(),
        load: s.server.load,
        rtt_ms: s.rtt.as_secs_f64() * 1000.0,
        score: s.score,
        entry: s.entry,
        endpoint: s.endpoint,
    }
}
