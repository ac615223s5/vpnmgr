//! Daemon state and the operations clients can drive.
//!
//! All privileged work happens here. The socket layer is only responsible for
//! framing and for handing requests over.

use std::time::{Duration, Instant, SystemTime};

use vpnmgr_core::airvpn::{self, Server, ServerList};
use vpnmgr_core::config::Config;
use vpnmgr_core::{ClientConfig, filter, score};
use vpnmgr_ipc::{
    KillswitchReport, PendingSwitch, RankedServer, ServerSummary, SpeedReport, SpeedSample,
    StatusReport, SweepSummary, TuneReport,
};
use vpnmgr_probe::{Prober, sweep};
use vpnmgr_tunnel::{DEFAULT_FWMARK, Killswitch, LinuxTunnel, TunnelBackend, TunnelSpec};

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

/// How long to wait for a retargeted tunnel to complete a handshake before
/// giving up on a candidate. Generous, because a switch rotates the listen
/// port and the new server has to be found again.
const CANDIDATE_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// What the daemon is currently connected to.
#[derive(Debug, Clone)]
pub struct Connection {
    pub server: String,
    pub location: String,
    pub country_code: String,
    pub endpoint: std::net::SocketAddr,
    pub entry: u8,
}

impl From<&RankedServer> for Connection {
    fn from(s: &RankedServer) -> Self {
        Self {
            server: s.name.clone(),
            location: s.location.clone(),
            country_code: s.country_code.clone(),
            endpoint: s.endpoint,
            entry: s.entry,
        }
    }
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
    /// Throughput measured per server, keyed by name.
    ///
    /// Fills in as servers are actually used: a measurement costs tens of
    /// megabytes, so it only ever exists for servers the user has speed-tested
    /// while connected. Held in memory rather than persisted -- the daemon is
    /// long-lived, and a stale figure from before a restart would be worth less
    /// than the complexity of storing it.
    throughput_seen: std::collections::HashMap<String, (f64, Instant)>,
    /// What the connection itself managed with the tunnel down, and when.
    /// Anchors the capacity term to the user's real line rate instead of a
    /// guess. Timestamped because it is shown to the user, and a line rate
    /// measured hours ago is a much weaker claim than one from a minute ago.
    direct_mbps: Option<(f64, Instant)>,
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
    #[error("measuring throughput: {0}")]
    Throughput(#[from] vpnmgr_probe::throughput::Error),
    #[error(
        "this drops the tunnel, exposing your real IP address and releasing the \
         kill switch, so it needs explicit confirmation: pass --yes"
    )]
    ConsentRequired,
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
            throughput_seen: std::collections::HashMap::new(),
            direct_mbps: None,
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
        self.apply_filters_to_cached_results();
        Ok(())
    }

    /// Drop anything the newly-loaded filters no longer allow.
    ///
    /// The stored ranking and the pending proposal both outlive a reload, and
    /// both are offered to the user as things to connect to. Left alone they
    /// would keep offering servers the config has just excluded — for up to a
    /// full tuning interval, which reads as the filter being ignored.
    ///
    /// Measurements for surviving servers are kept: an RTT does not stop being
    /// true because the country list changed, and re-probing on every reload
    /// would make editing the config needlessly expensive.
    fn apply_filters_to_cached_results(&mut self) {
        let rules = filter::Ruleset::new(&self.config.filters);

        let before = self.last_ranking.len();
        self.last_ranking
            .retain(|s| rules.accepts(&s.name, &s.country_code, s.load));
        let dropped = before - self.last_ranking.len();
        if dropped > 0 {
            tracing::info!(
                "filters now exclude {dropped} of the {before} ranked servers; \
                 run `vpnmgr test` to rank the rest"
            );
        }

        if let Some((pending, _, _)) = &self.pending
            && !rules.accepts(&pending.name, &pending.country_code, pending.load)
        {
            tracing::info!(
                server = %pending.name,
                "dropping the pending proposal: the new filters exclude it"
            );
            self.pending = None;
        }
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

    /// Ranking inputs, including the capacity target derived from this
    /// machine's own measured throughput.
    fn scoring(&self) -> score::Scoring {
        score::Scoring::new(
            self.config.autotune.weights,
            self.config
                .autotune
                .headroom_target_mbps(self.direct_mbps()),
        )
    }

    /// The last measured line rate, without its timestamp.
    fn direct_mbps(&self) -> Option<f64> {
        self.direct_mbps.map(|(mbps, _)| mbps)
    }

    /// Record a line rate measured with the tunnel down.
    fn record_direct(&mut self, mbps: f64) {
        self.direct_mbps = Some((mbps, Instant::now()));
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
            prober = prober
                .with_fwmark(DEFAULT_FWMARK)
                .excluding(current.endpoint);
        }
        prober
    }

    /// Filter, probe and rank. The measurement path shared by connect and test.
    pub async fn sweep(&mut self, country: Option<String>) -> Result<Vec<RankedServer>> {
        let probe_settings = self.config.probe.clone();
        let scoring = self.scoring();
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
        let ranked = score::rank(&measured, &scoring);

        let best = ranked.first().map(|s| self.to_ranked(s));
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
        let ranking: Vec<RankedServer> = ranked.iter().map(|s| self.to_ranked(s)).collect();
        self.last_ranking = ranking.clone();
        Ok(ranking)
    }

    pub async fn connect(
        &mut self,
        server: Option<String>,
        measure: Option<bool>,
    ) -> Result<RankedServer> {
        if let Some(current) = &self.current {
            return Err(Error::AlreadyConnected(current.server.clone()));
        }

        // A named server is the user's decision, so it is taken at face value.
        // Only automatic selection second-guesses itself by measuring.
        let Some(name) = server else {
            return self.connect_best(measure).await;
        };

        let chosen = self.probe_named(&name).await?;
        self.establish(&chosen)?;
        Ok(chosen)
    }

    /// Bring the tunnel up on `chosen`.
    fn establish(&mut self, chosen: &RankedServer) -> Result<()> {
        let spec = TunnelSpec::new(&self.client, chosen.endpoint)
            .with_interface(vpnmgr_tunnel::DEFAULT_INTERFACE)
            .with_fwmark(DEFAULT_FWMARK);

        let mut tunnel = self.new_tunnel()?;
        tunnel.up(&spec)?;

        self.tunnel = Some(tunnel);
        self.current = Some(Connection::from(chosen));
        tracing::info!(server = %chosen.name, endpoint = %chosen.endpoint, "connected");
        Ok(())
    }

    /// Retarget an existing tunnel at `chosen`, without re-probing it.
    fn move_to(&mut self, chosen: &RankedServer) -> Result<()> {
        let spec = TunnelSpec::new(&self.client, chosen.endpoint)
            .with_interface(vpnmgr_tunnel::DEFAULT_INTERFACE)
            .with_fwmark(DEFAULT_FWMARK);

        let tunnel = self.tunnel.as_mut().ok_or(Error::NotConnected)?;
        tunnel.switch_endpoint(&spec)?;
        self.current = Some(Connection::from(chosen));
        Ok(())
    }

    /// Wait for a handshake newer than `since`, so a measurement is not taken
    /// against a tunnel that is not carrying traffic yet.
    ///
    /// A freshly retargeted tunnel needs a few seconds before data flows, and
    /// measuring inside that window reads as "this server is terrible" when it
    /// is really "this server has not answered yet".
    async fn wait_until_carrying(&self, since: SystemTime, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(tunnel) = &self.tunnel
                && let Ok(status) = tunnel.status()
                && status.last_handshake.is_some_and(|at| at > since)
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        false
    }

    /// Pick a server by measuring, not just by predicting.
    ///
    /// Ranking says which servers *should* be fast. This connects to the best
    /// few in turn and keeps the first that actually delivers `min_mbps`,
    /// because a server can be close, idle and still slow — and nothing short
    /// of routing traffic through it will reveal that.
    ///
    /// Stops at the first success, so the common case costs one measurement.
    /// If none clear the bar it settles on whichever measured fastest, which is
    /// still a better-informed choice than the top of the ranking.
    async fn connect_best(&mut self, measure_first: Option<bool>) -> Result<RankedServer> {
        let should_measure = measure_first.unwrap_or(self.config.autotune.measure_before_connect);

        // Measured first, while the tunnel is still down — which is precisely
        // what makes it a *direct* reading, and why it needs no consent the way
        // `baseline` does. It calibrates the bar the candidates are judged
        // against, so without it that bar is a guess about this machine.
        if should_measure {
            match self.measure_direct().await {
                Ok(mbps) => {
                    self.record_direct(mbps);
                    tracing::info!(
                        mbps = format!("{mbps:.1}"),
                        "measured this connection directly"
                    );
                }
                Err(e) => tracing::warn!(
                    "could not measure the connection before connecting ({e}); \
                     falling back to the configured target"
                ),
            }
        }

        let ranked = self.sweep(None).await?;
        let target = self.config.autotune.acceptance_mbps(self.direct_mbps());
        let attempts = if should_measure {
            self.config.autotune.verify_candidates.min(ranked.len())
        } else {
            // Not measuring the line and then measuring the candidates against
            // a guessed bar is the worst of both: slow and uncalibrated.
            0
        };

        let mut candidates = ranked.into_iter();
        let Some(first) = candidates.next() else {
            return Err(Error::AllUnreachable { probed: 0 });
        };

        // Verification turned off, or nothing to choose between: trust the rank.
        if attempts == 0 {
            self.establish(&first)?;
            return Ok(first);
        }

        let shortlist: Vec<RankedServer> = std::iter::once(first)
            .chain(candidates)
            .take(attempts)
            .collect();

        let settings = vpnmgr_probe::throughput::Settings {
            url: self
                .config
                .throughput
                .request_url_for(self.config.throughput.select_bytes),
            bytes: self.config.throughput.select_bytes,
            timeout: Duration::from_secs(self.config.throughput.timeout_secs),
        };

        let mut best: Option<(RankedServer, f64)> = None;

        for (index, candidate) in shortlist.iter().enumerate() {
            let since = SystemTime::now();
            if index == 0 {
                self.establish(candidate)?;
            } else {
                self.move_to(candidate)?;
            }

            if !self
                .wait_until_carrying(since, CANDIDATE_READY_TIMEOUT)
                .await
            {
                tracing::warn!(
                    server = %candidate.name,
                    "no handshake after retargeting; skipping this candidate"
                );
                continue;
            }

            let sample = match measure(&settings).await {
                Ok(sample) => sample,
                Err(e) => {
                    tracing::warn!(server = %candidate.name, "could not measure: {e}");
                    continue;
                }
            };
            self.record_throughput(&candidate.name, sample.mbps);

            tracing::info!(
                server = %candidate.name,
                mbps = format!("{:.1}", sample.mbps),
                needs = format!("{target:.0}"),
                candidate = index + 1,
                of = shortlist.len(),
                "measured a candidate"
            );

            if sample.mbps >= target {
                let mut chosen = candidate.clone();
                chosen.mbps = Some(sample.mbps);
                chosen.mbps_age_secs = Some(0);
                tracing::info!(
                    server = %chosen.name,
                    "settled after {} of {} candidates",
                    index + 1,
                    shortlist.len()
                );
                return Ok(chosen);
            }

            if best.as_ref().is_none_or(|(_, mbps)| sample.mbps > *mbps) {
                best = Some((candidate.clone(), sample.mbps));
            }
        }

        // Nothing cleared the bar. Settle on the best measured rather than
        // leaving the user on whichever candidate happened to be tried last.
        match best {
            Some((server, mbps)) => {
                tracing::warn!(
                    "no candidate reached {target:.0} Mbps; settling on {} at {mbps:.1} Mbps",
                    server.name
                );
                if self
                    .current
                    .as_ref()
                    .is_none_or(|c| c.server != server.name)
                {
                    self.move_to(&server)?;
                }
                let mut chosen = server;
                chosen.mbps = Some(mbps);
                chosen.mbps_age_secs = Some(0);
                Ok(chosen)
            }
            // Every candidate failed to come up or measure; the tunnel is
            // pointed at the last one tried, which is the best we can say.
            None => {
                let fallback = shortlist
                    .into_iter()
                    .next()
                    .expect("shortlist is non-empty");
                if self.current.is_none() {
                    self.establish(&fallback)?;
                }
                Ok(fallback)
            }
        }
    }

    /// Probe one named server's entries and return the faster.
    async fn probe_named(&mut self, name: &str) -> Result<RankedServer> {
        let entries = airvpn::WG_ENTRIES;
        let port = self.config.provider.airvpn.port;
        let scoring = self.scoring();
        let prober = self.prober();

        let list = self.server_list().await?;
        let server = list
            .get(name)
            .ok_or_else(|| Error::UnknownServer(name.to_owned()))?;

        let measured = sweep(&prober, &[server], &entries, port).await;
        let ranked = score::rank(&measured, &scoring);
        let chosen = ranked.first().map(|s| RankedServer {
            name: s.server.name.clone(),
            country_code: s.server.country_code.clone(),
            country_name: s.server.country_name.clone(),
            location: s.server.location.clone(),
            load: s.server.load,
            rtt_ms: s.rtt.as_secs_f64() * 1000.0,
            score: s.score,
            entry: s.entry,
            endpoint: s.endpoint,
            mbps: None,
            mbps_age_secs: None,
            headroom_mbps: s.server.headroom_mbps(),
        });
        let mut chosen = chosen.ok_or_else(|| Error::ServerUnreachable {
            server: name.to_owned(),
        })?;
        if let Some((mbps, at)) = self.throughput_seen.get(&chosen.name) {
            chosen.mbps = Some(*mbps);
            chosen.mbps_age_secs = Some(at.elapsed().as_secs());
        }
        Ok(chosen)
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
                baseline_mbps: self.direct_mbps(),
                baseline_age_secs: self.direct_mbps.map(|(_, at)| at.elapsed().as_secs()),
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
            baseline_mbps: self.direct_mbps(),
            baseline_age_secs: self.direct_mbps.map(|(_, at)| at.elapsed().as_secs()),
        }
    }

    /// Known servers, narrowed by the configured filters unless `all` is set.
    ///
    /// Filtered by default because the answer feeds the tray's quick-connect
    /// list, and offering a server the config excludes is a bug there. `all`
    /// exists for the browsing case — deciding what to put in a whitelist means
    /// seeing what you have not whitelisted yet.
    ///
    /// An explicit `country` replaces the country whitelist rather than
    /// intersecting with it, matching how `sweep` treats the same argument; the
    /// blacklists, `max_load` and the health check still apply.
    pub async fn servers(
        &mut self,
        country: Option<String>,
        limit: Option<usize>,
        all: bool,
    ) -> Result<Vec<ServerSummary>> {
        let mut filters = self.config.filters.clone();
        let wanted = country.map(|c| c.trim().to_ascii_lowercase());
        if let Some(country) = wanted.clone() {
            filters.country_whitelist = vec![country];
        }
        let rules = filter::Ruleset::new(&filters);

        let list = self.server_list().await?;
        let mut out: Vec<ServerSummary> = list
            .servers
            .iter()
            .filter(|s| {
                if all {
                    return wanted
                        .as_ref()
                        .is_none_or(|c| s.country_code.eq_ignore_ascii_case(c));
                }
                s.is_healthy() && rules.accepts(&s.name, &s.country_code, s.load)
            })
            .map(|s| ServerSummary {
                name: s.name.clone(),
                country_code: s.country_code.clone(),
                country_name: s.country_name.clone(),
                location: s.location.clone(),
                load: s.load,
                users: s.users,
                healthy: s.is_healthy(),
                headroom_mbps: s.headroom_mbps(),
            })
            .collect();
        out.sort_by(|a, b| a.load.cmp(&b.load).then_with(|| a.name.cmp(&b.name)));
        if let Some(limit) = limit {
            out.truncate(limit);
        }
        Ok(out)
    }

    /// A tunnel handle carrying the configured kill switch and bypass, if any.
    ///
    /// The bypass is planned here rather than once at startup because it
    /// depends on what the machine looks like *now*: which VPNs are running,
    /// what the default gateway is, and what the configured hostnames currently
    /// resolve to.
    fn new_tunnel(&self) -> Result<LinuxTunnel> {
        let mut tunnel = LinuxTunnel::new(vpnmgr_tunnel::DEFAULT_INTERFACE)?;

        let plan = vpnmgr_tunnel::Bypass::plan(
            &self.config.bypass.cidrs,
            &self.config.bypass.hosts,
            self.config.bypass.other_vpns,
            vpnmgr_tunnel::DEFAULT_INTERFACE,
        );
        if !plan.is_empty() {
            tracing::info!(
                destinations = plan.len(),
                "routing some destinations around the tunnel"
            );
            tunnel = tunnel.with_bypass(plan);
        }

        if self.config.killswitch.enabled {
            tunnel = tunnel.with_killswitch(Killswitch::new(
                vpnmgr_tunnel::DEFAULT_INTERFACE,
                DEFAULT_FWMARK,
                self.config.killswitch.allow_lan,
            ));
        }
        Ok(tunnel)
    }

    fn throughput_settings(&self) -> vpnmgr_probe::throughput::Settings {
        vpnmgr_probe::throughput::Settings {
            url: self.config.throughput.request_url(),
            bytes: self.config.throughput.bytes,
            timeout: Duration::from_secs(self.config.throughput.timeout_secs),
        }
    }

    /// Measure the connection itself, with no tunnel involved.
    ///
    /// Uses the short selection payload rather than the full one: this runs on
    /// every connect, and a rough figure is all the acceptance bar needs.
    async fn measure_direct(&self) -> Result<f64> {
        let settings = vpnmgr_probe::throughput::Settings {
            url: self
                .config
                .throughput
                .request_url_for(self.config.throughput.select_bytes),
            bytes: self.config.throughput.select_bytes,
            timeout: Duration::from_secs(self.config.throughput.timeout_secs),
        };
        Ok(measure(&settings).await?.mbps)
    }

    /// Measure throughput on whatever path is currently in use.
    pub async fn speedtest(&mut self) -> Result<SpeedReport> {
        let settings = self.throughput_settings();
        let min_mbps = self.config.autotune.min_mbps;
        let connected = self.current.as_ref().map(|c| c.server.clone());

        let sample = measure(&settings).await?;
        let meets_target = sample.mbps >= min_mbps;
        match &connected {
            Some(server) => self.record_throughput(server, sample.mbps),
            // With no tunnel up this measurement *is* the direct line rate —
            // the same thing `baseline` goes to the trouble of dropping the
            // tunnel to obtain. Recording it costs nothing and means a
            // speedtest run while disconnected calibrates the target instead
            // of being discarded.
            None => self.record_direct(sample.mbps),
        }

        let verdict = match &connected {
            Some(server) => format!(
                "{:.1} Mbps through {server} ({} the {:.0} Mbps target)",
                sample.mbps,
                if meets_target { "meets" } else { "below" },
                min_mbps
            ),
            None => format!(
                "{:.1} Mbps with no tunnel up; this is your direct connection",
                sample.mbps
            ),
        };

        Ok(SpeedReport {
            tunnelled: connected.is_some().then(|| sample.clone()),
            direct: connected.is_none().then_some(sample),
            server: connected,
            min_mbps,
            meets_target,
            verdict,
        })
    }

    /// Measure through the tunnel, then without it, then restore the tunnel.
    ///
    /// This is the "is it the VPN or my connection?" question answered
    /// directly. It is disruptive on purpose: the tunnel comes down, which
    /// exposes the real IP and releases the kill switch, so the caller has to
    /// have said yes explicitly.
    pub async fn baseline(&mut self) -> Result<SpeedReport> {
        let settings = self.throughput_settings();
        let min_mbps = self.config.autotune.min_mbps;

        let Some(current) = self.current.clone() else {
            // Nothing to compare against; this is just a direct measurement.
            return self.speedtest().await;
        };

        let tunnelled = measure(&settings).await?;
        self.record_throughput(&current.server, tunnelled.mbps);

        tracing::info!("dropping the tunnel for a direct measurement");
        self.disconnect()?;

        // Whatever happens to the direct measurement, the tunnel goes back up.
        let direct = measure(&settings).await;

        tracing::info!(server = %current.server, "restoring the tunnel");
        let restored = self
            .connect(Some(current.server.clone()), Some(false))
            .await;
        if let Err(e) = &restored {
            tracing::error!(
                server = %current.server,
                "could not restore the tunnel after the baseline: {e}"
            );
        }

        let direct = direct?;
        restored?;

        // The direct figure is this connection's own ceiling, so it anchors the
        // capacity term from here on unless the user set target_mbps explicitly.
        self.record_direct(direct.mbps);

        let meets_target = tunnelled.mbps >= min_mbps;
        // A ratio is what answers the question; absolute numbers on their own
        // do not say whether the VPN is the bottleneck.
        let retained = if direct.mbps > 0.0 {
            tunnelled.mbps / direct.mbps
        } else {
            0.0
        };
        let verdict = format!(
            "{:.1} Mbps through {} vs {:.1} Mbps direct — the tunnel keeps {:.0}% of \
             your connection. {}",
            tunnelled.mbps,
            current.server,
            direct.mbps,
            retained * 100.0,
            if retained >= 0.7 {
                "That is normal overhead; a slow link here is your connection, not the VPN."
            } else if direct.mbps < min_mbps {
                "Your connection itself is below the target, so no server can fix it."
            } else {
                "The VPN is costing you a lot; a different server may do better."
            }
        );

        Ok(SpeedReport {
            tunnelled: Some(tunnelled),
            direct: Some(direct),
            server: Some(current.server),
            min_mbps,
            meets_target,
            verdict,
        })
    }

    /// Turn the kill switch on or off at runtime, or just report on it.
    pub fn killswitch(&mut self, enable: Option<bool>) -> Result<KillswitchReport> {
        match enable {
            Some(true) => {
                Killswitch::new(
                    vpnmgr_tunnel::DEFAULT_INTERFACE,
                    DEFAULT_FWMARK,
                    self.config.killswitch.allow_lan,
                )
                .engage()?;
                self.config.killswitch.enabled = true;
            }
            Some(false) => {
                Killswitch::release()?;
                self.config.killswitch.enabled = false;
            }
            None => {}
        }
        Ok(KillswitchReport {
            engaged: Killswitch::is_engaged(),
            configured: self.config.killswitch.enabled,
            dropped: Killswitch::dropped(),
        })
    }

    /// Attach any recorded throughput to a scored server.
    fn to_ranked(&self, s: &score::Scored<'_>) -> RankedServer {
        let measured = self.throughput_seen.get(&s.server.name);
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
            mbps: measured.map(|(mbps, _)| *mbps),
            mbps_age_secs: measured.map(|(_, at)| at.elapsed().as_secs()),
            headroom_mbps: s.server.headroom_mbps(),
        }
    }

    /// Remember what a server actually delivered.
    fn record_throughput(&mut self, server: &str, mbps: f64) {
        self.throughput_seen
            .insert(server.to_owned(), (mbps, Instant::now()));
        // The cached ranking is what clients read, so update it in place rather
        // than making them wait for the next sweep to see the figure.
        for entry in &mut self.last_ranking {
            if entry.name == server {
                entry.mbps = Some(mbps);
                entry.mbps_age_secs = Some(0);
            }
        }
    }

    /// The cached ranking from the last sweep, best first.
    pub fn last_ranking(&self, limit: Option<usize>) -> Vec<RankedServer> {
        let mut out = self.last_ranking.clone();
        // Ages are relative to now, not to when the sweep ran.
        for entry in &mut out {
            if let Some((mbps, at)) = self.throughput_seen.get(&entry.name) {
                entry.mbps = Some(*mbps);
                entry.mbps_age_secs = Some(at.elapsed().as_secs());
            }
        }
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
        let prober =
            Prober::new(&self.client, self.config.probe.clone()).with_fwmark(DEFAULT_FWMARK);

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

/// Run one throughput measurement, converting it for the wire.
async fn measure(settings: &vpnmgr_probe::throughput::Settings) -> Result<SpeedSample> {
    let t = vpnmgr_probe::throughput::measure(settings).await?;
    Ok(SpeedSample {
        mbps: t.mbps,
        bytes: t.bytes,
        elapsed_ms: t.elapsed.as_millis() as u64,
        truncated: t.truncated,
    })
}
