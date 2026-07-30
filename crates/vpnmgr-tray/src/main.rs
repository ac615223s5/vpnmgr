//! `vpnmgr-tray` — a StatusNotifierItem tray for `vpnmgrd`.
//!
//! Unprivileged, like the CLI: everything it does is a request over the daemon
//! socket. It exists so the auto-tuner's "ask before switching" policy has
//! somewhere to ask that does not involve watching a terminal.
//!
//! # Structure
//!
//! Menu callbacks are synchronous and must not block — the tray would freeze
//! for as long as a request took, and `connect` takes a fleet-wide sweep. So a
//! click only pushes an [`Action`] onto a channel; a worker task performs the
//! round trip and then refreshes the displayed state. A separate poller keeps
//! the menu current when the daemon changes things on its own, which it does
//! every time the scheduler runs.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, Status, ToolTip, Tray, TrayMethods};
use tokio::sync::mpsc;
use vpnmgr_ipc::{DEFAULT_SOCKET, RankedServer, Request, Response, ServerSummary, StatusReport};

/// How often the daemon is polled. The daemon is the source of truth, and a
/// scheduled tuning pass can change the connection with no involvement from us.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// How many servers to offer under "Connect to". Enough to be useful without
/// turning the menu into the full 250-server list.
const QUICK_CONNECT_LIMIT: usize = 12;

#[derive(Parser)]
#[command(
    name = "vpnmgr-tray",
    about = "System tray for the WireGuard VPN manager",
    version
)]
struct Args {
    /// Daemon socket.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
}

/// A request raised by clicking a menu item.
#[derive(Debug, Clone)]
enum Action {
    /// `measure` of `None` follows the daemon's configured default.
    Connect {
        server: Option<String>,
        measure: Option<bool>,
    },
    Disconnect,
    Autotune,
    Approve,
    Dismiss,
    Quit,
}

/// Everything the tray draws from. Mutated only through `Handle::update`.
struct VpnTray {
    /// `None` when the daemon could not be reached.
    status: Option<StatusReport>,
    /// Latency-ordered servers from the daemon's last sweep. Preferred for
    /// quick-connect, because offering the *lightest-loaded* servers first
    /// recommends whichever ones happen to be idle — for a user in Toronto that
    /// meant a menu of 135ms Uppsala servers presented as the best choices.
    ranking: Vec<RankedServer>,
    /// Load-ordered fallback, used until a sweep has run.
    servers: Vec<ServerSummary>,
    /// Why the last request failed, if it did.
    error: Option<String>,
    /// Why the daemon could not be reached. Kept separate from `error` and
    /// shown in full: the usual cause is missing `vpnmgr` group membership,
    /// which is invisible and unfixable from a tray that only says
    /// "unreachable".
    unreachable: Option<String>,
    /// Set while a request is in flight, so the menu can say so instead of
    /// looking unresponsive during a 12-second sweep.
    busy: Option<String>,
    actions: mpsc::UnboundedSender<Action>,
}

impl VpnTray {
    fn new(actions: mpsc::UnboundedSender<Action>) -> Self {
        Self {
            status: None,
            ranking: Vec::new(),
            servers: Vec::new(),
            error: None,
            unreachable: None,
            busy: None,
            actions,
        }
    }

    fn connected(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.connected)
    }

    /// A pending proposal, or a connected-but-unhealthy tunnel, both want the
    /// user's eye.
    fn needs_attention(&self) -> bool {
        self.status
            .as_ref()
            .is_some_and(|s| s.pending_switch.is_some() || (s.connected && !s.healthy))
    }

    /// Queue an action. Failure means the worker is gone, i.e. we are exiting.
    fn dispatch(&self, action: Action) {
        if self.actions.send(action).is_err() {
            tracing::debug!("action channel closed; ignoring the click");
        }
    }

    /// `(server name, menu label)` for the quick-connect submenu.
    ///
    /// Measured latency when a sweep has produced a ranking, since that is what
    /// makes a server a good choice. Falls back to the API's load figures before
    /// the first sweep, labelled as load so the two are not confusable.
    ///
    /// Servers that have actually been speed-tested show that figure too. It is
    /// deliberately shown only where it was measured rather than estimated for
    /// everything: a real number for three servers is more use than a guess for
    /// two hundred.
    ///
    /// Headroom is shown for every server, because the provider gives it away
    /// for free, and it is the third of the three things the ranking weighs.
    /// It is labelled "free" rather than presented as a speed: it is the room
    /// the server has, not the rate you would get through it.
    fn quick_connect_entries(&self) -> Vec<(String, String)> {
        if !self.ranking.is_empty() {
            return self
                .ranking
                .iter()
                .take(QUICK_CONNECT_LIMIT)
                .map(|s| {
                    (
                        s.name.clone(),
                        format!(
                            "{} — {} ({:.0}ms{}, {}% load, {} free)",
                            s.name,
                            truncate(&s.location, 22),
                            s.rtt_ms,
                            match (s.mbps, s.mbps_age_secs) {
                                (Some(mbps), Some(age)) =>
                                    format!(", {mbps:.0} Mbps {}", measured_ago(age)),
                                _ => String::new(),
                            },
                            s.load,
                            rate(s.headroom_mbps as f64),
                        ),
                    )
                })
                .collect();
        }
        self.servers
            .iter()
            .take(QUICK_CONNECT_LIMIT)
            .map(|s| {
                (
                    s.name.clone(),
                    format!(
                        "{} — {} ({}% load, {} free)",
                        s.name,
                        truncate(&s.location, 24),
                        s.load,
                        rate(s.headroom_mbps as f64),
                    ),
                )
            })
            .collect()
    }

    /// The measured no-VPN line rate, as a menu line.
    ///
    /// Worth its own line because it is the yardstick: "is this server fast
    /// enough" is decided as a fraction of this number, so a user looking at a
    /// server's measured speed has no way to judge it without knowing what the
    /// line itself does. Absent until something has measured it.
    fn baseline_line(&self) -> Option<String> {
        let s = self.status.as_ref()?;
        let mbps = s.baseline_mbps?;
        Some(match s.baseline_age_secs {
            Some(age) => format!("without VPN: {} ({})", rate(mbps), measured_ago(age)),
            None => format!("without VPN: {}", rate(mbps)),
        })
    }

    /// The one-line summary used for both the tooltip and the menu header.
    fn headline(&self) -> String {
        match &self.status {
            None => "vpnmgrd is not reachable".to_owned(),
            Some(s) if !s.connected => "Disconnected".to_owned(),
            Some(s) => format!(
                "{} — {}",
                s.server.as_deref().unwrap_or("?"),
                s.location.as_deref().unwrap_or("?")
            ),
        }
    }
}

impl Tray for VpnTray {
    fn id(&self) -> String {
        env!("CARGO_PKG_NAME").into()
    }

    fn title(&self) -> String {
        "vpnmgr".into()
    }

    fn icon_name(&self) -> String {
        // Stock freedesktop names, so this works without shipping an icon
        // theme. `network-vpn` is the one that reliably exists.
        match &self.status {
            None => "network-offline".into(),
            Some(s) if !s.connected => "network-offline".into(),
            Some(s) if !s.healthy => "network-error".into(),
            Some(_) => "network-vpn".into(),
        }
    }

    fn status(&self) -> Status {
        if self.needs_attention() {
            Status::NeedsAttention
        } else {
            Status::Active
        }
    }

    fn tool_tip(&self) -> ToolTip {
        let mut description = String::new();
        if let Some(s) = &self.status
            && s.connected
        {
            description = format!(
                "{}\nhandshake {}\n{} up, {} down",
                s.endpoint
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no endpoint".into()),
                match s.last_handshake_secs {
                    Some(secs) => format!("{secs}s ago"),
                    None => "never".to_owned(),
                },
                human_bytes(s.tx_bytes),
                human_bytes(s.rx_bytes),
            );
        }
        if let Some(baseline) = self.baseline_line() {
            if !description.is_empty() {
                description.push('\n');
            }
            description.push_str(&baseline);
        }
        ToolTip {
            icon_name: self.icon_name(),
            title: self.headline(),
            description,
            ..Default::default()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items = Vec::new();

        items.push(disabled(self.headline()));

        // Render the reason line by line. The IPC layer's messages carry the
        // remedy on their own lines, and a menu cannot show embedded newlines.
        if self.status.is_none()
            && let Some(reason) = &self.unreachable
        {
            for line in reason.lines() {
                // Wide enough that a remedy line stays a complete, copyable
                // command rather than being cut mid-word.
                items.push(disabled(format!("  {}", truncate(line.trim(), 90))));
            }
        }

        if let Some(s) = &self.status
            && s.connected
        {
            items.push(disabled(format!(
                "entry {} · handshake {} · {}",
                s.entry.unwrap_or(0),
                match s.last_handshake_secs {
                    Some(secs) => format!("{secs}s ago"),
                    None => "never".to_owned(),
                },
                if s.healthy { "healthy" } else { "NO TRAFFIC" },
            )));
        }
        // Shown whether or not a tunnel is up: disconnected is exactly when you
        // are deciding what counts as a good server.
        if let Some(baseline) = self.baseline_line() {
            items.push(disabled(baseline));
        }
        if let Some(busy) = &self.busy {
            items.push(disabled(format!("{busy}…")));
        }
        if let Some(error) = &self.error {
            items.push(disabled(format!("error: {}", truncate(error, 60))));
        }

        // The pending proposal goes first, above the routine controls: it is
        // the only thing here that is waiting on the user.
        if let Some(pending) = self.status.as_ref().and_then(|s| s.pending_switch.as_ref()) {
            items.push(MenuItem::Separator);
            items.push(disabled(format!(
                "Suggested: {} ({:.1}ms)",
                pending.to.name, pending.to.rtt_ms
            )));
            let target = pending.to.name.clone();
            items.push(
                StandardItem {
                    label: format!("Switch to {target}"),
                    icon_name: "go-next".into(),
                    activate: Box::new(|this: &mut Self| this.dispatch(Action::Approve)),
                    ..Default::default()
                }
                .into(),
            );
            items.push(
                StandardItem {
                    label: "Keep current server".into(),
                    activate: Box::new(|this: &mut Self| this.dispatch(Action::Dismiss)),
                    ..Default::default()
                }
                .into(),
            );
        }

        items.push(MenuItem::Separator);

        let reachable = self.status.is_some();
        // Offering actions that cannot possibly work is worse than hiding them.
        let idle = self.busy.is_none() && reachable;

        items.push(
            StandardItem {
                label: "Test now".into(),
                icon_name: "view-refresh".into(),
                enabled: reachable && idle,
                activate: Box::new(|this: &mut Self| this.dispatch(Action::Autotune)),
                ..Default::default()
            }
            .into(),
        );

        if self.connected() {
            items.push(
                StandardItem {
                    label: "Disconnect".into(),
                    icon_name: "network-offline".into(),
                    enabled: idle,
                    activate: Box::new(|this: &mut Self| this.dispatch(Action::Disconnect)),
                    ..Default::default()
                }
                .into(),
            );
        } else {
            // Two explicit choices rather than one and a hidden default: the
            // measured path is markedly slower, and which one you want depends
            // on whether you are about to rely on the connection.
            items.push(
                StandardItem {
                    label: "Connect to best server".into(),
                    icon_name: "network-vpn".into(),
                    enabled: reachable && idle,
                    activate: Box::new(|this: &mut Self| {
                        this.dispatch(Action::Connect {
                            server: None,
                            measure: Some(false),
                        })
                    }),
                    ..Default::default()
                }
                .into(),
            );
            items.push(
                StandardItem {
                    label: "Connect, measuring speed first".into(),
                    icon_name: "speedometer".into(),
                    enabled: reachable && idle,
                    activate: Box::new(|this: &mut Self| {
                        this.dispatch(Action::Connect {
                            server: None,
                            measure: Some(true),
                        })
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }

        let quick = self.quick_connect_entries();
        if !quick.is_empty() {
            let verb = if self.connected() {
                "Switch to"
            } else {
                "Connect to"
            };
            let submenu = quick
                .into_iter()
                .map(|(name, label)| {
                    StandardItem {
                        label,
                        enabled: idle,
                        activate: Box::new(move |this: &mut Self| {
                            this.dispatch(Action::Connect {
                                server: Some(name.clone()),
                                measure: None,
                            })
                        }),
                        ..Default::default()
                    }
                    .into()
                })
                .collect();
            items.push(
                SubMenu {
                    label: verb.into(),
                    submenu,
                    ..Default::default()
                }
                .into(),
            );
        }

        if let Some(tune) = self.status.as_ref().and_then(|s| s.last_tune.as_ref()) {
            items.push(MenuItem::Separator);
            items.push(disabled(truncate(tune, 70)));
        }

        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Quit tray".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|this: &mut Self| this.dispatch(Action::Quit)),
                ..Default::default()
            }
            .into(),
        );

        items
    }
}

/// Holds the single-instance lock for as long as the process lives.
///
/// The tray is reachable two ways — autostart at login and the applications
/// menu — so without this, launching it from the menu while it is already
/// running would put a second identical icon in the tray. The lock is an
/// advisory `flock` released by the kernel when the process exits, so it
/// cannot be left stale by a crash the way a pidfile can.
struct InstanceLock(#[allow(dead_code)] std::fs::File);

/// Why we did or did not get the lock.
///
/// "Another instance holds it" and "the lock file could not be created" have to
/// be told apart. Treating them the same would mean an unwritable runtime
/// directory stopped the tray from ever starting, while telling the user it was
/// already running.
enum Instance {
    /// We are the only instance.
    Only(InstanceLock),
    /// Another tray already has it.
    AlreadyRunning,
    /// The lock could not be taken at all. Not a reason to refuse to start.
    Unavailable(std::io::Error),
}

fn acquire_instance_lock() -> Instance {
    // Per-user, and cleared on reboot.
    let dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    lock_at(std::path::Path::new(&dir).join("vpnmgr-tray.lock"))
}

/// The lock itself, against an explicit path so it is testable without
/// disturbing a tray the user actually has running.
fn lock_at(path: impl AsRef<std::path::Path>) -> Instance {
    use std::os::unix::io::AsRawFd;

    let file = match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path.as_ref())
    {
        Ok(file) => file,
        Err(e) => return Instance::Unavailable(e),
    };

    // SAFETY: the fd is valid for the duration of the call, and LOCK_NB means
    // this never blocks.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Instance::Only(InstanceLock(file))
    } else {
        Instance::AlreadyRunning
    }
}

/// Tell the user something when there is no terminal to print to.
///
/// Launching from the applications menu discards stdout and stderr, so a bare
/// `eprintln!` would look like the menu entry simply did nothing.
fn notify_user(summary: &str, body: &str) {
    eprintln!("{summary}: {body}");
    let _ = std::process::Command::new("notify-send")
        .args(["--app-name=vpnmgr", "--icon=network-vpn", summary, body])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// A non-interactive line of text in the menu.
fn disabled(label: String) -> MenuItem<VpnTray> {
    StandardItem {
        label,
        enabled: false,
        ..Default::default()
    }
    .into()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vpnmgr_tray=info".into()),
        )
        .init();

    let args = Args::parse();

    // Held for the whole run; dropping it would let a second icon appear.
    let _lock = match acquire_instance_lock() {
        Instance::Only(lock) => Some(lock),
        Instance::AlreadyRunning => {
            notify_user(
                "vpnmgr is already running",
                "Look for the VPN icon in your system tray.",
            );
            return;
        }
        // Starting without the guard is better than not starting at all; the
        // worst case is a duplicate icon, which the user can close.
        Instance::Unavailable(e) => {
            tracing::warn!("could not take the single-instance lock ({e}); starting anyway");
            None
        }
    };

    let (tx, rx) = mpsc::unbounded_channel();

    let handle = match VpnTray::new(tx).spawn().await {
        Ok(handle) => handle,
        Err(e) => {
            notify_user(
                "vpnmgr tray could not start",
                &format!(
                    "No system tray was found on the session bus ({e}). \
                     Cinnamon needs xapp-sn-watcher; GNOME needs the AppIndicator \
                     extension. The `vpnmgr` command still works."
                ),
            );
            std::process::exit(1);
        }
    };

    // First paint before the poll loop's initial sleep, so the menu is
    // populated by the time anyone can click it.
    refresh(&handle, &args.socket).await;

    let worker = tokio::spawn(run_actions(rx, handle.clone(), args.socket.clone()));

    let poller = handle.clone();
    let socket = args.socket.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if poller.is_closed() {
                return;
            }
            refresh(&poller, &socket).await;
        }
    });

    // The worker returns when Quit is chosen.
    let _ = worker.await;
    handle.shutdown().await;
}

/// Perform queued actions one at a time, refreshing afterwards.
///
/// Serialising them is deliberate: the daemon holds one lock over its state, so
/// firing a connect and a disconnect concurrently would only queue them there
/// instead, with a less predictable order.
async fn run_actions(
    mut rx: mpsc::UnboundedReceiver<Action>,
    handle: ksni::Handle<VpnTray>,
    socket: PathBuf,
) {
    while let Some(action) = rx.recv().await {
        if matches!(action, Action::Quit) {
            return;
        }

        // Picking a named server means "switch" once a tunnel exists, because
        // the daemon rejects connecting while already connected.
        let connected = handle
            .update(|tray| tray.connected())
            .await
            .unwrap_or(false);

        let (request, busy) = match &action {
            Action::Connect {
                server: None,
                measure,
            } => (
                Request::Connect {
                    server: None,
                    measure: *measure,
                },
                if measure.unwrap_or(false) {
                    "Measuring, then choosing a server"
                } else {
                    "Finding the best server"
                },
            ),
            Action::Connect {
                server: Some(server),
                ..
            } if connected => (
                Request::Switch {
                    server: server.clone(),
                },
                "Switching",
            ),
            Action::Connect {
                server: Some(server),
                measure,
            } => (
                Request::Connect {
                    server: Some(server.clone()),
                    measure: *measure,
                },
                "Connecting",
            ),
            Action::Disconnect => (Request::Disconnect, "Disconnecting"),
            Action::Autotune => (Request::Autotune, "Testing servers"),
            Action::Approve => (Request::Approve, "Switching"),
            Action::Dismiss => (Request::Dismiss, "Dismissing"),
            Action::Quit => unreachable!("handled above"),
        };

        handle
            .update(|tray| {
                tray.busy = Some(busy.to_owned());
                tray.error = None;
            })
            .await;

        let outcome = vpnmgr_ipc::client::request(&socket, &request).await;
        let error = match outcome {
            Err(e) => Some(e.to_string()),
            Ok(Response::Error { message }) => Some(message),
            Ok(_) => None,
        };
        if let Some(error) = &error {
            tracing::warn!("{request:?} failed: {error}");
        }

        handle
            .update(|tray| {
                tray.busy = None;
                tray.error = error;
            })
            .await;

        refresh(&handle, &socket).await;
    }
}

/// Pull current state from the daemon into the tray.
async fn refresh(handle: &ksni::Handle<VpnTray>, socket: &PathBuf) {
    let (status, unreachable) = match vpnmgr_ipc::client::request(socket, &Request::Status).await {
        Ok(Response::Status(report)) => (Some(*report), None),
        Ok(Response::Error { message }) => {
            tracing::debug!("daemon refused a status request: {message}");
            (None, Some(message))
        }
        Ok(other) => {
            tracing::debug!("unexpected reply to a status request: {other:?}");
            (None, Some("vpnmgrd sent an unexpected reply".to_owned()))
        }
        Err(e) => {
            tracing::debug!("could not reach the daemon: {e}");
            (None, Some(e.to_string()))
        }
    };

    // Only worth asking for server lists once the daemon is answering. The
    // ranking is free (cached from the last sweep) and preferred; the load-
    // ordered list is only needed as a fallback before any sweep has run.
    let (ranking, servers) = if status.is_some() {
        let ranking = match vpnmgr_ipc::client::request(
            socket,
            &Request::LastRanking {
                limit: Some(QUICK_CONNECT_LIMIT),
            },
        )
        .await
        {
            Ok(Response::Ranking(ranking)) => ranking,
            _ => Vec::new(),
        };

        let servers = if ranking.is_empty() {
            match vpnmgr_ipc::client::request(
                socket,
                &Request::Servers {
                    country: None,
                    limit: Some(QUICK_CONNECT_LIMIT),
                    // Never `all`: the picker connects to what it shows, so it
                    // must only show what the config allows.
                    all: false,
                },
            )
            .await
            {
                Ok(Response::Servers(servers)) => Some(servers),
                _ => None,
            }
        } else {
            None
        };
        (Some(ranking), servers)
    } else {
        (None, None)
    };

    handle
        .update(|tray| {
            tray.status = status;
            tray.unreachable = unreachable;
            if let Some(ranking) = ranking {
                tray.ranking = ranking;
            }
            if let Some(servers) = servers {
                tray.servers = servers;
            }
        })
        .await;
}

/// How long ago a throughput figure was taken, compactly.
///
/// Always shown alongside the number: an old measurement describes conditions
/// that may be long gone, and presenting it bare would imply it still holds.
fn measured_ago(secs: u64) -> String {
    match secs {
        s if s < 90 => "just now".to_owned(),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86_400),
    }
}

/// A rate in Mbit/s, at a scale that stays readable in a menu.
///
/// Server headroom runs from tens of Mbit/s to well over ten thousand, and six
/// digits in a menu label are noise — nobody is comparing 11400 against 11380.
fn rate(mbps: f64) -> String {
    if mbps >= 1000.0 {
        format!("{:.1} Gbps", mbps / 1000.0)
    } else {
        format!("{mbps:.0} Mbps")
    }
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_owned()
    } else {
        s.chars().take(width.saturating_sub(1)).collect::<String>() + "…"
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "vpnmgr-tray-test-{name}-{}.lock",
            std::process::id()
        ));
        p
    }

    /// The whole point: launching from the applications menu while the tray is
    /// already running must not produce a second icon.
    #[test]
    fn a_second_instance_cannot_take_the_lock() {
        let path = temp_path("second");
        let first = match lock_at(&path) {
            Instance::Only(lock) => lock,
            _ => panic!("first instance should acquire the lock"),
        };
        assert!(
            matches!(lock_at(&path), Instance::AlreadyRunning),
            "a second instance acquired the lock and would have added a duplicate tray icon"
        );
        drop(first);
        let _ = std::fs::remove_file(&path);
    }

    /// flock is released by the kernel on close, so an exited instance never
    /// leaves the lock stale the way a pidfile would.
    #[test]
    fn the_lock_is_released_when_the_holder_exits() {
        let path = temp_path("released");
        let first = lock_at(&path);
        assert!(matches!(first, Instance::Only(_)));
        drop(first);
        assert!(
            matches!(lock_at(&path), Instance::Only(_)),
            "the lock outlived its holder, so the tray could never be restarted"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// An unwritable lock location must not masquerade as "already running",
    /// which would stop the tray from ever starting and say the wrong reason.
    #[test]
    fn an_unusable_lock_path_is_not_mistaken_for_a_running_instance() {
        assert!(matches!(
            lock_at("/proc/definitely/not/writable.lock"),
            Instance::Unavailable(_)
        ));
    }

    #[test]
    fn rates_switch_to_gigabits_once_the_digits_stop_meaning_anything() {
        assert_eq!(rate(84.0), "84 Mbps");
        assert_eq!(rate(999.4), "999 Mbps");
        assert_eq!(rate(1000.0), "1.0 Gbps");
        assert_eq!(rate(11_400.0), "11.4 Gbps");
    }

    fn status_with_baseline(mbps: Option<f64>, age: Option<u64>) -> StatusReport {
        StatusReport {
            connected: false,
            interface: "vpnmgr0".into(),
            server: None,
            location: None,
            country_code: None,
            endpoint: None,
            entry: None,
            last_handshake_secs: None,
            healthy: false,
            tx_bytes: 0,
            rx_bytes: 0,
            last_sweep: None,
            pending_switch: None,
            last_tune: None,
            next_tune_secs: None,
            baseline_mbps: mbps,
            baseline_age_secs: age,
        }
    }

    fn tray_showing(status: Option<StatusReport>) -> VpnTray {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut tray = VpnTray::new(tx);
        tray.status = status;
        tray
    }

    /// The baseline is a claim about the line right now, so it is never shown
    /// without saying how old it is.
    #[test]
    fn the_baseline_line_carries_its_age() {
        let tray = tray_showing(Some(status_with_baseline(Some(843.2), Some(7200))));
        assert_eq!(
            tray.baseline_line().as_deref(),
            Some("without VPN: 843 Mbps (2h ago)")
        );
    }

    fn ranked(name: &str, headroom_mbps: u64) -> RankedServer {
        RankedServer {
            name: name.into(),
            country_code: "ca".into(),
            country_name: "Canada".into(),
            location: "Toronto, Ontario".into(),
            load: 27,
            rtt_ms: 6.9,
            score: 0.9,
            entry: 3,
            endpoint: "1.2.3.4:1637".parse().unwrap(),
            mbps: None,
            mbps_age_secs: None,
            headroom_mbps,
        }
    }

    /// Headroom is what separates two servers reporting the same load, so it
    /// has to reach the label the user actually clicks.
    #[test]
    fn picker_labels_carry_headroom() {
        let mut tray = tray_showing(Some(status_with_baseline(None, None)));
        tray.ranking = vec![ranked("Kornephoros", 14_400), ranked("Angetenar", 756)];
        let labels: Vec<String> = tray
            .quick_connect_entries()
            .into_iter()
            .map(|(_, label)| label)
            .collect();
        assert_eq!(
            labels[0],
            "Kornephoros — Toronto, Ontario (7ms, 27% load, 14.4 Gbps free)"
        );
        assert!(labels[1].ends_with("756 Mbps free)"), "{}", labels[1]);
    }

    /// The pre-sweep fallback list is a different code path, and it is the one
    /// shown on a freshly started daemon.
    #[test]
    fn the_fallback_picker_carries_headroom_too() {
        let mut tray = tray_showing(Some(status_with_baseline(None, None)));
        tray.servers = vec![ServerSummary {
            name: "Kornephoros".into(),
            country_code: "ca".into(),
            country_name: "Canada".into(),
            location: "Toronto, Ontario".into(),
            load: 27,
            users: 345,
            healthy: true,
            headroom_mbps: 14_400,
        }];
        assert_eq!(
            tray.quick_connect_entries()[0].1,
            "Kornephoros — Toronto, Ontario (27% load, 14.4 Gbps free)"
        );
    }

    /// Nothing has measured it yet on a fresh daemon, and inventing a figure
    /// there would misrepresent the bar every server is judged against.
    #[test]
    fn no_baseline_line_until_something_has_measured_one() {
        assert!(
            tray_showing(Some(status_with_baseline(None, None)))
                .baseline_line()
                .is_none()
        );
        assert!(tray_showing(None).baseline_line().is_none());
    }
}
