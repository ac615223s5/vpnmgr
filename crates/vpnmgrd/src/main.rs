//! The vpnmgr daemon.
//!
//! Runs as root, owns the tunnel, and serves a line-delimited JSON protocol on
//! a Unix socket. Unprivileged clients (`vpnmgr`, the tray) drive it through
//! that socket, so nothing else needs elevated privileges and the user is never
//! prompted for a password to change servers.

mod notify;
mod state;
mod tuner;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use vpnmgr_ipc::{DEFAULT_SOCKET, MAX_LINE, Request, Response, SOCKET_GROUP};

use crate::state::State;

#[derive(Parser)]
#[command(name = "vpnmgrd", about = "WireGuard VPN manager daemon")]
struct Args {
    /// Configuration file.
    #[arg(long, default_value = vpnmgr_core::config::DEFAULT_PATH)]
    config: PathBuf,

    /// Unix socket to listen on.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vpnmgrd=info,vpnmgr_tunnel=info".into()),
        )
        .init();

    let args = Args::parse();

    let state = match State::load(args.config.clone()) {
        Ok(state) => Arc::new(Mutex::new(state)),
        Err(e) => {
            tracing::error!("failed to load {}: {e}", args.config.display());
            std::process::exit(1);
        }
    };

    let listener = match bind(&args.socket) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("failed to bind {}: {e}", args.socket.display());
            std::process::exit(1);
        }
    };

    tracing::info!("listening on {}", args.socket.display());

    {
        let interval = state.lock().await.tune_interval_minutes();
        tracing::info!("auto-tuning every {interval} minutes");
    }
    let tuner_task = tokio::spawn(scheduler(Arc::clone(&state)));

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(e) = serve(stream, state).await {
                                tracing::debug!("client disconnected: {e}");
                            }
                        });
                    }
                    Err(e) => tracing::warn!("accept failed: {e}"),
                }
            }
            _ = &mut shutdown => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    // Stop tuning before teardown, so a sweep in flight cannot bring the
    // tunnel back up behind us.
    tuner_task.abort();

    // Tear the tunnel down on exit. Leaving a default route pointing at a
    // dead interface would strand the machine.
    let mut state = state.lock().await;
    if state.is_connected() {
        tracing::info!("removing the tunnel before exit");
        if let Err(e) = state.disconnect() {
            tracing::error!("failed to disconnect cleanly: {e}");
        }
    }
    let _ = std::fs::remove_file(&args.socket);
}

fn bind(path: &std::path::Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A socket left behind by a crash would block binding.
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;

    match vpnmgr_ipc::socket_permissions(path) {
        Ok(true) => tracing::info!("socket owned by group {SOCKET_GROUP} (mode 0660)"),
        Ok(false) => tracing::warn!(
            "group {SOCKET_GROUP} does not exist, so the socket is root-only (mode 0600). \
             Create it and add your user: sudo groupadd -f {SOCKET_GROUP} && \
             sudo usermod -aG {SOCKET_GROUP} $USER"
        ),
        Err(e) => tracing::warn!("could not set socket ownership: {e}"),
    }

    Ok(listener)
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

async fn serve(stream: UnixStream, state: Arc<Mutex<State>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        // take() bounds what a client can make us buffer.
        let n = (&mut reader)
            .take(MAX_LINE as u64)
            .read_line(&mut line)
            .await?;
        if n == 0 {
            return Ok(());
        }

        let response = match serde_json::from_str::<Request>(line.trim_end()) {
            Ok(request) => handle(request, &state).await,
            Err(e) => Response::error(format!("malformed request: {e}")),
        };

        let mut out = serde_json::to_string(&response)
            .unwrap_or_else(|e| format!(r#"{{"response":"error","message":"{e}"}}"#));
        out.push('\n');
        reader.get_mut().write_all(out.as_bytes()).await?;
        reader.get_mut().flush().await?;
    }
}

async fn handle(request: Request, state: &Arc<Mutex<State>>) -> Response {
    let mut state = state.lock().await;
    match request {
        Request::Version => Response::Version {
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },

        Request::Status => Response::Status(Box::new(state.status())),

        Request::Connect { server } => match state.connect(server).await {
            Ok(chosen) => Response::ok(format!(
                "connected to {} ({}, {}) via entry {} at {:.1}ms{}",
                chosen.name,
                chosen.location,
                chosen.country_name,
                chosen.entry,
                chosen.rtt_ms,
                match chosen.mbps {
                    Some(mbps) => format!(", measured {mbps:.0} Mbps"),
                    None => String::new(),
                }
            )),
            Err(e) => Response::error(e),
        },

        Request::Disconnect => match state.disconnect() {
            Ok(()) => Response::ok("disconnected"),
            Err(e) => Response::error(e),
        },

        Request::Switch { server } => match state.switch(&server).await {
            Ok(chosen) => Response::ok(format!(
                "switched to {} ({}) via entry {} at {:.1}ms",
                chosen.name, chosen.location, chosen.entry, chosen.rtt_ms
            )),
            Err(e) => Response::error(e),
        },

        Request::Test { country } => match state.sweep(country).await {
            Ok(ranking) => Response::Ranking(ranking),
            Err(e) => Response::error(e),
        },

        Request::LastRanking { limit } => Response::Ranking(state.last_ranking(limit)),

        Request::Servers { country, limit } => match state.servers(country, limit).await {
            Ok(servers) => Response::Servers(servers),
            Err(e) => Response::error(e),
        },

        Request::Reload => match state.reload() {
            Ok(()) => Response::ok("configuration reloaded"),
            Err(e) => Response::error(e),
        },

        Request::Autotune => match state.autotune().await {
            Ok(report) => Response::Tuned(Box::new(report)),
            Err(e) => Response::error(e),
        },

        Request::Approve => match state.approve().await {
            Ok(chosen) => Response::ok(format!(
                "switched to {} ({}) via entry {} at {:.1}ms",
                chosen.name, chosen.location, chosen.entry, chosen.rtt_ms
            )),
            Err(e) => Response::error(e),
        },

        Request::Speedtest => match state.speedtest().await {
            Ok(report) => Response::Speed(Box::new(report)),
            Err(e) => Response::error(e),
        },

        Request::Baseline { confirm } => {
            if confirm {
                match state.baseline().await {
                    Ok(report) => Response::Speed(Box::new(report)),
                    Err(e) => Response::error(e),
                }
            } else {
                Response::error(crate::state::Error::ConsentRequired)
            }
        }

        Request::Killswitch { enable } => match state.killswitch(enable) {
            Ok(report) => Response::Killswitch(report),
            Err(e) => Response::error(e),
        },

        Request::Dismiss => match state.dismiss() {
            Ok(name) => Response::ok(format!("dismissed the proposal to move to {name}")),
            Err(e) => Response::error(e),
        },
    }
}

/// Run a tuning pass whenever one falls due.
///
/// The wait is recomputed from the daemon's own record of the last pass rather
/// than driven by a fixed ticker, so a manual `vpnmgr autotune` postpones the
/// next scheduled one instead of being followed immediately by a redundant
/// sweep of the whole fleet.
async fn scheduler(state: Arc<Mutex<State>>) {
    loop {
        let wait = state.lock().await.time_until_next_tune();
        tokio::time::sleep(wait).await;

        // Re-check under the lock: a manual pass may have run while we slept.
        let mut guard = state.lock().await;
        if !guard.time_until_next_tune().is_zero() {
            continue;
        }
        let report = match guard.autotune().await {
            Ok(report) => report,
            Err(e) => {
                tracing::warn!("scheduled tuning pass failed: {e}");
                continue;
            }
        };
        drop(guard);

        announce(&report);
    }
}

/// Surface a tuning result to the desktop, when it is worth interrupting for.
///
/// A healthy check-in is the overwhelmingly common outcome and is deliberately
/// silent; notifying every 30 minutes that nothing happened would train the
/// user to ignore the ones that matter.
fn announce(report: &vpnmgr_ipc::TuneReport) {
    let (summary, urgency) = if report.switched {
        ("VPN server switched", notify::Urgency::Normal)
    } else if report.pending.is_some() {
        ("A faster VPN server is available", notify::Urgency::Normal)
    } else if report.nothing_reachable {
        // The tunnel is up but no server answers, so traffic is going nowhere.
        // Worth interrupting for even though the tuner deliberately does not
        // act on it.
        ("VPN is not reaching any server", notify::Urgency::Critical)
    } else {
        return;
    };

    let body = report.summary.clone();
    // notify-send blocks on the session bus, so keep it off the runtime.
    tokio::task::spawn_blocking(move || notify::desktop(summary, &body, urgency));
}
