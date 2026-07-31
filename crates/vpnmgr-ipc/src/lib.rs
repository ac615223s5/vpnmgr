//! Wire protocol between `vpnmgrd` and its clients.
//!
//! One JSON object per line over a Unix socket. Line framing keeps the daemon
//! debuggable with `socat` and avoids a length-prefix codec for what are only
//! ever small control messages.
//!
//! # Trust boundary
//!
//! The daemon runs as root; clients do not. Everything here crosses that
//! boundary, so no message carries key material — the daemon reads keys from
//! `0600` files itself and never echoes them back. Access control is the
//! socket's group ownership, applied by [`socket_permissions`].

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod client;
pub mod transport;

/// Where clients reach the daemon: a socket under `/run` on Unix, a named pipe
/// on Windows. See [`transport`] for why access control lives there.
pub const DEFAULT_SOCKET: &str = transport::DEFAULT_ENDPOINT;

/// Group granted access to the socket.
pub const SOCKET_GROUP: &str = "vpnmgr";

/// Longest message accepted, to bound what a client can make the daemon buffer.
pub const MAX_LINE: usize = 1024 * 1024;

/// How to check the daemon is running. Both failures below are far more often
/// a stopped service than a real fault, so the hint names the exact command.
#[cfg(unix)]
const DAEMON_HINT: &str = "is the daemon running? try: systemctl status vpnmgrd";
#[cfg(windows)]
const DAEMON_HINT: &str = "is the daemon running? try: sc query vpnmgrd";

#[cfg(unix)]
const ACCESS_HINT: &str = "add yourself to the 'vpnmgr' group: \
                           sudo usermod -aG vpnmgr $USER\nthen log out and back in";
/// On Windows the pipe already admits interactive users, so a refusal here is
/// not something group membership fixes — it means the daemon is running under
/// a desktop that is not yours, or you are reaching it over a network.
#[cfg(windows)]
const ACCESS_HINT: &str = "the daemon only accepts administrators and users logged in \
                           at this machine, and never remote clients";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Current tunnel state.
    Status,
    /// Connect, picking the best server when `server` is `None`.
    ///
    /// `measure` chooses whether to test the connection and the candidates
    /// before settling; `None` follows `autotune.measure_before_connect`.
    Connect {
        server: Option<String>,
        #[serde(default)]
        measure: Option<bool>,
    },
    Disconnect,
    /// Move an existing tunnel to a different server.
    Switch {
        server: String,
    },
    /// Run a probe sweep and return the ranking without connecting.
    Test {
        country: Option<String>,
    },
    /// The ranking from the most recent sweep, without probing again.
    ///
    /// Distinct from [`Request::Test`], which costs a full fleet sweep. This is
    /// for callers that want latency-ordered servers cheaply and often — a tray
    /// menu redrawn every few seconds cannot afford to probe.
    LastRanking {
        limit: Option<usize>,
    },
    /// List known servers from the cached API data. Does not probe.
    Servers {
        country: Option<String>,
        limit: Option<usize>,
        /// Ignore the configured filters and list the whole fleet.
        ///
        /// Defaulted so that a client built before this field existed still
        /// gets the safe, filtered answer.
        #[serde(default)]
        all: bool,
    },
    /// Re-read the config file from disk.
    Reload,
    Version,
    /// Run a tuning pass now instead of waiting for the schedule.
    Autotune,
    /// Accept the pending switch proposal.
    Approve,
    /// Discard the pending switch proposal without moving.
    Dismiss,
    /// Measure throughput on the current path.
    Speedtest,
    /// Compare throughput through the tunnel against throughput without it.
    ///
    /// `confirm` must be set: this briefly drops the tunnel, which exposes the
    /// real IP address and releases the kill switch. The daemon refuses
    /// otherwise rather than assuming consent.
    Baseline {
        confirm: bool,
    },
    /// Turn the kill switch on or off, or report its state when `enable` is
    /// `None`.
    Killswitch {
        enable: Option<bool>,
    },
}

/// Adjacently tagged rather than internally tagged: serde cannot serialise a
/// sequence into an internally-tagged variant, which silently rules out every
/// list-valued reply. The `content` field keeps all variants representable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "response", content = "data", rename_all = "snake_case")]
pub enum Response {
    Status(Box<StatusReport>),
    Ranking(Vec<RankedServer>),
    Servers(Vec<ServerSummary>),
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
    Version {
        version: String,
    },
    /// Outcome of a tuning pass.
    Tuned(Box<TuneReport>),
    /// Outcome of a throughput measurement.
    Speed(Box<SpeedReport>),
    /// State of the kill switch.
    Killswitch(KillswitchReport),
}

impl Response {
    pub fn error(message: impl std::fmt::Display) -> Self {
        Self::Error {
            message: message.to_string(),
        }
    }

    pub fn ok(message: impl Into<String>) -> Self {
        Self::Ok {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusReport {
    pub connected: bool,
    pub interface: String,
    pub server: Option<String>,
    pub location: Option<String>,
    pub country_code: Option<String>,
    pub endpoint: Option<SocketAddr>,
    /// Which AirVPN entry address is in use.
    pub entry: Option<u8>,
    /// Seconds since the last WireGuard handshake.
    pub last_handshake_secs: Option<u64>,
    /// Whether a handshake happened recently enough for traffic to be flowing.
    pub healthy: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Result of the most recent sweep, if one has run.
    pub last_sweep: Option<SweepSummary>,
    /// A switch the tuner wants to make but is waiting to be approved.
    pub pending_switch: Option<PendingSwitch>,
    /// Plain-language outcome of the most recent tuning pass.
    pub last_tune: Option<String>,
    /// Seconds until the next scheduled tuning pass.
    pub next_tune_secs: Option<u64>,
    /// What this connection managed with the tunnel down, when that has been
    /// measured. Every judgement about whether a server is fast enough is made
    /// relative to this, so it is worth showing rather than leaving implicit.
    pub baseline_mbps: Option<f64>,
    /// Age of that measurement. A line rate from last week describes a link
    /// that may have changed, so it is never shown bare.
    pub baseline_age_secs: Option<u64>,
}

/// A proposal raised under `switch_policy = "ask"`, held until the user
/// approves or dismisses it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingSwitch {
    pub to: RankedServer,
    /// Why the tuner wants to move.
    pub reason: String,
    /// Seconds since the proposal was raised.
    pub age_secs: u64,
}

/// What a tuning pass concluded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TuneReport {
    /// One-line explanation, suitable for a notification.
    pub summary: String,
    /// Whether the tunnel was actually moved.
    pub switched: bool,
    /// Set when the pass raised a proposal needing approval.
    pub pending: Option<PendingSwitch>,
    /// The tunnel is up but no server answered. Deliberately not acted on —
    /// it implicates the local link — but the user should know.
    pub nothing_reachable: bool,
}

/// One throughput measurement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpeedSample {
    pub mbps: f64,
    pub bytes: u64,
    pub elapsed_ms: u64,
    /// The transfer hit its timeout before the full payload arrived. Still a
    /// real rate over a real interval, but not the whole payload.
    pub truncated: bool,
}

/// Result of `speedtest` or `baseline`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpeedReport {
    /// Measured through the tunnel, when one was up.
    pub tunnelled: Option<SpeedSample>,
    /// Measured with the tunnel down. Only ever set by `baseline`.
    pub direct: Option<SpeedSample>,
    /// Server the tunnelled sample went through.
    pub server: Option<String>,
    /// The `autotune.min_mbps` floor this was judged against.
    pub min_mbps: f64,
    /// Whether the tunnelled rate cleared that floor.
    pub meets_target: bool,
    /// Plain-language conclusion, including the VPN-versus-direct comparison
    /// when both samples exist.
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KillswitchReport {
    /// Whether the firewall rules are currently installed.
    pub engaged: bool,
    /// Whether the config asks for it on every connect.
    pub configured: bool,
    /// Packets it has dropped, when the counter could be read. Non-zero means
    /// something genuinely tried to leave outside the tunnel.
    pub dropped: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SweepSummary {
    pub probed: usize,
    pub reachable: usize,
    pub elapsed_ms: u64,
    /// Seconds since the sweep finished.
    pub age_secs: u64,
    pub best: Option<RankedServer>,
    /// Set when every server was unreachable, which is ambiguous between a
    /// dead local link and stale credentials.
    pub all_unreachable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankedServer {
    pub name: String,
    pub country_code: String,
    pub country_name: String,
    pub location: String,
    pub load: u32,
    pub rtt_ms: f64,
    pub score: f64,
    pub entry: u8,
    pub endpoint: SocketAddr,
    /// Measured throughput, for servers that have actually been speed-tested.
    ///
    /// `None` for the overwhelming majority: a throughput test costs tens of
    /// megabytes and is only ever run on the server you are connected to, so
    /// this fills in gradually as you use them. Latency is what ranks servers;
    /// this is recorded evidence, not a prediction.
    pub mbps: Option<f64>,
    /// Age of that measurement. A number from last week says much less than
    /// one from ten minutes ago, so callers can show or discount it.
    pub mbps_age_secs: Option<u64>,
    /// Spare capacity in Mbit/s, from the provider's own figures.
    ///
    /// Unlike `mbps` this is known for every server, because it costs nothing —
    /// but it is the room the server has, not the rate you would get. The two
    /// answer different questions and are shown as different things.
    pub headroom_mbps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerSummary {
    pub name: String,
    pub country_code: String,
    pub country_name: String,
    pub location: String,
    pub load: u32,
    pub users: u32,
    pub healthy: bool,
    /// Spare capacity in Mbit/s. See [`RankedServer::headroom_mbps`].
    pub headroom_mbps: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot reach vpnmgrd at {path}: {source}\n{}", DAEMON_HINT)]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("permission denied opening {path}\n{}", ACCESS_HINT)]
    PermissionDenied { path: PathBuf },

    #[error("talking to vpnmgrd: {0}")]
    Io(#[from] std::io::Error),

    #[error("vpnmgrd sent something unparseable: {0}")]
    Protocol(#[from] serde_json::Error),

    #[error("vpnmgrd closed the connection without replying")]
    Closed,

    #[error("message exceeded the {MAX_LINE} byte limit")]
    TooLong,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Apply `0660` and `root:vpnmgr` ownership to the socket.
///
/// Group membership is the whole access-control story: the daemon runs as root
/// and will do what it is told, so anyone who can open the socket can control
/// the VPN. Returns `Ok(false)` when the group does not exist, leaving the
/// socket root-only rather than opening it up.
///
/// Windows has no equivalent step: a named pipe's access control is fixed when
/// the pipe is created, so it is applied in [`transport`] rather than after the
/// fact. There is no window in which the endpoint exists but is unprotected.
#[cfg(unix)]
pub fn socket_permissions(path: &std::path::Path) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let Some(gid) = group_id(SOCKET_GROUP) else {
        // Fail closed: 0600 means only root can talk to the daemon.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        return Ok(false);
    };

    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: c_path is a valid NUL-terminated string for the duration of the
    // call; -1 for uid leaves the owner unchanged.
    let rc = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(true)
}

/// Look up a group's gid by name.
#[cfg(unix)]
fn group_id(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: c_name is a valid NUL-terminated string. The returned pointer is
    // owned by libc and only read before the next getgrnam call.
    let group = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if group.is_null() {
        return None;
    }
    // SAFETY: getgrnam returned a non-null pointer to a valid struct group.
    Some(unsafe { (*group).gr_gid })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(request: Request) {
        let line = serde_json::to_string(&request).unwrap();
        assert!(
            !line.contains('\n'),
            "framing requires single-line messages"
        );
        assert_eq!(serde_json::from_str::<Request>(&line).unwrap(), request);
    }

    #[test]
    fn requests_round_trip() {
        roundtrip(Request::Status);
        roundtrip(Request::Connect {
            server: None,
            measure: None,
        });
        roundtrip(Request::Connect {
            server: Some("Kornephoros".into()),
            measure: Some(true),
        });
        roundtrip(Request::Connect {
            server: None,
            measure: Some(false),
        });
        roundtrip(Request::Disconnect);
        roundtrip(Request::Switch {
            server: "Chamukuy".into(),
        });
        roundtrip(Request::Test {
            country: Some("ca".into()),
        });
        roundtrip(Request::Servers {
            country: None,
            limit: Some(10),
            all: false,
        });
        roundtrip(Request::Servers {
            country: Some("ca".into()),
            limit: None,
            all: true,
        });
        roundtrip(Request::LastRanking { limit: Some(12) });
        roundtrip(Request::LastRanking { limit: None });
        roundtrip(Request::Reload);
        roundtrip(Request::Version);
        roundtrip(Request::Autotune);
        roundtrip(Request::Approve);
        roundtrip(Request::Dismiss);
        roundtrip(Request::Speedtest);
        roundtrip(Request::Baseline { confirm: true });
        roundtrip(Request::Baseline { confirm: false });
        roundtrip(Request::Killswitch { enable: None });
        roundtrip(Request::Killswitch { enable: Some(true) });
    }

    fn sample_ranked() -> RankedServer {
        RankedServer {
            name: "Kornephoros".into(),
            country_code: "ca".into(),
            country_name: "Canada".into(),
            location: "Toronto, Ontario".into(),
            load: 27,
            rtt_ms: 5.4,
            score: 0.891,
            entry: 3,
            endpoint: "1.2.3.4:1637".parse().unwrap(),
            mbps: Some(187.4),
            mbps_age_secs: Some(600),
            headroom_mbps: 4200,
        }
    }

    fn sample_status() -> StatusReport {
        StatusReport {
            connected: true,
            interface: "vpnmgr0".into(),
            server: Some("Kornephoros".into()),
            location: Some("Toronto, Ontario".into()),
            country_code: Some("ca".into()),
            endpoint: Some("1.2.3.4:1637".parse().unwrap()),
            entry: Some(3),
            last_handshake_secs: Some(12),
            healthy: true,
            tx_bytes: 100,
            rx_bytes: 200,
            last_sweep: Some(SweepSummary {
                probed: 231,
                reachable: 231,
                elapsed_ms: 12910,
                age_secs: 42,
                best: Some(sample_ranked()),
                all_unreachable: false,
            }),
            pending_switch: Some(sample_pending()),
            last_tune: Some("Kornephoros is healthy at 5.4ms".into()),
            next_tune_secs: Some(1500),
            baseline_mbps: Some(843.2),
            baseline_age_secs: Some(900),
        }
    }

    fn sample_pending() -> PendingSwitch {
        PendingSwitch {
            to: sample_ranked(),
            reason: "200.0ms is over the 80ms limit and this is 90% better".into(),
            age_secs: 12,
        }
    }

    fn response_roundtrip(response: Response) {
        let line = serde_json::to_string(&response)
            .unwrap_or_else(|e| panic!("{response:?} failed to serialise: {e}"));
        assert!(
            !line.contains('\n'),
            "framing requires single-line messages"
        );
        assert_eq!(serde_json::from_str::<Response>(&line).unwrap(), response);
    }

    /// Every variant, not just one. A list-valued variant used to fail to
    /// serialise while the map-valued ones passed, so covering a single
    /// variant proved nothing.
    #[test]
    fn every_response_variant_round_trips() {
        response_roundtrip(Response::Status(Box::new(sample_status())));
        response_roundtrip(Response::Ranking(vec![sample_ranked(), sample_ranked()]));
        response_roundtrip(Response::Ranking(vec![]));
        response_roundtrip(Response::Servers(vec![ServerSummary {
            name: "Kornephoros".into(),
            country_code: "ca".into(),
            country_name: "Canada".into(),
            location: "Toronto, Ontario".into(),
            load: 27,
            users: 300,
            healthy: true,
            headroom_mbps: 4200,
        }]));
        response_roundtrip(Response::Servers(vec![]));
        response_roundtrip(Response::ok("connected"));
        response_roundtrip(Response::error("nope"));
        response_roundtrip(Response::Version {
            version: "0.1.0".into(),
        });
        response_roundtrip(Response::Killswitch(KillswitchReport {
            engaged: true,
            configured: true,
            dropped: Some(0),
        }));
        response_roundtrip(Response::Speed(Box::new(SpeedReport {
            tunnelled: Some(SpeedSample {
                mbps: 187.4,
                bytes: 25_000_000,
                elapsed_ms: 1067,
                truncated: false,
            }),
            direct: None,
            server: Some("Kornephoros".into()),
            min_mbps: 50.0,
            meets_target: true,
            verdict: "187.4 Mbps through Kornephoros".into(),
        })));
        response_roundtrip(Response::Tuned(Box::new(TuneReport {
            summary: "switching to Chamukuy".into(),
            switched: true,
            nothing_reachable: false,
            pending: None,
        })));
        response_roundtrip(Response::Tuned(Box::new(TuneReport {
            summary: "Chamukuy looks better".into(),
            switched: false,
            nothing_reachable: false,
            pending: Some(sample_pending()),
        })));
    }

    #[test]
    fn an_unknown_request_is_rejected_rather_than_defaulted() {
        assert!(serde_json::from_str::<Request>(r#"{"request":"self_destruct"}"#).is_err());
    }

    #[test]
    fn error_responses_carry_their_message() {
        let e = Response::error("no candidates");
        assert!(matches!(e, Response::Error { message } if message == "no candidates"));
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_group_is_reported_rather_than_guessed() {
        assert_eq!(group_id("definitely-not-a-real-group-9x8y7z"), None);
    }

    #[cfg(unix)]
    #[test]
    fn root_group_resolves() {
        // Present on every Linux system; sanity-checks the getgrnam binding.
        assert!(group_id("root").is_some() || group_id("wheel").is_some());
    }

    /// The endpoint has to be the kind of name its platform can actually open:
    /// a filesystem path on Unix, and a name in the pipe namespace on Windows
    /// — where a path would be created as a file and never accept a client.
    #[test]
    fn the_default_endpoint_suits_its_platform() {
        if cfg!(windows) {
            assert!(
                DEFAULT_SOCKET.starts_with(r"\\.\pipe\"),
                "{DEFAULT_SOCKET} is not in the named pipe namespace"
            );
        } else {
            assert!(
                DEFAULT_SOCKET.starts_with('/'),
                "{DEFAULT_SOCKET} is not a path"
            );
        }
    }
}
