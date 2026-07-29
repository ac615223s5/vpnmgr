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
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub mod client;

/// Default socket path. Under `/run` so it vanishes on reboot.
pub const DEFAULT_SOCKET: &str = "/run/vpnmgr/sock";

/// Group granted access to the socket.
pub const SOCKET_GROUP: &str = "vpnmgr";

/// Longest message accepted, to bound what a client can make the daemon buffer.
pub const MAX_LINE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Current tunnel state.
    Status,
    /// Connect, picking the best server when `server` is `None`.
    Connect { server: Option<String> },
    Disconnect,
    /// Move an existing tunnel to a different server.
    Switch { server: String },
    /// Run a probe sweep and return the ranking without connecting.
    Test { country: Option<String> },
    /// List known servers from the cached API data. Does not probe.
    Servers {
        country: Option<String>,
        limit: Option<usize>,
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
    Ok { message: String },
    Error { message: String },
    Version { version: String },
    /// Outcome of a tuning pass.
    Tuned(Box<TuneReport>),
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
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "cannot reach vpnmgrd at {path}: {source}\n\
         is the daemon running? try: systemctl status vpnmgrd"
    )]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "permission denied opening {path}\n\
         add yourself to the '{SOCKET_GROUP}' group: sudo usermod -aG {SOCKET_GROUP} $USER\n\
         then log out and back in"
    )]
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
pub fn socket_permissions(path: &Path) -> std::io::Result<bool> {
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
        assert!(!line.contains('\n'), "framing requires single-line messages");
        assert_eq!(serde_json::from_str::<Request>(&line).unwrap(), request);
    }

    #[test]
    fn requests_round_trip() {
        roundtrip(Request::Status);
        roundtrip(Request::Connect { server: None });
        roundtrip(Request::Connect {
            server: Some("Kornephoros".into()),
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
        });
        roundtrip(Request::Reload);
        roundtrip(Request::Version);
        roundtrip(Request::Autotune);
        roundtrip(Request::Approve);
        roundtrip(Request::Dismiss);
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
        assert!(!line.contains('\n'), "framing requires single-line messages");
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
        }]));
        response_roundtrip(Response::Servers(vec![]));
        response_roundtrip(Response::ok("connected"));
        response_roundtrip(Response::error("nope"));
        response_roundtrip(Response::Version {
            version: "0.1.0".into(),
        });
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

    #[test]
    fn a_missing_group_is_reported_rather_than_guessed() {
        assert_eq!(group_id("definitely-not-a-real-group-9x8y7z"), None);
    }

    #[test]
    fn root_group_resolves() {
        // Present on every Linux system; sanity-checks the getgrnam binding.
        assert!(group_id("root").is_some() || group_id("wheel").is_some());
    }
}
