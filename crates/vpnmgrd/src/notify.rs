//! Desktop notifications, sent from a root daemon into a user's session.
//!
//! There is no ambient way for a system service to reach a desktop: the
//! notification bus is per-session, owned by the logged-in user. So each
//! candidate session is located under `/run/user/<uid>`, and `notify-send` is
//! run *as that user* with `DBUS_SESSION_BUS_ADDRESS` pointed at their bus.
//!
//! Dropping privileges for the child matters beyond correctness — D-Bus
//! rejects a connection whose SO_PEERCRED uid does not own the bus, so running
//! it as root would fail anyway.
//!
//! Every failure here is swallowed. A missing `notify-send`, a headless
//! machine, or a user who logged out are all normal, and none of them are a
//! reason to disturb the tunnel.

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

/// Below this, a uid belongs to a system account rather than a person.
#[cfg(target_os = "linux")]
const FIRST_HUMAN_UID: u32 = 1000;

/// Urgency hint passed to `notify-send`. Only the levels the daemon actually
/// raises are modelled; `low` would be indistinguishable from staying silent,
/// which is what routine outcomes already do.
#[derive(Debug, Clone, Copy)]
pub enum Urgency {
    Normal,
    Critical,
}

impl Urgency {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn as_str(self) -> &'static str {
        match self {
            Urgency::Normal => "normal",
            Urgency::Critical => "critical",
        }
    }
}

/// Post a notification to every logged-in desktop session. Never fails.
///
/// Blocking, but only for as long as `notify-send` takes to hand the message
/// to the bus; call it from a blocking context.
#[cfg(target_os = "linux")]
pub fn desktop(summary: &str, body: &str, urgency: Urgency) {
    for (uid, gid) in sessions() {
        let result = Command::new("notify-send")
            // The child must *be* the user, or their bus will refuse it.
            .uid(uid)
            .gid(gid)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path=/run/user/{uid}/bus"),
            )
            .env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"))
            .args([
                "--app-name=vpnmgr",
                "--icon=network-vpn",
                &format!("--urgency={}", urgency.as_str()),
                summary,
                body,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match result {
            Ok(status) if status.success() => {
                tracing::debug!(uid, "posted a desktop notification");
            }
            Ok(status) => {
                tracing::debug!(uid, %status, "notify-send rejected the notification");
            }
            Err(e) => {
                // Almost always "notify-send not installed"; log once at debug
                // so a headless box does not fill its journal.
                tracing::debug!(uid, error = %e, "could not run notify-send");
            }
        }
    }
}

/// The `(uid, gid)` of every session that currently has a D-Bus socket.
#[cfg(target_os = "linux")]
fn sessions() -> Vec<(u32, u32)> {
    let Ok(entries) = std::fs::read_dir("/run/user") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(uid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if uid < FIRST_HUMAN_UID {
            continue;
        }
        // No bus socket means nobody is home, so there is nothing to notify.
        if !entry.path().join("bus").exists() {
            continue;
        }
        let gid = entry.metadata().map(|m| m.gid()).unwrap_or(uid);
        out.push((uid, gid));
    }
    out
}

/// Windows services run in Session 0, which has no desktop and cannot be given
/// one -- that isolation is the whole point of it, and the reason the
/// "Interactive Services Detection" shim was removed from Windows years ago.
/// A service therefore has no way to raise a notification at all.
///
/// So the daemon records the event and the tray, which does run in the user's
/// session and already polls for state, is what surfaces it. Keeping the same
/// signature means the calling code does not have to know any of this.
#[cfg(not(target_os = "linux"))]
pub fn desktop(summary: &str, body: &str, urgency: Urgency) {
    tracing::info!(?urgency, "{summary}: {body}");
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn enumerating_sessions_never_panics() {
        // Works whether or not anyone is logged in, and on a machine with no
        // /run/user at all.
        let _ = sessions();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_accounts_are_not_treated_as_desktops() {
        // root has a /run/user/0 on some systems; notifying it is meaningless.
        assert!(sessions().iter().all(|(uid, _)| *uid >= FIRST_HUMAN_UID));
    }

    #[test]
    fn posting_a_notification_cannot_fail() {
        // The point of the API: safe to call unconditionally.
        desktop("vpnmgr test", "this is a unit test", Urgency::Normal);
    }
}
