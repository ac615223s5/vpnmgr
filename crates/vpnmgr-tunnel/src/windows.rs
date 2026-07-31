//! Windows tunnel backend, driving the official WireGuard tunnel service.
//!
//! # Why not the same library as Linux
//!
//! `defguard_wireguard_rs` does support Windows, but its backend loads
//! `wireguard.dll` (WireGuardNT) from a path relative to the process working
//! directory and `expect()`s the result — a missing DLL is a panic inside a
//! `LazyLock`, not an error we could report. That DLL is also not part of the
//! WireGuard for Windows package; it ships separately. Worse, on Windows the
//! library's `configure_peer`, `remove_peer` and `configure_peer_routing` are
//! all no-ops, so the peer-level operations the Linux backend is built on do
//! not exist there at all.
//!
//! The official `wireguard.exe` is already installed, already signed, already
//! handles the adapter, addresses, routes and DNS, and exposes exactly the two
//! operations this design needs.
//!
//! # How the pieces map
//!
//! | Operation | Windows |
//! |---|---|
//! | up | write a `.conf`, `wireguard.exe /installtunnelservice` |
//! | switch | `wg.exe set <if> peer <key> endpoint <addr>` |
//! | down | `wireguard.exe /uninstalltunnelservice` |
//! | status | `wg.exe show <if> <field>` |
//!
//! The switch is the important one: it rewrites the endpoint on the running
//! adapter, leaving addresses, routes and DNS untouched. That is the same
//! cheap-switch property the Linux backend relies on, and it is what makes
//! re-tuning every 30 minutes reasonable.
//!
//! # The private key never passes through this process's output
//!
//! `wg show <if> dump` would answer every status question in one call, but its
//! first field is the interface *private key*. Anything that captured or
//! logged that output — an error path printing stderr, a trace of the command
//! — would leak it. The narrower `wg show <if> endpoints|latest-handshakes|
//! transfer|listen-port` subcommands return only what they name, so the key is
//! never in a buffer this process owns. Four spawns instead of one is a cheap
//! price for that.

use std::net::SocketAddr;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use crate::bypass::{Bypass, Route};
use crate::{Error, Result, TunnelBackend, TunnelSpec, TunnelStatus};

/// Stops a console window flashing up for every `wg show`. The tray polls
/// several times a minute, which without this is a visible flicker.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Where the WireGuard package puts its executables.
const INSTALL_DIR: &str = r"C:\Program Files\WireGuard";

/// Directory holding the rendered `.conf`.
///
/// Under `ProgramData` rather than a temp directory because the tunnel service
/// is registered with this path and re-reads it when Windows restarts the
/// service; a file removed after installation would leave a tunnel that works
/// until the first service restart and then does not.
fn config_dir() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_owned());
    Path::new(&base).join("vpnmgr")
}

fn wireguard_exe() -> PathBuf {
    Path::new(INSTALL_DIR).join("wireguard.exe")
}

fn wg_exe() -> PathBuf {
    Path::new(INSTALL_DIR).join("wg.exe")
}

/// A tunnel managed by the WireGuard tunnel service.
pub struct WindowsTunnel {
    interface: String,
    conf_path: PathBuf,
    /// Whether *we* installed the service, so `down` does not try to remove a
    /// tunnel somebody else owns.
    installed: bool,
    /// Destinations to keep on the physical link, and the routes installed for
    /// them once the tunnel is up.
    bypass_plan: Vec<Route>,
    bypass: Bypass,
}

impl WindowsTunnel {
    pub fn new(interface: impl Into<String>) -> Result<Self> {
        let interface = interface.into();
        if !wireguard_exe().exists() {
            return Err(Error::Wireguard {
                operation: "locating wireguard.exe",
                interface: interface.clone(),
                source: format!(
                    "{} not found. Install WireGuard for Windows \
                     (winget install WireGuard.WireGuard)",
                    wireguard_exe().display()
                )
                .into(),
            });
        }
        let conf_path = config_dir().join(format!("{interface}.conf"));
        Ok(Self {
            interface,
            conf_path,
            installed: false,
            bypass_plan: Vec::new(),
            bypass: Bypass::new(),
        })
    }

    /// Destinations that must not travel through the tunnel.
    pub fn with_bypass(mut self, plan: Vec<Route>) -> Self {
        self.bypass_plan = plan;
        self
    }

    /// Whether a tunnel service for this interface currently exists.
    ///
    /// Consulted rather than trusting `installed`, so a daemon restart adopts a
    /// tunnel it left behind instead of reporting it as down.
    pub fn service_exists(&self) -> bool {
        // `wg show <if>` fails when the interface is absent, and unlike
        // querying the service manager it needs no extra privilege.
        run(wg_exe(), &["show".into(), self.interface.clone()]).is_ok()
    }

    /// Write the config the tunnel service will read.
    ///
    /// The file holds the private and preshared keys, so the directory is
    /// stripped of inherited access and re-granted to SYSTEM and the
    /// administrators only. `ProgramData` is world-readable by default, and
    /// inheriting that here would publish the key to every account on the
    /// machine.
    fn write_config(&self, spec: &TunnelSpec<'_>) -> Result<()> {
        let dir = config_dir();
        std::fs::create_dir_all(&dir).map_err(|e| Error::Killswitch {
            operation: "creating the configuration directory",
            source: e,
        })?;

        // Best effort: a failure here is reported but does not stop the
        // connection, because the alternative is no VPN at all. It is logged
        // loudly since it means the key file is more readable than intended.
        match run(
            "icacls".into(),
            &[
                dir.display().to_string(),
                "/inheritance:r".into(),
                "/grant:r".into(),
                "*S-1-5-18:(OI)(CI)F".into(), // LocalSystem
                "/grant:r".into(),
                "*S-1-5-32-544:(OI)(CI)F".into(), // BUILTIN\Administrators
            ],
        ) {
            Ok(_) => tracing::debug!("locked down {}", dir.display()),
            Err(e) => tracing::warn!(
                "could not restrict access to {}: {e}. The WireGuard key file \
                 there may be readable by other accounts on this machine",
                dir.display()
            ),
        }

        let conf = vpnmgr_core::render::to_conf(spec.client, spec.endpoint);
        std::fs::write(&self.conf_path, conf).map_err(|e| Error::Killswitch {
            operation: "writing the tunnel configuration",
            source: e,
        })?;
        Ok(())
    }
}

impl TunnelBackend for WindowsTunnel {
    fn up(&mut self, spec: &TunnelSpec<'_>) -> Result<()> {
        spec.validate()?;

        // An interface left over from an unclean shutdown would make
        // /installtunnelservice fail with a name clash rather than take over.
        if self.service_exists() {
            tracing::info!(
                interface = %self.interface,
                "a tunnel service for this interface already exists; removing it first"
            );
            let _ = self.remove_service();
        }

        // Before the tunnel, not after. Windows picks the longest matching
        // prefix, so these beat the tunnel's default the moment it appears --
        // but only if they are already there. Installing them afterwards
        // leaves a window in which the LAN is unreachable.
        self.bypass.install(std::mem::take(&mut self.bypass_plan));

        self.write_config(spec)?;

        run(
            wireguard_exe(),
            &[
                "/installtunnelservice".into(),
                self.conf_path.display().to_string(),
            ],
        )
        .map_err(|e| self.classify("installing the tunnel service", e))?;

        self.installed = true;
        tracing::info!(
            interface = %self.interface,
            endpoint = %spec.endpoint,
            "tunnel service installed"
        );
        Ok(())
    }

    fn switch_endpoint(&mut self, spec: &TunnelSpec<'_>) -> Result<()> {
        spec.validate()?;

        // Rewrite the peer's endpoint in place. Addresses, routes and DNS are
        // properties of the adapter and are not touched.
        run(
            wg_exe(),
            &[
                "set".into(),
                self.interface.clone(),
                "peer".into(),
                spec.client.peer_public_key.to_string(),
                "endpoint".into(),
                spec.endpoint.to_string(),
            ],
        )
        .map_err(|e| self.classify("retargeting the peer", e))?;

        // The same endpoint-hijack hazard as on Linux: every AirVPN server
        // shares one peer key, so the server we just left can answer with a
        // handshake the kernel cannot distinguish from the intended one and
        // take the endpoint back. A fresh listen port makes its packets arrive
        // nowhere.
        if let Err(e) = run(
            wg_exe(),
            &[
                "set".into(),
                self.interface.clone(),
                "listen-port".into(),
                "0".into(),
            ],
        ) {
            tracing::warn!(
                "could not rotate the listen port after a switch: {e}. \
                 The previous server may be able to reclaim the endpoint"
            );
        }

        // The config on disk is what the service replays after a restart, so it
        // has to move with the tunnel or a reboot silently returns to the old
        // server.
        self.write_config(spec)?;

        tracing::info!(interface = %self.interface, endpoint = %spec.endpoint, "retargeted");
        Ok(())
    }

    fn down(&mut self) -> Result<()> {
        self.remove_service()?;
        self.bypass.remove();
        // The key material has no reason to outlive the tunnel.
        if let Err(e) = std::fs::remove_file(&self.conf_path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!("could not remove {}: {e}", self.conf_path.display());
        }
        self.installed = false;
        Ok(())
    }

    fn status(&self) -> Result<TunnelStatus> {
        let interface = self.interface.clone();

        // Absent interface means down, which is a state and not a failure.
        let Ok(listen_port) = wg_field(&interface, "listen-port") else {
            return Ok(TunnelStatus {
                interface,
                up: false,
                endpoint: None,
                last_handshake: None,
                tx_bytes: 0,
                rx_bytes: 0,
                listen_port: 0,
                fwmark: None,
            });
        };

        let endpoint = wg_field(&interface, "endpoints")
            .ok()
            .and_then(|s| peer_field(&s, 1))
            .and_then(|s| s.parse::<SocketAddr>().ok());

        let last_handshake = wg_field(&interface, "latest-handshakes")
            .ok()
            .and_then(|s| peer_field(&s, 1))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|secs| *secs > 0)
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));

        let transfer = wg_field(&interface, "transfer").unwrap_or_default();
        let rx_bytes = peer_field(&transfer, 1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let tx_bytes = peer_field(&transfer, 2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(TunnelStatus {
            interface,
            up: true,
            endpoint,
            last_handshake,
            tx_bytes,
            rx_bytes,
            listen_port: listen_port.trim().parse().unwrap_or(0),
            // No fwmark on Windows; the probe escape works by source-address
            // selection instead.
            fwmark: None,
        })
    }

    fn interface(&self) -> &str {
        &self.interface
    }
}

impl WindowsTunnel {
    fn remove_service(&mut self) -> Result<()> {
        run(
            wireguard_exe(),
            &["/uninstalltunnelservice".into(), self.interface.clone()],
        )
        .map_err(|e| self.classify("removing the tunnel service", e))?;
        Ok(())
    }

    /// Turn a command failure into the right error, so "run me as a service"
    /// is not reported as a generic WireGuard fault.
    fn classify(&self, operation: &'static str, e: CommandError) -> Error {
        if e.denied() {
            Error::PermissionDenied {
                operation,
                interface: self.interface.clone(),
            }
        } else {
            Error::Wireguard {
                operation,
                interface: self.interface.clone(),
                source: Box::new(e),
            }
        }
    }
}

impl Drop for WindowsTunnel {
    fn drop(&mut self) {
        if self.installed {
            let _ = self.down();
        }
    }
}

/// One `wg show <interface> <field>` call.
fn wg_field(interface: &str, field: &str) -> std::result::Result<String, CommandError> {
    run(
        wg_exe(),
        &["show".into(), interface.to_owned(), field.to_owned()],
    )
}

/// Field `n` of the first peer line, tab-separated as `wg` prints it.
///
/// There is exactly one peer — the whole AirVPN fleet shares a key — so the
/// first line is the only one.
fn peer_field(text: &str, n: usize) -> Option<String> {
    text.lines()
        .next()?
        .split('\t')
        .nth(n)
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty() && s != "(none)")
}

#[derive(Debug)]
pub struct CommandError {
    program: String,
    status: Option<i32>,
    stderr: String,
}

impl CommandError {
    /// Whether this looks like a privilege problem rather than a real fault.
    fn denied(&self) -> bool {
        let s = self.stderr.to_ascii_lowercase();
        s.contains("access is denied")
            || s.contains("administrator")
            || s.contains("elevat")
            || self.status == Some(5)
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.program)?;
        match self.status {
            Some(code) => write!(f, " exited {code}")?,
            None => write!(f, " did not run")?,
        }
        if !self.stderr.trim().is_empty() {
            write!(f, ": {}", self.stderr.trim())?;
        }
        Ok(())
    }
}

impl std::error::Error for CommandError {}

fn run(program: PathBuf, args: &[String]) -> std::result::Result<String, CommandError> {
    let output = Command::new(&program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| CommandError {
            program: program.display().to_string(),
            status: None,
            stderr: e.to_string(),
        })?;

    if !output.status.success() {
        return Err(CommandError {
            program: program.display().to_string(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_line_is_split_on_tabs() {
        let text = "PUBKEY\t1.2.3.4:1637\n";
        assert_eq!(peer_field(text, 1).as_deref(), Some("1.2.3.4:1637"));
    }

    /// `wg` prints `(none)` for an endpoint that has never been set, and an
    /// empty string for absent transfer counters. Neither is a value.
    #[test]
    fn absent_fields_are_none_rather_than_a_literal() {
        assert_eq!(peer_field("PUBKEY\t(none)\n", 1), None);
        assert_eq!(peer_field("PUBKEY\t\n", 1), None);
        assert_eq!(peer_field("PUBKEY\n", 1), None);
    }

    #[test]
    fn transfer_counters_are_rx_then_tx() {
        let text = "PUBKEY\t1024\t2048\n";
        assert_eq!(peer_field(text, 1).as_deref(), Some("1024"));
        assert_eq!(peer_field(text, 2).as_deref(), Some("2048"));
    }

    #[test]
    fn access_denied_is_recognised_as_a_privilege_problem() {
        let denied = CommandError {
            program: "wireguard.exe".into(),
            status: Some(1),
            stderr: "Access is denied.".into(),
        };
        assert!(denied.denied());

        let other = CommandError {
            program: "wireguard.exe".into(),
            status: Some(1),
            stderr: "Unable to parse config".into(),
        };
        assert!(!other.denied());
    }

    #[test]
    fn the_config_lives_somewhere_writable_by_a_service() {
        let dir = config_dir();
        assert!(
            dir.ends_with("vpnmgr"),
            "unexpected config directory: {dir:?}"
        );
    }
}
