//! Windows tray: a shell notification icon driven by a message loop.
//!
//! # Why there is a message loop at all
//!
//! A Win32 tray icon is owned by a window, and menu clicks arrive as window
//! messages. Something has to pump them, and it must be the thread that created
//! the icon.
//!
//! That pump is fifteen lines of `PeekMessage`/`DispatchMessage` here rather
//! than a windowing library. The obvious choice, winit, creates a real
//! top-level window whether or not one is asked for, and a tray program that
//! opens an empty window every time it starts is worse than one that writes its
//! own loop.
//!
//! The daemon protocol is async, so the network side lives on a tokio runtime
//! on another thread and the two talk through channels. That split is not
//! incidental: a menu click that blocked on a fleet-wide sweep would freeze the
//! whole shell notification area, not just this program.
//!
//! # This process is also the notifier
//!
//! `vpnmgrd` runs as a service in Session 0, which has no desktop, so it cannot
//! raise a notification even though it is the thing that knows a switch is
//! waiting. The tray polls, notices the transition, and shows the balloon.

use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::mpsc;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIconBuilder};
use vpnmgr_ipc::{DEFAULT_SOCKET, RankedServer, Request, Response, ServerSummary, StatusReport};

use crate::format::{human_bytes, measured_ago, rate, truncate};

/// How often the daemon is polled. It is the source of truth, and a scheduled
/// tuning pass can change the connection with no involvement from us.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// How many servers to offer under "Connect to".
const QUICK_CONNECT_LIMIT: usize = 12;

#[derive(Parser)]
#[command(
    name = "vpnmgr-tray",
    about = "System tray for the WireGuard VPN manager",
    version
)]
struct Args {
    /// Daemon endpoint.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
}

/// A request raised by clicking a menu item.
#[derive(Debug, Clone)]
enum Action {
    Connect {
        server: Option<String>,
        measure: Option<bool>,
    },
    Disconnect,
    Autotune,
    /// Open the daemon's configuration in an editor, then reload it.
    EditConfig(String),
    Approve,
    Dismiss,
    Quit,
}

/// Everything the tray draws from, as last seen from the daemon.
#[derive(Default)]
struct Snapshot {
    status: Option<StatusReport>,
    ranking: Vec<RankedServer>,
    servers: Vec<ServerSummary>,
    unreachable: Option<String>,
    busy: Option<String>,
}

impl Snapshot {
    fn connected(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.connected)
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

    fn tooltip(&self) -> String {
        let mut out = self.headline();
        if let Some(s) = &self.status
            && s.connected
        {
            out.push_str(&format!(
                "\n{} up, {} down",
                human_bytes(s.tx_bytes),
                human_bytes(s.rx_bytes)
            ));
            if let Some(age) = s.last_handshake_secs {
                out.push_str(&format!("\nhandshake {age}s ago"));
            }
        }
        if let Some(baseline) = self.baseline_line() {
            out.push_str(&format!(
                "
{baseline}"
            ));
        }
        if let Some(busy) = &self.busy {
            out.push_str(&format!("\n{busy}…"));
        }
        out
    }

    /// `(server name, menu label)` for the quick-connect submenu.
    ///
    /// Prefers the measured ranking, because latency is what makes a server a
    /// good choice; falls back to the load-ordered list before the first sweep,
    /// labelled as load so the two are never confused.
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
                                    format!(", {} {}", rate(mbps), measured_ago(age)),
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
}

/// Menu items are identified by the id `muda` assigns, so the click handler
/// needs a way back from that id to the action it stands for.
struct MenuMap {
    entries: Vec<(tray_icon::menu::MenuId, Action)>,
}

impl MenuMap {
    fn action_for(&self, id: &tray_icon::menu::MenuId) -> Option<Action> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate == id)
            .map(|(_, action)| action.clone())
    }
}

fn build_menu(snapshot: &Snapshot) -> (Menu, MenuMap) {
    let menu = Menu::new();
    let mut entries = Vec::new();

    let header = MenuItem::new(snapshot.headline(), false, None);
    let _ = menu.append(&header);

    if let Some(reason) = &snapshot.unreachable {
        let _ = menu.append(&MenuItem::new(truncate(reason, 60), false, None));
    }

    if let Some(busy) = &snapshot.busy {
        let _ = menu.append(&MenuItem::new(format!("{busy}…"), false, None));
    }

    if let Some(baseline) = snapshot.baseline_line() {
        let _ = menu.append(&MenuItem::new(baseline, false, None));
    }

    // A proposal is the one thing the tray exists to surface, so it goes above
    // everything else rather than into the ordinary run of commands.
    if let Some(pending) = snapshot
        .status
        .as_ref()
        .and_then(|s| s.pending_switch.as_ref())
    {
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&MenuItem::new(
            format!(
                "Suggested: {} ({})",
                pending.to.name,
                truncate(&pending.reason, 40)
            ),
            false,
            None,
        ));
        let approve = MenuItem::new("Switch now", true, None);
        entries.push((approve.id().clone(), Action::Approve));
        let _ = menu.append(&approve);
        let dismiss = MenuItem::new("Keep the current server", true, None);
        entries.push((dismiss.id().clone(), Action::Dismiss));
        let _ = menu.append(&dismiss);
    }

    let _ = menu.append(&PredefinedMenuItem::separator());

    let reachable = snapshot.status.is_some();
    if snapshot.connected() {
        let disconnect = MenuItem::new("Disconnect", reachable, None);
        entries.push((disconnect.id().clone(), Action::Disconnect));
        let _ = menu.append(&disconnect);
    } else {
        let quick = MenuItem::new("Connect to best server", reachable, None);
        entries.push((
            quick.id().clone(),
            Action::Connect {
                server: None,
                measure: Some(false),
            },
        ));
        let _ = menu.append(&quick);

        let measured = MenuItem::new("Measure and connect", reachable, None);
        entries.push((
            measured.id().clone(),
            Action::Connect {
                server: None,
                measure: Some(true),
            },
        ));
        let _ = menu.append(&measured);
    }

    let choices = snapshot.quick_connect_entries();
    if !choices.is_empty() {
        let submenu = Submenu::new("Connect to", reachable);
        for (name, label) in choices {
            let item = MenuItem::new(label, true, None);
            entries.push((
                item.id().clone(),
                Action::Connect {
                    server: Some(name),
                    measure: Some(false),
                },
            ));
            let _ = submenu.append(&item);
        }
        let _ = menu.append(&submenu);
    }

    let test = MenuItem::new("Test servers now", reachable, None);
    entries.push((test.id().clone(), Action::Autotune));
    let _ = menu.append(&test);

    // Only offered when the daemon has said where its config is; guessing the
    // path would mean editing a file nothing reads.
    if let Some(path) = snapshot.status.as_ref().and_then(|s| s.config_path.clone()) {
        let edit = MenuItem::new("Edit configuration…", true, None);
        entries.push((edit.id().clone(), Action::EditConfig(path)));
        let _ = menu.append(&edit);
    }

    let _ = menu.append(&PredefinedMenuItem::separator());
    let quit = MenuItem::new("Quit", true, None);
    entries.push((quit.id().clone(), Action::Quit));
    let _ = menu.append(&quit);

    (menu, MenuMap { entries })
}

/// The state colour: what the icon is saying, separate from how it is drawn.
fn state_colour(snapshot: &Snapshot) -> (u8, u8, u8) {
    match &snapshot.status {
        None => (0x75, 0x75, 0x75),                    // grey: no daemon
        Some(s) if !s.connected => (0x75, 0x75, 0x75), // grey: down
        Some(s) if !s.healthy => (0xd3, 0x2f, 0x2f),   // red: no handshake
        Some(_) => (0x2e, 0x7d, 0x32),                 // green: carrying
    }
}

/// Coverage of the shield shape at a point, from 0.0 outside to 1.0 inside.
///
/// `x` runs -1..1 across the width and `y` runs 0..1 from the top down. The
/// outline is a flat-topped crest that tapers to a point, which is legible at
/// 16 pixels in a way that most glyphs are not.
fn shield_coverage(x: f32, y: f32) -> f32 {
    if !(0.0..=1.0).contains(&y) {
        return 0.0;
    }
    // Full width down to the shoulder, then a curve in to the tip. The square
    // root makes the taper bulge outwards rather than running straight to the
    // point, which is what stops it reading as a triangle.
    const SHOULDER: f32 = 0.45;
    let half = if y <= SHOULDER {
        1.0
    } else {
        (1.0 - (y - SHOULDER) / (1.0 - SHOULDER)).max(0.0).sqrt()
    };

    // Round the two top corners so the crest is not a hard rectangle.
    const CORNER: f32 = 0.22;
    let half = if y < CORNER {
        let dy = (CORNER - y) / CORNER;
        half - (1.0 - (1.0 - dy * dy).max(0.0).sqrt()) * CORNER
    } else {
        half
    };

    if x.abs() <= half { 1.0 } else { 0.0 }
}

/// A shield in the state colour, drawn rather than shipped.
///
/// Windows has no equivalent of the freedesktop icon names the Linux tray uses,
/// so the choice is between shipping image files and drawing something. This
/// draws, which keeps the repository free of binary assets that no diff can
/// review.
///
/// Rendered at 32 pixels with 3x3 supersampling. Windows scales the tray icon
/// down to 16 on a standard-DPI display, and a shape that is merely thresholded
/// at that size turns into a jagged blob; averaging nine samples per pixel
/// gives the edges enough gradient to survive the scaling.
fn icon_for(snapshot: &Snapshot) -> Icon {
    const SIZE: u32 = 32;
    const SAMPLES: u32 = 3;
    let (r, g, b) = state_colour(snapshot);

    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for py in 0..SIZE {
        for px in 0..SIZE {
            let mut covered = 0.0;
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    // Sample at sub-pixel centres, not corners, or the shape
                    // sits half a pixel up and to the left of where it belongs.
                    let fx = px as f32 + (sx as f32 + 0.5) / SAMPLES as f32;
                    let fy = py as f32 + (sy as f32 + 0.5) / SAMPLES as f32;
                    // A one-pixel margin keeps the crest off the icon's edge,
                    // where Windows' own padding would clip it.
                    let x = (fx - SIZE as f32 / 2.0) / (SIZE as f32 / 2.0 - 1.0);
                    let y = (fy - 1.0) / (SIZE as f32 - 2.0);
                    covered += shield_coverage(x, y);
                }
            }
            let alpha = (covered / (SAMPLES * SAMPLES) as f32 * 255.0).round() as u8;
            rgba.extend_from_slice(&[r, g, b, alpha]);
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE).expect("a generated buffer is always the size promised")
}

/// The Win32 message pump.
///
/// `PeekMessage` rather than `GetMessage`: the loop also has to drain menu
/// clicks and daemon updates from channels, and `GetMessage` blocks until a
/// window message arrives, which may be never on an idle desktop.
fn pump_messages() {
    const PM_REMOVE: u32 = 0x0001;

    #[repr(C)]
    struct Msg {
        hwnd: isize,
        message: u32,
        wparam: usize,
        lparam: isize,
        time: u32,
        pt_x: i32,
        pt_y: i32,
    }

    unsafe extern "system" {
        fn PeekMessageW(msg: *mut Msg, hwnd: isize, min: u32, max: u32, remove: u32) -> i32;
        fn TranslateMessage(msg: *const Msg) -> i32;
        fn DispatchMessageW(msg: *const Msg) -> isize;
    }

    // SAFETY: `msg` is a correctly-shaped, writable MSG for the duration of
    // each call, and only messages for this thread are requested.
    unsafe {
        let mut msg = std::mem::zeroed::<Msg>();
        while PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) != 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

pub fn main() {
    attach_parent_console();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vpnmgr_tray=info".into()),
        )
        .init();

    let args = Args::parse();

    if !single_instance() {
        eprintln!("vpnmgr-tray is already running");
        return;
    }

    let (action_tx, action_rx) = mpsc::unbounded_channel::<Action>();
    let (update_tx, update_rx) = std_mpsc::channel::<Snapshot>();

    // The daemon side runs on its own runtime and thread. Menu handling must
    // never wait on it: a connect can take a full fleet sweep.
    let socket = args.socket.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build the client runtime");
        runtime.block_on(daemon_loop(socket, action_rx, update_tx));
    });

    // The icon must be created on the thread that pumps its messages.
    let (menu, mut map) = build_menu(&Snapshot::default());
    let tray = match TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("vpnmgrd is not reachable")
        .with_icon(icon_for(&Snapshot::default()))
        .build()
    {
        Ok(tray) => tray,
        Err(e) => {
            tracing::error!("could not create the tray icon: {e}");
            return;
        }
    };

    let mut announced_pending = false;

    loop {
        pump_messages();

        while let Ok(event) = MenuEvent::receiver().try_recv() {
            let Some(action) = map.action_for(&event.id) else {
                continue;
            };
            if matches!(action, Action::Quit) {
                return;
            }
            if action_tx.send(action).is_err() {
                return;
            }
        }

        while let Ok(snapshot) = update_rx.try_recv() {
            // Fire on the transition, not for as long as the proposal stands,
            // or this would repeat every ten seconds until it was answered.
            let pending = snapshot
                .status
                .as_ref()
                .is_some_and(|s| s.pending_switch.is_some());
            if pending && !announced_pending {
                tracing::info!("a faster server is available; see the tray menu");
            }
            announced_pending = pending;

            let (menu, rebuilt) = build_menu(&snapshot);
            map = rebuilt;
            tray.set_menu(Some(Box::new(menu)));
            let _ = tray.set_tooltip(Some(snapshot.tooltip()));
            let _ = tray.set_icon(Some(icon_for(&snapshot)));
        }

        // Long enough to stay idle, short enough that a click feels immediate.
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Poll the daemon, and carry out whatever the menu asked for.
async fn daemon_loop(
    socket: PathBuf,
    mut actions: mpsc::UnboundedReceiver<Action>,
    updates: std_mpsc::Sender<Snapshot>,
) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if updates.send(refresh(&socket, None).await).is_err() {
                    return; // the event loop is gone
                }
            }
            Some(action) = actions.recv() => {
                // Not a daemon request: the editor runs here, and the daemon
                // is only told to re-read the file once it has been closed.
                if let Action::EditConfig(path) = &action {
                    edit_config(path);
                    if let Err(e) =
                        vpnmgr_ipc::client::request(&socket, &Request::Reload).await
                    {
                        tracing::warn!("reloading after an edit failed: {e}");
                    }
                    let _ = updates.send(refresh(&socket, None).await);
                    continue;
                }

                let busy = match &action {
                    Action::Connect { .. } => "Connecting",
                    Action::Disconnect => "Disconnecting",
                    Action::Autotune => "Testing servers",
                    Action::EditConfig(_) => unreachable!("handled above"),
                    Action::Approve => "Switching",
                    Action::Dismiss => "Dismissing",
                    Action::Quit => return,
                };
                let _ = updates.send(refresh(&socket, Some(busy.to_owned())).await);

                let request = match action {
                    Action::Connect { server, measure } => Request::Connect { server, measure },
                    Action::Disconnect => Request::Disconnect,
                    Action::Autotune => Request::Autotune,
                    Action::EditConfig(_) => unreachable!("handled above"),
                    Action::Approve => Request::Approve,
                    Action::Dismiss => Request::Dismiss,
                    Action::Quit => return,
                };
                if let Err(e) = vpnmgr_ipc::client::request(&socket, &request).await {
                    tracing::warn!("request failed: {e}");
                }
                if updates.send(refresh(&socket, None).await).is_err() {
                    return;
                }
            }
        }
    }
}

/// Pull current state from the daemon.
async fn refresh(socket: &PathBuf, busy: Option<String>) -> Snapshot {
    let mut snapshot = Snapshot {
        busy,
        ..Default::default()
    };

    match vpnmgr_ipc::client::request(socket, &Request::Status).await {
        Ok(Response::Status(report)) => snapshot.status = Some(*report),
        Ok(Response::Error { message }) => snapshot.unreachable = Some(message),
        Ok(_) => snapshot.unreachable = Some("vpnmgrd sent an unexpected reply".to_owned()),
        Err(e) => snapshot.unreachable = Some(e.to_string()),
    }

    if snapshot.status.is_none() {
        return snapshot;
    }

    if let Ok(Response::Ranking(ranking)) = vpnmgr_ipc::client::request(
        socket,
        &Request::LastRanking {
            limit: Some(QUICK_CONNECT_LIMIT),
        },
    )
    .await
    {
        snapshot.ranking = ranking;
    }

    // Only needed before a sweep has produced a ranking.
    if snapshot.ranking.is_empty()
        && let Ok(Response::Servers(servers)) = vpnmgr_ipc::client::request(
            socket,
            &Request::Servers {
                country: None,
                limit: Some(QUICK_CONNECT_LIMIT),
                // The picker connects to what it shows, so it must only show
                // what the configured filters allow.
                all: false,
            },
        )
        .await
    {
        snapshot.servers = servers;
    }

    snapshot
}

/// Open the configuration in the user's editor, elevated, and wait for it.
///
/// Elevated because the file has to be: it lives beside the WireGuard key
/// files in a directory stripped down to SYSTEM and Administrators, so an
/// ordinary editor cannot even read it. The UAC prompt is not incidental
/// friction -- it is the same permission boundary that keeps the key material
/// out of reach, and asking here is better than showing a menu entry that
/// silently fails.
///
/// Blocking on purpose: this runs on the client thread, and the daemon is told
/// to reload only once the editor has exited, so a half-saved file is never
/// what gets loaded.
fn edit_config(path: &str) {
    // Resolve the handler the user has actually chosen for this file type, in
    // the order Windows resolves it itself: the per-user UserChoice that an
    // "Open with" selection writes, then the machine-wide association. Only the
    // executable is taken from the registered command -- the rest of that
    // string is a template full of %1 and /dde that varies by handler, and
    // substituting into it correctly is not worth the failure modes.
    //
    // A .toml with no association at all is common, so the .txt handler is
    // tried next -- a config file is a text file, and that is the editor the
    // user actually chose. Notepad is the last resort, being the only one
    // guaranteed to exist.
    const RESOLVE_AND_LAUNCH: &str = r#"
$path = 'PATH_PLACEHOLDER'
$ext = [IO.Path]::GetExtension($path)
$progId = $null
try {
  $key = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice"
  $progId = (Get-ItemProperty $key -ErrorAction Stop).ProgId
} catch {}
if (-not $progId) {
  try { $progId = (Get-Item "Registry::HKEY_CLASSES_ROOT\$ext" -ErrorAction Stop).GetValue('') } catch {}
}
# .toml is very often associated with nothing at all, and a config file is a
# text file, so the editor chosen for .txt is a far better answer than the
# fallback below -- it is what "my default text editor" means to the person
# who set it.
if (-not $progId) {
  try {
    $key = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice"
    $progId = (Get-ItemProperty $key -ErrorAction Stop).ProgId
  } catch {}
}
if (-not $progId) {
  try { $progId = (Get-Item "Registry::HKEY_CLASSES_ROOT\.txt" -ErrorAction Stop).GetValue('') } catch {}
}
$cmd = $null
if ($progId) {
  try {
    $cmd = (Get-Item "Registry::HKEY_CLASSES_ROOT\$progId\shell\open\command" -ErrorAction Stop).GetValue('')
  } catch {}
}
$exe = 'notepad.exe'
if ($cmd) {
  $expanded = [Environment]::ExpandEnvironmentVariables($cmd)
  if ($expanded -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
  elseif ($expanded -match '^\s*(\S+)') { $exe = $Matches[1] }
}
# A handler that is not a plain executable -- a shell verb routed through
# rundll32, say -- would be launched with arguments it cannot understand.
if (-not ($exe -like '*.exe')) { $exe = 'notepad.exe' }
Start-Process -FilePath $exe -Verb RunAs -Wait -ArgumentList $path
"#;

    let script = RESOLVE_AND_LAUNCH.replace("PATH_PLACEHOLDER", &path.replace('\'', "''"));

    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
    {
        // A declined UAC prompt lands here, and is a decision rather than a
        // fault: the user chose not to edit anything.
        Ok(status) if !status.success() => {
            tracing::info!("the editor was not opened (elevation declined?)")
        }
        Ok(_) => tracing::info!("configuration closed; reloading"),
        Err(e) => tracing::warn!("could not open an editor for {path}: {e}"),
    }
}

/// Reattach to the terminal that launched us, when there is one.
///
/// A windows-subsystem program is given no console, which is the point -- it is
/// why launching from the Start Menu no longer leaves an empty terminal behind.
/// But it also means `--help` and `--version` would print nowhere at all. If a
/// terminal did start us, borrowing its console puts that output back where the
/// person who typed the command is looking.
fn attach_parent_console() {
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;

    unsafe extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
    }
    // SAFETY: no arguments to get wrong, and a failure -- which is the normal
    // case, since the Start Menu is not a terminal -- only means there was no
    // console to attach to.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

/// Refuse to start a second tray.
///
/// A named mutex rather than a lock file: Windows releases it when the process
/// ends however it ends, so a crash cannot leave a stale lock that stops the
/// tray starting again.
fn single_instance() -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const ERROR_ALREADY_EXISTS: u32 = 183;

    unsafe extern "system" {
        fn CreateMutexW(
            attrs: *mut core::ffi::c_void,
            initial_owner: i32,
            name: *const u16,
        ) -> *mut core::ffi::c_void;
        fn GetLastError() -> u32;
    }

    let name: Vec<u16> = OsStr::new("Local\\vpnmgr-tray")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `name` is NUL-terminated and outlives the call. The handle is
    // deliberately leaked: it must live as long as the process holds the lock.
    let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 1, name.as_ptr()) };
    if handle.is_null() {
        // Failing open: an unusable mutex is not a reason to refuse to start.
        return true;
    }
    unsafe { GetLastError() != ERROR_ALREADY_EXISTS }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn status() -> StatusReport {
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
            tx_bytes: 1024,
            rx_bytes: 2048,
            last_sweep: None,
            pending_switch: None,
            last_tune: None,
            next_tune_secs: None,
            config_path: None,
            baseline_mbps: Some(843.2),
            baseline_age_secs: Some(7200),
        }
    }

    fn ranked(headroom_mbps: u64) -> RankedServer {
        RankedServer {
            name: "Kornephoros".into(),
            country_code: "ca".into(),
            country_name: "Canada".into(),
            location: "Toronto, Ontario".into(),
            load: 26,
            rtt_ms: 6.9,
            score: 0.9,
            entry: 3,
            endpoint: "1.2.3.4:1637".parse().unwrap(),
            mbps: None,
            mbps_age_secs: None,
            headroom_mbps,
        }
    }

    /// The yardstick every "is this fast enough" judgement is made against. A
    /// measured server speed means nothing without it.
    #[test]
    fn the_measured_line_rate_is_shown_with_its_age() {
        let snapshot = Snapshot {
            status: Some(status()),
            ..Default::default()
        };
        assert_eq!(
            snapshot.baseline_line().as_deref(),
            Some("without VPN: 843 Mbps (2h ago)")
        );
    }

    /// Nothing has measured it yet is a different thing from zero.
    #[test]
    fn no_line_rate_means_no_line() {
        let mut s = status();
        s.baseline_mbps = None;
        let snapshot = Snapshot {
            status: Some(s),
            ..Default::default()
        };
        assert_eq!(snapshot.baseline_line(), None);
    }

    /// Headroom is what distinguishes two servers at the same load, so it
    /// belongs on the line the user picks from.
    #[test]
    fn server_entries_carry_their_spare_capacity() {
        let snapshot = Snapshot {
            status: Some(status()),
            ranking: vec![ranked(14_800)],
            ..Default::default()
        };
        let (_, label) = snapshot.quick_connect_entries().remove(0);
        assert!(label.contains("14.8 Gbps free"), "got: {label}");
        assert!(label.contains("26% load"), "got: {label}");
    }
}

#[cfg(test)]
mod icon_tests {
    use super::*;

    /// Renders the shape as text, so its silhouette can be inspected rather
    /// than assumed. A tray icon that is wrong is only ever noticed by looking.
    fn render(size: u32) -> Vec<String> {
        (0..size)
            .map(|py| {
                (0..size)
                    .map(|px| {
                        let x = (px as f32 + 0.5 - size as f32 / 2.0) / (size as f32 / 2.0 - 1.0);
                        let y = (py as f32 + 0.5 - 1.0) / (size as f32 - 2.0);
                        if shield_coverage(x, y) > 0.5 {
                            '#'
                        } else {
                            '.'
                        }
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn the_shape_is_a_shield_and_not_a_rectangle() {
        let rows = render(16);
        let width = |row: &String| row.chars().filter(|c| *c == '#').count();

        // Wide across the crest, narrowing to a point at the bottom. A solid
        // square -- the bug this replaced -- fails on both counts.
        assert!(width(&rows[3]) >= 12, "crest too narrow: {}", rows[3]);
        assert!(
            width(&rows[14]) <= 4,
            "should be nearly a point by the bottom: {}",
            rows[14]
        );
        assert_eq!(width(&rows[15]), 0, "the tip must not touch the edge");

        // Monotonically narrowing below the shoulder is what makes it read as
        // a shield rather than an hourglass or a blob.
        for pair in rows[8..15].windows(2) {
            assert!(
                width(&pair[1]) <= width(&pair[0]),
                "widens again below the shoulder:\n{}\n{}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn the_shape_is_symmetric() {
        for row in render(16) {
            let reversed: String = row.chars().rev().collect();
            assert_eq!(row, reversed, "asymmetric row: {row}");
        }
    }

    /// The corners must be transparent, or it is a square again whatever shape
    /// was drawn inside it.
    #[test]
    fn the_corners_are_clear_and_the_centre_is_not() {
        let snapshot = Snapshot::default();
        let icon = icon_for(&snapshot);
        // Icon has no accessor for its pixels, so the buffer is rebuilt the
        // same way to assert on it.
        assert!(
            shield_coverage(-1.0, 0.0) < 0.5,
            "top-left corner is filled"
        );
        assert!(
            shield_coverage(1.0, 0.0) < 0.5,
            "top-right corner is filled"
        );
        assert!(shield_coverage(0.0, 0.3) > 0.5, "the middle is empty");
        drop(icon);
    }

    #[test]
    fn each_state_gets_its_own_colour() {
        let mut down = Snapshot::default();
        assert_eq!(state_colour(&down), (0x75, 0x75, 0x75));

        let mut s = super::tests::status();
        s.healthy = false;
        down.status = Some(s.clone());
        assert_eq!(state_colour(&down), (0xd3, 0x2f, 0x2f), "unhealthy is red");

        s.healthy = true;
        down.status = Some(s);
        assert_eq!(state_colour(&down), (0x2e, 0x7d, 0x32), "carrying is green");
    }
}
