//! `vpnmgr-tray` — the desktop front end for `vpnmgrd`.
//!
//! Unprivileged, like the CLI: everything it does is a request over the daemon
//! endpoint. It exists so the auto-tuner's "ask before switching" policy has
//! somewhere to ask that does not involve watching a terminal.
//!
//! # Two trays, no shared code
//!
//! The Linux tray speaks StatusNotifierItem over D-Bus; the Windows one is a
//! Win32 shell notification icon driven by a message loop. They share the
//! protocol and nothing else, so each lives in its own module rather than
//! behind an abstraction that would fit neither.
//!
//! On Windows the tray carries a second responsibility. `vpnmgrd` runs as a
//! service in Session 0, which has no desktop and cannot raise a notification,
//! so the tray is the only thing that can tell the user a switch is waiting.

// Without this the tray is a console program, and Windows gives every console
// program a console: launching it from the Start Menu left an empty terminal
// sitting behind the tray icon for as long as the program ran. Ignored when
// building for anything else.
//
// The cost is that stdout and stderr go nowhere, so `--help` and `--version`
// would print into the void. `attach_parent_console` below buys them back when
// there is a terminal to attach to.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod format;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(target_os = "windows")]
fn main() {
    windows::main()
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn main() {
    eprintln!("vpnmgr-tray supports Linux and Windows; use the vpnmgr CLI here");
    std::process::exit(1);
}
