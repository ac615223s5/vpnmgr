//! `vpnmgr` — the command-line client for `vpnmgrd`.
//!
//! Does no privileged work of its own; every command is a round trip over the
//! daemon socket.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vpnmgr_ipc::{DEFAULT_SOCKET, RankedServer, Request, Response, SpeedReport, StatusReport};

#[derive(Parser)]
#[command(name = "vpnmgr", about = "Control the WireGuard VPN manager", version)]
struct Args {
    /// Daemon socket.
    #[arg(long, default_value = DEFAULT_SOCKET, global = true)]
    socket: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the current connection.
    Status,
    /// Connect, choosing the best server unless one is named.
    Connect {
        /// Server name, e.g. Kornephoros.
        server: Option<String>,
        /// Measure this connection and the candidates before settling.
        ///
        /// Slower, and the only way the acceptance bar reflects your actual
        /// line rate rather than a default.
        #[arg(long, conflicts_with = "quick")]
        measure: bool,
        /// Connect straight away, trusting the ranking without measuring.
        #[arg(long, conflicts_with = "measure")]
        quick: bool,
    },
    /// Tear the tunnel down.
    Disconnect,
    /// Move an existing connection to another server.
    Switch {
        server: String,
    },
    /// Probe servers and show the ranking without connecting.
    Test {
        /// Restrict to one country code, e.g. ca.
        #[arg(long)]
        country: Option<String>,
        /// How many results to show.
        #[arg(long, default_value_t = 15)]
        limit: usize,
    },
    /// List known servers and their load. Does not probe.
    Servers {
        #[arg(long)]
        country: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show the ranking from the last sweep without probing again.
    Ranking {
        /// How many results to show.
        #[arg(long, default_value_t = 15)]
        limit: usize,
    },
    /// Re-read the daemon's configuration file.
    Reload,
    /// Run a tuning pass now rather than waiting for the schedule.
    Autotune,
    /// Carry out the switch the tuner is waiting on.
    Approve,
    /// Discard the tuner's pending proposal.
    Dismiss,
    /// Measure throughput on the current connection.
    Speedtest,
    /// Compare throughput through the VPN against your connection without it.
    ///
    /// Briefly drops the tunnel, which exposes your real IP address.
    Baseline {
        /// Required, because this exposes your real IP address.
        #[arg(long)]
        yes: bool,
    },
    /// Turn the kill switch on or off, or show its state.
    Killswitch {
        #[arg(value_parser = ["on", "off"])]
        state: Option<String>,
    },
    /// Import an AirVPN .conf and print the config file to install.
    Import {
        /// Path to the .conf from AirVPN's Config Generator.
        conf: PathBuf,
        /// Directory the key files will live in.
        #[arg(long, default_value = "/etc/vpnmgr")]
        dir: PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Import is purely local, so it works before the daemon is installed.
    if let Command::Import { conf, dir } = &args.command {
        return import(conf, dir);
    }

    let request = match &args.command {
        Command::Status => Request::Status,
        Command::Connect {
            server,
            measure,
            quick,
        } => Request::Connect {
            server: server.clone(),
            // Neither flag leaves the choice to autotune.measure_before_connect.
            measure: match (measure, quick) {
                (true, _) => Some(true),
                (_, true) => Some(false),
                _ => None,
            },
        },
        Command::Disconnect => Request::Disconnect,
        Command::Switch { server } => Request::Switch {
            server: server.clone(),
        },
        Command::Test { country, .. } => Request::Test {
            country: country.clone(),
        },
        Command::Servers { country, limit } => Request::Servers {
            country: country.clone(),
            limit: *limit,
        },
        Command::Ranking { limit } => Request::LastRanking {
            limit: Some(*limit),
        },
        Command::Reload => Request::Reload,
        Command::Autotune => Request::Autotune,
        Command::Approve => Request::Approve,
        Command::Dismiss => Request::Dismiss,
        Command::Speedtest => Request::Speedtest,
        Command::Baseline { yes } => Request::Baseline { confirm: *yes },
        Command::Killswitch { state } => Request::Killswitch {
            enable: state.as_deref().map(|s| s == "on"),
        },
        Command::Import { .. } => unreachable!("handled above"),
    };

    let response = match vpnmgr_ipc::client::request(&args.socket, &request).await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    match response {
        Response::Error { message } => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
        Response::Ok { message } => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Response::Version { version } => {
            println!("vpnmgrd {version}");
            ExitCode::SUCCESS
        }
        Response::Status(report) => {
            print_status(&report);
            ExitCode::SUCCESS
        }
        Response::Ranking(ranking) => {
            let limit = match args.command {
                Command::Test { limit, .. } | Command::Ranking { limit } => limit,
                _ => ranking.len(),
            };
            if ranking.is_empty() {
                println!("no sweep has run yet; try `vpnmgr test`");
                return ExitCode::SUCCESS;
            }
            print_ranking(&ranking, limit);
            ExitCode::SUCCESS
        }
        Response::Servers(servers) => {
            println!(
                "{:<16} {:<20} {:<16} {:>5} {:>7}  health",
                "SERVER", "LOCATION", "COUNTRY", "LOAD", "USERS"
            );
            for s in &servers {
                println!(
                    "{:<16} {:<20} {:<16} {:>4}% {:>7}  {}",
                    s.name,
                    truncate(&s.location, 20),
                    truncate(&s.country_name, 16),
                    s.load,
                    s.users,
                    if s.healthy { "ok" } else { "DEGRADED" }
                );
            }
            println!("\n{} servers", servers.len());
            ExitCode::SUCCESS
        }
        Response::Speed(report) => {
            print_speed(&report);
            ExitCode::SUCCESS
        }
        Response::Killswitch(report) => {
            println!(
                "kill switch: {}",
                if report.engaged { "ENGAGED" } else { "off" }
            );
            println!(
                "  applied on connect: {}",
                if report.configured { "yes" } else { "no" }
            );
            if let Some(dropped) = report.dropped {
                println!("  packets blocked   : {dropped}");
            }
            if report.engaged && !report.configured {
                println!("\n  engaged manually; `vpnmgr killswitch off` to clear it");
            }
            ExitCode::SUCCESS
        }
        Response::Tuned(report) => {
            println!("{}", report.summary);
            if let Some(pending) = &report.pending {
                println!(
                    "\n  {} ({}) at {:.1}ms, load {}%",
                    pending.to.name, pending.to.location, pending.to.rtt_ms, pending.to.load
                );
                println!("  run `vpnmgr approve` to switch, or `vpnmgr dismiss` to keep the current server");
            }
            ExitCode::SUCCESS
        }
    }
}

fn print_speed(report: &SpeedReport) {
    let line = |label: &str, s: &vpnmgr_ipc::SpeedSample| {
        println!(
            "  {label:<10}: {:>7.1} Mbps  ({:.1} MB in {:.2}s{})",
            s.mbps,
            s.bytes as f64 / 1_000_000.0,
            s.elapsed_ms as f64 / 1000.0,
            if s.truncated { ", timed out" } else { "" }
        );
    };

    if let Some(s) = &report.tunnelled {
        line(
            report.server.as_deref().unwrap_or("via VPN"),
            s,
        );
    }
    if let Some(s) = &report.direct {
        line("direct", s);
    }
    println!("\n{}", report.verdict);
}

fn print_status(report: &StatusReport) {
    if !report.connected {
        println!("disconnected");
    } else {
        let health = if report.healthy {
            "healthy"
        } else {
            // An interface can exist while carrying no traffic; saying
            // "connected" alone would be misleading.
            "NO RECENT HANDSHAKE"
        };
        println!(
            "connected to {} ({}, {})",
            report.server.as_deref().unwrap_or("?"),
            report.location.as_deref().unwrap_or("?"),
            report.country_code.as_deref().unwrap_or("?"),
        );
        println!("  interface : {}", report.interface);
        if let Some(endpoint) = report.endpoint {
            println!(
                "  endpoint  : {endpoint} (entry {})",
                report.entry.unwrap_or(0)
            );
        }
        println!(
            "  handshake : {} ({health})",
            match report.last_handshake_secs {
                Some(secs) => format!("{secs}s ago"),
                None => "never".to_owned(),
            }
        );
        println!(
            "  transfer  : {} up, {} down",
            human_bytes(report.tx_bytes),
            human_bytes(report.rx_bytes)
        );
    }

    if let Some(sweep) = &report.last_sweep {
        println!(
            "\nlast sweep: {}/{} reachable in {:.1}s, {}s ago",
            sweep.reachable,
            sweep.probed,
            sweep.elapsed_ms as f64 / 1000.0,
            sweep.age_secs
        );
        if let Some(best) = &sweep.best {
            println!(
                "  best available: {} ({}) at {:.1}ms",
                best.name, best.location, best.rtt_ms
            );
        }
    }

    if let Some(tune) = &report.last_tune {
        println!("\nlast tune: {tune}");
    }
    if let Some(secs) = report.next_tune_secs {
        println!("next tune: in {}", human_duration(secs));
    }

    // Last, and unmissable: this is the one thing in the report that is
    // waiting on the user rather than merely informing them.
    if let Some(pending) = &report.pending_switch {
        println!(
            "\nPENDING SWITCH to {} ({}) at {:.1}ms, raised {} ago",
            pending.to.name,
            pending.to.location,
            pending.to.rtt_ms,
            human_duration(pending.age_secs)
        );
        println!("  {}", pending.reason);
        println!("  `vpnmgr approve` to switch, `vpnmgr dismiss` to keep the current server");
    }
}

fn human_duration(secs: u64) -> String {
    match secs {
        0 => "moments".to_owned(),
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        s => format!("{}h {}m", s / 3600, (s % 3600) / 60),
    }
}

fn print_ranking(ranking: &[RankedServer], limit: usize) {
    // The speed column is blank for servers that have never been measured,
    // which is most of them: a throughput test moves tens of megabytes and only
    // runs against the server you are connected to.
    let any_measured = ranking.iter().any(|s| s.mbps.is_some());
    if any_measured {
        println!(
            "{:<16} {:<20} {:>4} {:>8} {:>6} {:>6} {:>12}  entry",
            "SERVER", "LOCATION", "CC", "RTT", "LOAD", "SCORE", "MEASURED"
        );
    } else {
        println!(
            "{:<16} {:<20} {:>4} {:>8} {:>6} {:>6}  entry",
            "SERVER", "LOCATION", "CC", "RTT", "LOAD", "SCORE"
        );
    }
    for s in ranking.iter().take(limit) {
        let measured = match (s.mbps, s.mbps_age_secs) {
            (Some(mbps), Some(age)) => format!("{mbps:.0} Mbps {}", short_age(age)),
            _ => String::new(),
        };
        if any_measured {
            println!(
                "{:<16} {:<20} {:>4} {:>6.1}ms {:>5}% {:>6.3} {:>12}  {}",
                s.name,
                truncate(&s.location, 20),
                s.country_code,
                s.rtt_ms,
                s.load,
                s.score,
                measured,
                s.entry
            );
        } else {
            println!(
                "{:<16} {:<20} {:>4} {:>6.1}ms {:>5}% {:>6.3}  {}",
                s.name,
                truncate(&s.location, 20),
                s.country_code,
                s.rtt_ms,
                s.load,
                s.score,
                s.entry
            );
        }
    }
    println!("\n{} servers ranked", ranking.len());
    if !any_measured {
        println!("run `vpnmgr speedtest` while connected to record a server's real speed");
    }
}

/// Compact age for the measured-speed column.
fn short_age(secs: u64) -> String {
    match secs {
        s if s < 90 => "now".to_owned(),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

/// Turn an AirVPN `.conf` into the files the daemon expects.
fn import(conf: &std::path::Path, dir: &std::path::Path) -> ExitCode {
    let client = match vpnmgr_core::ClientConfig::import(conf) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !client.matches_known_airvpn_key() {
        eprintln!(
            "warning: the peer key in this config is not the AirVPN fleet key this\n\
             build knows about. That is fine if AirVPN rotated it or this is another\n\
             provider -- the imported key is what gets used -- but server selection\n\
             assumes AirVPN's server list."
        );
    }
    if !client.is_full_tunnel() {
        eprintln!(
            "warning: this config does not route all traffic (no 0.0.0.0/0 in\n\
             AllowedIPs), so traffic outside its AllowedIPs will bypass the VPN."
        );
    }

    let (key_path, psk_path) = vpnmgr_core::wgconf::secret_paths(dir);
    let config = vpnmgr_core::Config::from_imported(&client, key_path.clone(), psk_path.clone());

    let toml = match toml_string(&config) {
        Ok(toml) => toml,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Printed rather than written: this needs root, and showing the commands
    // makes it obvious what is about to touch the system.
    println!("# Run these as root to install:\n");
    println!("install -d -m 0750 {}", dir.display());
    println!(
        "printf '%s' '<PRIVATE KEY FROM {}>' | install -m 0600 /dev/stdin {}",
        conf.display(),
        key_path.display()
    );
    if client.preshared_key.is_some() {
        println!(
            "printf '%s' '<PRESHARED KEY FROM {}>' | install -m 0600 /dev/stdin {}",
            conf.display(),
            psk_path.display()
        );
    }
    println!("\n# Then write {}/config.toml:\n", dir.display());
    println!("{toml}");
    ExitCode::SUCCESS
}

fn toml_string(config: &vpnmgr_core::Config) -> Result<String, String> {
    // toml is a dependency of vpnmgr-core; re-serialising here keeps the CLI
    // from needing its own copy.
    config
        .to_toml()
        .map_err(|e| format!("could not render config: {e}"))
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
