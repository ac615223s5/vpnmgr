//! Running `vpnmgrd` as a Windows service.
//!
//! This is what `packaging/vpnmgrd.service` and systemd do on Linux: start the
//! daemon at boot, as an account with enough privilege to create network
//! adapters, and stop it cleanly on shutdown.
//!
//! # Why LocalSystem
//!
//! Installing a WireGuard tunnel service and rewriting the routing table are
//! administrative operations. Holding that privilege in one long-lived service
//! is the entire reason the CLI and tray can stay unprivileged — the same trade
//! the Linux build makes by running as root. The named pipe's DACL, not the
//! account, is what limits who can ask it to do things.
//!
//! # The shutdown bridge
//!
//! systemd sends SIGTERM; the SCM instead calls a control handler on one of its
//! own threads and expects the service to report progress. That handler cannot
//! await anything, so it flips a channel that the async side is selecting on,
//! which turns a callback into the same shutdown signal the Unix build gets.

use std::ffi::OsString;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::Notify;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

/// Name the SCM knows us by. Matches the Linux unit name so documentation and
/// muscle memory carry across.
pub const SERVICE_NAME: &str = "vpnmgrd";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Where the service writes its log.
///
/// Deliberately not inside `C:\ProgramDatapnmgr`, which is stripped down to
/// SYSTEM and Administrators to protect the key files -- a log nobody can read
/// without elevation is most of the way to no log at all.
pub const LOG_PATH: &str = r"C:\ProgramData\vpnmgr-logs\vpnmgrd.log";

/// Signalled when the SCM asks us to stop.
static SHUTDOWN: OnceLock<Notify> = OnceLock::new();

fn shutdown() -> &'static Notify {
    SHUTDOWN.get_or_init(Notify::new)
}

/// Wait for the service control manager to ask for a stop.
pub async fn stop_requested() {
    shutdown().notified().await;
}

define_windows_service!(ffi_service_main, service_main);

/// Hand this process to the SCM. Returns an error when we were not started as
/// a service, which is how `main` tells the two launch modes apart.
pub fn run() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = serve() {
        tracing::error!("service failed: {e}");
    }
}

fn serve() -> Result<(), windows_service::Error> {
    let handler = move |control| -> ServiceControlHandlerResult {
        match control {
            // Interrogate must be answered or the SCM considers us hung.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown().notify_waiters();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;

    let running = |state: ServiceState, wait_hint: Duration| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        // Shutdown as well as Stop: a machine powering off must tear the
        // tunnel down, or the next boot starts with a default route pointing
        // at an adapter that no longer exists.
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    };

    status_handle.set_service_status(running(ServiceState::Running, Duration::default()))?;

    crate::run_daemon();

    // Tearing the tunnel down can take a moment; the hint stops the SCM
    // declaring us unresponsive while it happens.
    status_handle.set_service_status(running(ServiceState::Stopped, Duration::from_secs(10)))?;
    Ok(())
}

/// Register the service with the SCM, pointing it at this executable.
pub fn install(config: &std::path::Path) -> Result<(), windows_service::Error> {
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("vpnmgr WireGuard VPN manager"),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().map_err(windows_service::Error::Winapi)?,
        // --service is what tells the copy the SCM launches to hand itself to
        // the dispatcher instead of running as a console program.
        launch_arguments: vec![
            OsString::from("--service"),
            OsString::from("--config"),
            config.as_os_str().to_owned(),
            // A service has no console. Without a log file its diagnostics are
            // written to a handle nobody holds.
            OsString::from("--log-file"),
            OsString::from(LOG_PATH),
        ],
        dependencies: vec![],
        // LocalSystem: see the module docs.
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description(
        "Keeps this machine on a fast AirVPN WireGuard server, re-testing periodically.",
    )?;
    Ok(())
}

pub fn uninstall() -> Result<(), windows_service::Error> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;

    // Stopping first means the tunnel comes down through the normal path
    // rather than being orphaned by the service record disappearing.
    if let Ok(status) = service.query_status()
        && status.current_state != ServiceState::Stopped
    {
        let _ = service.stop();
        std::thread::sleep(Duration::from_secs(2));
    }
    service.delete()?;
    Ok(())
}
