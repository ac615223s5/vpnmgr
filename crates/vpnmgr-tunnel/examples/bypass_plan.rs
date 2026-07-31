//! Show what would be routed around the tunnel, without changing anything.
//!
//!     cargo run --release -p vpnmgr-tunnel --example bypass_plan -- \
//!         [--lan] [--reserve 10.128.0.1] [--apply] [host...]
//!
//! `--lan` plans the private-address bypass, and `--reserve` names an address
//! the tunnel itself would occupy, which excludes whichever private range
//! contains it. Together those reproduce what the daemon plans on connect,
//! while the tunnel stays down.

use std::net::IpAddr;

use vpnmgr_tunnel::Bypass;
use vpnmgr_tunnel::bypass::Request;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("vpnmgr_tunnel=info")
        .init();
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // `--apply` installs the routes and then withdraws them, to prove the
    // mechanism works without needing a tunnel. The routes it adds duplicate
    // paths that already exist, so they change nothing while installed.
    let apply = args.iter().any(|a| a == "--apply");
    let lan = args.iter().any(|a| a == "--lan");

    let mut reserved: Vec<IpAddr> = Vec::new();
    let mut rest: Vec<String> = Vec::new();
    let mut it = args.drain(..);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--apply" | "--lan" => {}
            "--reserve" => match it.next().map(|a| a.parse::<IpAddr>()) {
                Some(Ok(addr)) => reserved.push(addr),
                _ => {
                    eprintln!("--reserve needs an IP address");
                    std::process::exit(2);
                }
            },
            _ => rest.push(arg),
        }
    }

    let plan = Bypass::plan(&Request {
        cidrs: &[],
        hosts: &rest,
        other_vpns: true,
        lan,
        tunnel_addresses: &reserved,
        our_interface: "vpnmgr0",
    });
    if plan.is_empty() {
        println!("nothing would bypass the tunnel");
        return;
    }
    println!("{} destination(s) would bypass the tunnel:", plan.len());
    for route in &plan {
        println!("  {:<24} {:?}", route.destination, route.via);
    }

    if !apply {
        return;
    }

    let mut bypass = Bypass::new();
    bypass.install(plan);
    println!("\ninstalled {} route(s):", bypass.destinations().len());
    for d in bypass.destinations() {
        println!("  {d}");
    }
    println!(
        "\n-- verify with `Get-NetRoute` (Windows) or `ip route show table main` (Linux) now --"
    );
    std::thread::sleep(std::time::Duration::from_secs(6));
    bypass.remove();
    println!("withdrawn");
}
