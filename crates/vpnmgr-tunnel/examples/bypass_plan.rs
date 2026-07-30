//! Show what would be routed around the tunnel, without changing anything.
//!
//!     cargo run --release -p vpnmgr-tunnel --example bypass_plan -- [host...]

use vpnmgr_tunnel::Bypass;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // `--apply` installs the routes and then withdraws them, to prove the
    // mechanism works without needing a tunnel. The routes it adds duplicate
    // paths that already exist, so they change nothing while installed.
    let apply = args.iter().any(|a| a == "--apply");
    args.retain(|a| a != "--apply");

    let plan = Bypass::plan(&[], &args, true, "vpnmgr0");
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
    println!("\n-- verify with `ip route show table main` now --");
    std::thread::sleep(std::time::Duration::from_secs(6));
    bypass.remove();
    println!("withdrawn");
}
