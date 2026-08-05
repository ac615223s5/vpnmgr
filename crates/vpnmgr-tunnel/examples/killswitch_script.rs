//! Print the kill switch ruleset without applying it.
//!
//!     cargo run -p vpnmgr-tunnel --example killswitch_script -- [--lan] [cidr...]
//!
//! The counterpart of reading `nft list table inet vpnmgr` on Linux, except
//! that this works before the rules exist. Worth checking before engaging
//! anything: the Windows ruleset is generated PowerShell, and a quoting mistake
//! there would fail halfway through, after some rules were created and possibly
//! after the default action had already changed.

use vpnmgr_tunnel::Killswitch;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let lan = args.iter().any(|a| a == "--lan");
    args.retain(|a| a != "--lan");

    let killswitch = Killswitch::new(
        vpnmgr_tunnel::DEFAULT_INTERFACE,
        vpnmgr_tunnel::DEFAULT_FWMARK,
        lan,
    )
    .allowing(args);

    println!("{}", killswitch.script());
    eprintln!("--- not applied. To apply: vpnmgr killswitch on ---");
    eprintln!("{}", Killswitch::recovery_hint());
}
