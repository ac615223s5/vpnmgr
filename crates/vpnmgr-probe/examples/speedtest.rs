//! Measure throughput on whatever path this process routes over.
//!
//!     cargo run --release -p vpnmgr-probe --example speedtest

use vpnmgr_probe::throughput::{self, Settings};

#[tokio::main]
async fn main() {
    let settings = Settings::default();
    println!("downloading {} bytes...", settings.bytes);
    match throughput::measure(&settings).await {
        Ok(t) => println!(
            "{:.1} Mbps ({} bytes in {:.2}s{})",
            t.mbps,
            t.bytes,
            t.elapsed.as_secs_f64(),
            if t.truncated { ", truncated" } else { "" }
        ),
        Err(e) => eprintln!("failed: {e}"),
    }
}
