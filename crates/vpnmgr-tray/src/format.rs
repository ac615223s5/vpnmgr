//! Label formatting shared by both trays.
//!
//! The two implementations have no code in common — D-Bus on one side, Win32 on
//! the other — but they describe the same state, and a figure that reads one way
//! on Linux and another on Windows would be a bug of its own.

/// How long ago a throughput figure was taken, compactly.
///
/// Always shown alongside the number: an old measurement describes conditions
/// that may be long gone, and presenting it bare would imply it still holds.
pub fn measured_ago(secs: u64) -> String {
    match secs {
        s if s < 90 => "just now".to_owned(),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86_400),
    }
}

/// A rate in Mbit/s, at a scale that stays readable in a menu.
///
/// Server headroom runs from tens of Mbit/s to well over ten thousand, and six
/// digits in a menu label are noise — nobody is comparing 11400 against 11380.
pub fn rate(mbps: f64) -> String {
    if mbps >= 1000.0 {
        format!("{:.1} Gbps", mbps / 1000.0)
    } else {
        format!("{mbps:.0} Mbps")
    }
}

pub fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_owned()
    } else {
        s.chars().take(width.saturating_sub(1)).collect::<String>() + "…"
    }
}

pub fn human_bytes(bytes: u64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_switch_to_gbps_where_the_digits_stop_helping() {
        assert_eq!(rate(940.0), "940 Mbps");
        assert_eq!(rate(11_400.0), "11.4 Gbps");
    }

    #[test]
    fn ages_read_naturally_at_every_scale() {
        assert_eq!(measured_ago(5), "just now");
        assert_eq!(measured_ago(600), "10m ago");
        assert_eq!(measured_ago(7200), "2h ago");
        assert_eq!(measured_ago(200_000), "2d ago");
    }

    #[test]
    fn truncation_keeps_the_width_it_promises() {
        assert_eq!(truncate("Toronto", 20), "Toronto");
        assert_eq!(truncate("a-very-long-location", 10).chars().count(), 10);
    }
}
