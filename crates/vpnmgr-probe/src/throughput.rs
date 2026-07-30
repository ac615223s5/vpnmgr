//! Tier 2: how fast is the link actually carrying data?
//!
//! Handshake RTT answers "is this server close and alive", which is what makes
//! it cheap enough to run across the whole fleet. It says nothing about
//! bandwidth: a nearby server can still be saturated. This measures the thing
//! the user actually cares about, by downloading a payload and timing it.
//!
//! It is expensive by comparison — seconds and megabytes per measurement — so
//! it is never part of a sweep. It measures one path: whatever the process's
//! routing sends it down. With the tunnel up that is the tunnel, which is
//! exactly the "test the current connection" case.
//!
//! # Why the first stretch is discarded
//!
//! TCP starts slow and ramps up. Timing a whole short transfer therefore
//! measures the ramp rather than the steady state and under-reports badly. A
//! warm-up prefix is excluded from the timing, so what is reported is the rate
//! once the connection has opened up.

use std::time::{Duration, Instant};

use futures_util::StreamExt;

/// Default payload source. Cloudflare's speed-test endpoint takes the byte
/// count as a parameter, is anycast so it is near almost everyone, and does not
/// require an account.
pub const DEFAULT_URL: &str = "https://speed.cloudflare.com/__down?bytes=";

/// How much to pull. Large enough to get past TCP slow start on a fast link,
/// small enough not to be rude to run occasionally.
pub const DEFAULT_BYTES: u64 = 25_000_000;

/// Bytes ignored before timing starts, to exclude TCP slow start.
const WARMUP_BYTES: u64 = 2_000_000;

#[derive(Debug, Clone)]
pub struct Settings {
    pub url: String,
    pub bytes: u64,
    pub timeout: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            url: format!("{DEFAULT_URL}{DEFAULT_BYTES}"),
            bytes: DEFAULT_BYTES,
            timeout: Duration::from_secs(30),
        }
    }
}

/// A completed throughput measurement.
#[derive(Debug, Clone, PartialEq)]
pub struct Throughput {
    /// Megabits per second, measured after the warm-up.
    pub mbps: f64,
    /// Bytes counted toward the measurement, excluding warm-up.
    pub bytes: u64,
    /// Time those bytes took.
    pub elapsed: Duration,
    /// Whether the transfer finished or was cut short by the timeout. A
    /// truncated measurement is still usable — it is a real rate over a real
    /// interval — but it is not the full payload.
    pub truncated: bool,
}

impl Throughput {
    fn from_parts(bytes: u64, elapsed: Duration, truncated: bool) -> Self {
        let seconds = elapsed.as_secs_f64();
        let mbps = if seconds > 0.0 {
            (bytes as f64 * 8.0) / seconds / 1_000_000.0
        } else {
            0.0
        };
        Self {
            mbps,
            bytes,
            elapsed,
            truncated,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("building the throughput client: {0}")]
    Client(#[source] reqwest::Error),
    #[error(
        "the download never started: {0}\n\
         if the tunnel is up, this usually means traffic is not flowing through it"
    )]
    Request(#[source] reqwest::Error),
    #[error("the server answered with {0}")]
    Status(reqwest::StatusCode),
    #[error("the transfer failed partway: {0}")]
    Transfer(#[source] reqwest::Error),
    #[error(
        "the link delivered nothing measurable in {0:?}; \
         it is either extremely slow or not carrying traffic at all"
    )]
    NothingTransferred(Duration),
}

/// Download the payload and report the rate.
///
/// Follows whatever route the process has, so the caller controls *what* is
/// being measured by controlling the tunnel, not by configuring this.
pub async fn measure(settings: &Settings) -> Result<Throughput, Error> {
    let client = reqwest::Client::builder()
        .timeout(settings.timeout)
        // A redirect to a different host would silently measure a different
        // path than the one asked for.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Error::Client)?;

    let response = client
        .get(&settings.url)
        // Compression must be off. The stream yields *decoded* bytes, so a
        // payload the server gzipped would be counted at its expanded size and
        // report a throughput far above what the link actually carried.
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(Error::Request)?;

    if !response.status().is_success() {
        return Err(Error::Status(response.status()));
    }

    let started = Instant::now();
    let mut stream = response.bytes_stream();

    let mut total: u64 = 0;
    // Timing starts once warm-up is past, not when the request was sent.
    let mut measuring_from: Option<Instant> = None;
    let mut measured: u64 = 0;
    let mut truncated = true;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(Error::Transfer)?;
        total += chunk.len() as u64;

        match measuring_from {
            None if total >= WARMUP_BYTES => measuring_from = Some(Instant::now()),
            Some(_) => measured += chunk.len() as u64,
            None => {}
        }

        if started.elapsed() >= settings.timeout {
            break;
        }
        if total >= settings.bytes {
            truncated = false;
            break;
        }
    }

    // On a link too slow (or too fast) to reach the warm-up mark, fall back to
    // timing the whole transfer rather than reporting nothing.
    let (bytes, elapsed) = match measuring_from {
        Some(at) if measured > 0 => (measured, at.elapsed()),
        _ => (total, started.elapsed()),
    };

    if bytes == 0 {
        return Err(Error::NothingTransferred(started.elapsed()));
    }

    Ok(Throughput::from_parts(bytes, elapsed, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn megabits_are_computed_from_bytes_and_time() {
        // 12.5 MB in one second is 100 Mbps.
        let t = Throughput::from_parts(12_500_000, Duration::from_secs(1), false);
        assert!((t.mbps - 100.0).abs() < 1e-6, "got {}", t.mbps);
    }

    #[test]
    fn a_faster_transfer_reports_a_higher_rate() {
        let slow = Throughput::from_parts(1_000_000, Duration::from_secs(2), false);
        let fast = Throughput::from_parts(1_000_000, Duration::from_secs(1), false);
        assert!(fast.mbps > slow.mbps);
    }

    /// Guards against a divide-by-zero turning into NaN or infinity, which
    /// would then propagate into a `min_mbps` comparison and behave oddly.
    #[test]
    fn a_zero_duration_does_not_produce_a_nonsense_rate() {
        let t = Throughput::from_parts(1_000, Duration::ZERO, false);
        assert!(t.mbps.is_finite());
        assert_eq!(t.mbps, 0.0);
    }

    #[test]
    fn the_default_url_requests_the_default_size() {
        let s = Settings::default();
        assert!(s.url.contains(&DEFAULT_BYTES.to_string()));
        assert_eq!(s.bytes, DEFAULT_BYTES);
    }

    #[test]
    fn truncation_is_reported_so_a_partial_result_is_not_mistaken_for_a_full_one() {
        let full = Throughput::from_parts(100, Duration::from_secs(1), false);
        let cut = Throughput::from_parts(100, Duration::from_secs(1), true);
        assert!(!full.truncated);
        assert!(cut.truncated);
    }

    /// Live, and therefore opt-in: needs working internet and moves 25 MB.
    #[tokio::test]
    #[ignore = "hits the network and transfers 25MB"]
    async fn measures_a_plausible_rate_against_the_real_endpoint() {
        let result = measure(&Settings::default()).await.expect("should measure");
        assert!(result.mbps > 0.1, "implausibly slow: {}", result.mbps);
        assert!(result.mbps < 100_000.0, "implausibly fast: {}", result.mbps);
        assert!(result.bytes > 0);
    }
}
