//! Reset handling for per-object kernel counters.
//!
//! metrics-rs implements `Counter::absolute` as `fetch_max`, so an exported
//! counter can never decrease. Kernel counters of individual objects do reset
//! while calipers runs: a network interface is destroyed and recreated with
//! the same name, a disk is re-attached, a pool is re-imported, a PID is
//! reused. Exported as-is, the counter would freeze at its old maximum until
//! the new value overtakes it, and `rate()` would read 0 in between.
//!
//! [`Monotonic`] turns such raw values into a monotonic series: when a raw
//! value drops, the previous total is carried forward as an offset, so the
//! exported counter keeps increasing and `rate()` stays correct across the
//! reset. System-wide counters that only reset at reboot (when calipers
//! restarts too) don't need this.

// Used by the FreeBSD collectors (and tests).
#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Series not updated for this long are forgotten. Longer than the
/// exporter's idle timeout, so a series that comes back after being dropped
/// there starts a fresh exported series anyway.
const RETENTION: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct Series {
    last_raw: u64,
    offset: u64,
    seen: Instant,
}

#[derive(Debug, Default)]
pub struct Monotonic {
    series: HashMap<String, Series>,
}

impl Monotonic {
    /// Returns the value to export for the series `id` given its current raw
    /// value. `id` must identify the series uniquely (metric name + labels).
    pub fn correct(&mut self, id: &str, raw: u64) -> u64 {
        self.correct_at(id, raw, Instant::now())
    }

    fn correct_at(&mut self, id: &str, raw: u64, now: Instant) -> u64 {
        let series = match self.series.get_mut(id) {
            Some(s) => s,
            None => self.series.entry(id.to_owned()).or_insert(Series {
                last_raw: raw,
                offset: 0,
                seen: now,
            }),
        };
        if raw < series.last_raw {
            series.offset = series.offset.saturating_add(series.last_raw);
        }
        series.last_raw = raw;
        series.seen = now;
        series.offset.saturating_add(raw)
    }

    /// Forgets series that haven't been updated for a long time. Call once
    /// per collection.
    pub fn prune(&mut self) {
        self.prune_at(Instant::now());
    }

    fn prune_at(&mut self, now: Instant) {
        self.series
            .retain(|_, s| now.duration_since(s.seen) < RETENTION);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_through_until_reset_then_continues() {
        let mut m = Monotonic::default();
        let now = Instant::now();
        assert_eq!(m.correct_at("a", 100, now), 100);
        assert_eq!(m.correct_at("a", 150, now), 150);
        // Interface recreated: raw restarts at 10.
        assert_eq!(m.correct_at("a", 10, now), 160);
        assert_eq!(m.correct_at("a", 30, now), 180);
        // Second reset.
        assert_eq!(m.correct_at("a", 5, now), 185);
        // Other series are independent.
        assert_eq!(m.correct_at("b", 7, now), 7);
    }

    #[test]
    fn forgets_old_series() {
        let mut m = Monotonic::default();
        let start = Instant::now();
        m.correct_at("a", 100, start);
        m.correct_at("b", 100, start + RETENTION);
        m.prune_at(start + RETENTION + Duration::from_secs(1));
        assert!(!m.series.contains_key("a"));
        assert!(m.series.contains_key("b"));
        // A forgotten series starts over without an offset.
        assert_eq!(m.correct_at("a", 3, start + RETENTION), 3);
    }
}
