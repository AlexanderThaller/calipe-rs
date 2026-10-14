//! Self-monitoring: build info and the agent's own resource usage.
//! Per-collector timings and errors are recorded by the scheduler.

use std::time::Duration;

use anyhow::Result;
use metrics::{
    describe_gauge,
    gauge,
};
use serde::Deserialize;

use crate::{
    collector::Collector,
    sys,
};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
}

pub struct Internal {
    start_time: f64,
}

impl Internal {
    pub fn new() -> Self {
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self { start_time }
    }
}

impl Collector for Internal {
    fn name(&self) -> &'static str {
        "internal"
    }

    fn describe(&self) {
        describe_gauge!(
            "calipers_build_info",
            "Always 1; labels carry build information."
        );
        describe_gauge!(
            "calipers_cpu_seconds_total",
            "CPU time consumed by calipers."
        );
        describe_gauge!("calipers_memory_rss_bytes", "Resident memory of calipers.");
        describe_gauge!("calipers_start_time_seconds", "Unix time calipers started.");
    }

    async fn collect(&mut self) -> Result<()> {
        // Re-set every time so these don't hit the exporter's idle timeout.
        gauge!("calipers_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
        gauge!("calipers_start_time_seconds").set(self.start_time);

        let (user, system) = sys::self_cpu_seconds()?;
        // metrics-rs counters are u64, so fractional totals are exported as
        // gauges (see dev.adoc, "Counters").
        gauge!("calipers_cpu_seconds_total", "mode" => "user").set(user);
        gauge!("calipers_cpu_seconds_total", "mode" => "system").set(system);

        gauge!("calipers_memory_rss_bytes").set(sys::self_rss_bytes()? as f64);
        Ok(())
    }
}
