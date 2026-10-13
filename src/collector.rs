//! Collector trait and the scheduler that drives collectors on their intervals.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use metrics::{counter, describe_counter, describe_gauge, gauge};
use tokio::time::{MissedTickBehavior, interval_at, timeout};

/// A source of metrics. `collect` updates metrics-rs handles directly.
///
/// Collectors must be cheap to call repeatedly: resolve sysctl MIBs, compile
/// regexes, etc. at construction time, not in `collect`.
pub trait Collector: Send + 'static {
    /// Stable name used for the `collector` label on self-monitoring metrics.
    fn name(&self) -> &'static str;

    /// Registers HELP texts. Called once, after the recorder is installed.
    fn describe(&self) {}

    fn collect(&mut self) -> impl Future<Output = Result<()>> + Send;
}

/// Object-safe adapter so collectors of different types can live in one list.
trait DynCollector: Send {
    fn name(&self) -> &'static str;
    fn describe(&self);
    fn collect_boxed(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

impl<C: Collector> DynCollector for C {
    fn name(&self) -> &'static str {
        Collector::name(self)
    }

    fn describe(&self) {
        Collector::describe(self);
    }

    fn collect_boxed(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(self.collect())
    }
}

/// A collector together with its schedule and error-logging state.
pub struct Scheduled {
    collector: Box<dyn DynCollector>,
    interval: Duration,
    last_error: Option<(String, Instant)>,
}

/// Repeated identical errors are logged at most this often.
const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(300);

impl Scheduled {
    pub fn new(collector: impl Collector, interval: Duration) -> Self {
        Self {
            collector: Box::new(collector),
            interval,
            last_error: None,
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn describe(&self) {
        self.collector.describe();
    }

    /// Runs one collection, bounded by the collector's interval, and records
    /// self-monitoring metrics. Returns whether it succeeded.
    pub async fn run_once(&mut self) -> bool {
        let name = self.collector.name();
        let start = Instant::now();
        let result = match timeout(self.interval, self.collector.collect_boxed()).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("timed out after {:?}", self.interval)),
        };
        gauge!("calipers_collector_duration_seconds", "collector" => name)
            .set(start.elapsed().as_secs_f64());

        let errors = counter!("calipers_collector_errors_total", "collector" => name);
        match result {
            Ok(()) => {
                // Touch the counter so it exists (and doesn't expire) while healthy.
                errors.increment(0);
                gauge!("calipers_collector_last_success_timestamp_seconds", "collector" => name)
                    .set(unix_now());
                if self.last_error.take().is_some() {
                    tracing::info!(collector = name, "collector recovered");
                }
                true
            }
            Err(err) => {
                errors.increment(1);
                let message = format!("{err:#}");
                let should_log = match &self.last_error {
                    Some((last, at)) => *last != message || at.elapsed() >= ERROR_LOG_INTERVAL,
                    None => true,
                };
                if should_log {
                    tracing::warn!(collector = name, error = %message, "collection failed");
                    self.last_error = Some((message, Instant::now()));
                }
                false
            }
        }
    }

    /// Collects immediately, then on every wall-clock multiple of the interval
    /// (like Telegraf's `round_interval`), forever.
    pub async fn run_forever(mut self) {
        self.run_once().await;
        let start = tokio::time::Instant::now() + delay_to_next_boundary(self.interval);
        let mut ticker = interval_at(start, self.interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            self.run_once().await;
        }
    }
}

pub fn describe() {
    describe_gauge!(
        "calipers_collector_duration_seconds",
        "Wall-clock duration of the last collection."
    );
    describe_counter!(
        "calipers_collector_errors_total",
        "Number of failed or timed-out collections."
    );
    describe_gauge!(
        "calipers_collector_last_success_timestamp_seconds",
        "Unix time of the last successful collection."
    );
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn delay_to_next_boundary(interval: Duration) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let interval_ns = interval.as_nanos();
    let rem = now.as_nanos() % interval_ns;
    // `rem < interval_ns <= u64::MAX` for any sane interval.
    Duration::from_nanos(u64::try_from(interval_ns - rem).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_delay_is_within_interval() {
        for secs in [1, 10, 60, 3600] {
            let interval = Duration::from_secs(secs);
            let delay = delay_to_next_boundary(interval);
            assert!(!delay.is_zero() && delay <= interval);
        }
    }

    struct Failing;

    impl Collector for Failing {
        fn name(&self) -> &'static str {
            "failing"
        }

        async fn collect(&mut self) -> Result<()> {
            anyhow::bail!("boom")
        }
    }

    struct Hanging;

    impl Collector for Hanging {
        fn name(&self) -> &'static str {
            "hanging"
        }

        async fn collect(&mut self) -> Result<()> {
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failures_and_timeouts_are_reported() {
        assert!(
            !Scheduled::new(Failing, Duration::from_secs(1))
                .run_once()
                .await
        );
        assert!(
            !Scheduled::new(Hanging, Duration::from_secs(1))
                .run_once()
                .await
        );
    }
}
