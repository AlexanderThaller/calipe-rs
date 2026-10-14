#![expect(
    clippy::cast_precision_loss,
    reason = "metric values are f64; precision loss above 2^53 is irrelevant for metrics"
)]
#![expect(
    clippy::unused_async_trait_impl,
    reason = "Collector::collect is async; sysctl-based collectors implement it without awaiting"
)]

mod collector;
mod collectors;
mod config;
mod counter;
mod libnv;
mod nvlist;
mod sys;

use std::path::PathBuf;

use anyhow::{
    Context,
    Result,
};
use clap::Parser;
use metrics_exporter_prometheus::{Matcher, NativeHistogramConfig, PrometheusBuilder};
use metrics_util::MetricKindMask;
use mimalloc::MiMalloc;

use crate::config::Config;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Lightweight system metrics agent exposing a Prometheus endpoint.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "/usr/local/etc/calipers.toml")]
    config: PathBuf,

    /// Validate the configuration and that every input can start, then exit.
    #[arg(long)]
    check_config: bool,

    /// Run every collector once, print the metrics to stdout and exit.
    #[arg(long)]
    once: bool,
}

/// Native histogram bucket growth: ~10% relative error (schema 3).
const NATIVE_HISTOGRAM_BUCKET_FACTOR: f64 = 1.1;
/// Caps buckets per series; 160 at schema 3 covers 10 µs to 10 s.
const NATIVE_HISTOGRAM_MAX_BUCKETS: u32 = 160;
/// Durations at or below 1 ns count as zero.
const NATIVE_HISTOGRAM_ZERO_THRESHOLD: f64 = 1e-9;

/// Series not updated for this many times the longest collector interval are
/// dropped, so metrics of vanished processes, disks, etc. disappear.
const IDLE_TIMEOUT_INTERVALS: u32 = 3;

/// Blocking-pool threads (getaddrinfo for HTTP probes, disk, smart) outlive
/// any collector interval. With tokio's 10s default they exit and respawn
/// every 10s cycle, and each new thread costs allocator state again.
const BLOCKING_THREAD_KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(3600);

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging();

    let config = Config::load(&cli.config)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_keep_alive(BLOCKING_THREAD_KEEP_ALIVE)
        .build()?;
    if cli.check_config {
        // Set up every input (open devices, resolve sysctls, compile regexes),
        // so a config that parses but can't start is rejected too.
        let collectors = runtime.block_on(async { collectors::build(&config) })?;
        println!("{}: OK ({} inputs)", cli.config.display(), collectors.len());
        return Ok(());
    }
    runtime.block_on(run(config, cli.once))
}

async fn run(config: Config, once: bool) -> Result<()> {
    let scheduled = collectors::build(&config)?;

    // Latencies span µs (collector runtimes) to seconds (probes), so use
    // native histograms: exponential buckets fit any range and still
    // aggregate. They are only served in protobuf, not in the text format.
    let mut builder = PrometheusBuilder::new()
        .with_recommended_naming(true)
        .set_native_histogram_for_metric(
            Matcher::Suffix("_duration_seconds".to_owned()),
            NativeHistogramConfig::new(
                NATIVE_HISTOGRAM_BUCKET_FACTOR,
                NATIVE_HISTOGRAM_MAX_BUCKETS,
                NATIVE_HISTOGRAM_ZERO_THRESHOLD,
            )
            .map_err(|e| anyhow::anyhow!(e))
            .context("configuring native histograms")?,
        );
    for (key, value) in &config.global_tags {
        builder = builder.add_global_label(key, value);
    }
    if !config.agent.omit_hostname {
        let host = if config.agent.hostname.is_empty() {
            sys::hostname().context("reading hostname")?
        } else {
            config.agent.hostname.clone()
        };
        builder = builder.add_global_label("host", host);
    }

    if once {
        let recorder = builder.build_recorder();
        let handle = recorder.handle();
        metrics::set_global_recorder(recorder).context("installing metrics recorder")?;
        describe(&scheduled);
        for mut s in scheduled {
            s.run_once().await;
        }
        print!("{}", handle.render());
        return Ok(());
    }

    let longest = scheduled
        .iter()
        .map(collector::Scheduled::interval)
        .max()
        .unwrap_or(config.agent.interval);
    let (recorder, exporter) = builder
        .with_http_listener(config.exporter.listen)
        .idle_timeout(MetricKindMask::ALL, Some(longest * IDLE_TIMEOUT_INTERVALS))
        .build()
        .context("starting Prometheus exporter")?;
    metrics::set_global_recorder(recorder).context("installing metrics recorder")?;
    describe(&scheduled);

    tracing::info!(
        listen = %config.exporter.listen,
        collectors = scheduled.len(),
        "calipers started"
    );
    let exporter = tokio::spawn(exporter);
    for s in scheduled {
        tokio::spawn(s.run_forever());
    }

    tokio::select! {
        result = exporter => match result {
            Ok(Ok(())) => anyhow::bail!("exporter stopped unexpectedly"),
            Ok(Err(err)) => anyhow::bail!("exporter failed: {err:?}"),
            Err(err) => Err(err.into()),
        },
        signal = shutdown_signal() => {
            tracing::info!(signal, "shutting down");
            Ok(())
        }
    }
}

fn describe(scheduled: &[collector::Scheduled]) {
    collector::describe();
    for s in scheduled {
        s.describe();
    }
}

/// Logs to stderr. Under daemon(8)/syslog (stderr not a terminal) colors and
/// timestamps are left out: syslog adds its own timestamps.
fn init_logging() {
    use std::io::IsTerminal;
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if std::io::stderr().is_terminal() {
        builder.init();
    } else {
        builder.with_ansi(false).without_time().init();
    }
}

async fn shutdown_signal() -> &'static str {
    use tokio::signal::unix::{
        SignalKind,
        signal,
    };
    let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("installing SIGINT handler");
    tokio::select! {
        _ = term.recv() => "SIGTERM",
        _ = int.recv() => "SIGINT",
    }
}
