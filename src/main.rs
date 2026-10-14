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
mod runner;
mod sys;

use std::{
    path::{
        Path,
        PathBuf,
    },
    time::Duration,
};

use anyhow::{
    Context,
    Result,
};
use clap::Parser;
use metrics_exporter_prometheus::{
    Matcher,
    NativeHistogramConfig,
    PrometheusBuilder,
};
use metrics_util::MetricKindMask;
use mimalloc::MiMalloc;
use tokio::signal::unix::{
    SignalKind,
    signal,
};

use crate::{
    config::Config,
    runner::Collectors,
};

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
    if cli.once {
        return runtime.block_on(run_once(config));
    }
    runtime.block_on(run(&cli.config, config))
}

/// The exporter without listener or idle timeout: global labels and native
/// histograms.
fn exporter_builder(config: &Config) -> Result<PrometheusBuilder> {
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
    Ok(builder)
}

async fn run_once(config: Config) -> Result<()> {
    let scheduled = collectors::build(&config)?;
    let recorder = exporter_builder(&config)?.build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder).context("installing metrics recorder")?;
    collector::describe();
    for mut s in scheduled {
        s.describe();
        s.run_once().await;
    }
    print!("{}", handle.render());
    Ok(())
}

async fn run(path: &Path, config: Config) -> Result<()> {
    let mut collectors = Collectors::default();
    let plan = collectors.plan(&config)?;
    let idle_timeout =
        plan.longest_interval().unwrap_or(config.agent.interval) * IDLE_TIMEOUT_INTERVALS;
    let (recorder, exporter) = exporter_builder(&config)?
        .with_http_listener(config.exporter.listen)
        .idle_timeout(MetricKindMask::ALL, Some(idle_timeout))
        .build()
        .context("starting Prometheus exporter")?;
    metrics::set_global_recorder(recorder).context("installing metrics recorder")?;
    collector::describe();
    collectors.apply(plan);

    tracing::info!(
        listen = %config.exporter.listen,
        collectors = collectors.len(),
        "calipers started"
    );
    let mut exporter = tokio::spawn(exporter);
    let mut hangup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = &mut exporter => match result {
                Ok(Ok(())) => anyhow::bail!("exporter stopped unexpectedly"),
                Ok(Err(err)) => anyhow::bail!("exporter failed: {err:?}"),
                Err(err) => return Err(err.into()),
            },
            signal = &mut shutdown => {
                tracing::info!(signal, "shutting down");
                return Ok(());
            }
            _ = hangup.recv() => reload(path, &config, &mut collectors, idle_timeout),
        }
    }
}

/// Rereads the configuration file and applies changed inputs. On any error
/// the running collectors stay as they are.
fn reload(path: &Path, startup: &Config, collectors: &mut Collectors, idle_timeout: Duration) {
    let planned = Config::load(path).and_then(|config| {
        let plan = collectors.plan(&config)?;
        Ok((config, plan))
    });
    let (config, plan) = match planned {
        Ok(planned) => planned,
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "reload failed, configuration unchanged");
            return;
        }
    };
    for setting in restart_required(startup, &config) {
        tracing::warn!(setting, "changed setting takes effect only after a restart");
    }
    if let Some(longest) = plan.longest_interval()
        && longest * IDLE_TIMEOUT_INTERVALS > idle_timeout
    {
        tracing::warn!(
            interval = ?longest,
            idle_timeout = ?idle_timeout,
            "interval longer than at startup; series may expire between collections until restart"
        );
    }
    let changes = collectors.apply(plan);
    tracing::info!(
        started = ?changes.started,
        restarted = ?changes.restarted,
        stopped = ?changes.stopped,
        kept = changes.kept,
        "configuration reloaded"
    );
}

/// Settings fixed when the exporter is built: global labels and the listener.
fn restart_required(startup: &Config, new: &Config) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if startup.exporter.listen != new.exporter.listen {
        changed.push("exporter.listen");
    }
    if startup.global_tags != new.global_tags {
        changed.push("global_tags");
    }
    if startup.agent.hostname != new.agent.hostname {
        changed.push("agent.hostname");
    }
    if startup.agent.omit_hostname != new.agent.omit_hostname {
        changed.push("agent.omit_hostname");
    }
    changed
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
    let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("installing SIGINT handler");
    tokio::select! {
        _ = term.recv() => "SIGTERM",
        _ = int.recv() => "SIGINT",
    }
}
