//! CPU time per mode, plus optional temperature and frequency.
//!
//! Unlike Telegraf, this exports cumulative CPU seconds instead of usage
//! percentages; `rate(cpu_seconds_total[5m])` gives exact utilization over any
//! window.
//!
//! FreeBSD sources: `kern.cp_times` (per CPU), `kern.cp_time` (sum over all
//! CPUs), both in statclock ticks (`kern.clockrate`); `dev.cpu.N.temperature`
//! and `dev.cpu.N.freq`.

// The helpers are only used by the FreeBSD implementation (and tests).
#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

use std::time::Duration;

use metrics::{describe_gauge, gauge};
use serde::Deserialize;

use crate::collector::Collector;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
    /// Export `cpu_seconds_total{cpu="N"}` per CPU.
    #[serde(default = "yes")]
    pub percpu: bool,
    /// Export `cpu_all_seconds_total`, summed over all CPUs.
    #[serde(default = "yes")]
    pub totalcpu: bool,
    /// Export `cpu_temperature_celsius` (needs coretemp(4) or amdtemp(4)).
    #[serde(default)]
    pub temperature: bool,
    /// Export `cpu_frequency_hertz` (needs cpufreq(4)).
    #[serde(default)]
    pub frequency: bool,
}

fn yes() -> bool {
    true
}

/// CPU modes in `kern.cp_time(s)` order (`CP_USER` .. `CP_IDLE`, `CPUSTATES`).
const MODES: [&str; 5] = ["user", "nice", "system", "interrupt", "idle"];

pub fn describe() {
    describe_gauge!(
        "cpu_seconds_total",
        "CPU time spent per CPU and mode. Cumulative; use rate()."
    );
    describe_gauge!(
        "cpu_all_seconds_total",
        "CPU time spent per mode, summed over all CPUs. Cumulative; use rate()."
    );
    describe_gauge!("cpu_temperature_celsius", "CPU core temperature.");
    describe_gauge!("cpu_frequency_hertz", "Current CPU clock frequency.");
}

/// Converts tick counters to seconds. `ticks.len()` must be a multiple of
/// [`MODES`]; returns one `[f64; 5]` per CPU.
fn ticks_to_seconds(ticks: &[i64], stathz: f64) -> Vec<[f64; MODES.len()]> {
    let (cpus, _) = ticks.as_chunks::<{ MODES.len() }>();
    cpus.iter()
        .map(|cpu| std::array::from_fn(|mode| cpu[mode] as f64 / stathz))
        .collect()
}

/// `kern.cp_times` has a slot for every possible CPU ID up to `mp_maxid`.
/// Absent CPUs never accumulate ticks, so all-zero slots are skipped.
fn is_present(seconds: &[f64]) -> bool {
    seconds.iter().any(|&s| s > 0.0)
}

/// Converts a sysctl `IK[n]` temperature (Kelvin scaled by 10^n, n defaults to
/// 1) to degrees Celsius.
fn kelvin_to_celsius(raw: i32, format: &str) -> Option<f64> {
    let precision = match format.strip_prefix("IK")? {
        "" => 1,
        digits => digits.parse::<i32>().ok().filter(|p| (0..=9).contains(p))?,
    };
    Some(f64::from(raw) / 10f64.powi(precision) - 273.15)
}

fn export_modes(name: &'static str, cpu: Option<&str>, seconds: &[f64; MODES.len()]) {
    for (mode, &value) in MODES.iter().zip(seconds) {
        match cpu {
            Some(cpu) => gauge!(name, "cpu" => cpu.to_owned(), "mode" => *mode).set(value),
            None => gauge!(name, "mode" => *mode).set(value),
        }
    }
}

#[cfg(target_os = "freebsd")]
pub use freebsd::Cpu;

#[cfg(not(target_os = "freebsd"))]
pub struct Cpu;

#[cfg(not(target_os = "freebsd"))]
impl Cpu {
    pub fn new(_config: &Config) -> anyhow::Result<Self> {
        anyhow::bail!("the cpu input is only supported on FreeBSD")
    }
}

#[cfg(not(target_os = "freebsd"))]
impl Collector for Cpu {
    fn name(&self) -> &'static str {
        "cpu"
    }

    async fn collect(&mut self) -> anyhow::Result<()> {
        unreachable!("Cpu::new always fails on this platform")
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::{Context, Result, bail};
    use metrics::gauge;

    use super::{
        Collector, Config, MODES, describe, export_modes, is_present, kelvin_to_celsius,
        ticks_to_seconds,
    };
    use crate::sys::freebsd::{Mib, cast_slice};

    struct Sensor {
        cpu: String,
        mib: Mib,
        /// For temperatures: the `IK[n]` format, read once.
        format: String,
    }

    pub struct Cpu {
        stathz: f64,
        cp_times: Option<Mib>,
        cp_time: Option<Mib>,
        temperatures: Vec<Sensor>,
        frequencies: Vec<Sensor>,
        buf: Vec<u8>,
    }

    impl Cpu {
        pub fn new(config: &Config) -> Result<Self> {
            let clock: libc::clockinfo = Mib::new("kern.clockrate")?
                .read()
                .context("reading kern.clockrate")?;
            // cp_time ticks are counted by statclock, which falls back to
            // hardclock when there is no separate stat clock.
            let stathz = if clock.stathz > 0 {
                clock.stathz
            } else {
                clock.hz
            };
            if stathz <= 0 {
                bail!("kern.clockrate reports no clock frequency");
            }
            let ncpu: i32 = Mib::new("hw.ncpu")?.read().context("reading hw.ncpu")?;

            let mut temperatures = Vec::new();
            let mut frequencies = Vec::new();
            for cpu in 0..ncpu {
                if config.temperature
                    && let Ok(mib) = Mib::new(&format!("dev.cpu.{cpu}.temperature"))
                {
                    let format = mib.format().context("reading temperature format")?;
                    if !format.starts_with("IK") {
                        bail!("dev.cpu.{cpu}.temperature has unexpected format {format:?}");
                    }
                    temperatures.push(Sensor {
                        cpu: cpu.to_string(),
                        mib,
                        format,
                    });
                }
                if config.frequency
                    && let Ok(mib) = Mib::new(&format!("dev.cpu.{cpu}.freq"))
                {
                    frequencies.push(Sensor {
                        cpu: cpu.to_string(),
                        mib,
                        format: String::new(),
                    });
                }
            }
            if config.temperature && temperatures.is_empty() {
                bail!(
                    "temperature = true, but no dev.cpu.N.temperature sysctl exists (load coretemp or amdtemp)"
                );
            }
            if config.frequency && frequencies.is_empty() {
                bail!(
                    "frequency = true, but no dev.cpu.N.freq sysctl exists (cpufreq not attached)"
                );
            }

            Ok(Self {
                stathz: f64::from(stathz),
                cp_times: config
                    .percpu
                    .then(|| Mib::new("kern.cp_times"))
                    .transpose()?,
                cp_time: config
                    .totalcpu
                    .then(|| Mib::new("kern.cp_time"))
                    .transpose()?,
                temperatures,
                frequencies,
                buf: Vec::new(),
            })
        }

        fn read_ticks(mib: &Mib, buf: &mut Vec<u8>, name: &str) -> Result<Vec<i64>> {
            mib.read_into(buf)
                .with_context(|| format!("reading {name}"))?;
            // `long` is 64-bit on every supported FreeBSD platform.
            let ticks: Vec<libc::c_long> = cast_slice(buf)?;
            if ticks.is_empty() || !ticks.len().is_multiple_of(MODES.len()) {
                bail!(
                    "{name} returned {} values, not a multiple of {}",
                    ticks.len(),
                    MODES.len()
                );
            }
            Ok(ticks)
        }
    }

    impl Collector for Cpu {
        fn name(&self) -> &'static str {
            "cpu"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            if let Some(mib) = &self.cp_times {
                let ticks = Self::read_ticks(mib, &mut self.buf, "kern.cp_times")?;
                for (cpu, seconds) in ticks_to_seconds(&ticks, self.stathz).iter().enumerate() {
                    if is_present(seconds) {
                        export_modes("cpu_seconds_total", Some(&cpu.to_string()), seconds);
                    }
                }
            }
            if let Some(mib) = &self.cp_time {
                let ticks = Self::read_ticks(mib, &mut self.buf, "kern.cp_time")?;
                if ticks.len() != MODES.len() {
                    bail!(
                        "kern.cp_time returned {} values, expected {}",
                        ticks.len(),
                        MODES.len()
                    );
                }
                export_modes(
                    "cpu_all_seconds_total",
                    None,
                    &ticks_to_seconds(&ticks, self.stathz)[0],
                );
            }
            for sensor in &self.temperatures {
                let raw: i32 = sensor.mib.read().context("reading CPU temperature")?;
                if let Some(celsius) = kelvin_to_celsius(raw, &sensor.format) {
                    gauge!("cpu_temperature_celsius", "cpu" => sensor.cpu.clone()).set(celsius);
                }
            }
            for sensor in &self.frequencies {
                let mhz: i32 = sensor.mib.read().context("reading CPU frequency")?;
                gauge!("cpu_frequency_hertz", "cpu" => sensor.cpu.clone())
                    .set(f64::from(mhz) * 1e6);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ticks_per_cpu() {
        let ticks = [127, 0, 254, 0, 1270, 0, 0, 0, 0, 0];
        let seconds = ticks_to_seconds(&ticks, 127.0);
        assert_eq!(seconds.len(), 2);
        assert_eq!(seconds[0], [1.0, 0.0, 2.0, 0.0, 10.0]);
        assert!(is_present(&seconds[0]));
        assert!(!is_present(&seconds[1]));
    }

    #[test]
    fn converts_kelvin_formats() {
        let close = |a: Option<f64>, b: f64| (a.unwrap() - b).abs() < 1e-9;
        assert!(close(kelvin_to_celsius(3231, "IK"), 49.95));
        assert!(close(kelvin_to_celsius(3231, "IK1"), 49.95));
        assert!(close(kelvin_to_celsius(323_150, "IK3"), 50.0));
        assert!(close(kelvin_to_celsius(323, "IK0"), 49.85));
        assert_eq!(kelvin_to_celsius(1, "I"), None);
        assert_eq!(kelvin_to_celsius(1, "IKx"), None);
    }

    #[test]
    fn config_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.percpu && config.totalcpu);
        assert!(!config.temperature && !config.frequency);
    }
}
