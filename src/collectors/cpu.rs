//! CPU time per mode, plus optional temperature and frequency.
//!
//! Unlike Telegraf, this exports cumulative CPU seconds instead of usage
//! percentages; `rate(cpu_seconds_total[5m])` gives exact utilization over any
//! window.
//!
//! FreeBSD sources: `kern.cp_times` (per CPU), `kern.cp_time` (sum over all
//! CPUs), both in statclock ticks (`kern.clockrate`); `dev.cpu.N.temperature`
//! and `dev.cpu.N.freq`.
//!
//! Linux sources: the `cpuN` and `cpu` lines of `/proc/stat`, in `USER_HZ`
//! ticks, with Linux's own modes ([`LINUX_MODES`]). Temperatures come from
//! hwmon: coretemp's `Core N` sensor for the CPUs of that core, or k10temp's
//! `Tdie` (`Tctl` if there is no `Tdie`) for every CPU of the package.
//! Frequencies come from `cpuN/cpufreq/scaling_cur_freq`.

// The helpers are only used by the platform implementations (and tests).
#![cfg_attr(
    not(any(target_os = "freebsd", target_os = "linux")),
    expect(dead_code, reason = "used by the FreeBSD and Linux implementations")
)]

use std::time::Duration;

use metrics::{
    describe_gauge,
    gauge,
};
use serde::Deserialize;

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent on/off switches from the config file"
)]
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
    /// Export `cpu_temperature_celsius` (needs coretemp(4) or amdtemp(4); on
    /// Linux the coretemp or k10temp module).
    #[serde(default)]
    pub temperature: bool,
    /// Export `cpu_frequency_hertz` (needs cpufreq(4); on Linux cpufreq).
    #[serde(default)]
    pub frequency: bool,
}

fn yes() -> bool {
    true
}

/// CPU modes in `kern.cp_time(s)` order (`CP_USER` .. `CP_IDLE`, `CPUSTATES`).
#[cfg(any(target_os = "freebsd", test))]
const MODES: [&str; 5] = ["user", "nice", "system", "interrupt", "idle"];

/// CPU modes in `/proc/stat` column order. The `guest` and `guest_nice`
/// columns that follow are already included in user and nice.
#[cfg(any(target_os = "linux", test))]
const LINUX_MODES: [&str; 8] = [
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
];

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
#[cfg(any(target_os = "freebsd", test))]
fn ticks_to_seconds(ticks: &[i64], stathz: f64) -> Vec<[f64; MODES.len()]> {
    let (cpus, _) = ticks.as_chunks::<{ MODES.len() }>();
    cpus.iter()
        .map(|cpu| std::array::from_fn(|mode| cpu[mode] as f64 / stathz))
        .collect()
}

/// `kern.cp_times` has a slot for every possible CPU ID up to `mp_maxid`.
/// Absent CPUs never accumulate ticks, so all-zero slots are skipped.
#[cfg(any(target_os = "freebsd", test))]
fn is_present(seconds: &[f64]) -> bool {
    seconds.iter().any(|&s| s > 0.0)
}

/// Converts a sysctl `IK[n]` temperature (Kelvin scaled by 10^n, n defaults to
/// 1) to degrees Celsius.
#[cfg(any(target_os = "freebsd", test))]
fn kelvin_to_celsius(raw: i32, format: &str) -> Option<f64> {
    let precision = match format.strip_prefix("IK")? {
        "" => 1,
        digits => digits.parse::<i32>().ok().filter(|p| (0..=9).contains(p))?,
    };
    // Subtract before dividing: `3437 / 10 - 273.15` gives 70.55000000000001,
    // `(3437 - 2731.5) / 10` gives 70.55.
    let scale = 10f64.powi(precision);
    Some((f64::from(raw) - 273.15 * scale) / scale)
}

fn export_modes<const N: usize>(
    name: &'static str,
    cpu: Option<&str>,
    modes: &[&'static str; N],
    seconds: &[f64; N],
) {
    for (mode, &value) in modes.iter().zip(seconds) {
        match cpu {
            Some(cpu) => gauge!(name, "cpu" => cpu.to_owned(), "mode" => *mode).set(value),
            None => gauge!(name, "mode" => *mode).set(value),
        }
    }
}

/// Ticks per [`LINUX_MODES`] from one `cpu` or `cpuN` line of `/proc/stat`.
#[cfg(any(target_os = "linux", test))]
type LinuxTicks = [u64; LINUX_MODES.len()];

/// The CPU lines of `/proc/stat`.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default, PartialEq)]
struct ProcStat {
    /// The `cpu` line, summed over all CPUs.
    total: Option<LinuxTicks>,
    /// `cpuN` lines of the online CPUs.
    cpus: Vec<(u32, LinuxTicks)>,
}

/// Parses the `cpu` and `cpuN` lines of `/proc/stat`. Lines with fewer than
/// [`LINUX_MODES`] columns (kernels before 2.6.11) are an error.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat(text: &str) -> Result<ProcStat, String> {
    let mut stat = ProcStat::default();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(id) = fields.next().and_then(|name| name.strip_prefix("cpu")) else {
            continue;
        };
        let mut ticks = LinuxTicks::default();
        for tick in &mut ticks {
            *tick = fields
                .next()
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| format!("malformed /proc/stat line {line:?}"))?;
        }
        if id.is_empty() {
            stat.total = Some(ticks);
        } else {
            let cpu = id
                .parse()
                .map_err(|_| format!("malformed /proc/stat line {line:?}"))?;
            stat.cpus.push((cpu, ticks));
        }
    }
    Ok(stat)
}

/// Where a CPU sits, from `cpuN/topology`.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq)]
struct Topology {
    cpu: u32,
    package: u32,
    core: u32,
}

/// One hwmon device with its temperature sensors, as `(label, input file)`.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq)]
struct Hwmon<P> {
    /// The hwmon `name`, e.g. `coretemp` or `k10temp`.
    name: String,
    sensors: Vec<(String, P)>,
}

/// Maps CPU temperature sensors to the CPUs they measure: coretemp's
/// `Core N` to the CPUs with that core ID in the package named by its
/// `Package id P` sensor, and k10temp's `Tdie` (else `Tctl`) to every CPU of
/// a package. k10temp devices are matched to packages in order, so `hwmons`
/// must be sorted by device. Returns each input file with its CPUs.
#[cfg(any(target_os = "linux", test))]
fn temperature_sensors<P: Clone>(hwmons: &[Hwmon<P>], cpus: &[Topology]) -> Vec<(P, Vec<u32>)> {
    let mut packages: Vec<u32> = cpus.iter().map(|t| t.package).collect();
    packages.sort_unstable();
    packages.dedup();
    let mut k10temp_packages = packages.iter();
    let cpus_where = |pred: &dyn Fn(&Topology) -> bool| -> Vec<u32> {
        cpus.iter().filter(|t| pred(t)).map(|t| t.cpu).collect()
    };

    let mut out = Vec::new();
    for hwmon in hwmons {
        match hwmon.name.as_str() {
            "coretemp" => {
                let Some(package) = hwmon
                    .sensors
                    .iter()
                    .find_map(|(label, _)| label.strip_prefix("Package id ")?.parse::<u32>().ok())
                else {
                    continue;
                };
                for (label, input) in &hwmon.sensors {
                    if let Some(core) = label
                        .strip_prefix("Core ")
                        .and_then(|c| c.parse::<u32>().ok())
                    {
                        let on_core = cpus_where(&|t| t.package == package && t.core == core);
                        if !on_core.is_empty() {
                            out.push((input.clone(), on_core));
                        }
                    }
                }
            }
            "k10temp" => {
                let Some(&package) = k10temp_packages.next() else {
                    continue;
                };
                let sensor = ["Tdie", "Tctl"].iter().find_map(|want| {
                    hwmon
                        .sensors
                        .iter()
                        .find(|(label, _)| label == want)
                        .map(|(_, input)| input)
                });
                if let Some(input) = sensor {
                    out.push((input.clone(), cpus_where(&|t| t.package == package)));
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(target_os = "freebsd")]
pub use freebsd::Cpu;
#[cfg(target_os = "linux")]
pub use linux::Cpu;

native_only!(Cpu, "cpu");

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::{
        Context,
        Result,
        bail,
    };
    use metrics::gauge;

    use super::{
        Config,
        MODES,
        describe,
        export_modes,
        is_present,
        kelvin_to_celsius,
        ticks_to_seconds,
    };
    use crate::{
        collector::Collector,
        sys::freebsd::{
            Mib,
            cast_slice,
        },
    };

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
                    "temperature = true, but no dev.cpu.N.temperature sysctl exists (load \
                     coretemp or amdtemp)"
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
                        export_modes("cpu_seconds_total", Some(&cpu.to_string()), &MODES, seconds);
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
                    &MODES,
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

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io,
        path::{
            Path,
            PathBuf,
        },
    };

    use anyhow::{
        Context,
        Result,
        bail,
    };
    use metrics::gauge;

    use super::{
        Config,
        Hwmon,
        LINUX_MODES,
        LinuxTicks,
        Topology,
        describe,
        export_modes,
        parse_proc_stat,
        temperature_sensors,
    };
    use crate::{
        collector::Collector,
        sys::linux::read_into,
    };

    const PROC_STAT: &str = "/proc/stat";
    const SYS_CPU: &str = "/sys/devices/system/cpu";
    const SYS_HWMON: &str = "/sys/class/hwmon";

    /// A sysfs file and the CPUs (as label values) its value applies to.
    struct Sensor {
        cpus: Vec<String>,
        path: PathBuf,
    }

    pub struct Cpu {
        /// `USER_HZ`, the unit of `/proc/stat`.
        user_hz: f64,
        percpu: bool,
        totalcpu: bool,
        temperatures: Vec<Sensor>,
        frequencies: Vec<Sensor>,
        buf: String,
    }

    #[expect(unsafe_code, reason = "sysconf(3) FFI")]
    fn user_hz() -> Result<f64> {
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 {
            bail!("sysconf(_SC_CLK_TCK) returned {hz}");
        }
        Ok(hz as f64)
    }

    fn read_trimmed(path: &Path) -> io::Result<String> {
        Ok(std::fs::read_to_string(path)?.trim().to_owned())
    }

    fn read_u32(path: &Path) -> Result<u32> {
        read_trimmed(path)
            .with_context(|| format!("reading {}", path.display()))?
            .parse()
            .with_context(|| format!("parsing {}", path.display()))
    }

    fn topology(cpu: u32) -> Result<Topology> {
        let dir = Path::new(SYS_CPU).join(format!("cpu{cpu}/topology"));
        Ok(Topology {
            cpu,
            package: read_u32(&dir.join("physical_package_id"))?,
            core: read_u32(&dir.join("core_id"))?,
        })
    }

    /// The coretemp and k10temp hwmon devices, sorted by device path so
    /// k10temp instances come in node (and so package) order.
    fn cpu_hwmons() -> Result<Vec<Hwmon<PathBuf>>> {
        let mut found = Vec::new();
        let entries = match std::fs::read_dir(SYS_HWMON) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err).context("listing /sys/class/hwmon"),
        };
        for entry in entries {
            let dir = entry?.path();
            let Ok(name) = read_trimmed(&dir.join("name")) else {
                continue;
            };
            if name != "coretemp" && name != "k10temp" {
                continue;
            }
            let mut sensors = Vec::new();
            for file in std::fs::read_dir(&dir)? {
                let file = file?.file_name();
                let Some(file) = file.to_str() else {
                    continue;
                };
                if let Some(sensor) = file.strip_suffix("_label")
                    && sensor.starts_with("temp")
                {
                    let label = read_trimmed(&dir.join(file))?;
                    sensors.push((label, dir.join(format!("{sensor}_input"))));
                }
            }
            sensors.sort();
            let device = std::fs::canonicalize(dir.join("device")).unwrap_or_default();
            found.push((device, Hwmon { name, sensors }));
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(found.into_iter().map(|(_, hwmon)| hwmon).collect())
    }

    /// Reads a sysfs integer; `None` if the file went away (CPU offlined).
    fn read_sensor(path: &Path, buf: &mut String) -> Result<Option<i64>> {
        match read_into(path, buf) {
            Ok(()) => {}
            Err(err)
                if err.kind() == io::ErrorKind::NotFound
                    || err.raw_os_error() == Some(libc::ENODEV) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        }
        let value = buf
            .trim()
            .parse()
            .with_context(|| format!("parsing {}", path.display()))?;
        Ok(Some(value))
    }

    impl Cpu {
        pub fn new(config: &Config) -> Result<Self> {
            let user_hz = user_hz()?;
            let mut buf = String::new();
            read_into(PROC_STAT, &mut buf).context("reading /proc/stat")?;
            let stat = parse_proc_stat(&buf).map_err(anyhow::Error::msg)?;
            if stat.total.is_none() || stat.cpus.is_empty() {
                bail!("/proc/stat has no cpu lines");
            }

            let mut temperatures = Vec::new();
            if config.temperature {
                let cpus = stat
                    .cpus
                    .iter()
                    .map(|&(cpu, _)| topology(cpu))
                    .collect::<Result<Vec<_>>>()?;
                for (path, cpus) in temperature_sensors(&cpu_hwmons()?, &cpus) {
                    temperatures.push(Sensor {
                        cpus: cpus.iter().map(u32::to_string).collect(),
                        path,
                    });
                }
                if temperatures.is_empty() {
                    bail!(
                        "temperature = true, but there is no coretemp or k10temp hwmon sensor \
                         (load the coretemp or k10temp module)"
                    );
                }
            }

            let mut frequencies = Vec::new();
            if config.frequency {
                for &(cpu, _) in &stat.cpus {
                    let path =
                        Path::new(SYS_CPU).join(format!("cpu{cpu}/cpufreq/scaling_cur_freq"));
                    if path.exists() {
                        frequencies.push(Sensor {
                            cpus: vec![cpu.to_string()],
                            path,
                        });
                    }
                }
                if frequencies.is_empty() {
                    bail!("frequency = true, but no CPU has cpufreq/scaling_cur_freq");
                }
            }

            Ok(Self {
                user_hz,
                percpu: config.percpu,
                totalcpu: config.totalcpu,
                temperatures,
                frequencies,
                buf,
            })
        }

        fn seconds(&self, ticks: &LinuxTicks) -> [f64; LINUX_MODES.len()] {
            ticks.map(|t| t as f64 / self.user_hz)
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
            if self.percpu || self.totalcpu {
                read_into(PROC_STAT, &mut self.buf).context("reading /proc/stat")?;
                let stat = parse_proc_stat(&self.buf).map_err(anyhow::Error::msg)?;
                if self.percpu {
                    for (cpu, ticks) in &stat.cpus {
                        export_modes(
                            "cpu_seconds_total",
                            Some(&cpu.to_string()),
                            &LINUX_MODES,
                            &self.seconds(ticks),
                        );
                    }
                }
                if self.totalcpu {
                    let total = stat.total.context("/proc/stat has no cpu line")?;
                    export_modes(
                        "cpu_all_seconds_total",
                        None,
                        &LINUX_MODES,
                        &self.seconds(&total),
                    );
                }
            }
            for sensor in &self.temperatures {
                if let Some(millicelsius) = read_sensor(&sensor.path, &mut self.buf)? {
                    for cpu in &sensor.cpus {
                        gauge!("cpu_temperature_celsius", "cpu" => cpu.clone())
                            .set(millicelsius as f64 / 1000.0);
                    }
                }
            }
            for sensor in &self.frequencies {
                if let Some(khz) = read_sensor(&sensor.path, &mut self.buf)? {
                    for cpu in &sensor.cpus {
                        gauge!("cpu_frequency_hertz", "cpu" => cpu.clone()).set(khz as f64 * 1e3);
                    }
                }
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
        assert_eq!(kelvin_to_celsius(3437, "IK").unwrap().to_string(), "70.55");
        assert!(close(kelvin_to_celsius(3231, "IK1"), 49.95));
        assert!(close(kelvin_to_celsius(323_150, "IK3"), 50.0));
        assert!(close(kelvin_to_celsius(323, "IK0"), 49.85));
        assert_eq!(kelvin_to_celsius(1, "I"), None);
        assert_eq!(kelvin_to_celsius(1, "IKx"), None);
    }

    /// From a 32-thread Ryzen 9 5950X, trimmed to two CPUs.
    const PROC_STAT: &str = "\
cpu  31708642 784473 6805706 2007002845 1366658 1137876 705889 0 86400 0
cpu0 3033114 230734 627415 59932296 95514 81611 196067 0 13332 0
cpu1 1128880 7478 304142 62597835 74635 124629 83048 0 1816 0
intr 6629315375 131 0 0 0
ctxt 10892194287
btime 1791358996
";

    #[test]
    fn parses_proc_stat() {
        let stat = parse_proc_stat(PROC_STAT).unwrap();
        assert_eq!(
            stat.total,
            Some([
                31_708_642,
                784_473,
                6_805_706,
                2_007_002_845,
                1_366_658,
                1_137_876,
                705_889,
                0
            ])
        );
        assert_eq!(stat.cpus.len(), 2);
        assert_eq!(stat.cpus[1].0, 1);
        assert_eq!(stat.cpus[1].1[LINUX_MODES.len() - 1], 0, "steal");
        assert_eq!(stat.cpus[0].1[0], 3_033_114);

        assert!(parse_proc_stat("cpu0 1 2 3\n").is_err(), "too few columns");
        assert!(parse_proc_stat("cpux 1 2 3 4 5 6 7 8\n").is_err());
        assert_eq!(parse_proc_stat("ctxt 5\n").unwrap(), ProcStat::default());
    }

    fn topo(cpu: u32, package: u32, core: u32) -> Topology {
        Topology { cpu, package, core }
    }

    fn hwmon(name: &str, sensors: &[(&str, &'static str)]) -> Hwmon<&'static str> {
        Hwmon {
            name: name.to_owned(),
            sensors: sensors.iter().map(|&(l, p)| (l.to_owned(), p)).collect(),
        }
    }

    #[test]
    fn maps_coretemp_cores_to_cpus() {
        // Two packages, two cores each, hyperthreaded.
        let cpus = [
            topo(0, 0, 0),
            topo(1, 0, 1),
            topo(2, 1, 0),
            topo(3, 1, 1),
            topo(4, 0, 0),
            topo(5, 0, 1),
        ];
        let hwmons = [
            hwmon(
                "coretemp",
                &[("Package id 1", "p1"), ("Core 0", "c10"), ("Core 1", "c11")],
            ),
            hwmon("nvme", &[("Composite", "nvme")]),
            hwmon(
                "coretemp",
                &[("Core 0", "c00"), ("Core 1", "c01"), ("Package id 0", "p0")],
            ),
        ];
        assert_eq!(
            temperature_sensors(&hwmons, &cpus),
            [
                ("c10", vec![2]),
                ("c11", vec![3]),
                ("c00", vec![0, 4]),
                ("c01", vec![1, 5]),
            ]
        );
    }

    #[test]
    fn maps_k10temp_to_packages() {
        let cpus = [topo(0, 0, 0), topo(1, 0, 1), topo(2, 1, 0)];
        let hwmons = [
            hwmon(
                "k10temp",
                &[("Tccd1", "ccd"), ("Tctl", "tctl0"), ("Tdie", "tdie0")],
            ),
            hwmon("k10temp", &[("Tctl", "tctl1")]),
            hwmon("k10temp", &[("Tctl", "extra")]),
        ];
        assert_eq!(
            temperature_sensors(&hwmons, &cpus),
            [("tdie0", vec![0, 1]), ("tctl1", vec![2])]
        );
        assert_eq!(temperature_sensors(&hwmons[..0], &cpus), []);
    }

    #[test]
    fn config_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.percpu && config.totalcpu);
        assert!(!config.temperature && !config.frequency);
    }
}
