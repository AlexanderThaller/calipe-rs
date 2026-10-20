//! Kernel activity counters: context switches, interrupts, syscalls, traps
//! and process creation.
//!
//! Telegraf's kernel input is Linux-only (it reads `/proc/stat`), so on
//! FreeBSD this is new data. All values are 64-bit kernel counters
//! (`vm.stats.sys.*`, `vm.stats.vm.v_*forks`) exported as real counters.
//!
//! Linux source: the `ctxt`, `intr` (total of all hard interrupts,
//! `type="irq"`), `softirq` (total, `type="softirq"`) and `processes` lines
//! of `/proc/stat`. Linux counts
//! every new task in `processes`, threads and kernel threads included, so it
//! is exported as `kernel_forks_total{type="clone"}`. Linux has no syscall or
//! trap counters, so those metrics are absent.

use std::time::Duration;

use metrics::describe_counter;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
}

/// (sysctl, metric, label name, label value). The label is empty for metrics
/// without one.
#[cfg_attr(
    not(target_os = "freebsd"),
    expect(dead_code, reason = "used by the FreeBSD implementation")
)]
#[rustfmt::skip]
const COUNTERS: [(&str, &str, &str, &str); 9] = [
    ("vm.stats.sys.v_swtch",   "kernel_context_switches_total", "", ""),
    ("vm.stats.sys.v_intr",    "kernel_interrupts_total", "type", "hard"),
    ("vm.stats.sys.v_soft",    "kernel_interrupts_total", "type", "soft"),
    ("vm.stats.sys.v_syscall", "kernel_syscalls_total", "", ""),
    ("vm.stats.sys.v_trap",    "kernel_traps_total", "", ""),
    ("vm.stats.vm.v_forks",    "kernel_forks_total", "type", "fork"),
    ("vm.stats.vm.v_vforks",   "kernel_forks_total", "type", "vfork"),
    ("vm.stats.vm.v_rforks",   "kernel_forks_total", "type", "rfork"),
    ("vm.stats.vm.v_kthreads", "kernel_forks_total", "type", "kthread"),
];

/// (`/proc/stat` line, metric, label name, label value), as [`COUNTERS`].
/// The counter is the line's first number.
#[cfg(any(target_os = "linux", test))]
#[rustfmt::skip]
const LINUX_COUNTERS: [(&str, &str, &str, &str); 4] = [
    ("ctxt",      "kernel_context_switches_total", "", ""),
    ("intr",      "kernel_interrupts_total", "type", "irq"),
    ("softirq",   "kernel_interrupts_total", "type", "softirq"),
    ("processes", "kernel_forks_total", "type", "clone"),
];

#[cfg(not(target_os = "linux"))]
const FORKS_HELP: &str =
    "New processes and kernel threads, by creation call (fork, vfork, rfork, kthread).";
#[cfg(target_os = "linux")]
const FORKS_HELP: &str = "New tasks (processes, threads and kernel threads); type=clone.";

// Only called from the platform implementations.
#[cfg_attr(
    not(any(target_os = "freebsd", target_os = "linux")),
    expect(dead_code, reason = "used by the FreeBSD and Linux implementations")
)]
pub fn describe() {
    describe_counter!("kernel_context_switches_total", "Context switches.");
    #[cfg(not(target_os = "linux"))]
    describe_counter!(
        "kernel_interrupts_total",
        "Interrupts; type=hard for device interrupts, type=soft for software interrupts."
    );
    #[cfg(target_os = "linux")]
    describe_counter!(
        "kernel_interrupts_total",
        "Interrupts; type=irq for hardware interrupts, type=softirq for softirqs."
    );
    #[cfg(not(target_os = "linux"))]
    {
        describe_counter!("kernel_syscalls_total", "System calls.");
        describe_counter!("kernel_traps_total", "Traps, including page faults.");
    }
    describe_counter!("kernel_forks_total", FORKS_HELP);
}

/// The [`LINUX_COUNTERS`] values from `/proc/stat`, in table order.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat(text: &str) -> Result<[u64; LINUX_COUNTERS.len()], String> {
    let mut values = [None; LINUX_COUNTERS.len()];
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        if let Some(i) = LINUX_COUNTERS.iter().position(|c| c.0 == key) {
            values[i] = fields.next().and_then(|v| v.parse().ok());
        }
    }
    let mut out = [0; LINUX_COUNTERS.len()];
    for ((value, out), counter) in values.into_iter().zip(&mut out).zip(&LINUX_COUNTERS) {
        *out = value.ok_or_else(|| format!("/proc/stat has no valid {:?} line", counter.0))?;
    }
    Ok(out)
}

native_only!(Kernel, "kernel");

#[cfg(target_os = "freebsd")]
pub use freebsd::Kernel;
#[cfg(target_os = "linux")]
pub use linux::Kernel;

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{
        Context,
        Result,
    };
    use metrics::counter;

    use super::{
        Config,
        LINUX_COUNTERS,
        describe,
        parse_proc_stat,
    };
    use crate::{
        collector::Collector,
        sys::linux::read_into,
    };

    pub struct Kernel {
        buf: String,
    }

    impl Kernel {
        pub fn new(_config: &Config) -> Result<Self> {
            let mut kernel = Self { buf: String::new() };
            kernel.read()?;
            Ok(kernel)
        }

        fn read(&mut self) -> Result<[u64; LINUX_COUNTERS.len()]> {
            read_into("/proc/stat", &mut self.buf).context("reading /proc/stat")?;
            parse_proc_stat(&self.buf).map_err(anyhow::Error::msg)
        }
    }

    impl Collector for Kernel {
        fn name(&self) -> &'static str {
            "kernel"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            for (&(_, metric, key, value), count) in LINUX_COUNTERS.iter().zip(self.read()?) {
                if key.is_empty() {
                    counter!(metric).absolute(count);
                } else {
                    counter!(metric, key => value).absolute(count);
                }
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::Result;
    use metrics::counter;

    use super::{
        COUNTERS,
        Config,
        describe,
    };
    use crate::{
        collector::Collector,
        sys::freebsd::Uint,
    };

    pub struct Kernel {
        counters: Vec<(Uint, &'static str, &'static str, &'static str)>,
    }

    impl Kernel {
        pub fn new(_config: &Config) -> Result<Self> {
            let counters = COUNTERS
                .iter()
                .map(|&(sysctl, metric, key, value)| Ok((Uint::new(sysctl)?, metric, key, value)))
                .collect::<Result<_>>()?;
            Ok(Self { counters })
        }
    }

    impl Collector for Kernel {
        fn name(&self) -> &'static str {
            "kernel"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            for (sysctl, metric, key, value) in &self.counters {
                let count = sysctl.read()?;
                if key.is_empty() {
                    counter!(*metric).absolute(count);
                } else {
                    counter!(*metric, *key => *value).absolute(count);
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
    fn parses_proc_stat() {
        // From a Ryzen 9 5950X, CPU lines trimmed, intr/softirq shortened.
        let stat = "\
cpu  31708642 784473 6805706 2007002845 1366658 1137876 705889 0 86400 0
intr 6629315375 131 0 0 0 0 1 1
ctxt 10892194287
btime 1791358996
processes 18145006
procs_running 1
procs_blocked 0
softirq 2050381473 16960400 239133426 5385 360796985
";
        assert_eq!(
            parse_proc_stat(stat).unwrap(),
            [10_892_194_287, 6_629_315_375, 2_050_381_473, 18_145_006]
        );
        assert!(parse_proc_stat("ctxt 1\nintr 2\nsoftirq 3\n").is_err());
        assert!(parse_proc_stat("ctxt x\nintr 2\nsoftirq 3\nprocesses 4\n").is_err());
    }
}
