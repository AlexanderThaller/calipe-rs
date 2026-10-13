//! Kernel activity counters: context switches, interrupts, syscalls, traps
//! and process creation.
//!
//! Telegraf's kernel input is Linux-only (it reads `/proc/stat`), so on
//! FreeBSD this is new data. All values are 64-bit kernel counters
//! (`vm.stats.sys.*`, `vm.stats.vm.v_*forks`) exported as real counters.

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
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
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

// Only called from the FreeBSD implementation.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub fn describe() {
    describe_counter!("kernel_context_switches_total", "Context switches.");
    describe_counter!(
        "kernel_interrupts_total",
        "Interrupts; type=hard for device interrupts, type=soft for software interrupts."
    );
    describe_counter!("kernel_syscalls_total", "System calls.");
    describe_counter!("kernel_traps_total", "Traps, including page faults.");
    describe_counter!(
        "kernel_forks_total",
        "New processes and kernel threads, by creation call (fork, vfork, rfork, kthread)."
    );
}

freebsd_only!(Kernel, "kernel");

#[cfg(target_os = "freebsd")]
pub use freebsd::Kernel;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::Result;
    use metrics::counter;

    use super::{COUNTERS, Config, describe};
    use crate::collector::Collector;
    use crate::sys::freebsd::Uint;

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
