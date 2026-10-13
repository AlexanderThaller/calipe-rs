//! Load averages, boot time, CPU count and logged-in users.
//!
//! Exports the boot time rather than Telegraf's uptime: it only changes on
//! reboot, and uptime is `time() - system_boot_time_seconds` in PromQL.
//!
//! FreeBSD sources: getloadavg(3) (`vm.loadavg`), `kern.boottime`, `hw.ncpu`,
//! and the utmpx database (getutxent(3)) for user sessions.

use std::time::Duration;

use metrics::describe_gauge;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
}

// Only called from the FreeBSD implementation.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub fn describe() {
    describe_gauge!("system_load1", "1-minute load average.");
    describe_gauge!("system_load5", "5-minute load average.");
    describe_gauge!("system_load15", "15-minute load average.");
    describe_gauge!("system_boot_time_seconds", "Unix time the system booted.");
    describe_gauge!("system_cpus", "Number of online CPUs.");
    describe_gauge!("system_users", "Logged-in user sessions.");
    describe_gauge!("system_unique_users", "Distinct logged-in users.");
}

freebsd_only!(System, "system");

#[cfg(target_os = "freebsd")]
pub use freebsd::System;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::collections::HashSet;
    use std::io;

    use anyhow::{Context, Result};
    use metrics::gauge;

    use super::{Config, describe};
    use crate::collector::Collector;
    use crate::sys::freebsd::Mib;
    use crate::sys::timeval_secs;

    pub struct System {
        boottime: Mib,
        ncpu: Mib,
    }

    impl System {
        pub fn new(_config: &Config) -> Result<Self> {
            Ok(Self {
                boottime: Mib::new("kern.boottime")?,
                ncpu: Mib::new("hw.ncpu")?,
            })
        }
    }

    fn load_averages() -> io::Result<[f64; 3]> {
        let mut loads = [0f64; 3];
        // SAFETY: `loads` has room for the 3 requested values.
        let n = unsafe { libc::getloadavg(loads.as_mut_ptr(), 3) };
        if n == 3 {
            Ok(loads)
        } else {
            Err(io::Error::other("getloadavg failed"))
        }
    }

    /// (sessions, distinct users) from the utmpx database.
    fn users() -> (usize, usize) {
        let mut sessions = 0;
        let mut names = HashSet::new();
        // SAFETY: the utmpx functions are only called from the collector task,
        // which runs on a single thread; each returned record is copied out
        // before the next call reuses the static buffer.
        unsafe {
            libc::setutxent();
            loop {
                let entry = libc::getutxent();
                if entry.is_null() {
                    break;
                }
                if (*entry).ut_type == libc::USER_PROCESS {
                    sessions += 1;
                    names.insert((*entry).ut_user);
                }
            }
            libc::endutxent();
        }
        (sessions, names.len())
    }

    impl Collector for System {
        fn name(&self) -> &'static str {
            "system"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            let names = ["system_load1", "system_load5", "system_load15"];
            for (name, load) in names.into_iter().zip(load_averages()?) {
                gauge!(name).set(load);
            }

            let boot: libc::timeval = self.boottime.read().context("reading kern.boottime")?;
            gauge!("system_boot_time_seconds").set(timeval_secs(boot));

            let ncpu: i32 = self.ncpu.read().context("reading hw.ncpu")?;
            gauge!("system_cpus").set(f64::from(ncpu));

            let (sessions, unique) = users();
            gauge!("system_users").set(sessions as f64);
            gauge!("system_unique_users").set(unique as f64);
            Ok(())
        }
    }
}
