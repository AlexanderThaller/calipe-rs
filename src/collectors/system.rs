//! Load averages, boot time, CPU count and logged-in users.
//!
//! Exports the boot time rather than Telegraf's uptime: it only changes on
//! reboot, and uptime is `time() - system_boot_time_seconds` in PromQL.
//!
//! FreeBSD sources: getloadavg(3) (`vm.loadavg`), `kern.boottime`, `hw.ncpu`,
//! and the utmpx database (getutxent(3)) for user sessions.
//!
//! Linux sources: getloadavg(3) (glibc reads the unrounded loads via
//! sysinfo(2)), `btime` in `/proc/stat` (whole seconds; setting the clock moves
//! it), the online CPU count (`_SC_NPROCESSORS_ONLN`), and the utmp database
//! like who(1). Systems that don't write utmp report no users.

use std::time::Duration;

use metrics::describe_gauge;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
}

// Only called from the platform implementations.
#[cfg_attr(
    not(any(target_os = "freebsd", target_os = "linux")),
    expect(dead_code, reason = "used by the FreeBSD and Linux implementations")
)]
pub fn describe() {
    describe_gauge!("system_load1", "1-minute load average.");
    describe_gauge!("system_load5", "5-minute load average.");
    describe_gauge!("system_load15", "15-minute load average.");
    describe_gauge!("system_boot_time_seconds", "Unix time the system booted.");
    describe_gauge!("system_cpus", "Number of online CPUs.");
    describe_gauge!("system_users", "Logged-in user sessions.");
    describe_gauge!("system_unique_users", "Distinct logged-in users.");
}

/// `btime` (boot time in Unix seconds) from `/proc/stat`.
#[cfg(any(target_os = "linux", test))]
fn parse_btime(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|line| line.strip_prefix("btime "))
        .and_then(|value| value.trim().parse().ok())
}

native_only!(System, "system");

#[cfg(target_os = "freebsd")]
pub use freebsd::System;
#[cfg(target_os = "linux")]
pub use linux::System;

#[cfg(any(target_os = "freebsd", target_os = "linux"))]
mod common {
    use std::{
        collections::HashSet,
        io,
    };

    use anyhow::Result;
    use metrics::gauge;

    #[expect(unsafe_code, reason = "getloadavg(3) FFI")]
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
    #[expect(unsafe_code, reason = "utmpx(3) FFI")]
    fn users() -> (usize, usize) {
        let mut sessions = 0;
        let mut names = HashSet::new();
        // SAFETY: this is the only caller of the utmpx functions, and
        // collection is serialized through `&mut self`, so no other thread
        // touches the shared utmpx state.
        unsafe { libc::setutxent() };
        loop {
            // SAFETY: as above.
            let entry = unsafe { libc::getutxent() };
            // SAFETY: getutxent returns NULL or a valid record, which stays
            // valid until the next utmpx call; we copy what we need first.
            let Some(entry) = (unsafe { entry.as_ref() }) else {
                break;
            };
            if entry.ut_type == libc::USER_PROCESS {
                sessions += 1;
                names.insert(entry.ut_user);
            }
        }
        // SAFETY: as above.
        unsafe { libc::endutxent() };
        (sessions, names.len())
    }

    /// Exports the load averages and users, shared by both platforms.
    pub fn export_loads_and_users() -> Result<()> {
        let names = ["system_load1", "system_load5", "system_load15"];
        for (name, load) in names.into_iter().zip(load_averages()?) {
            gauge!(name).set(load);
        }
        let (sessions, unique) = users();
        gauge!("system_users").set(sessions as f64);
        gauge!("system_unique_users").set(unique as f64);
        Ok(())
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::{
        Context,
        Result,
    };
    use metrics::gauge;

    use super::{
        Config,
        common::export_loads_and_users,
        describe,
    };
    use crate::{
        collector::Collector,
        sys::{
            freebsd::Mib,
            timeval_secs,
        },
    };

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

    impl Collector for System {
        fn name(&self) -> &'static str {
            "system"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            export_loads_and_users()?;

            let boot: libc::timeval = self.boottime.read().context("reading kern.boottime")?;
            gauge!("system_boot_time_seconds").set(timeval_secs(boot));

            let ncpu: i32 = self.ncpu.read().context("reading hw.ncpu")?;
            gauge!("system_cpus").set(f64::from(ncpu));
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{
        Context,
        Result,
        bail,
    };
    use metrics::gauge;

    use super::{
        Config,
        common::export_loads_and_users,
        describe,
        parse_btime,
    };
    use crate::{
        collector::Collector,
        sys::linux::read_into,
    };

    pub struct System {
        buf: String,
    }

    impl System {
        pub fn new(_config: &Config) -> Result<Self> {
            let mut system = Self { buf: String::new() };
            system.boot_time()?;
            Ok(system)
        }

        /// Boot time in Unix seconds. Not cached: setting the clock moves it.
        fn boot_time(&mut self) -> Result<u64> {
            read_into("/proc/stat", &mut self.buf).context("reading /proc/stat")?;
            parse_btime(&self.buf).context("/proc/stat has no btime")
        }
    }

    #[expect(unsafe_code, reason = "sysconf(3) FFI")]
    fn online_cpus() -> Result<u64> {
        // SAFETY: sysconf has no preconditions.
        let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        match u64::try_from(n) {
            Ok(n) if n > 0 => Ok(n),
            _ => bail!("sysconf(_SC_NPROCESSORS_ONLN) returned {n}"),
        }
    }

    impl Collector for System {
        fn name(&self) -> &'static str {
            "system"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            export_loads_and_users()?;
            gauge!("system_boot_time_seconds").set(self.boot_time()? as f64);
            gauge!("system_cpus").set(online_cpus()? as f64);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_btime() {
        let stat =
            "cpu  1 2 3 4 5 6 7 8 9 10\nctxt 10892194287\nbtime 1791358996\nprocesses 18145006\n";
        assert_eq!(parse_btime(stat), Some(1_791_358_996));
        assert_eq!(parse_btime("ctxt 1\n"), None);
    }
}
