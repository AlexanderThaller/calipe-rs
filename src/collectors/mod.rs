/// Defines a stand-in for a FreeBSD-only collector on other platforms whose
/// constructor fails, so enabling it there is a startup error.
macro_rules! freebsd_only {
    ($ty:ident, $name:literal) => {
        #[cfg(not(target_os = "freebsd"))]
        pub struct $ty;

        #[cfg(not(target_os = "freebsd"))]
        impl $ty {
            pub fn new(_config: &Config) -> anyhow::Result<Self> {
                anyhow::bail!(concat!(
                    "the ",
                    $name,
                    " input is only supported on FreeBSD"
                ))
            }
        }

        #[cfg(not(target_os = "freebsd"))]
        impl $crate::collector::Collector for $ty {
            fn name(&self) -> &'static str {
                $name
            }

            async fn collect(&mut self) -> anyhow::Result<()> {
                unreachable!("constructor always fails on this platform")
            }
        }
    };
}

/// Defines a stand-in for a collector implemented on FreeBSD and Linux whose
/// constructor fails on other platforms, so enabling it there is a startup
/// error.
macro_rules! native_only {
    ($ty:ident, $name:literal) => {
        #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
        pub struct $ty;

        #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
        impl $ty {
            pub fn new(_config: &Config) -> anyhow::Result<Self> {
                anyhow::bail!(concat!(
                    "the ",
                    $name,
                    " input is only supported on FreeBSD and Linux"
                ))
            }
        }

        #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
        impl $crate::collector::Collector for $ty {
            fn name(&self) -> &'static str {
                $name
            }

            async fn collect(&mut self) -> anyhow::Result<()> {
                unreachable!("constructor always fails on this platform")
            }
        }
    };
}

pub mod chrony;
pub mod cpu;
pub mod disk;
pub mod diskio;
pub mod dns_query;
pub mod http_response;
pub mod internal;
pub mod kernel;
pub mod mem;
pub mod net;
pub mod netstat;
pub mod pf;
pub mod processes;
pub mod smart;
pub mod swap;
pub mod system;
pub mod zfs;

use std::time::Duration;

use crate::{
    collector::{
        Collector,
        Scheduled,
    },
    config::Config,
};

/// One enabled input: the config sections it is built from (to detect
/// changes on reload) and how to build its collector.
pub struct Input<'a> {
    /// Stable key, the first of `sections`.
    pub key: &'static str,
    /// `[inputs.*]` sections the collector depends on.
    pub sections: &'static [&'static str],
    build: Box<dyn FnOnce() -> anyhow::Result<Scheduled> + 'a>,
}

impl<'a> Input<'a> {
    fn new<C: Collector>(
        sections: &'static [&'static str],
        interval: Duration,
        build: impl FnOnce() -> anyhow::Result<C> + 'a,
    ) -> Self {
        Input {
            key: sections[0],
            sections,
            build: Box::new(move || Ok(Scheduled::new(build()?, interval))),
        }
    }

    pub fn build(self) -> anyhow::Result<Scheduled> {
        (self.build)()
    }
}

/// Instantiates every enabled input. Fails if any input can't be set up
/// (e.g. a sysctl that doesn't exist), so misconfiguration is caught at start.
pub fn build(config: &Config) -> anyhow::Result<Vec<Scheduled>> {
    inputs(config).into_iter().map(Input::build).collect()
}

/// Every enabled input, not built yet.
pub fn inputs(config: &Config) -> Vec<Input<'_>> {
    let default = config.agent.interval;
    let interval = |own: Option<Duration>| own.unwrap_or(default);
    let i = &config.inputs;
    let mut out = Vec::new();
    if let Some(c) = &i.chrony {
        out.push(Input::new(&["chrony"], interval(c.interval), || {
            Ok(chrony::Chrony::new(c))
        }));
    }
    if let Some(c) = &i.cpu {
        out.push(Input::new(&["cpu"], interval(c.interval), || {
            cpu::Cpu::new(c)
        }));
    }
    if let Some(c) = &i.mem {
        out.push(Input::new(&["mem"], interval(c.interval), || {
            mem::Mem::new(c)
        }));
    }
    if let Some(c) = &i.swap {
        out.push(Input::new(&["swap"], interval(c.interval), || {
            swap::Swap::new(c)
        }));
    }
    if let Some(c) = &i.system {
        out.push(Input::new(&["system"], interval(c.interval), || {
            system::System::new(c)
        }));
    }
    if let Some(c) = &i.kernel {
        out.push(Input::new(&["kernel"], interval(c.interval), || {
            kernel::Kernel::new(c)
        }));
    }
    if let Some(c) = &i.zfs {
        out.push(Input::new(&["zfs"], interval(c.interval), || {
            zfs::Zfs::new(c)
        }));
    }
    if let Some(c) = &i.disk {
        out.push(Input::new(&["disk"], interval(c.interval), || {
            disk::Disk::new(c)
        }));
    }
    if let Some(c) = &i.diskio {
        out.push(Input::new(&["diskio"], interval(c.interval), || {
            diskio::DiskIo::new(c)
        }));
    }
    if let Some(c) = &i.net {
        out.push(Input::new(&["net"], interval(c.interval), || {
            net::Net::new(c)
        }));
    }
    if let Some(c) = &i.netstat {
        out.push(Input::new(&["netstat"], interval(c.interval), || {
            netstat::Netstat::new(c)
        }));
    }
    // Both read the same process table, so they share one collector.
    if i.processes.is_some() || !i.procstat.is_empty() {
        let own = i.processes.as_ref().and_then(|c| c.interval);
        out.push(Input::new(
            &["processes", "procstat"],
            interval(own),
            || processes::Processes::new(i.processes.is_some(), &i.procstat),
        ));
    }
    if !i.dns_query.is_empty() {
        out.push(Input::new(&["dns_query"], default, || {
            dns_query::DnsQuery::new(&i.dns_query)
        }));
    }
    if !i.http_response.is_empty() {
        out.push(Input::new(&["http_response"], default, || {
            http_response::HttpResponse::new(&i.http_response)
        }));
    }
    if let Some(c) = &i.pf {
        out.push(Input::new(&["pf"], interval(c.interval), || pf::Pf::new(c)));
    }
    if let Some(c) = &i.smart {
        let own = c.interval.unwrap_or(smart::DEFAULT_INTERVAL);
        out.push(Input::new(&["smart"], own, || smart::Smart::new(c)));
    }
    if let Some(c) = &i.internal {
        out.push(Input::new(&["internal"], interval(c.interval), || {
            Ok(internal::Internal::new())
        }));
    }
    out
}
