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
pub mod processes;
pub mod swap;
pub mod system;
pub mod zfs;

use std::time::Duration;

use crate::collector::Scheduled;
use crate::config::Config;

/// Instantiates every enabled input. Fails if any input can't be set up
/// (e.g. a sysctl that doesn't exist), so misconfiguration is caught at start.
pub fn build(config: &Config) -> anyhow::Result<Vec<Scheduled>> {
    let default = config.agent.interval;
    let interval = |own: Option<Duration>| own.unwrap_or(default);
    let mut out = Vec::new();

    if let Some(c) = &config.inputs.chrony {
        out.push(Scheduled::new(
            chrony::Chrony::new(c)?,
            interval(c.interval),
        ));
    }
    if let Some(c) = &config.inputs.cpu {
        out.push(Scheduled::new(cpu::Cpu::new(c)?, interval(c.interval)));
    }
    if let Some(c) = &config.inputs.mem {
        out.push(Scheduled::new(mem::Mem::new(c)?, interval(c.interval)));
    }
    if let Some(c) = &config.inputs.swap {
        out.push(Scheduled::new(swap::Swap::new(c)?, interval(c.interval)));
    }
    if let Some(c) = &config.inputs.system {
        out.push(Scheduled::new(
            system::System::new(c)?,
            interval(c.interval),
        ));
    }
    if let Some(c) = &config.inputs.kernel {
        out.push(Scheduled::new(
            kernel::Kernel::new(c)?,
            interval(c.interval),
        ));
    }
    if let Some(c) = &config.inputs.zfs {
        out.push(Scheduled::new(zfs::Zfs::new(c)?, interval(c.interval)));
    }
    if let Some(c) = &config.inputs.disk {
        out.push(Scheduled::new(disk::Disk::new(c)?, interval(c.interval)));
    }
    if let Some(c) = &config.inputs.diskio {
        out.push(Scheduled::new(
            diskio::DiskIo::new(c)?,
            interval(c.interval),
        ));
    }
    if let Some(c) = &config.inputs.net {
        out.push(Scheduled::new(net::Net::new(c)?, interval(c.interval)));
    }
    if let Some(c) = &config.inputs.netstat {
        out.push(Scheduled::new(
            netstat::Netstat::new(c)?,
            interval(c.interval),
        ));
    }
    // Both read the same process table, so they share one collector.
    if config.inputs.processes.is_some() || !config.inputs.procstat.is_empty() {
        let own = config.inputs.processes.as_ref().and_then(|c| c.interval);
        out.push(Scheduled::new(
            processes::Processes::new(config.inputs.processes.is_some(), &config.inputs.procstat)?,
            interval(own),
        ));
    }
    if !config.inputs.dns_query.is_empty() {
        out.push(Scheduled::new(
            dns_query::DnsQuery::new(&config.inputs.dns_query)?,
            default,
        ));
    }
    if !config.inputs.http_response.is_empty() {
        out.push(Scheduled::new(
            http_response::HttpResponse::new(&config.inputs.http_response)?,
            default,
        ));
    }
    if let Some(c) = &config.inputs.internal {
        out.push(Scheduled::new(
            internal::Internal::new(),
            interval(c.interval),
        ));
    }

    Ok(out)
}
