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

pub mod cpu;
pub mod internal;
pub mod mem;

use std::time::Duration;

use crate::collector::Scheduled;
use crate::config::Config;

/// Instantiates every enabled input. Fails if any input can't be set up
/// (e.g. a sysctl that doesn't exist), so misconfiguration is caught at start.
pub fn build(config: &Config) -> anyhow::Result<Vec<Scheduled>> {
    let default = config.agent.interval;
    let interval = |own: Option<Duration>| own.unwrap_or(default);
    let mut out = Vec::new();

    if let Some(c) = &config.inputs.cpu {
        out.push(Scheduled::new(cpu::Cpu::new(c)?, interval(c.interval)));
    }
    if let Some(c) = &config.inputs.mem {
        out.push(Scheduled::new(mem::Mem::new(c)?, interval(c.interval)));
    }
    if let Some(c) = &config.inputs.internal {
        out.push(Scheduled::new(
            internal::Internal::new(),
            interval(c.interval),
        ));
    }

    Ok(out)
}
