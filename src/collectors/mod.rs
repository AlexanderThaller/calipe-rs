pub mod cpu;
pub mod internal;

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
    if let Some(c) = &config.inputs.internal {
        out.push(Scheduled::new(
            internal::Internal::new(),
            interval(c.interval),
        ));
    }

    Ok(out)
}
