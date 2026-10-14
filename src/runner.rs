//! Running collectors, and swapping them when the configuration is reloaded.
//!
//! An input whose config sections and the agent interval are unchanged keeps
//! its running collector, and with it per-object state such as counter reset
//! offsets ([`crate::counter`]). Only new and changed inputs are rebuilt.

use std::{
    collections::BTreeMap,
    time::Duration,
};

use anyhow::{
    Context,
    Result,
};
use tokio::task::JoinHandle;

use crate::{
    collector::Scheduled,
    collectors,
    config::Config,
};

/// What an input's collector is built from.
#[derive(Debug, PartialEq)]
struct Fingerprint {
    interval: Duration,
    sections: Vec<Option<toml::Value>>,
}

impl Fingerprint {
    fn of(config: &Config, input: &collectors::Input<'_>) -> Self {
        let inputs = config.raw.get("inputs");
        Self {
            interval: config.agent.interval,
            sections: input
                .sections
                .iter()
                .map(|section| inputs.and_then(|i| i.get(section)).cloned())
                .collect(),
        }
    }
}

struct Running {
    fingerprint: Fingerprint,
    interval: Duration,
    task: JoinHandle<()>,
}

/// Collectors running on the tokio runtime, by input key.
#[derive(Default)]
pub struct Collectors {
    running: BTreeMap<&'static str, Running>,
}

/// Collectors built for a configuration, not running yet.
pub struct Plan {
    keep: Vec<&'static str>,
    build: Vec<(&'static str, Fingerprint, Scheduled)>,
    longest: Option<Duration>,
}

impl Plan {
    /// Longest collection interval of all inputs in the new configuration.
    pub fn longest_interval(&self) -> Option<Duration> {
        self.longest
    }
}

/// Input keys affected by [`Collectors::apply`].
#[derive(Debug, Default, PartialEq)]
pub struct Changes {
    pub started: Vec<&'static str>,
    pub restarted: Vec<&'static str>,
    pub stopped: Vec<&'static str>,
    pub kept: usize,
}

impl Collectors {
    pub fn len(&self) -> usize {
        self.running.len()
    }

    /// Builds the collectors of new and changed inputs. Fails without side
    /// effects if any of them can't be set up.
    pub fn plan(&self, config: &Config) -> Result<Plan> {
        let mut plan = Plan {
            keep: Vec::new(),
            build: Vec::new(),
            longest: None,
        };
        for input in collectors::inputs(config) {
            let fingerprint = Fingerprint::of(config, &input);
            let key = input.key;
            let interval = match self.running.get(key) {
                Some(running) if running.fingerprint == fingerprint => {
                    plan.keep.push(key);
                    running.interval
                }
                _ => {
                    let scheduled = input
                        .build()
                        .with_context(|| format!("setting up input {key}"))?;
                    let interval = scheduled.interval();
                    plan.build.push((key, fingerprint, scheduled));
                    interval
                }
            };
            plan.longest = plan.longest.max(Some(interval));
        }
        Ok(plan)
    }

    /// Stops removed and changed collectors and starts the newly built ones.
    /// Must run inside the tokio runtime, after the recorder is installed.
    pub fn apply(&mut self, plan: Plan) -> Changes {
        let mut changes = Changes {
            kept: plan.keep.len(),
            ..Changes::default()
        };
        for (key, ..) in &plan.build {
            if self.running.contains_key(key) {
                changes.restarted.push(*key);
            } else {
                changes.started.push(*key);
            }
        }
        self.running.retain(|key, running| {
            if plan.keep.contains(key) {
                return true;
            }
            running.task.abort();
            if !changes.restarted.contains(key) {
                changes.stopped.push(key);
            }
            false
        });
        for (key, fingerprint, scheduled) in plan.build {
            scheduled.describe();
            let interval = scheduled.interval();
            let task = tokio::spawn(scheduled.run_forever());
            self.running.insert(
                key,
                Running {
                    fingerprint,
                    interval,
                    task,
                },
            );
        }
        changes
    }
}

impl Drop for Collectors {
    fn drop(&mut self) {
        for running in self.running.values() {
            running.task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERNAL: &str = "[inputs.internal]\n";
    const DNS: &str = "[[inputs.dns_query]]\nservers = [\"127.0.0.1\"]\ndomains = \
                       [\"a.test\"]\nport = 9\ntimeout = \"10ms\"\n";

    fn apply(collectors: &mut Collectors, text: &str) -> Result<Changes> {
        let config = Config::parse(text)?;
        let plan = collectors.plan(&config)?;
        Ok(collectors.apply(plan))
    }

    #[tokio::test]
    async fn reload_rebuilds_only_changed_inputs() {
        let mut collectors = Collectors::default();
        let changes = apply(&mut collectors, INTERNAL).unwrap();
        assert_eq!(changes.started, ["internal"]);

        let changes = apply(&mut collectors, INTERNAL).unwrap();
        assert_eq!(
            changes,
            Changes {
                kept: 1,
                ..Changes::default()
            }
        );

        let changes = apply(&mut collectors, &format!("{INTERNAL}{DNS}")).unwrap();
        assert_eq!(
            changes,
            Changes {
                started: vec!["dns_query"],
                kept: 1,
                ..Changes::default()
            }
        );

        let changed_dns = DNS.replace("a.test", "b.test");
        let changes = apply(&mut collectors, &format!("{INTERNAL}{changed_dns}")).unwrap();
        assert_eq!(
            changes,
            Changes {
                restarted: vec!["dns_query"],
                kept: 1,
                ..Changes::default()
            }
        );

        let changes = apply(&mut collectors, &changed_dns).unwrap();
        assert_eq!(
            changes,
            Changes {
                stopped: vec!["internal"],
                kept: 1,
                ..Changes::default()
            }
        );
        assert_eq!(collectors.len(), 1);
    }

    #[tokio::test]
    async fn agent_interval_restarts_every_input() {
        let mut collectors = Collectors::default();
        apply(&mut collectors, &format!("{INTERNAL}{DNS}")).unwrap();
        let changes = apply(
            &mut collectors,
            &format!("[agent]\ninterval = \"30s\"\n{INTERNAL}{DNS}"),
        )
        .unwrap();
        assert_eq!(changes.restarted, ["dns_query", "internal"]);
    }

    #[tokio::test]
    async fn failed_plan_changes_nothing() {
        let mut collectors = Collectors::default();
        apply(&mut collectors, INTERNAL).unwrap();
        // Unparsable server address: the dns_query section fails to parse.
        assert!(
            apply(
                &mut collectors,
                "[[inputs.dns_query]]\nservers = [\"x\"]\ndomains = []\n"
            )
            .is_err()
        );
        // An input that can't be set up (pf is FreeBSD-only; on FreeBSD,
        // /dev/pf needs root) leaves the running collectors untouched.
        #[cfg(not(target_os = "freebsd"))]
        {
            assert!(apply(&mut collectors, "[inputs.pf]\n").is_err());
            assert_eq!(collectors.len(), 1);
            assert_eq!(apply(&mut collectors, INTERNAL).unwrap().kept, 1);
        }
    }
}
