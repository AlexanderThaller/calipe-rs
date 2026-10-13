//! Configuration file format.
//!
//! Close to Telegraf's layout, but our own: unknown keys are rejected so typos
//! fail at startup instead of being silently ignored.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub agent: Agent,
    #[serde(default)]
    pub global_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub exporter: Exporter,
    #[serde(default)]
    pub inputs: Inputs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    /// Default collection interval for all inputs.
    #[serde(default = "default_interval", with = "humantime_serde")]
    pub interval: Duration,
    /// Value of the `host` label. Empty means `gethostname()`.
    #[serde(default)]
    pub hostname: String,
    /// Don't add the `host` label at all.
    #[serde(default)]
    pub omit_hostname: bool,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            interval: default_interval(),
            hostname: String::new(),
            omit_hostname: false,
        }
    }
}

fn default_interval() -> Duration {
    Duration::from_secs(10)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exporter {
    /// Address of the Prometheus HTTP listener. Note that `[::]` on FreeBSD is
    /// IPv6-only by default (`net.inet6.ip6.v6only=1`).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
}

impl Default for Exporter {
    fn default() -> Self {
        Self {
            listen: default_listen(),
        }
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 9273))
}

/// Every input is optional; an absent section means the input is disabled.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub cpu: Option<crate::collectors::cpu::Config>,
    pub internal: Option<crate::collectors::internal::Config>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing config {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.agent.interval.is_zero() {
            bail!("agent.interval must be greater than zero");
        }
        for key in self.global_tags.keys() {
            if !is_valid_label_name(key) {
                bail!("global_tags: {key:?} is not a valid Prometheus label name");
            }
        }
        if !self.agent.omit_hostname && self.global_tags.contains_key("host") {
            bail!(
                "global_tags.host conflicts with the automatic host label; set agent.omit_hostname = true"
            );
        }
        Ok(())
    }
}

fn is_valid_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with("__")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_uses_defaults() {
        let config = Config::parse("").unwrap();
        assert_eq!(config.agent.interval, Duration::from_secs(10));
        assert_eq!(config.exporter.listen, "0.0.0.0:9273".parse().unwrap());
        assert!(config.inputs.internal.is_none());
    }

    #[test]
    fn parses_example_config() {
        let text = include_str!("../resources/calipers.toml");
        let config = Config::parse(text).unwrap();
        assert_eq!(config.global_tags["realm"], "hetzner");
        assert!(config.inputs.internal.is_some());
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::parse("[agent]\nintervall = \"10s\"").is_err());
        assert!(Config::parse("[inputs.nope]").is_err());
    }

    #[test]
    fn rejects_zero_interval() {
        assert!(Config::parse("[agent]\ninterval = \"0s\"").is_err());
    }

    #[test]
    fn rejects_bad_label_names() {
        assert!(Config::parse("[global_tags]\n\"a-b\" = \"x\"").is_err());
        assert!(Config::parse("[global_tags]\n__x = \"x\"").is_err());
        assert!(Config::parse("[global_tags]\nhost = \"x\"").is_err());
        assert!(
            Config::parse("[agent]\nomit_hostname = true\n[global_tags]\nhost = \"x\"").is_ok()
        );
    }
}
