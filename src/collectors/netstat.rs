//! TCP connections by state and UDP socket count.
//!
//! FreeBSD sources, two sysctls per collection and no socket list walk:
//!
//! * `net.inet.tcp.states`: `uint64_t[TCP_NSTATES]` connection counts the
//!   kernel maintains on every state change (IPv4 and IPv6).
//! * `net.inet.udp.pcblist`: only its 64-byte `struct xinpgen` header is read.
//!   The kernel writes the header first and stops with `ENOMEM` at the first
//!   socket record that doesn't fit, so this costs no copying. `xig_count` is
//!   the number of UDP sockets (IPv4 and IPv6).
//!
//! Telegraf gets the same numbers by listing every socket.

// The helpers are only used by the FreeBSD implementation (and tests).
#![cfg_attr(
    not(target_os = "freebsd"),
    expect(dead_code, reason = "used by the FreeBSD implementation")
)]

use std::time::Duration;

use metrics::describe_gauge;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
}

pub fn describe() {
    describe_gauge!(
        "netstat_tcp_connections",
        "TCP connections (including listeners) by state."
    );
    describe_gauge!("netstat_udp_sockets", "Open UDP sockets.");
}

/// TCP state names in `TCPS_*` order (`netinet/tcp_fsm.h`), as netstat(1)
/// prints them.
pub const TCP_STATES: [&str; 11] = [
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "CLOSE_WAIT",
    "FIN_WAIT_1",
    "CLOSING",
    "LAST_ACK",
    "FIN_WAIT_2",
    "TIME_WAIT",
];

/// `sizeof (struct xinpgen)`.
pub const XINPGEN_SIZE: usize = 64;

/// Extracts `xig_count` from a `struct xinpgen` header, checking `xig_len`.
pub fn xinpgen_count(header: &[u8]) -> Result<u32, String> {
    let len = header
        .get(..8)
        .map(|b| u64::from_ne_bytes(b.try_into().expect("8")));
    if len != Some(XINPGEN_SIZE as u64) {
        return Err(format!("unexpected xinpgen length {len:?}"));
    }
    Ok(u32::from_ne_bytes(header[8..12].try_into().expect("4")))
}

freebsd_only!(Netstat, "netstat");

#[cfg(target_os = "freebsd")]
pub use freebsd::Netstat;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::{
        Context,
        Result,
        anyhow,
    };
    use metrics::gauge;

    use super::{
        Config,
        TCP_STATES,
        XINPGEN_SIZE,
        describe,
        xinpgen_count,
    };
    use crate::{
        collector::Collector,
        sys::freebsd::Mib,
    };

    pub struct Netstat {
        tcp_states: Mib,
        udp_pcblist: Mib,
    }

    impl Netstat {
        pub fn new(_config: &Config) -> Result<Self> {
            Ok(Self {
                tcp_states: Mib::new("net.inet.tcp.states")?,
                udp_pcblist: Mib::new("net.inet.udp.pcblist")?,
            })
        }
    }

    impl Collector for Netstat {
        fn name(&self) -> &'static str {
            "netstat"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            let states: [u64; TCP_STATES.len()] = self
                .tcp_states
                .read()
                .context("reading net.inet.tcp.states")?;
            for (state, count) in TCP_STATES.iter().zip(states) {
                gauge!("netstat_tcp_connections", "state" => *state).set(count as f64);
            }

            // Header only: ENOMEM is expected whenever there is a socket.
            let mut header = [0u8; XINPGEN_SIZE];
            match self.udp_pcblist.read_prefix(&mut header) {
                Ok(n) if n >= XINPGEN_SIZE => {}
                Ok(n) => return Err(anyhow!("net.inet.udp.pcblist returned only {n} bytes")),
                Err(err) => return Err(err).context("reading net.inet.udp.pcblist"),
            }
            let count = xinpgen_count(&header).map_err(|e| anyhow!("net.inet.udp.pcblist: {e}"))?;
            gauge!("netstat_udp_sockets").set(f64::from(count));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_xinpgen_count() {
        let mut h = [0u8; XINPGEN_SIZE];
        h[..8].copy_from_slice(&64u64.to_ne_bytes());
        h[8..12].copy_from_slice(&12u32.to_ne_bytes());
        assert_eq!(xinpgen_count(&h), Ok(12));
        h[..8].copy_from_slice(&56u64.to_ne_bytes());
        assert!(xinpgen_count(&h).is_err(), "layout change is detected");
    }
}
