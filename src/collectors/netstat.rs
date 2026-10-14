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
//!
//! Linux keeps no per-state counts, so the TCP states come from a
//! `NETLINK_SOCK_DIAG` dump of all TCP sockets (IPv4 and IPv6, what `ss -ta`
//! reads) without any extensions, counting the 72-byte `inet_diag_msg`
//! records by state. That walks the socket tables in the kernel, but copies
//! nothing per socket beyond the record. State names are the ones Linux
//! netstat(8) prints (`SYN_RECV`, `FIN_WAIT1`, `CLOSE`, ...); all 11 are
//! always exported. Pending connections (`TCP_NEW_SYN_RECV` request sockets)
//! count as `SYN_RECV`, as in `ss`. The UDP count is `UDP: inuse` from
//! `/proc/net/sockstat` plus `UDP6: inuse` from `/proc/net/sockstat6`
//! (kernel-maintained counts of bound UDP sockets). Both cover the network
//! namespace calipers runs in.

// The FreeBSD helpers are only used by the FreeBSD implementation (and
// tests).
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

native_only!(Netstat, "netstat");

#[cfg(target_os = "freebsd")]
pub use freebsd::Netstat;
#[cfg(target_os = "linux")]
pub use linux::Netstat;

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
        describe,
    };
    use crate::{
        collector::Collector,
        sys::linux::{
            netlink,
            read_into,
        },
    };

    /// TCP state names in `TCP_*` order (`include/net/tcp_states.h`, from 1),
    /// as Linux netstat(8) prints them.
    pub const TCP_STATES: [&str; 11] = [
        "ESTABLISHED",
        "SYN_SENT",
        "SYN_RECV",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "TIME_WAIT",
        "CLOSE",
        "CLOSE_WAIT",
        "LAST_ACK",
        "LISTEN",
        "CLOSING",
    ];
    const TCP_SYN_RECV: u8 = 3;
    /// Request sockets of connections still in the handshake.
    const TCP_NEW_SYN_RECV: u8 = 12;

    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 10;
    const IPPROTO_TCP: u8 = 6;
    /// `sizeof (struct inet_diag_req_v2)`.
    const REQUEST_SIZE: usize = 56;

    /// `struct inet_diag_req_v2` for every TCP socket of `family`: no
    /// extensions, all states, no socket filter.
    fn request(family: u8) -> [u8; REQUEST_SIZE] {
        let mut req = [0; REQUEST_SIZE];
        req[0] = family;
        req[1] = IPPROTO_TCP;
        // idiag_states: bit per state, TCP_ESTABLISHED (1) to
        // TCP_NEW_SYN_RECV (12).
        req[4..8].copy_from_slice(&0x1ffe_u32.to_ne_bytes());
        req
    }

    /// Index into [`TCP_STATES`] for `idiag_state`.
    pub fn state_index(state: u8) -> Option<usize> {
        let state = if state == TCP_NEW_SYN_RECV {
            TCP_SYN_RECV
        } else {
            state
        };
        usize::from(state)
            .checked_sub(1)
            .filter(|&i| i < TCP_STATES.len())
    }

    /// The `inuse` count of the `label` line (`UDP:` or `UDP6:`) in
    /// `/proc/net/sockstat` or `sockstat6`.
    pub fn sockstat_inuse(text: &str, label: &str) -> Option<u64> {
        let mut fields = text
            .lines()
            .find_map(|line| line.strip_prefix(label)?.strip_prefix(' '))?
            .split_whitespace();
        while let Some(key) = fields.next() {
            let value = fields.next()?;
            if key == "inuse" {
                return value.parse().ok();
            }
        }
        None
    }

    pub struct Netstat {
        socket: netlink::Socket,
        text: String,
    }

    impl Netstat {
        pub fn new(_config: &Config) -> Result<Self> {
            Ok(Self {
                socket: netlink::Socket::new(libc::NETLINK_SOCK_DIAG)
                    .context("opening sock_diag socket")?,
                text: String::new(),
            })
        }

        fn udp_inuse(&mut self, path: &str, label: &str) -> Result<u64> {
            read_into(path, &mut self.text).with_context(|| format!("reading {path}"))?;
            sockstat_inuse(&self.text, label)
                .with_context(|| format!("no {label} inuse count in {path}"))
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
            let mut counts = [0u64; TCP_STATES.len()];
            let mut unknown = None;
            for family in [AF_INET, AF_INET6] {
                self.socket
                    .dump(SOCK_DIAG_BY_FAMILY, &request(family), |_, msg| {
                        // inet_diag_msg: idiag_family, idiag_state, ...
                        match msg.get(1).copied().map(state_index) {
                            Some(Some(i)) => counts[i] += 1,
                            Some(None) => unknown = msg.get(1).copied(),
                            None => unknown = Some(0),
                        }
                    })
                    .context("dumping TCP sockets (sock_diag)")?;
            }
            if let Some(state) = unknown {
                bail!("sock_diag returned a socket in unknown TCP state {state}");
            }
            for (state, count) in TCP_STATES.iter().zip(counts) {
                gauge!("netstat_tcp_connections", "state" => *state).set(count as f64);
            }

            let udp = self.udp_inuse("/proc/net/sockstat", "UDP:")?
                + self.udp_inuse("/proc/net/sockstat6", "UDP6:")?;
            gauge!("netstat_udp_sockets").set(udp as f64);
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn maps_states() {
            assert_eq!(state_index(1).map(|i| TCP_STATES[i]), Some("ESTABLISHED"));
            assert_eq!(state_index(10).map(|i| TCP_STATES[i]), Some("LISTEN"));
            assert_eq!(state_index(11).map(|i| TCP_STATES[i]), Some("CLOSING"));
            assert_eq!(state_index(12).map(|i| TCP_STATES[i]), Some("SYN_RECV"));
            assert_eq!(state_index(0), None);
            assert_eq!(state_index(13), None);
        }

        #[test]
        fn parses_sockstat() {
            let v4 = "sockets: used 2017\nTCP: inuse 83 orphan 0 tw 12 alloc 104 mem 9\nUDP: \
                      inuse 21 mem 15\nUDPLITE: inuse 0\nRAW: inuse 0\nFRAG: inuse 0 memory 0\n";
            let v6 = "TCP6: inuse 35\nUDP6: inuse 14\nUDPLITE6: inuse 0\nRAW6: inuse 1\nFRAG6: \
                      inuse 0 memory 0\n";
            assert_eq!(sockstat_inuse(v4, "UDP:"), Some(21));
            assert_eq!(sockstat_inuse(v6, "UDP6:"), Some(14));
            assert_eq!(sockstat_inuse(v6, "UDP:"), None);
            assert_eq!(sockstat_inuse("UDP: mem 3\n", "UDP:"), None);
        }

        #[test]
        fn counts_own_listener() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut socket = netlink::Socket::new(libc::NETLINK_SOCK_DIAG).unwrap();
            let mut found = false;
            socket
                .dump(SOCK_DIAG_BY_FAMILY, &request(AF_INET), |_, msg| {
                    // idiag_sport (network byte order) at offset 4.
                    let sport = u16::from_be_bytes([msg[4], msg[5]]);
                    if sport == port {
                        assert_eq!(state_index(msg[1]).map(|i| TCP_STATES[i]), Some("LISTEN"));
                        found = true;
                    }
                })
                .unwrap();
            assert!(found);
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
