//! Network interface counters.
//!
//! FreeBSD source: one `{CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLISTL, 0}` sysctl
//! (what getifaddrs(3) uses), which returns an `RTM_IFINFO` message with
//! `struct if_data` per interface, followed by its `sockaddr_dl` carrying the
//! name. The `if_msghdrl` variant states its own length and the offset of
//! `if_data`, so the parser doesn't depend on the header size. Address
//! messages in between are skipped.
//!
//! Linux source: one rtnetlink `RTM_GETLINK` dump for all interfaces
//! (`IFLA_IFNAME`, `IFLA_OPERSTATE`, `IFLA_STATS64`), what `ip -s link`
//! reads, plus `/sys/class/net/<interface>/speed` for the link speed, which
//! netlink doesn't carry. Linux has no transmitted multicast counter, so
//! `net_sent_multicast_packets_total` is absent. `net_receive_drops_total` is
//! `rx_dropped + rx_missed_errors` (packets the NIC dropped for lack of
//! buffers), as in `/proc/net/dev`. `net_link_up` comes from the RFC 2863
//! operational state: up is 1, unknown (common for virtual interfaces) is
//! absent, everything else 0.
//!
//! Without an `interfaces` list, loopback and administratively down
//! interfaces are skipped, like Telegraf.

// The routing message parser is only used by the FreeBSD implementation (and
// tests).
#![cfg_attr(
    not(target_os = "freebsd"),
    expect(dead_code, reason = "used by the FreeBSD implementation")
)]

use std::time::Duration;

use metrics::{
    describe_counter,
    describe_gauge,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
    /// Interfaces to report; `*` and `?` wildcards allowed. Empty means all
    /// interfaces that are up and not loopback.
    #[serde(default)]
    pub interfaces: Vec<String>,
}

pub fn describe() {
    describe_counter!("net_received_bytes_total", "Bytes received.");
    describe_counter!("net_sent_bytes_total", "Bytes sent.");
    describe_counter!("net_received_packets_total", "Packets received.");
    describe_counter!("net_sent_packets_total", "Packets sent.");
    describe_counter!(
        "net_received_multicast_packets_total",
        "Multicast packets received."
    );
    describe_counter!(
        "net_sent_multicast_packets_total",
        "Multicast packets sent."
    );
    describe_counter!("net_receive_errors_total", "Input errors.");
    describe_counter!("net_send_errors_total", "Output errors.");
    describe_counter!("net_receive_drops_total", "Packets dropped on input.");
    describe_counter!(
        "net_send_drops_total",
        "Packets dropped on output (queue full)."
    );
    describe_counter!("net_collisions_total", "Collisions (half-duplex links).");
    describe_gauge!(
        "net_link_up",
        "1 if the link is up, 0 if down; absent if the driver doesn't report it."
    );
    describe_gauge!(
        "net_speed_bits_per_second",
        "Link speed as reported by the driver; absent if unknown."
    );
}

/// `if_msghdrl` field offsets.
mod hdr {
    pub const MSGLEN: usize = 0;
    pub const VERSION: usize = 2;
    pub const TYPE: usize = 3;
    pub const ADDRS: usize = 4;
    pub const FLAGS: usize = 8;
    pub const LEN: usize = 16;
    pub const DATA_OFF: usize = 18;
}

/// `struct if_data` field offsets (identical on 14.x and 15.x).
mod data {
    pub const LINK_STATE: usize = 4;
    pub const DATALEN: usize = 6;
    pub const BAUDRATE: usize = 16;
    pub const IPACKETS: usize = 24;
    pub const IERRORS: usize = 32;
    pub const OPACKETS: usize = 40;
    pub const OERRORS: usize = 48;
    pub const COLLISIONS: usize = 56;
    pub const IBYTES: usize = 64;
    pub const OBYTES: usize = 72;
    pub const IMCASTS: usize = 80;
    pub const OMCASTS: usize = 88;
    pub const IQDROPS: usize = 96;
    pub const OQDROPS: usize = 104;
    /// Fields up to and including `ifi_oqdrops`.
    pub const MIN_LEN: usize = 112;
}

const RTM_VERSION: u8 = 5;
const RTM_IFINFO: u8 = 0xe;
const RTA_IFP: i32 = 0x10;
const AF_LINK: u8 = 18;
const IFF_UP: i32 = 0x1;
const IFF_LOOPBACK: i32 = 0x8;
const LINK_STATE_DOWN: u8 = 1;
const LINK_STATE_UP: u8 = 2;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Interface {
    pub name: String,
    pub up: bool,
    pub loopback: bool,
    /// `None` when the driver reports `LINK_STATE_UNKNOWN`.
    pub link_up: Option<bool>,
    pub baudrate: u64,
    pub counters: [(&'static str, u64); 11],
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn i32_at(b: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Parses one `RTM_IFINFO` message (`if_msghdrl` + `if_data` + sockaddrs).
fn parse_ifinfo(msg: &[u8]) -> Option<Interface> {
    let addrs = i32_at(msg, hdr::ADDRS)?;
    let flags = i32_at(msg, hdr::FLAGS)?;
    let len = usize::from(u16_at(msg, hdr::LEN)?);
    let data_off = usize::from(u16_at(msg, hdr::DATA_OFF)?);
    let data = msg.get(data_off..len)?;
    if usize::from(u16_at(data, data::DATALEN)?) < data::MIN_LEN || data.len() < data::MIN_LEN {
        return None;
    }
    // The interface's sockaddr_dl follows the header when RTA_IFP is set:
    // sdl_len, sdl_family, sdl_index (2), sdl_type, sdl_nlen, sdl_alen,
    // sdl_slen, then the name.
    if addrs & RTA_IFP == 0 {
        return None;
    }
    let sdl = msg.get(len..)?;
    if *sdl.get(1)? != AF_LINK {
        return None;
    }
    let nlen = usize::from(*sdl.get(5)?);
    let name = String::from_utf8_lossy(sdl.get(8..8 + nlen)?).into_owned();
    let counter = |off| u64_at(data, off).unwrap_or(0);
    Some(Interface {
        name,
        up: flags & IFF_UP != 0,
        loopback: flags & IFF_LOOPBACK != 0,
        link_up: match data[data::LINK_STATE] {
            LINK_STATE_UP => Some(true),
            LINK_STATE_DOWN => Some(false),
            _ => None,
        },
        baudrate: counter(data::BAUDRATE),
        counters: [
            ("net_received_bytes_total", counter(data::IBYTES)),
            ("net_sent_bytes_total", counter(data::OBYTES)),
            ("net_received_packets_total", counter(data::IPACKETS)),
            ("net_sent_packets_total", counter(data::OPACKETS)),
            (
                "net_received_multicast_packets_total",
                counter(data::IMCASTS),
            ),
            ("net_sent_multicast_packets_total", counter(data::OMCASTS)),
            ("net_receive_errors_total", counter(data::IERRORS)),
            ("net_send_errors_total", counter(data::OERRORS)),
            ("net_receive_drops_total", counter(data::IQDROPS)),
            ("net_send_drops_total", counter(data::OQDROPS)),
            ("net_collisions_total", counter(data::COLLISIONS)),
        ],
    })
}

/// Walks the routing messages and returns the interfaces.
pub fn parse(buf: &[u8]) -> Result<Vec<Interface>, String> {
    let mut out = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        let msglen = usize::from(u16_at(rest, hdr::MSGLEN).ok_or("truncated message header")?);
        if msglen < 4 || msglen > rest.len() {
            return Err(format!("bad message length {msglen}"));
        }
        let (msg, tail) = rest.split_at(msglen);
        rest = tail;
        if msg[hdr::VERSION] != RTM_VERSION {
            return Err(format!(
                "routing message version {} (expected {RTM_VERSION})",
                msg[hdr::VERSION]
            ));
        }
        if msg[hdr::TYPE] == RTM_IFINFO {
            out.push(parse_ifinfo(msg).ok_or("malformed RTM_IFINFO message")?);
        }
    }
    Ok(out)
}

/// Shell-style match with `*` (any run) and `?` (any one character).
pub fn glob_match(pattern: &str, name: &str) -> bool {
    fn go(p: &[u8], n: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], n) || (!n.is_empty() && go(p, &n[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &n[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &n[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), name.as_bytes())
}

impl Config {
    fn wants(&self, name: &str, up: bool, loopback: bool) -> bool {
        if self.interfaces.is_empty() {
            up && !loopback
        } else {
            self.interfaces.iter().any(|p| glob_match(p, name))
        }
    }
}

native_only!(Net, "net");

#[cfg(target_os = "freebsd")]
pub use freebsd::Net;
#[cfg(target_os = "linux")]
pub use linux::Net;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::{
        Context,
        Result,
        anyhow,
    };
    use metrics::{
        counter,
        gauge,
    };

    use super::{
        Config,
        describe,
        parse,
    };
    use crate::{
        collector::Collector,
        counter::Monotonic,
        sys::freebsd::Mib,
    };

    /// `NET_RT_IFLISTL` from `sys/socket.h`.
    const NET_RT_IFLISTL: libc::c_int = 5;

    pub struct Net {
        config: Config,
        iflist: Mib,
        buf: Vec<u8>,
        counters: Monotonic,
    }

    impl Net {
        #[expect(
            clippy::unnecessary_wraps,
            reason = "the non-FreeBSD stub of this constructor fails, so callers expect a Result"
        )]
        pub fn new(config: &Config) -> Result<Self> {
            Ok(Self {
                config: config.clone(),
                iflist: Mib::from_raw(&[libc::CTL_NET, libc::PF_ROUTE, 0, 0, NET_RT_IFLISTL, 0]),
                buf: Vec::new(),
                counters: Monotonic::default(),
            })
        }
    }

    impl Collector for Net {
        fn name(&self) -> &'static str {
            "net"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            self.iflist
                .read_into(&mut self.buf)
                .context("reading interface list")?;
            let interfaces = parse(&self.buf).map_err(|e| anyhow!("NET_RT_IFLISTL: {e}"))?;
            for iface in interfaces
                .into_iter()
                .filter(|i| self.config.wants(&i.name, i.up, i.loopback))
            {
                // Recreated interfaces (tun, epair, tailscale restarts) start
                // from zero again.
                for (metric, value) in iface.counters {
                    let value = self
                        .counters
                        .correct(&format!("{metric}\0{}", iface.name), value);
                    counter!(metric, "interface" => iface.name.clone()).absolute(value);
                }
                if let Some(up) = iface.link_up {
                    gauge!("net_link_up", "interface" => iface.name.clone())
                        .set(f64::from(u8::from(up)));
                }
                if iface.baudrate > 0 {
                    gauge!("net_speed_bits_per_second", "interface" => iface.name)
                        .set(iface.baudrate as f64);
                }
            }
            self.counters.prune();
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{
        Context,
        Result,
    };
    use metrics::{
        counter,
        gauge,
    };

    use super::{
        Config,
        describe,
    };
    use crate::{
        collector::Collector,
        counter::Monotonic,
        sys::linux::{
            netlink,
            read_into,
        },
    };

    const RTM_NEWLINK: u16 = 16;
    const RTM_GETLINK: u16 = 18;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_OPERSTATE: u16 = 16;
    const IFLA_STATS64: u16 = 23;
    const IFF_UP: u32 = 0x1;
    const IFF_LOOPBACK: u32 = 0x8;
    const IF_OPER_UNKNOWN: u8 = 0;
    const IF_OPER_UP: u8 = 6;
    /// `sizeof (struct ifinfomsg)`.
    const IFINFOMSG_SIZE: usize = 16;

    /// `struct rtnl_link_stats64` field indexes (in `u64`s).
    mod stats {
        pub const RX_PACKETS: usize = 0;
        pub const TX_PACKETS: usize = 1;
        pub const RX_BYTES: usize = 2;
        pub const TX_BYTES: usize = 3;
        pub const RX_ERRORS: usize = 4;
        pub const TX_ERRORS: usize = 5;
        pub const RX_DROPPED: usize = 6;
        pub const TX_DROPPED: usize = 7;
        pub const MULTICAST: usize = 8;
        pub const COLLISIONS: usize = 9;
        pub const RX_MISSED_ERRORS: usize = 15;
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct Interface {
        pub name: String,
        pub up: bool,
        pub loopback: bool,
        /// `None` when the operational state is unknown.
        pub link_up: Option<bool>,
        pub counters: [(&'static str, u64); 10],
    }

    /// Parses an `RTM_NEWLINK` payload (`struct ifinfomsg` + attributes).
    pub fn parse_link(payload: &[u8]) -> Option<Interface> {
        let flags = u32::from_ne_bytes(payload.get(8..12)?.try_into().ok()?);
        let mut name = None;
        let mut operstate = IF_OPER_UNKNOWN;
        let mut stats = None;
        for (kind, value) in netlink::attributes(payload.get(IFINFOMSG_SIZE..)?) {
            match kind {
                IFLA_IFNAME => {
                    let len = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                    name = Some(String::from_utf8_lossy(&value[..len]).into_owned());
                }
                IFLA_OPERSTATE => operstate = *value.first()?,
                IFLA_STATS64 => stats = Some(value),
                _ => {}
            }
        }
        let stats = stats?;
        let stat = |i: usize| -> Option<u64> {
            Some(u64::from_ne_bytes(
                stats.get(i * 8..i * 8 + 8)?.try_into().ok()?,
            ))
        };
        Some(Interface {
            name: name?,
            up: flags & IFF_UP != 0,
            loopback: flags & IFF_LOOPBACK != 0,
            link_up: match operstate {
                IF_OPER_UNKNOWN => None,
                oper => Some(oper == IF_OPER_UP),
            },
            counters: [
                ("net_received_bytes_total", stat(stats::RX_BYTES)?),
                ("net_sent_bytes_total", stat(stats::TX_BYTES)?),
                ("net_received_packets_total", stat(stats::RX_PACKETS)?),
                ("net_sent_packets_total", stat(stats::TX_PACKETS)?),
                (
                    "net_received_multicast_packets_total",
                    stat(stats::MULTICAST)?,
                ),
                ("net_receive_errors_total", stat(stats::RX_ERRORS)?),
                ("net_send_errors_total", stat(stats::TX_ERRORS)?),
                (
                    "net_receive_drops_total",
                    stat(stats::RX_DROPPED)?.wrapping_add(stat(stats::RX_MISSED_ERRORS)?),
                ),
                ("net_send_drops_total", stat(stats::TX_DROPPED)?),
                ("net_collisions_total", stat(stats::COLLISIONS)?),
            ],
        })
    }

    /// `/sys/class/net/<interface>/speed` in bits per second. The file holds
    /// Mb/s, `-1` when unknown, and fails to read when the link is down or
    /// the driver has no ethtool support.
    fn parse_speed(text: &str) -> Option<f64> {
        let mbps: i64 = text.trim().parse().ok()?;
        (mbps > 0).then_some(mbps as f64 * 1e6)
    }

    pub struct Net {
        config: Config,
        socket: netlink::Socket,
        counters: Monotonic,
        text: String,
    }

    impl Net {
        pub fn new(config: &Config) -> Result<Self> {
            Ok(Self {
                config: config.clone(),
                socket: netlink::Socket::new(libc::NETLINK_ROUTE)
                    .context("opening rtnetlink socket")?,
                counters: Monotonic::default(),
                text: String::new(),
            })
        }
    }

    impl Collector for Net {
        fn name(&self) -> &'static str {
            "net"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            let mut links = Vec::new();
            let mut malformed = false;
            // Request: an all-zero `struct ifinfomsg` (any family, all
            // interfaces).
            self.socket
                .dump(RTM_GETLINK, &[0; IFINFOMSG_SIZE], |kind, payload| {
                    if kind == RTM_NEWLINK {
                        match parse_link(payload) {
                            Some(link) => links.push(link),
                            None => malformed = true,
                        }
                    }
                })
                .context("dumping interfaces (RTM_GETLINK)")?;
            if malformed {
                anyhow::bail!("malformed RTM_NEWLINK message");
            }
            for link in links
                .into_iter()
                .filter(|l| self.config.wants(&l.name, l.up, l.loopback))
            {
                // Recreated interfaces (tun, veth, wireguard restarts) start
                // from zero again.
                for (metric, value) in link.counters {
                    let value = self
                        .counters
                        .correct(&format!("{metric}\0{}", link.name), value);
                    counter!(metric, "interface" => link.name.clone()).absolute(value);
                }
                if let Some(up) = link.link_up {
                    gauge!("net_link_up", "interface" => link.name.clone())
                        .set(f64::from(u8::from(up)));
                }
                let path = format!("/sys/class/net/{}/speed", link.name);
                if read_into(&path, &mut self.text).is_ok()
                    && let Some(speed) = parse_speed(&self.text)
                {
                    gauge!("net_speed_bits_per_second", "interface" => link.name).set(speed);
                }
            }
            self.counters.prune();
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// `RTM_NEWLINK` payload as the kernel builds it, trimmed to the
        /// attributes we read plus one we skip (`IFLA_MTU`).
        fn newlink(name: &str, flags: u32, operstate: u8, stats: &[u64]) -> Vec<u8> {
            fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
                let len = u16::try_from(4 + value.len()).unwrap();
                let mut a = [&len.to_ne_bytes()[..], &kind.to_ne_bytes(), value].concat();
                a.resize(a.len().next_multiple_of(4), 0);
                a
            }
            let mut ifinfo = vec![0u8; IFINFOMSG_SIZE];
            ifinfo[8..12].copy_from_slice(&flags.to_ne_bytes());
            let stats: Vec<u8> = stats.iter().flat_map(|v| v.to_ne_bytes()).collect();
            [
                ifinfo,
                attr(IFLA_IFNAME, &[name.as_bytes(), b"\0"].concat()),
                attr(4, &1500u32.to_ne_bytes()),
                attr(IFLA_OPERSTATE, &[operstate]),
                attr(IFLA_STATS64, &stats),
            ]
            .concat()
        }

        #[test]
        fn parses_link() {
            // rx_packets, tx_packets, rx_bytes, tx_bytes, rx_errors,
            // tx_errors, rx_dropped, tx_dropped, multicast, collisions, ...
            let mut stats: Vec<u64> = (1..=24).collect();
            stats[stats::RX_MISSED_ERRORS] = 100;
            let link = parse_link(&newlink("enp5s0", 0x1003, IF_OPER_UP, &stats)).unwrap();
            assert_eq!(link.name, "enp5s0");
            assert!(link.up && !link.loopback);
            assert_eq!(link.link_up, Some(true));
            assert_eq!(link.counters[0], ("net_received_bytes_total", 3));
            assert_eq!(link.counters[3], ("net_sent_packets_total", 2));
            assert_eq!(
                link.counters[4],
                ("net_received_multicast_packets_total", 9)
            );
            assert_eq!(
                link.counters[7],
                ("net_receive_drops_total", 107),
                "rx_dropped + rx_missed_errors"
            );
            assert_eq!(link.counters[9], ("net_collisions_total", 10));

            let lo = parse_link(&newlink("lo", 0x9, IF_OPER_UNKNOWN, &stats)).unwrap();
            assert!(lo.loopback);
            assert_eq!(lo.link_up, None);
            let down = parse_link(&newlink("eno1", 0x1002, 2, &stats)).unwrap();
            assert!(!down.up);
            assert_eq!(down.link_up, Some(false));
        }

        #[test]
        fn rejects_incomplete_links() {
            assert_eq!(parse_link(&newlink("eth0", 1, 6, &[1, 2, 3])), None);
            assert_eq!(parse_link(&[0; 8]), None);
        }

        #[test]
        fn parses_speed() {
            assert_eq!(parse_speed("1000\n"), Some(1e9));
            assert_eq!(parse_speed("-1\n"), None);
            assert_eq!(parse_speed(""), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `RTM_IFINFO` message as the kernel builds it: 24-byte `if_msghdrl`,
    /// 152-byte `if_data`, then a `sockaddr_dl` padded to 8 bytes.
    fn ifinfo(name: &str, flags: i32, link_state: u8, ibytes: u64) -> Vec<u8> {
        let mut m = vec![0u8; 24 + 152];
        m[hdr::VERSION] = RTM_VERSION;
        m[hdr::TYPE] = RTM_IFINFO;
        m[hdr::ADDRS..hdr::ADDRS + 4].copy_from_slice(&RTA_IFP.to_ne_bytes());
        m[hdr::FLAGS..hdr::FLAGS + 4].copy_from_slice(&flags.to_ne_bytes());
        m[hdr::LEN..hdr::LEN + 2].copy_from_slice(&176u16.to_ne_bytes());
        m[hdr::DATA_OFF..hdr::DATA_OFF + 2].copy_from_slice(&24u16.to_ne_bytes());
        m[24 + data::LINK_STATE] = link_state;
        m[24 + data::DATALEN..24 + data::DATALEN + 2].copy_from_slice(&152u16.to_ne_bytes());
        m[24 + data::IBYTES..24 + data::IBYTES + 8].copy_from_slice(&ibytes.to_ne_bytes());
        m[24 + data::BAUDRATE..24 + data::BAUDRATE + 8]
            .copy_from_slice(&1_000_000_000u64.to_ne_bytes());
        let mut sdl = vec![0u8; 8 + name.len()];
        sdl[0] = u8::try_from(sdl.len()).unwrap();
        sdl[1] = AF_LINK;
        sdl[5] = u8::try_from(name.len()).unwrap();
        sdl[8..].copy_from_slice(name.as_bytes());
        sdl.resize(sdl.len().next_multiple_of(8), 0);
        m.extend(sdl);
        let len = u16::try_from(m.len()).unwrap();
        m[hdr::MSGLEN..hdr::MSGLEN + 2].copy_from_slice(&len.to_ne_bytes());
        m
    }

    /// An `RTM_NEWADDR` message to be skipped.
    fn newaddr() -> Vec<u8> {
        let mut m = vec![0u8; 20];
        m[0] = 20;
        m[hdr::VERSION] = RTM_VERSION;
        m[hdr::TYPE] = 0xc;
        m
    }

    #[test]
    fn parses_interfaces_and_skips_address_messages() {
        let buf = [
            ifinfo("igb0", IFF_UP, LINK_STATE_UP, 42),
            newaddr(),
            ifinfo("lo0", IFF_UP | IFF_LOOPBACK, 0, 7),
        ]
        .concat();
        let ifaces = parse(&buf).unwrap();
        assert_eq!(ifaces.len(), 2);
        let igb = &ifaces[0];
        assert_eq!(igb.name, "igb0");
        assert_eq!(igb.link_up, Some(true));
        assert_eq!(igb.baudrate, 1_000_000_000);
        assert_eq!(igb.counters[0], ("net_received_bytes_total", 42));
        assert!(ifaces[1].loopback);
        assert_eq!(ifaces[1].link_up, None);
    }

    #[test]
    fn rejects_garbage() {
        let mut bad = ifinfo("igb0", IFF_UP, 2, 1);
        bad[hdr::VERSION] = 4;
        assert!(parse(&bad).is_err());
        assert!(parse(&[3, 0]).is_err());
    }

    #[test]
    fn default_filter_and_globs() {
        let all: Config = toml::from_str("").unwrap();
        assert!(all.wants("igb0", true, false));
        assert!(!all.wants("lo0", true, true));
        assert!(!all.wants("igb1", false, false));

        let some: Config = toml::from_str("interfaces = [\"igb*\", \"tailscale?\"]").unwrap();
        assert!(
            some.wants("igb1", false, false),
            "explicit list includes down interfaces"
        );
        assert!(some.wants("tailscale0", true, false));
        assert!(!some.wants("epair0a", true, false));
        assert!(glob_match("*", ""));
        assert!(!glob_match("a?", "a"));
    }
}
