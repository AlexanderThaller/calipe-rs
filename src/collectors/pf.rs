//! pf firewall status: what `pfctl -s info` shows, without running pfctl.
//!
//! FreeBSD source: the `DIOCGETSTATUSNV` ioctl on `/dev/pf` (the interface
//! libpfctl uses on 14.x; 15.x also offers netlink, and dropped the old
//! fixed-struct `DIOCGETSTATUS`). It returns a libnv nvlist decoded by
//! [`crate::libnv`]. Each counter group carries its own `names` array, so new
//! counters in later releases show up without code changes.
//!
//! Needs root, like `pfctl -s info`: `/dev/pf` is mode 0600. A read-only open
//! is enough.

// The helpers are only used by the FreeBSD implementation (and tests).
#![cfg_attr(
    not(target_os = "freebsd"),
    expect(dead_code, reason = "used by the FreeBSD implementation")
)]

use std::time::Duration;

use metrics::{describe_counter, describe_gauge};
use serde::Deserialize;

use crate::libnv::NvList;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
}

pub fn describe() {
    describe_gauge!("pf_running", "1 if pf is enabled.");
    describe_gauge!("pf_states", "Current state table entries.");
    describe_gauge!("pf_source_nodes", "Current source tracking nodes.");
    describe_counter!(
        "pf_state_operations_total",
        "State table operations (searches, inserts, removals)."
    );
    describe_counter!(
        "pf_source_node_operations_total",
        "Source tracking table operations (searches, inserts, removals)."
    );
    describe_counter!(
        "pf_counters_total",
        "Packets by pf counter reason (match, bad-offset, state-mismatch, memory, ...)."
    );
    describe_counter!(
        "pf_limit_counters_total",
        "Times a limit was hit (max-states-per-rule, src-conn, overload-table, ...)."
    );
    describe_counter!(
        "pf_loginterface_packets_total",
        "Packets on the loginterface by family, direction and action."
    );
    describe_counter!(
        "pf_loginterface_bytes_total",
        "Bytes on the loginterface by family and direction."
    );
}

/// `(name, value)` pairs of a `{counters, names, ids}` group.
pub fn named_counters<'a>(status: &NvList<'a>, group: &str) -> Option<Vec<(&'a str, u64)>> {
    let list = status.get_list(group)?;
    let values = list.get_numbers("counters")?;
    let names = list.get_strings("names")?;
    if values.len() != names.len() {
        return None;
    }
    Some(names.iter().copied().zip(values.iter().copied()).collect())
}

/// Packet counters labelled (family, direction, action).
pub type PacketCounters = Vec<([&'static str; 3], u64)>;
/// Byte counters labelled (family, direction).
pub type ByteCounters = Vec<([&'static str; 2], u64)>;

/// Loginterface counters: `pcounters[af][dir][action]`, `bcounters[af][dir]`.
pub fn loginterface(status: &NvList<'_>) -> Option<(PacketCounters, ByteCounters)> {
    const AF: [&str; 2] = ["ipv4", "ipv6"];
    const DIR: [&str; 2] = ["in", "out"];
    const ACTION: [&str; 2] = ["pass", "drop"];
    let p = status.get_numbers("pcounters")?;
    let b = status.get_numbers("bcounters")?;
    if p.len() != 8 || b.len() != 4 {
        return None;
    }
    let mut packets = Vec::with_capacity(8);
    let mut bytes = Vec::with_capacity(4);
    for (i, af) in AF.iter().enumerate() {
        for (j, dir) in DIR.iter().enumerate() {
            for (k, action) in ACTION.iter().enumerate() {
                packets.push(([*af, *dir, *action], p[i * 4 + j * 2 + k]));
            }
            bytes.push(([*af, *dir], b[i * 2 + j]));
        }
    }
    Some((packets, bytes))
}

freebsd_only!(Pf, "pf");

#[cfg(target_os = "freebsd")]
pub use freebsd::Pf;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    use anyhow::{Context, Result, anyhow};
    use metrics::{counter, gauge};

    use super::{Config, describe, loginterface, named_counters};
    use crate::collector::Collector;
    use crate::libnv;

    /// `struct pfioc_nv` from `net/pfvar.h`.
    #[repr(C)]
    struct PfiocNv {
        data: *mut libc::c_void,
        len: libc::size_t,
        size: libc::size_t,
    }

    /// `_IOWR('D', 21, struct pfioc_nv)`.
    const DIOCGETSTATUSNV: libc::c_ulong = 0xC000_0000
        | ((size_of::<PfiocNv>() as libc::c_ulong & 0x1fff) << 16)
        | ((b'D' as libc::c_ulong) << 8)
        | 0x15; // 21
    const MAX_BUF: usize = 1 << 20;

    pub struct Pf {
        dev: File,
        buf: Vec<u8>,
    }

    impl Pf {
        pub fn new(_config: &Config) -> Result<Self> {
            let dev = File::open("/dev/pf")
                .context("opening /dev/pf (is pf loaded, and calipers running as root?)")?;
            Ok(Self {
                dev,
                buf: vec![0; 4096],
            })
        }

        #[expect(unsafe_code, reason = "DIOCGETSTATUSNV ioctl")]
        fn status(&mut self) -> io::Result<usize> {
            loop {
                let mut nv = PfiocNv {
                    data: self.buf.as_mut_ptr().cast(),
                    len: 0,
                    size: self.buf.len(),
                };
                // SAFETY: `nv.data` is valid for `nv.size` bytes.
                if unsafe { libc::ioctl(self.dev.as_raw_fd(), DIOCGETSTATUSNV, &raw mut nv) } == 0 {
                    return Ok(nv.len.min(self.buf.len()));
                }
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOSPC) || self.buf.len() >= MAX_BUF {
                    return Err(err);
                }
                let doubled = self.buf.len() * 2;
                self.buf.resize(doubled, 0);
            }
        }
    }

    impl Collector for Pf {
        fn name(&self) -> &'static str {
            "pf"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            let len = self.status().context("DIOCGETSTATUSNV")?;
            let status = libnv::unpack(&self.buf[..len])?;
            let missing = |what: &str| anyhow!("pf status has no {what}");

            gauge!("pf_running").set(f64::from(u8::from(
                status
                    .get_bool("running")
                    .ok_or_else(|| missing("running"))?,
            )));
            gauge!("pf_states").set(
                status
                    .get_number("states")
                    .ok_or_else(|| missing("states"))? as f64,
            );
            gauge!("pf_source_nodes").set(status.get_number("src_nodes").unwrap_or(0) as f64);

            for (group, metric, label) in [
                ("fcounters", "pf_state_operations_total", "op"),
                ("scounters", "pf_source_node_operations_total", "op"),
                ("counters", "pf_counters_total", "reason"),
                ("lcounters", "pf_limit_counters_total", "limit"),
            ] {
                for (name, value) in named_counters(&status, group).ok_or_else(|| missing(group))? {
                    // Normalize "state searches" style names to label values.
                    let name = name.trim().replace(' ', "-");
                    counter!(metric, label => name).absolute(value);
                }
            }

            // Only meaningful when `set loginterface` is configured.
            if let Some(ifname) = status.get_str("ifname").filter(|n| !n.is_empty())
                && let Some((packets, bytes)) = loginterface(&status)
            {
                for ([af, dir, action], value) in packets {
                    counter!("pf_loginterface_packets_total", "interface" => ifname.to_owned(), "family" => af, "direction" => dir, "action" => action)
                        .absolute(value);
                }
                for ([af, dir], value) in bytes {
                    counter!("pf_loginterface_bytes_total", "interface" => ifname.to_owned(), "family" => af, "direction" => dir)
                        .absolute(value);
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libnv::tests::{Enc, pack};
    use crate::libnv::unpack;

    #[test]
    fn extracts_named_counters_and_loginterface() {
        let buf = pack(&[
            ("running", Enc::Bool(true)),
            (
                "fcounters",
                Enc::List(vec![
                    ("counters", Enc::Nums(&[100, 5, 3])),
                    ("names", Enc::Strs(&["searches", "inserts", "removals"])),
                    ("ids", Enc::Nums(&[0, 1, 2])),
                ]),
            ),
            ("pcounters", Enc::Nums(&[1, 2, 3, 4, 5, 6, 7, 8])),
            ("bcounters", Enc::Nums(&[10, 20, 30, 40])),
        ]);
        let status = unpack(&buf).unwrap();
        assert_eq!(
            named_counters(&status, "fcounters").unwrap(),
            vec![("searches", 100), ("inserts", 5), ("removals", 3)]
        );
        assert_eq!(named_counters(&status, "lcounters"), None);
        let (packets, bytes) = loginterface(&status).unwrap();
        assert_eq!(packets[0], (["ipv4", "in", "pass"], 1));
        assert_eq!(packets[3], (["ipv4", "out", "drop"], 4));
        assert_eq!(packets[4], (["ipv6", "in", "pass"], 5));
        assert_eq!(bytes[1], (["ipv4", "out"], 20));
        assert_eq!(bytes[3], (["ipv6", "out"], 40));
    }
}
