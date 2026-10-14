//! Per-disk I/O counters from devstat(9).
//!
//! FreeBSD source: the `kern.devstat.all` sysctl (what libdevstat and
//! iostat(8) read): a `long` generation followed by one `struct devstat`
//! (`sys/sys/devicestat.h`, `DEVSTAT_VERSION` 6, unchanged from 12 to 15)
//! per device. Records are parsed by offset so the layout is checked in tests.
//!
//! `diskio_busy_seconds_total` is the time the device had at least one
//! request outstanding; `rate()` of it is iostat's `%b`. Unlike libdevstat,
//! the busy time includes the in-flight interval of a device that is busy at
//! the moment of reading.
//!
//! Linux source: `/proc/diskstats` (Documentation/admin-guide/iostats.rst),
//! the same counters iostat(1) and `vmstat -d` read. Types map as read,
//! write, free = discard and other = flush; sectors are always 512 bytes.
//! The kernel prints the per-type times and `io_ticks` (busy time) as 32-bit
//! milliseconds that wrap after 49.7 days of accumulated time, so they are
//! accumulated from wrapping deltas; a device whose request counters drop
//! (re-attached under the same name) starts over on top of its old totals.
//! Without a `devices` list, whole disks are reported (the entries of
//! `/sys/block`, including virtual ones like zram, dm and md, but no
//! partitions), except loop and ram devices that never did I/O. `devices`
//! may name partitions too.

// The helpers are only used by the FreeBSD and Linux implementations (and
// tests).
#![cfg_attr(
    not(any(target_os = "freebsd", target_os = "linux")),
    expect(dead_code, reason = "used by the FreeBSD and Linux implementations")
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
    /// If set, only these devices (e.g. `["ada0", "nda0"]`) are reported.
    #[serde(default)]
    pub devices: Vec<String>,
}

pub fn describe() {
    describe_counter!(
        "diskio_operations_total",
        "Completed requests by type (read, write, free = TRIM/DELETE, other = e.g. cache flush)."
    );
    describe_counter!(
        "diskio_bytes_total",
        "Bytes transferred by completed requests, by type."
    );
    describe_gauge!(
        "diskio_time_seconds_total",
        "Total time spent on completed requests, by type. Cumulative; use rate()."
    );
    describe_gauge!(
        "diskio_busy_seconds_total",
        "Time with at least one request outstanding. Cumulative; rate() is the busy fraction."
    );
    describe_gauge!("diskio_in_progress", "Requests currently outstanding.");
}

/// `DEVSTAT_VERSION` this parser understands.
#[cfg(target_os = "freebsd")]
pub const DEVSTAT_VERSION: i32 = 6;
/// `sizeof (struct devstat)` on LP64.
#[cfg(any(target_os = "freebsd", test))]
pub const DEVSTAT_SIZE: usize = 288;

/// Field offsets in `struct devstat` (LP64).
#[cfg(any(target_os = "freebsd", test))]
mod off {
    pub const SEQUENCE0: usize = 0;
    pub const START_COUNT: usize = 8;
    pub const END_COUNT: usize = 12;
    pub const BUSY_FROM: usize = 16;
    pub const DEVICE_NAME: usize = 44;
    pub const UNIT_NUMBER: usize = 60;
    pub const BYTES: usize = 64;
    pub const OPERATIONS: usize = 96;
    pub const DURATION: usize = 128;
    pub const BUSY_TIME: usize = 192;
    pub const DEVICE_TYPE: usize = 260;
    pub const SEQUENCE1: usize = 280;
}

/// `DEVSTAT_TYPE_PASS`: pass(4) devices duplicate their disk's statistics.
#[cfg(any(target_os = "freebsd", test))]
const DEVSTAT_TYPE_PASS: u32 = 0x100;

/// Transaction types in `bytes[]`/`operations[]`/`duration[]` order
/// (`devstat_trans_flags`).
pub const TYPES: [&str; 4] = ["other", "read", "write", "free"];

#[cfg(any(target_os = "freebsd", test))]
#[derive(Debug, Clone, PartialEq)]
pub struct DevStat {
    pub name: String,
    pub bytes: [u64; 4],
    pub operations: [u64; 4],
    /// Seconds spent on completed transactions per type.
    pub duration: [f64; 4],
    /// Seconds busy, accounted up to `busy_from`.
    pub busy_time: f64,
    /// `busy_from` in uptime seconds.
    pub busy_from: f64,
    pub in_progress: u32,
}

#[cfg(any(target_os = "freebsd", test))]
impl DevStat {
    /// Busy time including the interval since `busy_from` if requests are
    /// outstanding at `uptime` (seconds since boot).
    pub fn busy_seconds(&self, uptime: f64) -> f64 {
        if self.in_progress > 0 && uptime > self.busy_from {
            self.busy_time + (uptime - self.busy_from)
        } else {
            self.busy_time
        }
    }
}

#[cfg(any(target_os = "freebsd", test))]
fn u32_at(rec: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(rec[at..at + 4].try_into().expect("4 bytes"))
}

#[cfg(any(target_os = "freebsd", test))]
fn u64_at(rec: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(rec[at..at + 8].try_into().expect("8 bytes"))
}

/// `struct bintime` (seconds + 64-bit binary fraction) in seconds.
#[cfg(any(target_os = "freebsd", test))]
fn bintime_at(rec: &[u8], at: usize) -> f64 {
    let sec = i64::from_ne_bytes(rec[at..at + 8].try_into().expect("8 bytes"));
    let frac = u64_at(rec, at + 8);
    sec as f64 + frac as f64 / 18_446_744_073_709_551_616.0
}

/// Parses the `kern.devstat.all` output. Pass devices and records torn by a
/// concurrent update (`sequence0 != sequence1`) are skipped.
#[cfg(any(target_os = "freebsd", test))]
pub fn parse(buf: &[u8]) -> Result<Vec<DevStat>, String> {
    let records = buf
        .get(size_of::<i64>()..)
        .ok_or("shorter than the generation header")?;
    if !records.len().is_multiple_of(DEVSTAT_SIZE) {
        return Err(format!(
            "{} bytes of records is not a multiple of struct devstat ({DEVSTAT_SIZE})",
            records.len()
        ));
    }
    let mut out = Vec::new();
    for rec in records.as_chunks::<DEVSTAT_SIZE>().0 {
        if u32_at(rec, off::SEQUENCE0) != u32_at(rec, off::SEQUENCE1)
            || u32_at(rec, off::DEVICE_TYPE) & DEVSTAT_TYPE_PASS != 0
        {
            continue;
        }
        let name_bytes = &rec[off::DEVICE_NAME..off::DEVICE_NAME + 16];
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let name = String::from_utf8_lossy(&name_bytes[..name_len]);
        let unit = i32::from_ne_bytes(
            rec[off::UNIT_NUMBER..off::UNIT_NUMBER + 4]
                .try_into()
                .expect("4"),
        );
        out.push(DevStat {
            name: format!("{name}{unit}"),
            bytes: std::array::from_fn(|i| u64_at(rec, off::BYTES + i * 8)),
            operations: std::array::from_fn(|i| u64_at(rec, off::OPERATIONS + i * 8)),
            duration: std::array::from_fn(|i| bintime_at(rec, off::DURATION + i * 16)),
            busy_time: bintime_at(rec, off::BUSY_TIME),
            busy_from: bintime_at(rec, off::BUSY_FROM),
            in_progress: u32_at(rec, off::START_COUNT).wrapping_sub(u32_at(rec, off::END_COUNT)),
        });
    }
    Ok(out)
}

/// One `/proc/diskstats` line. Arrays are in [`TYPES`] order: flush,
/// read, write, discard.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DiskStats {
    pub operations: [u64; 4],
    /// 512-byte sectors; always 0 for flushes.
    pub sectors: [u64; 4],
    /// Milliseconds spent on completed requests (32-bit, wraps).
    pub millis: [u32; 4],
    pub in_progress: u32,
    /// Milliseconds with requests outstanding (32-bit, wraps).
    pub busy_millis: u32,
}

/// Parses `/proc/diskstats`: `major minor name` followed by 11 fields, 15
/// with discards (4.18+) or 17 with flushes (5.5+). Malformed lines are
/// skipped.
#[cfg(any(target_os = "linux", test))]
pub fn parse_diskstats(text: &str) -> Vec<(&str, DiskStats)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace().skip(2);
        let Some(name) = fields.next() else { continue };
        let Ok(values) = fields.map(str::parse::<u64>).collect::<Result<Vec<_>, _>>() else {
            continue;
        };
        if values.len() < 11 {
            continue;
        }
        let at = |i: usize| values.get(i).copied().unwrap_or(0);
        // The kernel prints the times as `unsigned int`.
        let millis = |i: usize| u32::try_from(at(i)).unwrap_or(u32::MAX);
        out.push((
            name,
            DiskStats {
                operations: [at(15), at(0), at(4), at(11)],
                sectors: [0, at(2), at(6), at(13)],
                millis: [millis(16), millis(3), millis(7), millis(14)],
                in_progress: millis(8),
                busy_millis: millis(9),
            },
        ));
    }
    out
}

#[cfg(any(target_os = "linux", test))]
impl DiskStats {
    /// Whether a request or sector counter dropped since `last`: the device
    /// was re-attached and its counters started over.
    fn restarted_since(&self, last: &Self) -> bool {
        (0..TYPES.len())
            .any(|i| self.operations[i] < last.operations[i] || self.sectors[i] < last.sectors[i])
    }
}

/// Monotonic totals of one Linux device, in kernel units (bytes,
/// milliseconds), carried across 32-bit wraps of the time fields and resets
/// of the whole device.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Totals {
    pub operations: [u64; 4],
    pub bytes: [u64; 4],
    pub millis: [u64; 4],
    pub busy_millis: u64,
}

#[cfg(any(target_os = "linux", test))]
impl Totals {
    fn add(&mut self, operations: [u64; 4], sectors: [u64; 4], millis: [u64; 4], busy: u64) {
        for i in 0..TYPES.len() {
            self.operations[i] = self.operations[i].saturating_add(operations[i]);
            self.bytes[i] = self.bytes[i].saturating_add(sectors[i].saturating_mul(512));
            self.millis[i] = self.millis[i].saturating_add(millis[i]);
        }
        self.busy_millis = self.busy_millis.saturating_add(busy);
    }

    /// Advances from the previous reading `last` (if any) to `now`.
    pub fn advance(&mut self, last: Option<&DiskStats>, now: &DiskStats) {
        match last.filter(|last| !now.restarted_since(last)) {
            Some(last) => self.add(
                std::array::from_fn(|i| now.operations[i] - last.operations[i]),
                std::array::from_fn(|i| now.sectors[i] - last.sectors[i]),
                std::array::from_fn(|i| u64::from(now.millis[i].wrapping_sub(last.millis[i]))),
                u64::from(now.busy_millis.wrapping_sub(last.busy_millis)),
            ),
            // New or re-attached device: its counters started from zero.
            None => self.add(
                now.operations,
                now.sectors,
                now.millis.map(u64::from),
                u64::from(now.busy_millis),
            ),
        }
    }
}

native_only!(DiskIo, "diskio");

#[cfg(target_os = "freebsd")]
pub use freebsd::DiskIo;
#[cfg(target_os = "linux")]
pub use linux::DiskIo;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::{
        Context,
        Result,
        anyhow,
        bail,
    };
    use metrics::{
        counter,
        gauge,
    };

    use super::{
        Config,
        DEVSTAT_VERSION,
        TYPES,
        describe,
        parse,
    };
    use crate::{
        collector::Collector,
        counter::Monotonic,
        sys::freebsd::Mib,
    };

    pub struct DiskIo {
        config: Config,
        all: Mib,
        buf: Vec<u8>,
        counters: Monotonic,
    }

    impl DiskIo {
        pub fn new(config: &Config) -> Result<Self> {
            let version: i32 = Mib::new("kern.devstat.version")?
                .read()
                .context("reading kern.devstat.version")?;
            if version != DEVSTAT_VERSION {
                bail!("unsupported devstat version {version} (expected {DEVSTAT_VERSION})");
            }
            Ok(Self {
                config: config.clone(),
                all: Mib::new("kern.devstat.all")?,
                buf: Vec::new(),
                counters: Monotonic::default(),
            })
        }
    }

    #[expect(unsafe_code, reason = "clock_gettime(2) FFI")]
    fn uptime() -> Result<f64> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is valid for writes.
        if unsafe { libc::clock_gettime(libc::CLOCK_UPTIME_PRECISE, &raw mut ts) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9)
    }

    impl Collector for DiskIo {
        fn name(&self) -> &'static str {
            "diskio"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            // EBUSY means a device came or went during the read; retry.
            let mut attempts = 0;
            loop {
                match self.all.read_into(&mut self.buf) {
                    Ok(()) => break,
                    Err(err) if err.raw_os_error() == Some(libc::EBUSY) && attempts < 3 => {
                        attempts += 1;
                    }
                    Err(err) => return Err(err).context("reading kern.devstat.all"),
                }
            }
            let now = uptime()?;
            let devices = parse(&self.buf).map_err(|e| anyhow!("kern.devstat.all: {e}"))?;
            for dev in devices {
                if !self.config.devices.is_empty() && !self.config.devices.contains(&dev.name) {
                    continue;
                }
                for (i, typ) in TYPES.iter().enumerate() {
                    let labels = [("device", dev.name.clone()), ("type", (*typ).to_owned())];
                    let ops = self
                        .counters
                        .correct(&format!("ops\0{}\0{typ}", dev.name), dev.operations[i]);
                    counter!("diskio_operations_total", &labels).absolute(ops);
                    gauge!("diskio_time_seconds_total", &labels).set(dev.duration[i]);
                    // NO_DATA requests transfer nothing.
                    if i != 0 {
                        let bytes = self
                            .counters
                            .correct(&format!("bytes\0{}\0{typ}", dev.name), dev.bytes[i]);
                        counter!("diskio_bytes_total", &labels).absolute(bytes);
                    }
                }
                gauge!("diskio_busy_seconds_total", "device" => dev.name.clone())
                    .set(dev.busy_seconds(now));
                gauge!("diskio_in_progress", "device" => dev.name).set(f64::from(dev.in_progress));
            }
            self.counters.prune();
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::{
            HashMap,
            HashSet,
            hash_map::Entry,
        },
        time::{
            Duration,
            Instant,
        },
    };

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
        DiskStats,
        TYPES,
        Totals,
        describe,
        parse_diskstats,
    };
    use crate::{
        collector::Collector,
        sys::linux::read_into,
    };

    /// Devices not seen for this long are forgotten, like
    /// [`crate::counter::Monotonic`] series.
    const RETENTION: Duration = Duration::from_secs(3600);

    struct Device {
        last: DiskStats,
        totals: Totals,
        seen: Instant,
    }

    pub struct DiskIo {
        config: Config,
        devices: HashMap<String, Device>,
        buf: String,
    }

    impl DiskIo {
        pub fn new(config: &Config) -> Result<Self> {
            let mut buf = String::new();
            read_into("/proc/diskstats", &mut buf).context("reading /proc/diskstats")?;
            Ok(Self {
                config: config.clone(),
                devices: HashMap::new(),
                buf,
            })
        }
    }

    /// Whole disks: the entries of `/sys/block`, where `/` in a name is
    /// written as `!` (e.g. `cciss!c0d0`).
    fn whole_disks() -> Result<HashSet<String>> {
        std::fs::read_dir("/sys/block")
            .context("listing /sys/block")?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().replace('!', "/")))
            .collect::<std::io::Result<_>>()
            .context("listing /sys/block")
    }

    /// Loop and ram devices exist in numbers whether used or not.
    fn unused_placeholder(name: &str, stats: &DiskStats) -> bool {
        (name.starts_with("loop") || name.starts_with("ram"))
            && stats.operations.iter().all(|&ops| ops == 0)
    }

    impl Collector for DiskIo {
        fn name(&self) -> &'static str {
            "diskio"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            let disks = if self.config.devices.is_empty() {
                Some(whole_disks()?)
            } else {
                None
            };
            read_into("/proc/diskstats", &mut self.buf).context("reading /proc/diskstats")?;
            let now = Instant::now();
            for (name, stats) in parse_diskstats(&self.buf) {
                let wanted = match &disks {
                    Some(disks) => disks.contains(name) && !unused_placeholder(name, &stats),
                    None => self.config.devices.iter().any(|d| d == name),
                };
                if !wanted {
                    continue;
                }
                let device = match self.devices.entry(name.to_owned()) {
                    Entry::Occupied(entry) => {
                        let device = entry.into_mut();
                        device.totals.advance(Some(&device.last), &stats);
                        device
                    }
                    Entry::Vacant(entry) => {
                        let mut totals = Totals::default();
                        totals.advance(None, &stats);
                        entry.insert(Device {
                            last: stats,
                            totals,
                            seen: now,
                        })
                    }
                };
                device.last = stats;
                device.seen = now;

                let totals = &device.totals;
                for (i, typ) in TYPES.iter().enumerate() {
                    let labels = [("device", name.to_owned()), ("type", (*typ).to_owned())];
                    counter!("diskio_operations_total", &labels).absolute(totals.operations[i]);
                    gauge!("diskio_time_seconds_total", &labels).set(totals.millis[i] as f64 / 1e3);
                    // Flushes transfer nothing.
                    if i != 0 {
                        counter!("diskio_bytes_total", &labels).absolute(totals.bytes[i]);
                    }
                }
                gauge!("diskio_busy_seconds_total", "device" => name.to_owned())
                    .set(totals.busy_millis as f64 / 1e3);
                gauge!("diskio_in_progress", "device" => name.to_owned())
                    .set(f64::from(stats.in_progress));
            }
            self.devices
                .retain(|_, device| now.duration_since(device.seen) < RETENTION);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one record the way the kernel lays it out.
    fn record(name: &str, unit: i32, device_type: u32, seq: (u32, u32)) -> Vec<u8> {
        let mut r = vec![0u8; DEVSTAT_SIZE];
        let put32 =
            |r: &mut Vec<u8>, at: usize, v: u32| r[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        let put64 =
            |r: &mut Vec<u8>, at: usize, v: u64| r[at..at + 8].copy_from_slice(&v.to_ne_bytes());
        put32(&mut r, off::SEQUENCE0, seq.0);
        put32(&mut r, off::SEQUENCE1, seq.1);
        put32(&mut r, off::START_COUNT, 12);
        put32(&mut r, off::END_COUNT, 10);
        r[off::DEVICE_NAME..off::DEVICE_NAME + name.len()].copy_from_slice(name.as_bytes());
        r[off::UNIT_NUMBER..off::UNIT_NUMBER + 4].copy_from_slice(&unit.to_ne_bytes());
        put64(&mut r, off::BYTES + 8, 4096); // read
        put64(&mut r, off::BYTES + 16, 8192); // write
        put64(&mut r, off::OPERATIONS + 8, 1);
        put64(&mut r, off::OPERATIONS + 16, 2);
        // duration[read] = 1.5 s
        put64(&mut r, off::DURATION + 16, 1);
        put64(&mut r, off::DURATION + 24, 1 << 63);
        // busy_time = 3 s, busy_from = 100 s
        put64(&mut r, off::BUSY_TIME, 3);
        put64(&mut r, off::BUSY_FROM, 100);
        put32(&mut r, off::DEVICE_TYPE, device_type);
        r
    }

    fn stream(records: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = 7i64.to_ne_bytes().to_vec();
        for r in records {
            buf.extend(r);
        }
        buf
    }

    #[test]
    fn parses_devstat_records() {
        let buf = stream(&[
            record("ada", 0, 0x20, (5, 5)),
            record("pass", 0, 0x100, (1, 1)),
            record("nda", 1, 0x40, (3, 4)),
        ]);
        let devs = parse(&buf).unwrap();
        assert_eq!(devs.len(), 1, "pass device and torn record are skipped");
        let ada = &devs[0];
        assert_eq!(ada.name, "ada0");
        assert_eq!(ada.bytes, [0, 4096, 8192, 0]);
        assert_eq!(ada.operations, [0, 1, 2, 0]);
        assert_eq!(ada.duration, [0.0, 1.5, 0.0, 0.0]);
        assert_eq!(ada.in_progress, 2);
        assert_eq!(
            ada.busy_seconds(100.5),
            3.5,
            "in-flight time since busy_from"
        );
        assert_eq!(ada.busy_seconds(99.0), 3.0);
    }

    #[test]
    fn rejects_unknown_layout() {
        assert!(parse(&[0u8; 8 + DEVSTAT_SIZE - 8]).is_err());
        assert_eq!(parse(&7i64.to_ne_bytes()).unwrap(), vec![], "no devices");
    }

    /// From an Arch Linux host (kernel 7.2), plus a 4.18-era line without
    /// flush fields and a pre-4.18 line without discard fields.
    const DISKSTATS: &str = "\
 259       1 nvme1n1 22812353 40145 1728789278 23320356 17566433 13032902 1641758503 65724729 0 \
                             11296108 90450760 1599 69115 285996488 208683 759221 1196990
 259       4 nvme1n1p2 22810912 36749 1728761559 23319895 17566415 13032902 1641758492 65724726 0 \
                             11070431 89253297 1592 69115 284374512 208675 0 0
 253       0 zram0 295458 0 2367192 1835 2241058 0 18856440 49589 2 58593 51424 0 0 0 0 0 0
   8       0 sda 10 0 80 5 20 0 160 7 0 12 12 3 0 24 4
   8      16 sdb 10 0 80 5 20 0 160 7 0 12 12
   7       0 loop0 x 0 0 0 0 0 0 0 0 0 0
   7       1 loop1 0 0 0 0
";

    #[test]
    fn parses_diskstats() {
        let disks = parse_diskstats(DISKSTATS);
        let names: Vec<_> = disks.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            ["nvme1n1", "nvme1n1p2", "zram0", "sda", "sdb"],
            "malformed and short lines are skipped"
        );
        assert_eq!(
            disks[0].1,
            DiskStats {
                operations: [759_221, 22_812_353, 17_566_433, 1599],
                sectors: [0, 1_728_789_278, 1_641_758_503, 285_996_488],
                millis: [1_196_990, 23_320_356, 65_724_729, 208_683],
                in_progress: 0,
                busy_millis: 11_296_108,
            }
        );
        assert_eq!(disks[2].1.in_progress, 2);
        assert_eq!(disks[3].1.operations, [0, 10, 20, 3], "no flush fields");
        assert_eq!(disks[4].1.operations, [0, 10, 20, 0], "no discard fields");
        assert_eq!(disks[4].1.busy_millis, 12);
    }

    #[test]
    fn accumulates_across_wraps_and_resets() {
        let stats = |ops: u64, millis: u32| DiskStats {
            operations: [0, ops, 0, 0],
            sectors: [0, ops * 8, 0, 0],
            millis: [0, millis, 0, 0],
            in_progress: 0,
            busy_millis: millis,
        };
        let mut totals = Totals::default();
        let first = stats(100, u32::MAX - 10);
        totals.advance(None, &first);
        assert_eq!(totals.operations[1], 100);
        assert_eq!(totals.bytes[1], 100 * 8 * 512);
        assert_eq!(totals.millis[1], u64::from(u32::MAX - 10));

        // The 32-bit millisecond counters wrap; the totals keep growing.
        let wrapped = stats(150, 20);
        totals.advance(Some(&first), &wrapped);
        assert_eq!(totals.operations[1], 150);
        assert_eq!(totals.millis[1], u64::from(u32::MAX) + 21);
        assert_eq!(totals.busy_millis, u64::from(u32::MAX) + 21);

        // Re-attached device: counters start over, totals continue.
        let reset = stats(5, 3);
        totals.advance(Some(&wrapped), &reset);
        assert_eq!(totals.operations[1], 155);
        assert_eq!(totals.millis[1], u64::from(u32::MAX) + 24);
    }
}
