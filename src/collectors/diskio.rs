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

// The helpers are only used by the FreeBSD implementation (and tests).
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
pub const DEVSTAT_VERSION: i32 = 6;
/// `sizeof (struct devstat)` on LP64.
pub const DEVSTAT_SIZE: usize = 288;

/// Field offsets in `struct devstat` (LP64).
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
const DEVSTAT_TYPE_PASS: u32 = 0x100;

/// Transaction types in `bytes[]`/`operations[]`/`duration[]` order
/// (`devstat_trans_flags`).
pub const TYPES: [&str; 4] = ["other", "read", "write", "free"];

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

fn u32_at(rec: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(rec[at..at + 4].try_into().expect("4 bytes"))
}

fn u64_at(rec: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(rec[at..at + 8].try_into().expect("8 bytes"))
}

/// `struct bintime` (seconds + 64-bit binary fraction) in seconds.
fn bintime_at(rec: &[u8], at: usize) -> f64 {
    let sec = i64::from_ne_bytes(rec[at..at + 8].try_into().expect("8 bytes"));
    let frac = u64_at(rec, at + 8);
    sec as f64 + frac as f64 / 18_446_744_073_709_551_616.0
}

/// Parses the `kern.devstat.all` output. Pass devices and records torn by a
/// concurrent update (`sequence0 != sequence1`) are skipped.
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

freebsd_only!(DiskIo, "diskio");

#[cfg(target_os = "freebsd")]
pub use freebsd::DiskIo;

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
}
