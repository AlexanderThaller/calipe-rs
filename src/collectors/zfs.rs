//! ZFS: ARC and prefetch kstats, pool space/health, vdev errors and scrubs.
//!
//! Everything is read in-process, without running `zpool`:
//!
//! * kstats (`kstat.zfs.misc.<name>.*`) via a sysctl walk at startup and
//!   reads by MIB afterwards. Event counts become counters, everything else
//!   gauges (see [`kstat_kind`]).
//! * Pools via `/dev/zfs` ioctls, decoded with [`crate::nvlist`]:
//!   `ZFS_IOC_POOL_CONFIGS` lists pools (and is skipped via its generation
//!   cookie while nothing changed), `ZFS_IOC_POOL_GET_PROPS` gives the
//!   `zpool list` numbers, `ZFS_IOC_POOL_STATS` the vdev tree with I/O and
//!   error counters and the last scrub/resilver. None of these need
//!   privileges or write to the pool history.
//! * Pool health is `kstat.zfs.<pool>.misc.state`, which the kernel computes
//!   with the same logic `zpool list` uses.

// The helpers are only used by the FreeBSD implementation (and tests).
#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

use std::time::Duration;

use metrics::{describe_counter, describe_gauge};
use serde::Deserialize;

use crate::nvlist::{NvList, Value};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
    /// kstats under `kstat.zfs.misc` to export as `zfs_<kstat>_<field>`.
    #[serde(default = "default_kstats")]
    pub kstats: Vec<String>,
    /// Pool space, health, I/O and scrub metrics.
    #[serde(default = "yes")]
    pub pools: bool,
    /// Per-vdev state and error counters (needs `pools`).
    #[serde(default = "yes")]
    pub vdevs: bool,
}

fn default_kstats() -> Vec<String> {
    vec!["arcstats".to_owned(), "zfetchstats".to_owned()]
}

fn yes() -> bool {
    true
}

pub fn describe() {
    describe_gauge!("zfs_pool_size_bytes", "Pool size, as in zpool list SIZE.");
    describe_gauge!(
        "zfs_pool_allocated_bytes",
        "Allocated pool space, as in zpool list ALLOC."
    );
    describe_gauge!(
        "zfs_pool_free_bytes",
        "Free pool space, as in zpool list FREE."
    );
    describe_gauge!(
        "zfs_pool_freeing_bytes",
        "Space still being freed asynchronously."
    );
    describe_gauge!(
        "zfs_pool_fragmentation_ratio",
        "Free space fragmentation (0-1), as in zpool list FRAG."
    );
    describe_gauge!(
        "zfs_pool_dedup_ratio",
        "Deduplication ratio; 1 means no savings."
    );
    describe_gauge!(
        "zfs_pool_health",
        "1 for the pool's current health state, 0 for the others."
    );
    describe_counter!("zfs_pool_ops_total", "I/O operations on the pool, by type.");
    describe_counter!(
        "zfs_pool_bytes_total",
        "Bytes transferred by pool I/O, by type."
    );
    describe_gauge!(
        "zfs_pool_scan_info",
        "Always 1; labels give the function and state of the last scrub/resilver."
    );
    describe_gauge!(
        "zfs_pool_scan_start_time_seconds",
        "Unix time the last scrub/resilver started."
    );
    describe_gauge!(
        "zfs_pool_scan_end_time_seconds",
        "Unix time the last scrub/resilver ended; 0 while running."
    );
    describe_gauge!(
        "zfs_pool_scan_to_examine_bytes",
        "Bytes the last scrub/resilver has to check."
    );
    describe_gauge!(
        "zfs_pool_scan_issued_bytes",
        "Bytes checked so far by the last scrub/resilver."
    );
    describe_gauge!(
        "zfs_pool_scan_errors",
        "Errors found by the last scrub/resilver."
    );
    describe_gauge!(
        "zfs_vdev_state",
        "1 for the vdev's current state, 0 for the others."
    );
    describe_gauge!(
        "zfs_vdev_errors",
        "Read, write and checksum error counts, as in zpool status; reset by zpool clear."
    );
}

/// Whether a kstat field is a monotonic event count (exported as a counter)
/// or a level (gauge). Unknown fields are gauges: a counter exported as a
/// gauge still works with `rate()`, the reverse doesn't.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
}

pub fn kstat_kind(kstat: &str, field: &str) -> Kind {
    let counter = match kstat {
        "arcstats" => {
            field.ends_with("hits")
                || field.ends_with("misses")
                || field.ends_with("_prefetch")
                || field.starts_with("evict_")
                || field.starts_with("l2_rebuild_")
                || matches!(
                    field,
                    "deleted"
                        | "mutex_miss"
                        | "access_skip"
                        | "hash_collisions"
                        | "arc_prune"
                        | "async_upgrade_sync"
                        | "memory_throttle_count"
                        | "memory_direct_count"
                        | "memory_indirect_count"
                        | "l2_feeds"
                        | "l2_rw_clash"
                        | "l2_read_bytes"
                        | "l2_write_bytes"
                        | "l2_writes_sent"
                        | "l2_writes_done"
                        | "l2_writes_error"
                        | "l2_writes_lock_retry"
                        | "l2_evict_lock_retry"
                        | "l2_evict_reading"
                        | "l2_evict_l1cached"
                        | "l2_free_on_write"
                        | "l2_abort_lowmem"
                        | "l2_cksum_bad"
                        | "l2_io_error"
                        | "l2_log_blk_writes"
                )
        }
        // Everything but the in-flight gauge counts events.
        "zfetchstats" => field != "io_active",
        _ => false,
    };
    if counter { Kind::Counter } else { Kind::Gauge }
}

/// Health/state names as printed by `zpool list`/`zpool status`. All are
/// exported (0/1) so alerts can match on `state="ONLINE"` being 0.
const STATES: [&str; 9] = [
    "ONLINE",
    "DEGRADED",
    "FAULTED",
    "OFFLINE",
    "REMOVED",
    "UNAVAIL",
    "SPLIT",
    "SUSPENDED",
    "UNKNOWN",
];

/// `zpool_state_to_name()` from libzfs.
fn vdev_state_name(state: u64, aux: u64) -> &'static str {
    const VDEV_AUX_CORRUPT_DATA: u64 = 2;
    const VDEV_AUX_BAD_LOG: u64 = 13;
    const VDEV_AUX_SPLIT_POOL: u64 = 15;
    match state {
        1 | 2 => "OFFLINE",
        3 => "REMOVED",
        4 if aux == VDEV_AUX_CORRUPT_DATA || aux == VDEV_AUX_BAD_LOG => "FAULTED",
        4 if aux == VDEV_AUX_SPLIT_POOL => "SPLIT",
        4 => "UNAVAIL",
        5 => "FAULTED",
        6 => "DEGRADED",
        7 => "ONLINE",
        _ => "UNKNOWN",
    }
}

/// `zio_type_t` names for the `vs_ops`/`vs_bytes` slots (0 is `ZIO_TYPE_NULL`).
const ZIO_TYPES: [&str; 6] = ["null", "read", "write", "free", "claim", "flush"];

/// Indices into the `vdev_stats` uint64 array (`vdev_stat_t`).
mod vs {
    pub const STATE: usize = 1;
    pub const AUX: usize = 2;
    pub const OPS: usize = 8;
    pub const BYTES: usize = 14;
    pub const READ_ERRORS: usize = 20;
    pub const WRITE_ERRORS: usize = 21;
    pub const CHECKSUM_ERRORS: usize = 22;
}

#[derive(Debug, Default, PartialEq)]
pub struct PoolProps {
    pub size: Option<u64>,
    pub allocated: Option<u64>,
    pub free: Option<u64>,
    pub freeing: Option<u64>,
    /// 0-1; `None` when ZFS can't compute it (`ZFS_FRAG_INVALID`).
    pub fragmentation: Option<f64>,
    pub dedup_ratio: Option<f64>,
}

/// Parses `ZFS_IOC_POOL_GET_PROPS` output: `{name: {value, source}}`.
pub fn pool_props(props: &NvList<'_>) -> PoolProps {
    let value = |name: &str| props.get_list(name).and_then(|p| p.get_uint("value"));
    PoolProps {
        size: value("size"),
        allocated: value("allocated"),
        free: value("free"),
        freeing: value("freeing"),
        // Percent, or UINT64_MAX when unavailable.
        fragmentation: value("fragmentation")
            .filter(|&f| f <= 100)
            .map(|f| f as f64 / 100.0),
        // Ratio times 100.
        dedup_ratio: value("dedupratio").map(|r| r as f64 / 100.0),
    }
}

#[derive(Debug, PartialEq)]
pub struct Vdev {
    pub name: String,
    pub state: &'static str,
    pub ops: [u64; 6],
    pub bytes: [u64; 6],
    pub errors: [(&'static str, u64); 3],
}

impl Vdev {
    fn from_stats(name: String, stats: &[u64]) -> Option<Self> {
        let get = |i: usize| stats.get(i).copied();
        let array =
            |start: usize| -> Option<[u64; 6]> { stats.get(start..start + 6)?.try_into().ok() };
        Some(Self {
            name,
            state: vdev_state_name(get(vs::STATE)?, get(vs::AUX)?),
            ops: array(vs::OPS)?,
            bytes: array(vs::BYTES)?,
            errors: [
                ("read", get(vs::READ_ERRORS)?),
                ("write", get(vs::WRITE_ERRORS)?),
                ("checksum", get(vs::CHECKSUM_ERRORS)?),
            ],
        })
    }
}

/// `zpool_vdev_name()` without the optional flags.
fn vdev_name(pool: &str, vdev: &NvList<'_>) -> Option<String> {
    let typ = vdev.get_str("type")?;
    if typ == "root" {
        return Some(pool.to_owned());
    }
    if vdev.get("not_present").is_some() {
        return vdev.get_uint("guid").map(|g| g.to_string());
    }
    if let Some(path) = vdev.get_str("path") {
        let path = if typ == "disk" {
            path.strip_prefix("/dev/").unwrap_or(path)
        } else {
            path
        };
        return Some(path.to_owned());
    }
    let base = match (typ, vdev.get_uint("nparity")) {
        ("raidz", Some(parity)) => format!("raidz{parity}"),
        _ => typ.to_owned(),
    };
    Some(match vdev.get_uint("id") {
        Some(id) => format!("{base}-{id}"),
        None => base,
    })
}

/// Flattens the vdev tree (root first, then depth-first, including cache
/// and spare devices) into vdevs with stats.
pub fn vdevs(pool: &str, tree: &NvList<'_>) -> Vec<Vdev> {
    fn visit(pool: &str, vdev: &NvList<'_>, out: &mut Vec<Vdev>) {
        if matches!(vdev.get_str("type"), Some("hole" | "missing")) {
            return;
        }
        if let (Some(name), Some(Value::UintArray(stats))) =
            (vdev_name(pool, vdev), vdev.get("vdev_stats"))
            && let Some(v) = Vdev::from_stats(name, stats)
        {
            out.push(v);
        }
        for key in ["children", "l2cache", "spares"] {
            if let Some(Value::NvListArray(children)) = vdev.get(key) {
                for child in children {
                    visit(pool, child, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    visit(pool, tree, &mut out);
    out
}

#[derive(Debug, PartialEq)]
pub struct Scan {
    pub function: &'static str,
    pub state: &'static str,
    pub start_time: u64,
    pub end_time: u64,
    pub to_examine: u64,
    pub issued: u64,
    pub errors: u64,
}

/// Parses `scan_stats` (`pool_scan_stat_t`). `None` if the pool was never
/// scrubbed or resilvered.
pub fn scan(pss: &[u64]) -> Option<Scan> {
    let function = match *pss.first()? {
        1 => "scrub",
        2 => "resilver",
        3 => "errorscrub",
        _ => return None,
    };
    let state = match *pss.get(1)? {
        1 => "scanning",
        2 => "finished",
        3 => "canceled",
        4 => "errorscrubbing",
        _ => "none",
    };
    Some(Scan {
        function,
        state,
        start_time: *pss.get(2)?,
        end_time: *pss.get(3)?,
        to_examine: *pss.get(4)?,
        // pss_issued: what zpool status reports as "issued".
        issued: pss.get(14).copied().unwrap_or(0),
        errors: *pss.get(8)?,
    })
}

freebsd_only!(Zfs, "zfs");

#[cfg(target_os = "freebsd")]
pub use freebsd::Zfs;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    use anyhow::{Context, Result, bail};
    use metrics::{counter, gauge};

    use super::{Config, Kind, STATES, ZIO_TYPES, describe, kstat_kind, pool_props, scan, vdevs};
    use crate::collector::Collector;
    use crate::counter::Monotonic;
    use crate::nvlist::{self, Value};
    use crate::sys::freebsd::{Mib, walk};

    /// `ZFS_IOC_*` numbers (`zfs_ioc_t`, which starts at 0 on FreeBSD).
    const ZFS_IOC_POOL_CONFIGS: u8 = 0x04;
    const ZFS_IOC_POOL_STATS: u8 = 0x05;
    const ZFS_IOC_POOL_GET_PROPS: u8 = 0x27;
    /// `ZFS_IOCVER_OZFS`; checked against `vfs.zfs.version.ioctl`.
    const ZFS_IOCVER_OZFS: u32 = 15;

    /// `zfs_iocparm_t`, the FreeBSD ioctl argument wrapping `zfs_cmd_t`.
    #[repr(C)]
    struct IocParm {
        version: u32,
        cmd: u64,
        cmd_size: u64,
    }

    /// The leading fields of `zfs_cmd_t` (`include/sys/zfs_ioctl.h`) that we
    /// use. The kernel copies `sizeof (zfs_cmd_t)` bytes in and out regardless
    /// of the size we pass, so it lives at the start of a larger zeroed buffer.
    #[repr(C)]
    struct ZfsCmdHead {
        name: [u8; 1024],
        nvlist_src: u64,
        nvlist_src_size: u64,
        nvlist_dst: u64,
        nvlist_dst_size: u64,
        nvlist_dst_filled: i32,
        pad2: i32,
        history: u64,
        value: [u8; 2048],
        string: [u8; 256],
        guid: u64,
        nvlist_conf: u64,
        nvlist_conf_size: u64,
        cookie: u64,
    }

    /// Comfortably larger than `sizeof (zfs_cmd_t)` (about 13 KiB).
    const CMD_WORDS: usize = 64 * 1024 / 8;
    /// Output buffers grow on ENOMEM up to this size.
    const MAX_NVLIST: usize = 64 << 20;

    const _: () = assert!(std::mem::offset_of!(ZfsCmdHead, nvlist_dst) == 1040);
    const _: () = assert!(std::mem::offset_of!(ZfsCmdHead, cookie) == 3400);
    const _: () = assert!(size_of::<IocParm>() == 24);

    struct ZfsDev {
        file: File,
        cmd: Box<[u64; CMD_WORDS]>,
        dst: Vec<u8>,
    }

    impl ZfsDev {
        fn open() -> Result<Self> {
            let version: i32 = Mib::new("vfs.zfs.version.ioctl")
                .and_then(|m| m.read())
                .context("reading vfs.zfs.version.ioctl (is zfs.ko loaded?)")?;
            if u32::try_from(version).ok() != Some(ZFS_IOCVER_OZFS) {
                bail!("unsupported ZFS ioctl version {version} (expected {ZFS_IOCVER_OZFS})");
            }
            Ok(Self {
                file: File::open("/dev/zfs").context("opening /dev/zfs")?,
                cmd: vec![0u64; CMD_WORDS]
                    .into_boxed_slice()
                    .try_into()
                    .expect("size"),
                dst: vec![0; 256 * 1024],
            })
        }

        fn head(&mut self) -> &mut ZfsCmdHead {
            // SAFETY: the buffer is u64-aligned, larger than ZfsCmdHead, and
            // every bit pattern is valid for its integer/array fields.
            unsafe { &mut *self.cmd.as_mut_ptr().cast::<ZfsCmdHead>() }
        }

        /// Runs a ZFS ioctl on `name`, returning the output nvlist bytes and
        /// `zc_cookie`. Retries with a bigger buffer on ENOMEM.
        fn ioctl(&mut self, request: u8, name: &str, cookie: u64) -> io::Result<(&[u8], u64)> {
            let name = CString::new(name).map_err(io::Error::other)?;
            loop {
                self.cmd.fill(0);
                let dst_ptr = self.dst.as_mut_ptr() as u64;
                let dst_len = self.dst.len() as u64;
                let head = self.head();
                let bytes = name.as_bytes_with_nul();
                if bytes.len() > head.name.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "pool name too long",
                    ));
                }
                head.name[..bytes.len()].copy_from_slice(bytes);
                head.nvlist_dst = dst_ptr;
                head.nvlist_dst_size = dst_len;
                head.cookie = cookie;

                let mut parm = IocParm {
                    version: ZFS_IOCVER_OZFS,
                    cmd: self.cmd.as_mut_ptr() as u64,
                    cmd_size: (CMD_WORDS * 8) as u64,
                };
                // _IOWR('Z', request, zfs_iocparm_t)
                let req: libc::c_ulong = 0xC000_0000
                    | ((size_of::<IocParm>() as libc::c_ulong & 0x1fff) << 16)
                    | (libc::c_ulong::from(b'Z') << 8)
                    | libc::c_ulong::from(request);
                // SAFETY: `parm` points at our command buffer, which is larger
                // than zfs_cmd_t, and `dst` is valid for `dst_len` bytes.
                let rc = unsafe { libc::ioctl(self.file.as_raw_fd(), req, &raw mut parm) };
                if rc == 0 {
                    let head = self.head();
                    let len = usize::try_from(head.nvlist_dst_size).unwrap_or(usize::MAX);
                    let cookie = head.cookie;
                    let out = self
                        .dst
                        .get(..len)
                        .ok_or_else(|| io::Error::other("nvlist larger than buffer"))?;
                    return Ok((out, cookie));
                }
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOMEM) || self.dst.len() >= MAX_NVLIST {
                    return Err(err);
                }
                let wanted = usize::try_from(self.head().nvlist_dst_size).unwrap_or(0);
                let new_len = wanted.max(self.dst.len() * 2).min(MAX_NVLIST);
                self.dst.resize(new_len, 0);
            }
        }
    }

    struct KstatField {
        metric: String,
        kind: Kind,
        signed: bool,
        mib: Mib,
    }

    pub struct Zfs {
        kstats: Vec<KstatField>,
        dev: Option<ZfsDev>,
        vdevs: bool,
        generation: u64,
        pools: Vec<String>,
        states: HashMap<String, Mib>,
        counters: Monotonic,
    }

    impl Zfs {
        pub fn new(config: &Config) -> Result<Self> {
            let mut kstats = Vec::new();
            for kstat in &config.kstats {
                let prefix = format!("kstat.zfs.misc.{kstat}");
                let leaves = walk(&prefix).with_context(|| format!("listing {prefix}"))?;
                tracing::debug!(kstat, leaves = leaves.len(), first = ?leaves.first().map(|l| (&l.name, l.kind)), "resolved kstat");
                for leaf in leaves {
                    let signed = match leaf.kind {
                        libc::CTLTYPE_U64
                        | libc::CTLTYPE_UINT
                        | libc::CTLTYPE_U32
                        | libc::CTLTYPE_ULONG => false,
                        libc::CTLTYPE_S64
                        | libc::CTLTYPE_INT
                        | libc::CTLTYPE_S32
                        | libc::CTLTYPE_LONG => true,
                        _ => continue,
                    };
                    let Some(field) = leaf
                        .name
                        .strip_prefix(&prefix)
                        .and_then(|f| f.strip_prefix('.'))
                    else {
                        continue;
                    };
                    let kind = if signed {
                        Kind::Gauge
                    } else {
                        kstat_kind(kstat, field)
                    };
                    let metric = match kind {
                        Kind::Counter => format!("zfs_{kstat}_{field}_total"),
                        Kind::Gauge => format!("zfs_{kstat}_{field}"),
                    };
                    kstats.push(KstatField {
                        metric,
                        kind,
                        signed,
                        mib: leaf.mib,
                    });
                }
            }
            Ok(Self {
                kstats,
                dev: config.pools.then(ZfsDev::open).transpose()?,
                vdevs: config.vdevs,
                generation: 0,
                pools: Vec::new(),
                states: HashMap::new(),
                counters: Monotonic::default(),
            })
        }

        fn collect_kstats(&self) -> Result<()> {
            for field in &self.kstats {
                if field.signed {
                    gauge!(field.metric.clone()).set(field.mib.read_int()? as f64);
                } else {
                    let value = field.mib.read_uint()?;
                    match field.kind {
                        Kind::Counter => counter!(field.metric.clone()).absolute(value),
                        Kind::Gauge => gauge!(field.metric.clone()).set(value as f64),
                    }
                }
            }
            Ok(())
        }

        fn refresh_pool_list(&mut self) -> Result<()> {
            let Some(dev) = &mut self.dev else {
                return Ok(());
            };
            match dev.ioctl(ZFS_IOC_POOL_CONFIGS, "", self.generation) {
                Ok((bytes, generation)) => {
                    let configs = nvlist::unpack(bytes)?;
                    // Names starting with '$' are internal (e.g. "$import").
                    self.pools = configs
                        .iter()
                        .map(|(n, _)| n.to_owned())
                        .filter(|n| !n.starts_with('$'))
                        .collect();
                    self.generation = generation;
                    self.states.retain(|pool, _| self.pools.contains(pool));
                    Ok(())
                }
                Err(err) if err.raw_os_error() == Some(libc::EEXIST) => Ok(()),
                Err(err) => Err(err).context("ZFS_IOC_POOL_CONFIGS"),
            }
        }

        fn collect_pool(&mut self, pool: &str) -> Result<()> {
            let state = match self.states.get(pool) {
                Some(mib) => mib.read_string(),
                None => Mib::new(&format!("kstat.zfs.{pool}.misc.state")).and_then(|mib| {
                    let state = mib.read_string();
                    self.states.insert(pool.to_owned(), mib);
                    state
                }),
            }
            .with_context(|| format!("reading health of pool {pool}"))?;
            for s in STATES {
                gauge!("zfs_pool_health", "pool" => pool.to_owned(), "state" => s)
                    .set(f64::from(u8::from(s == state)));
            }
            if !STATES.contains(&state.as_str()) {
                gauge!("zfs_pool_health", "pool" => pool.to_owned(), "state" => state.clone())
                    .set(1.0);
            }

            let Some(dev) = &mut self.dev else {
                return Ok(());
            };
            let (bytes, _) = dev
                .ioctl(ZFS_IOC_POOL_GET_PROPS, pool, 0)
                .with_context(|| format!("getting properties of pool {pool}"))?;
            let props = pool_props(&nvlist::unpack(bytes)?);
            let set = |name: &'static str, value: Option<f64>| {
                if let Some(v) = value {
                    gauge!(name, "pool" => pool.to_owned()).set(v);
                }
            };
            set("zfs_pool_size_bytes", props.size.map(|v| v as f64));
            set(
                "zfs_pool_allocated_bytes",
                props.allocated.map(|v| v as f64),
            );
            set("zfs_pool_free_bytes", props.free.map(|v| v as f64));
            set("zfs_pool_freeing_bytes", props.freeing.map(|v| v as f64));
            set("zfs_pool_fragmentation_ratio", props.fragmentation);
            set("zfs_pool_dedup_ratio", props.dedup_ratio);

            // POOL_STATS returns the config even for faulted pools.
            let (bytes, _) = dev
                .ioctl(ZFS_IOC_POOL_STATS, pool, 0)
                .with_context(|| format!("getting stats of pool {pool}"))?;
            let config = nvlist::unpack(bytes)?;
            let Some(tree) = config.get_list("vdev_tree") else {
                return Ok(());
            };
            let vdevs = vdevs(pool, tree);
            if let Some(root) = vdevs.first() {
                // Re-importing a pool resets its vdev stats.
                for (i, typ) in ZIO_TYPES.iter().enumerate().skip(1) {
                    let ops = self
                        .counters
                        .correct(&format!("ops\0{pool}\0{typ}"), root.ops[i]);
                    let bytes = self
                        .counters
                        .correct(&format!("bytes\0{pool}\0{typ}"), root.bytes[i]);
                    counter!("zfs_pool_ops_total", "pool" => pool.to_owned(), "type" => *typ)
                        .absolute(ops);
                    counter!("zfs_pool_bytes_total", "pool" => pool.to_owned(), "type" => *typ)
                        .absolute(bytes);
                }
            }
            if self.vdevs {
                for vdev in &vdevs {
                    for s in STATES.iter().filter(|&&s| s != "SUSPENDED") {
                        gauge!("zfs_vdev_state", "pool" => pool.to_owned(), "vdev" => vdev.name.clone(), "state" => *s)
                            .set(f64::from(u8::from(*s == vdev.state)));
                    }
                    for (typ, count) in vdev.errors {
                        gauge!("zfs_vdev_errors", "pool" => pool.to_owned(), "vdev" => vdev.name.clone(), "type" => typ)
                            .set(count as f64);
                    }
                }
            }
            if let Some(Value::UintArray(stats)) = tree.get("scan_stats")
                && let Some(scan) = scan(stats)
            {
                gauge!("zfs_pool_scan_info", "pool" => pool.to_owned(), "function" => scan.function, "state" => scan.state).set(1.0);
                gauge!("zfs_pool_scan_start_time_seconds", "pool" => pool.to_owned())
                    .set(scan.start_time as f64);
                gauge!("zfs_pool_scan_end_time_seconds", "pool" => pool.to_owned())
                    .set(scan.end_time as f64);
                gauge!("zfs_pool_scan_to_examine_bytes", "pool" => pool.to_owned())
                    .set(scan.to_examine as f64);
                gauge!("zfs_pool_scan_issued_bytes", "pool" => pool.to_owned())
                    .set(scan.issued as f64);
                gauge!("zfs_pool_scan_errors", "pool" => pool.to_owned()).set(scan.errors as f64);
            }
            Ok(())
        }
    }

    impl Collector for Zfs {
        fn name(&self) -> &'static str {
            "zfs"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            self.collect_kstats()?;
            if self.dev.is_none() {
                return Ok(());
            }
            self.refresh_pool_list()?;
            // Report every pool even if one fails, then return the first error.
            let mut first_error = None;
            for pool in self.pools.clone() {
                if let Err(err) = self.collect_pool(&pool) {
                    first_error.get_or_insert(err);
                }
            }
            self.counters.prune();
            first_error.map_or(Ok(()), Err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nvlist::tests::{Enc, pack};
    use crate::nvlist::unpack;

    #[test]
    fn classifies_kstats() {
        for counter in [
            "hits",
            "demand_data_misses",
            "mru_ghost_hits",
            "evict_skip",
            "deleted",
            "l2_read_bytes",
            "predictive_prefetch",
        ] {
            assert_eq!(kstat_kind("arcstats", counter), Kind::Counter, "{counter}");
        }
        for gauge in [
            "size",
            "c",
            "c_max",
            "mfu_size",
            "l2_size",
            "hash_elements",
            "arc_no_grow",
            "memory_available_bytes",
            "something_new",
        ] {
            assert_eq!(kstat_kind("arcstats", gauge), Kind::Gauge, "{gauge}");
        }
        assert_eq!(kstat_kind("zfetchstats", "hits"), Kind::Counter);
        assert_eq!(kstat_kind("zfetchstats", "io_active"), Kind::Gauge);
        assert_eq!(kstat_kind("dbufstats", "hash_hits"), Kind::Gauge);
    }

    #[test]
    fn maps_vdev_states_like_zpool() {
        assert_eq!(vdev_state_name(7, 0), "ONLINE");
        assert_eq!(vdev_state_name(6, 0), "DEGRADED");
        assert_eq!(vdev_state_name(4, 1), "UNAVAIL");
        assert_eq!(vdev_state_name(4, 2), "FAULTED");
        assert_eq!(vdev_state_name(4, 15), "SPLIT");
        assert_eq!(vdev_state_name(2, 0), "OFFLINE");
        assert_eq!(vdev_state_name(99, 0), "UNKNOWN");
    }

    fn prop(value: u64) -> Enc<'static> {
        Enc::List(vec![("value", Enc::U64(value)), ("source", Enc::U64(0))])
    }

    #[test]
    fn parses_pool_props() {
        let buf = pack(&[
            ("size", prop(19_864_223_744)),
            ("allocated", prop(2_847_223_808)),
            ("free", prop(17_016_999_936)),
            ("fragmentation", prop(3)),
            ("dedupratio", prop(100)),
            (
                "name",
                Enc::List(vec![("value", Enc::Str("zroot")), ("source", Enc::U64(0))]),
            ),
        ]);
        let props = pool_props(&unpack(&buf).unwrap());
        assert_eq!(props.size, Some(19_864_223_744));
        assert_eq!(props.free, Some(17_016_999_936));
        assert_eq!(props.fragmentation, Some(0.03));
        assert_eq!(props.dedup_ratio, Some(1.0));
        assert_eq!(props.freeing, None);

        let invalid = pack(&[("fragmentation", prop(u64::MAX))]);
        assert_eq!(pool_props(&unpack(&invalid).unwrap()).fragmentation, None);
    }

    fn stats(state: u64, read_errors: u64) -> Vec<u64> {
        let mut s = vec![0u64; 41];
        s[vs::STATE] = state;
        s[vs::OPS + 1] = 10;
        s[vs::BYTES + 2] = 4096;
        s[vs::READ_ERRORS] = read_errors;
        s
    }

    #[test]
    fn names_and_flattens_vdev_tree() {
        let root_stats = stats(6, 0);
        let mirror_stats = stats(6, 0);
        let a = stats(7, 0);
        let b = stats(5, 3);
        let cache = stats(7, 0);
        let buf = pack(&[(
            "vdev_tree",
            Enc::List(vec![
                ("type", Enc::Str("root")),
                ("vdev_stats", Enc::U64s(&root_stats)),
                (
                    "children",
                    Enc::Lists(vec![
                        vec![
                            ("type", Enc::Str("mirror")),
                            ("id", Enc::U64(0)),
                            ("vdev_stats", Enc::U64s(&mirror_stats)),
                            (
                                "children",
                                Enc::Lists(vec![
                                    vec![
                                        ("type", Enc::Str("disk")),
                                        ("path", Enc::Str("/dev/ada0p3")),
                                        ("vdev_stats", Enc::U64s(&a)),
                                    ],
                                    vec![
                                        ("type", Enc::Str("file")),
                                        ("path", Enc::Str("/tank/f1")),
                                        ("vdev_stats", Enc::U64s(&b)),
                                    ],
                                ]),
                            ),
                        ],
                        vec![("type", Enc::Str("hole")), ("id", Enc::U64(1))],
                    ]),
                ),
                (
                    "l2cache",
                    Enc::Lists(vec![vec![
                        ("type", Enc::Str("disk")),
                        ("path", Enc::Str("/dev/nda0")),
                        ("vdev_stats", Enc::U64s(&cache)),
                    ]]),
                ),
                (
                    "scan_stats",
                    Enc::U64s(&[1, 2, 1000, 2000, 500, 500, 0, 500, 0, 0, 0, 0, 0, 0, 480]),
                ),
            ]),
        )]);
        let config = unpack(&buf).unwrap();
        let tree = config.get_list("vdev_tree").unwrap();
        let vdevs = vdevs("tank", tree);
        let names: Vec<_> = vdevs.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["tank", "mirror-0", "ada0p3", "/tank/f1", "nda0"]);
        assert_eq!(vdevs[0].state, "DEGRADED");
        assert_eq!(vdevs[0].ops[1], 10);
        assert_eq!(vdevs[0].bytes[2], 4096);
        assert_eq!(vdevs[3].state, "FAULTED");
        assert_eq!(vdevs[3].errors[0], ("read", 3));

        let Some(Value::UintArray(s)) = tree.get("scan_stats") else {
            panic!()
        };
        let scan = scan(s).unwrap();
        assert_eq!(
            (scan.function, scan.state, scan.end_time, scan.issued),
            ("scrub", "finished", 2000, 480)
        );
        assert_eq!(
            super::scan(&[0, 0, 0, 0, 0, 0, 0, 0, 0]),
            None,
            "never scanned"
        );
    }

    #[test]
    fn raidz_names_include_parity() {
        let buf = pack(&[
            ("type", Enc::Str("raidz")),
            ("nparity", Enc::U64(2)),
            ("id", Enc::U64(1)),
        ]);
        assert_eq!(
            vdev_name("tank", &unpack(&buf).unwrap()).as_deref(),
            Some("raidz2-1")
        );
    }
}
