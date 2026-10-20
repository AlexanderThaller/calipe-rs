//! Physical memory, as the kernel's VM sees it.
//!
//! FreeBSD and Linux describe memory differently, so instead of forcing one
//! OS's numbers into the other's terms (or Telegraf's mix of both), this
//! exports each kernel's own page accounting, plus one clearly defined
//! `available` value.
//!
//! FreeBSD:
//!
//! * `mem_bytes{state}` partitions all VM-managed memory into the page queues:
//!   active, inactive, laundry (dirty, waiting to be written to swap), wired
//!   (kernel, ZFS ARC, mlock), free, and `other` for pages that are on no queue
//!   at the moment (in transit). `sum(mem_bytes)` == `mem_managed_bytes`.
//! * `mem_physical_bytes` (`hw.physmem`) is slightly larger than the managed
//!   memory; the difference is reserved by the kernel at boot.
//! * Wired memory is broken down further where FreeBSD tells us: ZFS ARC, the
//!   UFS buffer cache and user-wired (mlock) memory. These overlap `wired`.
//! * `mem_available_bytes` = free + inactive + (ARC size - ARC minimum).
//!   Laundry is excluded because reclaiming it needs swap I/O, the same reason
//!   Linux's `MemAvailable` excludes anonymous memory. The ARC part matters on
//!   ZFS systems, where the ARC would otherwise make memory look permanently
//!   full.
//!
//! Linux (`/proc/meminfo`, `/proc/zoneinfo`, `/proc/vmstat`,
//! `/proc/spl/kstat/zfs/arcstats`):
//!
//! * `mem_bytes{state}` partitions `MemTotal` into uses that don't overlap:
//!   `free`, the five LRU lists (`active_anon`, `inactive_anon`, `active_file`,
//!   `inactive_file`, `unevictable`; anon includes shmem/tmpfs and the swap
//!   cache, file includes `Buffers`), `slab_reclaimable`, `slab_unreclaimable`,
//!   `kernel_stack`, `page_tables` (including KVM's secondary page tables),
//!   `hugetlb` (the reserved huge page pool), and `other` for the rest: pages
//!   that drivers and the kernel take from the page allocator directly,
//!   vmalloc, per-CPU data, and the ZFS ARC, which Linux doesn't account
//!   anywhere. `Cached`, `Shmem`, `Mapped` etc. are left out because they
//!   overlap the LRU lists.
//! * `mem_managed_bytes` is `MemTotal`, `mem_physical_bytes` the RAM present in
//!   the memory zones (`present` in `/proc/zoneinfo`); the difference is
//!   reserved by the kernel at boot, as on FreeBSD.
//! * `mem_buffer_bytes` is `Buffers` (block device cache, part of the file
//!   LRU), `mem_user_wired_bytes` is `Mlocked` (part of unevictable).
//! * `mem_available_bytes` = `MemAvailable` + (ARC size - ARC minimum). The
//!   kernel's estimate doesn't know about the ARC unless ZFS reports it as
//!   reclaimable kernel memory (`KReclaimable` above `SReclaimable`); that part
//!   isn't added twice.
//! * The page daemon is kswapd: `mem_free_target_bytes` is the sum of the
//!   zones' low watermarks (kswapd wakes up below them),
//!   `mem_pagedaemon_wakeups_total` counts kswapd reclaim runs (`pageoutrun`)
//!   and `mem_pagedaemon_scanned_pages_total` the pages it scanned. Direct
//!   reclaim, where allocating processes stall to reclaim memory themselves,
//!   has no FreeBSD counterpart: `mem_direct_reclaim_stalls_total` and
//!   `mem_direct_reclaim_scanned_pages_total`.

use std::time::Duration;

use metrics::{
    describe_counter,
    describe_gauge,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
}

const LINUX: bool = cfg!(target_os = "linux");

#[cfg_attr(
    not(any(target_os = "freebsd", target_os = "linux")),
    expect(dead_code, reason = "used by the FreeBSD and Linux implementations")
)]
pub fn describe() {
    describe_gauge!(
        "mem_bytes",
        if LINUX {
            "Managed memory by use (LRU lists, slab, kernel stacks, ...); the states sum to \
             mem_managed_bytes."
        } else {
            "VM-managed memory by page queue state; the states sum to mem_managed_bytes."
        }
    );
    describe_gauge!("mem_managed_bytes", "Memory managed by the VM system.");
    describe_gauge!(
        "mem_physical_bytes",
        if LINUX {
            "Physical memory present in the memory zones."
        } else {
            "Usable physical memory (hw.physmem)."
        }
    );
    describe_gauge!(
        "mem_available_bytes",
        if LINUX {
            "Estimate of memory available without swapping: MemAvailable + ARC above its minimum."
        } else {
            "Estimate of memory available without swapping: free + inactive + ARC above its \
             minimum."
        }
    );
    describe_gauge!(
        "mem_buffer_bytes",
        if LINUX {
            "Block device buffers (Buffers, part of the file LRU)."
        } else {
            "UFS buffer cache (part of wired)."
        }
    );
    describe_gauge!(
        "mem_user_wired_bytes",
        if LINUX {
            "Memory locked by user processes with mlock (part of unevictable)."
        } else {
            "Memory wired by user processes, e.g. mlock (part of wired)."
        }
    );
    describe_gauge!(
        "mem_zfs_arc_bytes",
        if LINUX {
            "ZFS ARC size (part of other)."
        } else {
            "ZFS ARC size (part of wired)."
        }
    );
    describe_gauge!(
        "mem_zfs_arc_min_bytes",
        "Size the ZFS ARC won't shrink below."
    );
    describe_gauge!(
        "mem_free_target_bytes",
        "Free memory the page daemon tries to maintain; free below this means memory pressure."
    );
    describe_counter!(
        "mem_pagedaemon_wakeups_total",
        "Times the page daemon woke up to reclaim memory."
    );
    describe_counter!(
        "mem_pagedaemon_scanned_pages_total",
        "Pages scanned by the page daemon."
    );
    if LINUX {
        describe_counter!(
            "mem_direct_reclaim_stalls_total",
            "Allocations that stalled to reclaim memory themselves (direct reclaim)."
        );
        describe_counter!(
            "mem_direct_reclaim_scanned_pages_total",
            "Pages scanned by direct reclaim."
        );
    }
}

/// One read of all memory sysctls. Page counts are in pages, the rest in bytes.
#[cfg(any(target_os = "freebsd", test))]
#[derive(Debug, Default, Clone, Copy)]
struct Snapshot {
    page_size: u64,
    page_count: u64,
    free: u64,
    active: u64,
    inactive: u64,
    laundry: u64,
    wired: u64,
    /// ZFS ARC size and minimum in bytes, if ZFS is loaded.
    arc: Option<(u64, u64)>,
}

#[cfg(any(target_os = "freebsd", test))]
impl Snapshot {
    /// Page queue states in bytes. `other` absorbs pages on no queue, so the
    /// values always sum to the managed total.
    fn states(&self) -> [(&'static str, u64); 6] {
        let queued = self.free + self.active + self.inactive + self.laundry + self.wired;
        [
            ("active", self.active),
            ("inactive", self.inactive),
            ("laundry", self.laundry),
            ("wired", self.wired),
            ("free", self.free),
            ("other", self.page_count.saturating_sub(queued)),
        ]
        .map(|(state, pages)| (state, pages * self.page_size))
    }

    fn available_bytes(&self) -> u64 {
        let arc_reclaimable = self.arc.map_or(0, |(size, min)| size.saturating_sub(min));
        (self.free + self.inactive) * self.page_size + arc_reclaimable
    }
}

/// Memory fields from `/proc/meminfo`, in bytes.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct MemInfo {
    total: u64,
    free: u64,
    available: u64,
    buffers: u64,
    active_anon: u64,
    inactive_anon: u64,
    active_file: u64,
    inactive_file: u64,
    unevictable: u64,
    mlocked: u64,
    slab_reclaimable: u64,
    slab_unreclaimable: u64,
    /// Reclaimable slab plus other kernel memory reported as reclaimable.
    kernel_reclaimable: u64,
    kernel_stack: u64,
    page_tables: u64,
    hugetlb: u64,
}

/// `Key:   value [kB]` from `/proc/meminfo`, with the value in bytes (or a
/// plain count for fields without unit).
#[cfg(any(target_os = "linux", test))]
fn meminfo_line(line: &str) -> Option<(&str, u64)> {
    let (key, rest) = line.split_once(':')?;
    let mut words = rest.split_whitespace();
    let value: u64 = words.next()?.parse().ok()?;
    match words.next() {
        Some("kB") => Some((key, value.saturating_mul(1024))),
        None => Some((key, value)),
        Some(_) => None,
    }
}

#[cfg(any(target_os = "linux", test))]
impl MemInfo {
    fn parse(text: &str) -> Result<Self, String> {
        let fields: Vec<_> = text.lines().filter_map(meminfo_line).collect();
        let get = |key: &str| fields.iter().find(|(k, _)| *k == key).map(|&(_, v)| v);
        let need = |key: &str| get(key).ok_or_else(|| format!("{key} missing in /proc/meminfo"));
        let slab_reclaimable = need("SReclaimable")?;
        Ok(Self {
            total: need("MemTotal")?,
            free: need("MemFree")?,
            available: need("MemAvailable")?,
            buffers: need("Buffers")?,
            active_anon: need("Active(anon)")?,
            inactive_anon: need("Inactive(anon)")?,
            active_file: need("Active(file)")?,
            inactive_file: need("Inactive(file)")?,
            unevictable: need("Unevictable")?,
            mlocked: get("Mlocked").unwrap_or(0),
            slab_reclaimable,
            slab_unreclaimable: need("SUnreclaim")?,
            // Linux 4.20+.
            kernel_reclaimable: get("KReclaimable").unwrap_or(slab_reclaimable),
            kernel_stack: need("KernelStack")?,
            // SecPageTables (KVM, Linux 6.0+) are page tables too.
            page_tables: need("PageTables")? + get("SecPageTables").unwrap_or(0),
            // Hugetlb (Linux 5.7+) covers all huge page sizes; before, only
            // the default size's pool is known.
            hugetlb: get("Hugetlb").unwrap_or_else(|| {
                get("HugePages_Total")
                    .unwrap_or(0)
                    .saturating_mul(get("Hugepagesize").unwrap_or(0))
            }),
        })
    }

    /// Disjoint uses of managed memory in bytes. `other` absorbs memory the
    /// kernel doesn't account in any of them, so the values sum to `MemTotal`.
    fn states(&self) -> [(&'static str, u64); 12] {
        let accounted = [
            ("free", self.free),
            ("active_anon", self.active_anon),
            ("inactive_anon", self.inactive_anon),
            ("active_file", self.active_file),
            ("inactive_file", self.inactive_file),
            ("unevictable", self.unevictable),
            ("slab_reclaimable", self.slab_reclaimable),
            ("slab_unreclaimable", self.slab_unreclaimable),
            ("kernel_stack", self.kernel_stack),
            ("page_tables", self.page_tables),
            ("hugetlb", self.hugetlb),
        ];
        let sum = accounted.iter().map(|(_, bytes)| bytes).sum::<u64>();
        let mut states = [("other", self.total.saturating_sub(sum)); 12];
        states[..accounted.len()].copy_from_slice(&accounted);
        states
    }

    /// `MemAvailable` plus the ARC above its minimum (`arc` = size, minimum),
    /// minus what the kernel already counts as reclaimable beyond the slab.
    fn available_bytes(&self, arc: Option<(u64, u64)>) -> u64 {
        let arc_reclaimable = arc.map_or(0, |(size, min)| size.saturating_sub(min));
        let counted = self
            .kernel_reclaimable
            .saturating_sub(self.slab_reclaimable);
        self.available + arc_reclaimable.saturating_sub(counted)
    }
}

/// Totals over all zones in `/proc/zoneinfo`, in pages.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct Zones {
    /// Physical pages (without holes).
    present: u64,
    /// Low watermarks: kswapd wakes up when a zone's free pages drop below.
    low: u64,
}

#[cfg(any(target_os = "linux", test))]
impl Zones {
    fn parse(text: &str) -> Result<Self, String> {
        let mut zones = Self::default();
        let mut seen = false;
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let field = match words.next() {
                Some("present") => &mut zones.present,
                Some("low") => &mut zones.low,
                _ => continue,
            };
            if let Some(Ok(pages)) = words.next().map(str::parse::<u64>) {
                *field += pages;
                seen = true;
            }
        }
        if !seen {
            return Err("no zones in /proc/zoneinfo".to_owned());
        }
        Ok(zones)
    }
}

/// Page reclaim counters from `/proc/vmstat`.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct Reclaim {
    kswapd_runs: u64,
    kswapd_scanned: u64,
    direct_stalls: u64,
    direct_scanned: u64,
}

#[cfg(any(target_os = "linux", test))]
impl Reclaim {
    fn parse(text: &str) -> Result<Self, String> {
        let mut reclaim = Self::default();
        let mut seen = 0;
        for line in text.lines() {
            let Some((key, value)) = line.split_once(' ') else {
                continue;
            };
            let Ok(value) = value.parse::<u64>() else {
                continue;
            };
            let field = match key {
                "pageoutrun" => &mut reclaim.kswapd_runs,
                "pgscan_kswapd" => &mut reclaim.kswapd_scanned,
                "pgscan_direct" => &mut reclaim.direct_scanned,
                // One counter per zone type since Linux 4.8, a single
                // `allocstall` before.
                _ if key.starts_with("allocstall") => {
                    reclaim.direct_stalls += value;
                    continue;
                }
                _ => continue,
            };
            *field = value;
            seen += 1;
        }
        if seen != 3 {
            return Err(
                "pageoutrun, pgscan_kswapd or pgscan_direct missing in /proc/vmstat".to_owned(),
            );
        }
        Ok(reclaim)
    }
}

/// ARC size and minimum in bytes from ZFS's `arcstats` kstat
/// (`name type data` rows).
#[cfg(any(target_os = "linux", test))]
fn arc_sizes(text: &str) -> Option<(u64, u64)> {
    let (mut size, mut min) = (None, None);
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let slot = match words.next() {
            Some("size") => &mut size,
            Some("c_min") => &mut min,
            _ => continue,
        };
        *slot = words.nth(1).and_then(|v| v.parse::<u64>().ok());
    }
    Some((size?, min?))
}

native_only!(Mem, "mem");

#[cfg(target_os = "freebsd")]
pub use freebsd::Mem;
#[cfg(target_os = "linux")]
pub use linux::Mem;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::Result;
    use metrics::{
        counter,
        gauge,
    };

    use super::{
        Config,
        Snapshot,
        describe,
    };
    use crate::{
        collector::Collector,
        sys::freebsd::Uint,
    };

    struct Arc {
        size: Uint,
        min: Uint,
    }

    impl Arc {
        /// `None` until the zfs module is loaded.
        fn resolve() -> Option<Self> {
            Some(Self {
                size: Uint::new("kstat.zfs.misc.arcstats.size").ok()?,
                min: Uint::new("kstat.zfs.misc.arcstats.c_min").ok()?,
            })
        }
    }

    pub struct Mem {
        page_size: u64,
        page_count: Uint,
        free: Uint,
        active: Uint,
        inactive: Uint,
        laundry: Uint,
        wired: Uint,
        user_wired: Uint,
        physmem: Uint,
        bufspace: Uint,
        free_target: Uint,
        pdwakeups: Uint,
        pdpages: Uint,
        arc: Option<Arc>,
    }

    impl Mem {
        pub fn new(_config: &Config) -> Result<Self> {
            let page_size = Uint::new("hw.pagesize")?.read()?;
            Ok(Self {
                page_size,
                page_count: Uint::new("vm.stats.vm.v_page_count")?,
                free: Uint::new("vm.stats.vm.v_free_count")?,
                active: Uint::new("vm.stats.vm.v_active_count")?,
                inactive: Uint::new("vm.stats.vm.v_inactive_count")?,
                laundry: Uint::new("vm.stats.vm.v_laundry_count")?,
                wired: Uint::new("vm.stats.vm.v_wire_count")?,
                user_wired: Uint::new("vm.stats.vm.v_user_wire_count")?,
                physmem: Uint::new("hw.physmem")?,
                bufspace: Uint::new("vfs.bufspace")?,
                free_target: Uint::new("vm.stats.vm.v_free_target")?,
                pdwakeups: Uint::new("vm.stats.vm.v_pdwakeups")?,
                pdpages: Uint::new("vm.stats.vm.v_pdpages")?,
                arc: Arc::resolve(),
            })
        }
    }

    impl Collector for Mem {
        fn name(&self) -> &'static str {
            "mem"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            if self.arc.is_none() {
                // zfs.ko may be loaded after we started.
                self.arc = Arc::resolve();
            }
            let arc = match &self.arc {
                Some(arc) => Some((arc.size.read()?, arc.min.read()?)),
                None => None,
            };
            let snap = Snapshot {
                page_size: self.page_size,
                page_count: self.page_count.read()?,
                free: self.free.read()?,
                active: self.active.read()?,
                inactive: self.inactive.read()?,
                laundry: self.laundry.read()?,
                wired: self.wired.read()?,
                arc,
            };
            let page = self.page_size as f64;

            for (state, bytes) in snap.states() {
                gauge!("mem_bytes", "state" => state).set(bytes as f64);
            }
            gauge!("mem_managed_bytes").set(snap.page_count as f64 * page);
            gauge!("mem_physical_bytes").set(self.physmem.read()? as f64);
            gauge!("mem_available_bytes").set(snap.available_bytes() as f64);
            gauge!("mem_buffer_bytes").set(self.bufspace.read()? as f64);
            gauge!("mem_user_wired_bytes").set(self.user_wired.read()? as f64 * page);
            if let Some((size, min)) = arc {
                gauge!("mem_zfs_arc_bytes").set(size as f64);
                gauge!("mem_zfs_arc_min_bytes").set(min as f64);
            }
            gauge!("mem_free_target_bytes").set(self.free_target.read()? as f64 * page);
            counter!("mem_pagedaemon_wakeups_total").absolute(self.pdwakeups.read()?);
            counter!("mem_pagedaemon_scanned_pages_total").absolute(self.pdpages.read()?);
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;

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
        MemInfo,
        Reclaim,
        Zones,
        arc_sizes,
        describe,
    };
    use crate::{
        collector::Collector,
        sys::{
            linux::read_into,
            page_size,
        },
    };

    const ARCSTATS: &str = "/proc/spl/kstat/zfs/arcstats";

    pub struct Mem {
        page_size: u64,
        buf: String,
    }

    impl Mem {
        pub fn new(_config: &Config) -> Result<Self> {
            let mut mem = Self {
                page_size: page_size(),
                buf: String::new(),
            };
            // Fail at startup if a file is missing or has an unknown format.
            mem.read("/proc/meminfo", MemInfo::parse)?;
            mem.read("/proc/zoneinfo", Zones::parse)?;
            mem.read("/proc/vmstat", Reclaim::parse)?;
            Ok(mem)
        }

        fn read<T>(&mut self, path: &str, parse: fn(&str) -> Result<T, String>) -> Result<T> {
            read_into(path, &mut self.buf).with_context(|| format!("reading {path}"))?;
            parse(&self.buf).map_err(|e| anyhow!(e))
        }

        /// ARC size and minimum; `None` while the zfs module isn't loaded.
        fn arc(&mut self) -> Result<Option<(u64, u64)>> {
            match read_into(ARCSTATS, &mut self.buf) {
                Ok(()) => arc_sizes(&self.buf)
                    .map(Some)
                    .ok_or_else(|| anyhow!("size or c_min missing in {ARCSTATS}")),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(err) => Err(err).context(format!("reading {ARCSTATS}")),
            }
        }
    }

    impl Collector for Mem {
        fn name(&self) -> &'static str {
            "mem"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            let info = self.read("/proc/meminfo", MemInfo::parse)?;
            let zones = self.read("/proc/zoneinfo", Zones::parse)?;
            let reclaim = self.read("/proc/vmstat", Reclaim::parse)?;
            let arc = self.arc()?;
            let page = self.page_size as f64;

            for (state, bytes) in info.states() {
                gauge!("mem_bytes", "state" => state).set(bytes as f64);
            }
            gauge!("mem_managed_bytes").set(info.total as f64);
            gauge!("mem_physical_bytes").set(zones.present as f64 * page);
            gauge!("mem_available_bytes").set(info.available_bytes(arc) as f64);
            gauge!("mem_buffer_bytes").set(info.buffers as f64);
            gauge!("mem_user_wired_bytes").set(info.mlocked as f64);
            if let Some((size, min)) = arc {
                gauge!("mem_zfs_arc_bytes").set(size as f64);
                gauge!("mem_zfs_arc_min_bytes").set(min as f64);
            }
            gauge!("mem_free_target_bytes").set(zones.low as f64 * page);
            counter!("mem_pagedaemon_wakeups_total").absolute(reclaim.kswapd_runs);
            counter!("mem_pagedaemon_scanned_pages_total").absolute(reclaim.kswapd_scanned);
            counter!("mem_direct_reclaim_stalls_total").absolute(reclaim.direct_stalls);
            counter!("mem_direct_reclaim_scanned_pages_total").absolute(reclaim.direct_scanned);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        // Numbers from the FreeBSD 15.1 test VM.
        Snapshot {
            page_size: 4096,
            page_count: 1_014_412,
            free: 988_785,
            active: 2325,
            inactive: 533,
            laundry: 0,
            wired: 21_926,
            arc: None,
        }
    }

    #[test]
    fn states_sum_to_managed_memory() {
        let snap = snapshot();
        let states = snap.states();
        assert_eq!(
            states.iter().map(|(_, b)| b).sum::<u64>(),
            snap.page_count * 4096
        );
        assert_eq!(states[5], ("other", 843 * 4096));
    }

    #[test]
    fn other_never_underflows() {
        let snap = Snapshot {
            page_count: 10,
            free: 20,
            ..snapshot()
        };
        assert_eq!(snap.states()[5].1, 0);
    }

    #[test]
    fn available_counts_reclaimable_arc_only() {
        let snap = Snapshot {
            laundry: 1000,
            ..snapshot()
        };
        let base = (988_785 + 533) * 4096;
        assert_eq!(snap.available_bytes(), base, "laundry is not available");

        let arc = Snapshot {
            arc: Some((10 << 30, 1 << 30)),
            ..snap
        };
        assert_eq!(arc.available_bytes(), base + (9 << 30));

        let below_min = Snapshot {
            arc: Some((1 << 20, 1 << 30)),
            ..snap
        };
        assert_eq!(below_min.available_bytes(), base);
    }

    // /proc files from an Arch Linux desktop (Linux 7.2, 64 GiB, ZFS).
    const MEMINFO: &str = include_str!("testdata/linux/mem.meminfo");

    #[test]
    fn parses_meminfo() {
        let info = MemInfo::parse(MEMINFO).unwrap();
        assert_eq!(info.total, 65_731_632 * 1024);
        assert_eq!(info.available, 34_195_456 * 1024);
        assert_eq!(info.buffers, 16 * 1024);
        assert_eq!(info.mlocked, 486_560 * 1024);
        assert_eq!(info.page_tables, (177_780 + 10_632) * 1024);
        assert_eq!(info.hugetlb, 0);
        assert_eq!(
            meminfo_line("HugePages_Total:       4"),
            Some(("HugePages_Total", 4))
        );
        assert_eq!(meminfo_line("Foo: 1 MB"), None);
        assert!(MemInfo::parse("MemTotal: 1 kB\n").is_err());
    }

    #[test]
    fn linux_states_partition_memtotal() {
        let info = MemInfo::parse(MEMINFO).unwrap();
        let states = info.states();
        assert_eq!(states.iter().map(|(_, b)| b).sum::<u64>(), info.total);
        // Free, the LRU lists, slab, kernel stacks and page tables in kB.
        let accounted = 18_934_008
            + 14_871_484
            + 2_387_620
            + 2_994_280
            + 10_122_348
            + 570_580
            + 2_869_832
            + 2_073_940
            + 54_176
            + 188_412;
        assert_eq!(states[11], ("other", (65_731_632 - accounted) * 1024));

        let overfull = MemInfo {
            total: 1,
            free: 2,
            ..info
        };
        assert_eq!(overfull.states()[11].1, 0);
    }

    #[test]
    fn hugetlb_falls_back_to_default_pool() {
        let old = MEMINFO.replace("Hugetlb:               0 kB\n", "");
        let old = old.replace("HugePages_Total:       0", "HugePages_Total:       4");
        assert_eq!(MemInfo::parse(&old).unwrap().hugetlb, 4 * 2048 * 1024);
    }

    #[test]
    fn linux_available_adds_arc_once() {
        let info = MemInfo::parse(MEMINFO).unwrap();
        assert_eq!(info.available_bytes(None), info.available);
        let arc = Some((10 << 30, 1 << 30));
        assert_eq!(info.available_bytes(arc), info.available + (9 << 30));
        assert_eq!(
            info.available_bytes(Some((1 << 20, 1 << 30))),
            info.available
        );
        let reported = MemInfo {
            kernel_reclaimable: info.slab_reclaimable + (4 << 30),
            ..info
        };
        assert_eq!(reported.available_bytes(arc), info.available + (5 << 30));
    }

    #[test]
    fn parses_zoneinfo() {
        let zones = Zones::parse(include_str!("testdata/linux/mem.zoneinfo")).unwrap();
        assert_eq!(
            zones,
            Zones {
                present: 3999 + 827_254 + 15_921_920,
                low: 6 + 1618 + 31_687 + 32,
            }
        );
        assert!(Zones::parse("").is_err());
    }

    #[test]
    fn parses_vmstat_reclaim_counters() {
        let reclaim = Reclaim::parse(include_str!("testdata/linux/mem.vmstat")).unwrap();
        assert_eq!(
            reclaim,
            Reclaim {
                kswapd_runs: 103_063,
                kswapd_scanned: 321_422_431,
                direct_stalls: 2561 + 255_882,
                direct_scanned: 16_769_854,
            }
        );
        assert!(Reclaim::parse("pgscan_kswapd 1\n").is_err());
    }

    #[test]
    fn parses_arcstats() {
        let text =
            "24 1 0x01 148 40256 6476338604 639159134422365\nname                            type \
             data\nhits                            4    566829807\nc_min                           \
             4    2103412224\nsize                            4    9170455784\n";
        assert_eq!(arc_sizes(text), Some((9_170_455_784, 2_103_412_224)));
        assert_eq!(arc_sizes("size 4 1\n"), None);
    }
}
