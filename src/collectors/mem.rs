//! Physical memory, as FreeBSD's VM sees it.
//!
//! FreeBSD and Linux describe memory differently, so instead of forcing
//! FreeBSD numbers into Linux terms (or Telegraf's mix of both), this exports
//! the page queues as they are, plus one clearly defined `available` value:
//!
//! * `mem_bytes{state}` partitions all VM-managed memory into the page queues:
//!   active, inactive, laundry (dirty, waiting to be written to swap), wired
//!   (kernel, ZFS ARC, mlock), free, and `other` for pages that are on no queue
//!   at the moment (in transit). `sum(mem_bytes)` == `mem_managed_bytes`.
//! * `mem_physical_bytes` (`hw.physmem`) is slightly larger than the managed
//!   memory; the difference is reserved by the kernel at boot.
//! * Wired memory is broken down further where FreeBSD tells us: ZFS ARC, the
//!   UFS buffer cache and user-wired (mlock) memory. These overlap `wired`.
//! * `mem_available_bytes` = free + inactive + (ARC size - ARC minimum). Laundry
//!   is excluded because reclaiming it needs swap I/O, the same reason Linux's
//!   `MemAvailable` excludes anonymous memory. The ARC part matters on ZFS
//!   systems, where the ARC would otherwise make memory look permanently full.

// The helpers are only used by the FreeBSD implementation (and tests).
#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

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
        "mem_bytes",
        "VM-managed memory by page queue state; the states sum to mem_managed_bytes."
    );
    describe_gauge!("mem_managed_bytes", "Memory managed by the VM system.");
    describe_gauge!("mem_physical_bytes", "Usable physical memory (hw.physmem).");
    describe_gauge!(
        "mem_available_bytes",
        "Estimate of memory available without swapping: free + inactive + ARC above its minimum."
    );
    describe_gauge!("mem_buffer_bytes", "UFS buffer cache (part of wired).");
    describe_gauge!(
        "mem_user_wired_bytes",
        "Memory wired by user processes, e.g. mlock (part of wired)."
    );
    describe_gauge!("mem_zfs_arc_bytes", "ZFS ARC size (part of wired).");
    describe_gauge!(
        "mem_zfs_arc_min_bytes",
        "Size the ZFS ARC won't shrink below."
    );
    describe_gauge!(
        "mem_free_target_bytes",
        "Free memory the page daemon tries to maintain; free below this means memory pressure."
    );
    describe_gauge!(
        "mem_pagedaemon_wakeups_total",
        "Times the page daemon woke up to reclaim memory. Cumulative; use rate()."
    );
    describe_gauge!(
        "mem_pagedaemon_scanned_pages_total",
        "Pages scanned by the page daemon. Cumulative; use rate()."
    );
}

/// One read of all memory sysctls. Page counts are in pages, the rest in bytes.
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

freebsd_only!(Mem, "mem");

#[cfg(target_os = "freebsd")]
pub use freebsd::Mem;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use anyhow::{Context, Result};
    use metrics::gauge;

    use super::{Config, Snapshot, describe};
    use crate::collector::Collector;
    use crate::sys::freebsd::Mib;

    /// A sysctl resolved at startup, read as an unsigned integer.
    struct Uint {
        name: &'static str,
        mib: Mib,
    }

    impl Uint {
        fn new(name: &'static str) -> Result<Self> {
            Ok(Self {
                name,
                mib: Mib::new(name)?,
            })
        }

        fn read(&self) -> Result<u64> {
            self.mib
                .read_uint()
                .with_context(|| format!("reading {}", self.name))
        }
    }

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
            gauge!("mem_pagedaemon_wakeups_total").set(self.pdwakeups.read()? as f64);
            gauge!("mem_pagedaemon_scanned_pages_total").set(self.pdpages.read()? as f64);
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
}
