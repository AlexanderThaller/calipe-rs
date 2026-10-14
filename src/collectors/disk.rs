//! Space and inode usage of mounted filesystems.
//!
//! FreeBSD sources: getfsstat(2) with `MNT_NOWAIT` lists the mounts without
//! touching the filesystems, then a fresh statfs(2) per mount gives current
//! numbers (`MNT_NOWAIT` data can be stale). The statfs calls run on the
//! blocking thread pool so a hung mount (e.g. NFS) can't stall the exporter.
//!
//! Pseudo filesystems ([`PSEUDO_FS`], and anything reporting zero blocks) are
//! always skipped.
//!
//! Used space is `disk_total_bytes - disk_free_bytes`. On UFS, `avail` is less
//! than `free` by the root reserve and goes negative when root dips into it.

// The helpers are only used by the FreeBSD implementation (and tests).
#![cfg_attr(
    not(target_os = "freebsd"),
    expect(dead_code, reason = "used by the FreeBSD implementation")
)]

use std::time::Duration;

use metrics::describe_gauge;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
    /// Filesystem types to skip, e.g. `["tmpfs"]`.
    #[serde(default)]
    pub ignore_fs: Vec<String>,
    /// If set, only these mount points are reported.
    #[serde(default)]
    pub mount_points: Vec<String>,
}

pub fn describe() {
    describe_gauge!("disk_total_bytes", "Filesystem size.");
    describe_gauge!(
        "disk_free_bytes",
        "Free space, including space reserved for root."
    );
    describe_gauge!("disk_avail_bytes", "Space available to unprivileged users.");
    describe_gauge!("disk_inodes_total", "Total inodes (file slots).");
    describe_gauge!("disk_inodes_free", "Free inodes.");
}

/// One mount from getfsstat(2).
#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub path: String,
    pub device: String,
    pub fstype: String,
    pub readonly: bool,
}

/// Kernel-provided filesystems without real storage. devfs reports a fake
/// 1 KiB size, so the zero-block check alone doesn't catch it.
const PSEUDO_FS: [&str; 7] = [
    "devfs",
    "fdescfs",
    "procfs",
    "linprocfs",
    "linsysfs",
    "autofs",
    "mqueuefs",
];

impl Config {
    fn wants(&self, mount: &Mount) -> bool {
        !PSEUDO_FS.contains(&mount.fstype.as_str())
            && !self.ignore_fs.contains(&mount.fstype)
            && (self.mount_points.is_empty() || self.mount_points.contains(&mount.path))
    }
}

/// `f_mntfromname` without the `/dev/` prefix (ZFS datasets have none).
fn device_label(from: &str) -> &str {
    from.strip_prefix("/dev/").unwrap_or(from)
}

/// Sizes from one statfs(2), in bytes and inodes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Usage {
    pub total: u64,
    pub free: u64,
    pub avail: i64,
    pub inodes_total: u64,
    pub inodes_free: i64,
}

impl Usage {
    fn from_blocks(
        bsize: u64,
        blocks: u64,
        bfree: u64,
        bavail: i64,
        files: u64,
        ffree: i64,
    ) -> Option<Self> {
        if blocks == 0 {
            return None;
        }
        let bsize_signed = i64::try_from(bsize).unwrap_or(i64::MAX);
        Some(Self {
            total: blocks.saturating_mul(bsize),
            free: bfree.saturating_mul(bsize),
            avail: bavail.saturating_mul(bsize_signed),
            inodes_total: files,
            inodes_free: ffree,
        })
    }
}

freebsd_only!(Disk, "disk");

#[cfg(target_os = "freebsd")]
pub use freebsd::Disk;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::ffi::{CStr, CString};
    use std::io;
    use std::mem::MaybeUninit;

    use anyhow::{Context, Result};
    use metrics::gauge;

    use super::{Config, Mount, Usage, describe, device_label};
    use crate::collector::Collector;
    use crate::sys::freebsd::c_chars_as_bytes;

    /// `MNT_RDONLY` from `sys/mount.h`.
    const MNT_RDONLY: u64 = 0x1;

    pub struct Disk {
        config: Config,
    }

    impl Disk {
        #[expect(
            clippy::unnecessary_wraps,
            reason = "the non-FreeBSD stub of this constructor fails, so callers expect a Result"
        )]
        pub fn new(config: &Config) -> Result<Self> {
            Ok(Self {
                config: config.clone(),
            })
        }
    }

    fn cstr(chars: &[libc::c_char]) -> String {
        CStr::from_bytes_until_nul(c_chars_as_bytes(chars))
            .map_or_else(|_| String::new(), |s| s.to_string_lossy().into_owned())
    }

    /// Lists mounts with `getfsstat(MNT_NOWAIT)`, which doesn't touch the
    /// filesystems themselves.
    #[expect(unsafe_code, reason = "getfsstat(2) FFI")]
    fn mounts() -> io::Result<Vec<Mount>> {
        loop {
            // SAFETY: a null buffer only returns the number of mounts.
            let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
            let count = usize::try_from(count).map_err(|_| io::Error::last_os_error())?;
            // Room for mounts added between the two calls.
            let capacity = count + 8;
            let mut buf: Vec<libc::statfs> = Vec::with_capacity(capacity);
            let bytes = libc::c_long::try_from(capacity * size_of::<libc::statfs>())
                .map_err(io::Error::other)?;
            // SAFETY: `buf` has room for `capacity` entries.
            let n = unsafe { libc::getfsstat(buf.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
            let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
            if n == capacity {
                // Possibly truncated; the mount table grew. Try again.
                continue;
            }
            // SAFETY: the kernel filled the first `n` entries.
            unsafe { buf.set_len(n) };
            return Ok(buf
                .iter()
                .map(|fs| Mount {
                    path: cstr(&fs.f_mntonname),
                    device: device_label(&cstr(&fs.f_mntfromname)).to_owned(),
                    fstype: cstr(&fs.f_fstypename),
                    readonly: fs.f_flags & MNT_RDONLY != 0,
                })
                .collect());
        }
    }

    #[expect(unsafe_code, reason = "statfs(2) FFI")]
    fn usage(path: &str) -> io::Result<Option<Usage>> {
        let cpath = CString::new(path).map_err(io::Error::other)?;
        let mut fs = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `fs` is valid for writes; statfs fills it on success.
        if unsafe { libc::statfs(cpath.as_ptr(), fs.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: initialized by the successful statfs call.
        let fs = unsafe { fs.assume_init() };
        Ok(Usage::from_blocks(
            fs.f_bsize,
            fs.f_blocks,
            fs.f_bfree,
            fs.f_bavail,
            fs.f_files,
            fs.f_ffree,
        ))
    }

    /// Lists and stats all wanted mounts; runs on the blocking pool.
    fn gather(config: &Config) -> Result<Vec<(Mount, Usage)>> {
        let mut out = Vec::new();
        for mount in mounts().context("getfsstat")? {
            if !config.wants(&mount) {
                continue;
            }
            match usage(&mount.path) {
                Ok(Some(usage)) => out.push((mount, usage)),
                Ok(None) => {} // pseudo filesystem
                // Unmounted between the two calls.
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
                Err(err) => return Err(err).with_context(|| format!("statfs {}", mount.path)),
            }
        }
        Ok(out)
    }

    impl Collector for Disk {
        fn name(&self) -> &'static str {
            "disk"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            let config = self.config.clone();
            let filesystems = tokio::task::spawn_blocking(move || gather(&config)).await??;
            for (mount, usage) in filesystems {
                let labels = [
                    ("path", mount.path),
                    ("device", mount.device),
                    ("fstype", mount.fstype),
                    ("mode", if mount.readonly { "ro" } else { "rw" }.to_owned()),
                ];
                gauge!("disk_total_bytes", &labels).set(usage.total as f64);
                gauge!("disk_free_bytes", &labels).set(usage.free as f64);
                gauge!("disk_avail_bytes", &labels).set(usage.avail as f64);
                gauge!("disk_inodes_total", &labels).set(usage.inodes_total as f64);
                gauge!("disk_inodes_free", &labels).set(usage.inodes_free as f64);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(path: &str, fstype: &str) -> Mount {
        Mount {
            path: path.into(),
            device: "x".into(),
            fstype: fstype.into(),
            readonly: false,
        }
    }

    #[test]
    fn filters_by_type_and_mount_point() {
        let config: Config = toml::from_str("ignore_fs = [\"tmpfs\"]").unwrap();
        assert!(config.wants(&mount("/", "zfs")));
        assert!(!config.wants(&mount("/tmp", "tmpfs")));
        assert!(
            !config.wants(&mount("/dev", "devfs")),
            "pseudo filesystems are always skipped"
        );

        let only: Config = toml::from_str("mount_points = [\"/\"]").unwrap();
        assert!(only.wants(&mount("/", "ufs")));
        assert!(!only.wants(&mount("/var", "ufs")));
    }

    #[test]
    fn computes_usage_and_skips_pseudo_filesystems() {
        let usage = Usage::from_blocks(4096, 1000, 100, -20, 500, 400).unwrap();
        assert_eq!(usage.total, 4_096_000);
        assert_eq!(usage.free, 409_600);
        assert_eq!(usage.avail, -81_920);
        assert_eq!(
            Usage::from_blocks(512, 0, 0, 0, 0, 0),
            None,
            "devfs reports 0 blocks"
        );
    }

    #[test]
    fn strips_dev_prefix() {
        assert_eq!(device_label("/dev/ada0p2"), "ada0p2");
        assert_eq!(device_label("zroot/ROOT/default"), "zroot/ROOT/default");
    }
}
