//! Space and inode usage of mounted filesystems.
//!
//! FreeBSD sources: getfsstat(2) with `MNT_NOWAIT` lists the mounts without
//! touching the filesystems, then a fresh statfs(2) per mount gives current
//! numbers (`MNT_NOWAIT` data can be stale). The statfs calls run on the
//! blocking thread pool so a hung mount (e.g. NFS) can't stall the exporter.
//!
//! Linux sources: `/proc/self/mountinfo` lists the mounts (of calipers' mount
//! namespace), then statvfs(3) per mount, also on the blocking pool. A mount
//! point that is mounted over is reported once, for the topmost mount, which
//! is the one statvfs sees. Mounts calipers may not stat (`EACCES`, e.g.
//! another user's FUSE mount) or whose FUSE daemon died (`ENOTCONN`) are
//! skipped. tmpfs and devtmpfs count as real filesystems (use `ignore_fs`),
//! as do overlay mounts (container root filesystems).
//!
//! Pseudo filesystems ([`PSEUDO_FS`], and anything reporting zero blocks) are
//! always skipped.
//!
//! Used space is `disk_total_bytes - disk_free_bytes`. On UFS and ext4,
//! `avail` is less than `free` by the root reserve; on UFS it goes negative
//! when root dips into it.

// The helpers are only used by the FreeBSD and Linux implementations (and tests).
#![cfg_attr(
    not(any(target_os = "freebsd", target_os = "linux")),
    expect(dead_code, reason = "used by the FreeBSD and Linux implementations")
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

/// One mount from getfsstat(2) or `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub path: String,
    pub device: String,
    pub fstype: String,
    pub readonly: bool,
}

/// Kernel-provided filesystems without real storage. devfs reports a fake
/// 1 KiB size, so the zero-block check alone doesn't catch it.
#[cfg(not(target_os = "linux"))]
const PSEUDO_FS: &[&str] = &[
    "devfs",
    "fdescfs",
    "procfs",
    "linprocfs",
    "linsysfs",
    "autofs",
    "mqueuefs",
];

/// Kernel-provided filesystems without real storage on Linux. Most report
/// zero blocks anyway; efivarfs (NVRAM variables) and hugetlbfs report sizes
/// that aren't disk space.
#[cfg(target_os = "linux")]
const PSEUDO_FS: &[&str] = &[
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "nsfs",
    "proc",
    "pstore",
    "rpc_pipefs",
    "securityfs",
    "selinuxfs",
    "sysfs",
    "tracefs",
];

impl Config {
    fn wants(&self, mount: &Mount) -> bool {
        !PSEUDO_FS.contains(&mount.fstype.as_str())
            && !self.ignore_fs.contains(&mount.fstype)
            && (self.mount_points.is_empty() || self.mount_points.contains(&mount.path))
    }
}

/// The mount source without the `/dev/` prefix (ZFS datasets have none).
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

/// Undoes the octal escapes (`\040` for space, `\011`, `\012`, `\134`) the
/// kernel writes into mountinfo fields.
#[cfg(any(target_os = "linux", test))]
fn unescape_octal(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let code = bytes
            .get(i + 1..i + 4)
            .filter(|digits| bytes[i] == b'\\' && digits.iter().all(|d| (b'0'..=b'7').contains(d)))
            .and_then(|digits| {
                digits
                    .iter()
                    .try_fold(0u8, |acc, d| acc.checked_mul(8)?.checked_add(d - b'0'))
            });
        if let Some(code) = code {
            out.push(code);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses `/proc/<pid>/mountinfo` (proc(5)): `id parent major:minor root
/// mount_point mount_options [optional fields...] - fstype source
/// super_options`. A mount point that is mounted over keeps only its last
/// (topmost) entry. Malformed lines are skipped.
#[cfg(any(target_os = "linux", test))]
fn parse_mountinfo(text: &str) -> Vec<Mount> {
    let mut out: Vec<Mount> = Vec::new();
    for line in text.lines() {
        let mut fields = line.split(' ');
        let (Some(path), Some(options)) = (fields.nth(4), fields.next()) else {
            continue;
        };
        // Skip the optional fields up to the separator.
        if !fields.by_ref().any(|f| f == "-") {
            continue;
        }
        let (Some(fstype), Some(source)) = (fields.next(), fields.next()) else {
            continue;
        };
        // Read-only per mount, or the whole filesystem (super options).
        let readonly = [Some(options), fields.next()]
            .into_iter()
            .flatten()
            .any(|opts| opts.split(',').any(|o| o == "ro"));
        let mount = Mount {
            path: unescape_octal(path),
            device: device_label(&unescape_octal(source)).to_owned(),
            fstype: fstype.to_owned(),
            readonly,
        };
        out.retain(|m| m.path != mount.path);
        out.push(mount);
    }
    out
}

native_only!(Disk, "disk");

#[cfg(target_os = "freebsd")]
pub use freebsd::Disk;
#[cfg(target_os = "linux")]
pub use linux::Disk;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::{
        ffi::{
            CStr,
            CString,
        },
        io,
        mem::MaybeUninit,
    };

    use anyhow::{
        Context,
        Result,
    };
    use metrics::gauge;

    use super::{
        Config,
        Mount,
        Usage,
        describe,
        device_label,
    };
    use crate::{
        collector::Collector,
        sys::freebsd::c_chars_as_bytes,
    };

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
            // getfsstat never reports more entries than fit.
            assert!(n < capacity, "getfsstat overran its buffer");
            // SAFETY: the kernel filled the first `n` entries, which fit in
            // the capacity.
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

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        ffi::CString,
        io,
        mem::MaybeUninit,
    };

    use anyhow::{
        Context,
        Result,
    };
    use metrics::gauge;

    use super::{
        Config,
        Mount,
        Usage,
        describe,
        parse_mountinfo,
    };
    use crate::collector::Collector;

    pub struct Disk {
        config: Config,
    }

    impl Disk {
        #[expect(
            clippy::unnecessary_wraps,
            reason = "the stub of this constructor on other platforms fails, so callers expect a \
                      Result"
        )]
        pub fn new(config: &Config) -> Result<Self> {
            Ok(Self {
                config: config.clone(),
            })
        }
    }

    #[expect(unsafe_code, reason = "statvfs(3) FFI")]
    fn usage(path: &str) -> io::Result<Option<Usage>> {
        let cpath = CString::new(path).map_err(io::Error::other)?;
        let mut fs = MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `fs` is valid for writes; statvfs fills it on success.
        if unsafe { libc::statvfs(cpath.as_ptr(), fs.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: initialized by the successful statvfs call.
        let fs = unsafe { fs.assume_init() };
        let signed = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
        // Block counts are in fragment-size units, as df(1) uses them.
        Ok(Usage::from_blocks(
            fs.f_frsize,
            fs.f_blocks,
            fs.f_bfree,
            signed(fs.f_bavail),
            fs.f_files,
            signed(fs.f_ffree),
        ))
    }

    /// Lists and stats all wanted mounts; runs on the blocking pool.
    fn gather(config: &Config) -> Result<Vec<(Mount, Usage)>> {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
            .context("reading /proc/self/mountinfo")?;
        let mut out = Vec::new();
        for mount in parse_mountinfo(&mountinfo) {
            if !config.wants(&mount) {
                continue;
            }
            match usage(&mount.path) {
                Ok(Some(usage)) => out.push((mount, usage)),
                Ok(None) => {} // pseudo filesystem
                // Unmounted between the two calls, not ours to stat, or a
                // dead FUSE daemon.
                Err(err)
                    if matches!(
                        err.raw_os_error(),
                        Some(libc::ENOENT | libc::EACCES | libc::EPERM | libc::ENOTCONN)
                    ) =>
                {
                    tracing::debug!(path = mount.path, error = %err, "skipping mount");
                }
                Err(err) => return Err(err).with_context(|| format!("statvfs {}", mount.path)),
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
            !config.wants(&mount("/dev", PSEUDO_FS[0])),
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

    #[test]
    fn parses_mountinfo() {
        // Lines from an Arch Linux host, plus an escaped path, a read-only
        // mount, a read-only superblock and an overmounted /mnt.
        let text = r"40 1 259:4 / / rw,relatime shared:1 - xfs /dev/nvme1n1p2 rw,inode64,noquota
22 40 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
39 40 0:7 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,size=32806028k,mode=755
95 40 0:47 / /tank/vms rw,noatime shared:52 - zfs tank/vms rw,xattr,posixacl
96 40 0:48 / /media/My\040Disk ro,relatime - vfat /dev/sda1 rw,fmask=0022
99 40 0:51 / /snap rw,relatime - squashfs /dev/loop0 ro
97 40 0:49 / /mnt rw - tmpfs tmpfs rw
98 97 0:50 / /mnt rw - ext4 /dev/sdb1 rw
bogus line
";
        let mounts = parse_mountinfo(text);
        let summary: Vec<_> = mounts
            .iter()
            .map(|m| {
                (
                    m.path.as_str(),
                    m.device.as_str(),
                    m.fstype.as_str(),
                    m.readonly,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("/", "nvme1n1p2", "xfs", false),
                ("/proc", "proc", "proc", false),
                ("/dev", "devtmpfs", "devtmpfs", false),
                ("/tank/vms", "tank/vms", "zfs", false),
                ("/media/My Disk", "sda1", "vfat", true),
                ("/snap", "loop0", "squashfs", true),
                ("/mnt", "sdb1", "ext4", false),
            ]
        );
    }

    #[test]
    fn unescapes_octal() {
        assert_eq!(unescape_octal(r"/a\040b\011c\134d"), "/a b\tc\\d");
        assert_eq!(unescape_octal(r"/x\09y\"), r"/x\09y\", "not an escape");
        assert_eq!(unescape_octal(r"\777"), r"\777", "out of range");
    }
}
