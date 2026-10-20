//! Swap devices and paging traffic.
//!
//! FreeBSD sources: `vm.swap_info.N` (one `struct xswdev` per device, read
//! until `ENOENT`, like swapinfo(8)) and the `vm.stats.vm.v_swappgs{in,out}`
//! page counters.
//!
//! Device sizes are the raw `xsw_nblks`, matching swapinfo(8) and
//! gopsutil/Telegraf. (libkvm's `kvm_getswapinfo` subtracts `vm.dmmax` per
//! device; swapinfo doesn't use it.)
//!
//! Linux sources: `/proc/swaps` (sizes in KiB, as `swapon --show` reports
//! them) and the `pswpin`/`pswpout` page counters in `/proc/vmstat`. The
//! device label is the swap device without `/dev/` (`zram0`, `nvme0n1p3`) or
//! the full path of a swap file.

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

#[cfg_attr(
    not(any(target_os = "freebsd", target_os = "linux")),
    expect(dead_code, reason = "used by the FreeBSD and Linux implementations")
)]
pub fn describe() {
    describe_gauge!("swap_total_bytes", "Size of the swap device.");
    describe_gauge!("swap_used_bytes", "Swap space in use on the device.");
    describe_counter!("swap_in_bytes_total", "Bytes paged in from swap.");
    describe_counter!("swap_out_bytes_total", "Bytes paged out to swap.");
}

/// `struct xswdev` from `sys/vm/vm_param.h`, `XSWDEV_VERSION` 2 (FreeBSD 12+).
/// Sizes are in pages.
#[cfg(any(target_os = "freebsd", test))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct XswDev {
    version: u32,
    dev: u64,
    flags: i32,
    nblks: i32,
    used: i32,
}

#[cfg(any(target_os = "freebsd", test))]
const XSWDEV_VERSION: u32 = 2;

#[cfg(any(target_os = "freebsd", test))]
impl XswDev {
    /// (total, used) in bytes; rejects other struct versions instead of
    /// misreading them.
    fn sizes(&self, page_size: u64) -> Result<(u64, u64), String> {
        if self.version != XSWDEV_VERSION {
            return Err(format!(
                "struct xswdev version {} (expected {XSWDEV_VERSION})",
                self.version
            ));
        }
        let pages = |n: i32| u64::try_from(n).unwrap_or(0) * page_size;
        Ok((pages(self.nblks), pages(self.used)))
    }
}

/// One row of `/proc/swaps`, sizes in bytes.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq)]
struct SwapArea {
    device: String,
    total: u64,
    used: u64,
}

/// Parses `/proc/swaps`: a header line, then `Filename Type Size Used
/// Priority` with sizes in KiB.
#[cfg(any(target_os = "linux", test))]
fn parse_swaps(text: &str) -> Result<Vec<SwapArea>, String> {
    let mut lines = text.lines();
    if !lines.next().is_some_and(|h| h.starts_with("Filename")) {
        return Err("unexpected /proc/swaps header".to_owned());
    }
    lines
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let kib = |i: usize| fields.get(i).and_then(|v| v.parse::<u64>().ok());
            match (fields.first(), kib(2), kib(3)) {
                (Some(path), Some(size), Some(used)) => Ok(SwapArea {
                    device: device_label(&unescape(path)).to_owned(),
                    total: size * 1024,
                    used: used * 1024,
                }),
                _ => Err(format!("malformed /proc/swaps line {line:?}")),
            }
        })
        .collect()
}

/// Undoes the kernel's octal escaping of space, tab, newline and backslash
/// in `/proc/swaps` paths (`\040` for a space).
#[cfg(any(target_os = "linux", test))]
fn unescape(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let code = rest
            .get(at + 1..at + 4)
            .filter(|digits| digits.bytes().all(|b| matches!(b, b'0'..=b'7')))
            .and_then(|digits| u8::from_str_radix(digits, 8).ok());
        if let Some(byte) = code {
            out.push(char::from(byte));
            rest = &rest[at + 4..];
        } else {
            out.push('\\');
            rest = &rest[at + 1..];
        }
    }
    out.push_str(rest);
    out
}

/// Device name without `/dev/`; swap files keep their full path.
#[cfg(any(target_os = "linux", test))]
fn device_label(path: &str) -> &str {
    path.strip_prefix("/dev/").unwrap_or(path)
}

/// `pswpin` and `pswpout` (pages) from `/proc/vmstat`.
#[cfg(any(target_os = "linux", test))]
fn swapped_pages(vmstat: &str) -> Option<(u64, u64)> {
    let (mut pages_in, mut pages_out) = (None, None);
    for line in vmstat.lines() {
        let slot = match line.split_once(' ') {
            Some(("pswpin", value)) => (&mut pages_in, value),
            Some(("pswpout", value)) => (&mut pages_out, value),
            _ => continue,
        };
        *slot.0 = slot.1.parse::<u64>().ok();
    }
    Some((pages_in?, pages_out?))
}

native_only!(Swap, "swap");

#[cfg(target_os = "freebsd")]
pub use freebsd::Swap;
#[cfg(target_os = "linux")]
pub use linux::Swap;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::{
        ffi::CStr,
        io,
    };

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
        XswDev,
        describe,
    };
    use crate::{
        collector::Collector,
        sys::freebsd::{
            Mib,
            Plain,
            Uint,
        },
    };

    // SAFETY: repr(C) struct of integers; padding bytes are never read.
    #[expect(unsafe_code, reason = "read from vm.swap_info via sysctl")]
    unsafe impl Plain for XswDev {}

    pub struct Swap {
        page_size: u64,
        info: Mib,
        pages_in: Uint,
        pages_out: Uint,
    }

    impl Swap {
        pub fn new(_config: &Config) -> Result<Self> {
            Ok(Self {
                page_size: Uint::new("hw.pagesize")?.read()?,
                info: Mib::new("vm.swap_info")?,
                pages_in: Uint::new("vm.stats.vm.v_swappgsin")?,
                pages_out: Uint::new("vm.stats.vm.v_swappgsout")?,
            })
        }
    }

    /// Device name without `/dev/`, as swapinfo(8) prints it.
    #[expect(unsafe_code, reason = "devname_r(3) FFI")]
    fn device_name(dev: u64) -> String {
        if dev == u64::MAX {
            // NODEV: swap over NFS.
            return "nfs".to_owned();
        }
        let mut buf = [0 as libc::c_char; 64];
        let len = libc::c_int::try_from(buf.len()).unwrap_or(0);
        // SAFETY: `buf` is valid for `len` bytes; devname_r NUL-terminates.
        let ptr = unsafe { libc::devname_r(dev, libc::S_IFCHR, buf.as_mut_ptr(), len) };
        if ptr.is_null() {
            return format!("#{dev:x}");
        }
        // SAFETY: devname_r returned a NUL-terminated string (in `buf` or
        // static).
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }

    impl Collector for Swap {
        fn name(&self) -> &'static str {
            "swap"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            for index in 0.. {
                let xsw: XswDev = match self.info.with(&[index]).read() {
                    Ok(xsw) => xsw,
                    Err(err) if err.raw_os_error() == Some(libc::ENOENT) => break,
                    Err(err) => return Err(err).context("reading vm.swap_info"),
                };
                let (total, used) = xsw.sizes(self.page_size).map_err(|e| anyhow!(e))?;
                let device = device_name(xsw.dev);
                gauge!("swap_total_bytes", "device" => device.clone()).set(total as f64);
                gauge!("swap_used_bytes", "device" => device).set(used as f64);
            }
            let bytes = |pages: io::Result<u64>| pages.map(|p| p * self.page_size);
            counter!("swap_in_bytes_total").absolute(bytes(self.pages_in.read())?);
            counter!("swap_out_bytes_total").absolute(bytes(self.pages_out.read())?);
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
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
        parse_swaps,
        swapped_pages,
    };
    use crate::{
        collector::Collector,
        sys::{
            linux::read_into,
            page_size,
        },
    };

    pub struct Swap {
        page_size: u64,
        buf: String,
    }

    impl Swap {
        pub fn new(_config: &Config) -> Result<Self> {
            let mut swap = Self {
                page_size: page_size(),
                buf: String::new(),
            };
            // Fail at startup without swap support or with an unknown format.
            swap.areas()?;
            swap.pages()?;
            Ok(swap)
        }

        fn areas(&mut self) -> Result<Vec<super::SwapArea>> {
            read_into("/proc/swaps", &mut self.buf).context("reading /proc/swaps")?;
            parse_swaps(&self.buf).map_err(|e| anyhow!(e))
        }

        fn pages(&mut self) -> Result<(u64, u64)> {
            read_into("/proc/vmstat", &mut self.buf).context("reading /proc/vmstat")?;
            swapped_pages(&self.buf)
                .ok_or_else(|| anyhow!("pswpin or pswpout missing in /proc/vmstat"))
        }
    }

    impl Collector for Swap {
        fn name(&self) -> &'static str {
            "swap"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            for area in self.areas()? {
                gauge!("swap_total_bytes", "device" => area.device.clone()).set(area.total as f64);
                gauge!("swap_used_bytes", "device" => area.device).set(area.used as f64);
            }
            let (pages_in, pages_out) = self.pages()?;
            counter!("swap_in_bytes_total").absolute(pages_in * self.page_size);
            counter!("swap_out_bytes_total").absolute(pages_out * self.page_size);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_swaps() {
        let areas = parse_swaps(include_str!("testdata/linux/swap.swaps")).unwrap();
        assert_eq!(
            areas,
            [
                SwapArea {
                    device: "zram0".to_owned(),
                    total: 4_194_300 * 1024,
                    used: 4_096_376 * 1024,
                },
                SwapArea {
                    device: "/swapfile".to_owned(),
                    total: 104_857_596 * 1024,
                    used: 19_630_532 * 1024,
                },
            ]
        );
        let header = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
        assert_eq!(parse_swaps(header), Ok(vec![]));
        assert!(parse_swaps("").is_err());
        assert!(parse_swaps(&format!("{header}/dev/sda2 partition x 0 -2\n")).is_err());
    }

    #[test]
    fn unescapes_paths() {
        assert_eq!(unescape("/swap\\040file"), "/swap file");
        assert_eq!(unescape("/a\\134b\\011"), "/a\\b\t");
        assert_eq!(unescape("/swapfile\\040(deleted)"), "/swapfile (deleted)");
        assert_eq!(unescape("/odd\\x"), "/odd\\x");
        assert_eq!(unescape("/end\\"), "/end\\");
    }

    #[test]
    fn reads_swapped_pages() {
        let vmstat = "pgpgout 1\npswpin 4047930\npswpout 16105138\npgalloc_dma 0\n";
        assert_eq!(swapped_pages(vmstat), Some((4_047_930, 16_105_138)));
        assert_eq!(swapped_pages("pswpin 1\n"), None);
    }

    #[test]
    fn xswdev_matches_kernel_layout() {
        // u_int, (pad), dev_t, int, int, int, (pad) on LP64.
        assert_eq!(size_of::<XswDev>(), 32);
        assert_eq!(std::mem::offset_of!(XswDev, dev), 8);
        assert_eq!(std::mem::offset_of!(XswDev, nblks), 20);
    }

    #[test]
    fn converts_pages_and_checks_version() {
        let xsw = XswDev {
            version: 2,
            nblks: 1024,
            used: 10,
            ..Default::default()
        };
        assert_eq!(xsw.sizes(4096), Ok((4 << 20, 40960)));
        let old = XswDev { version: 1, ..xsw };
        assert!(old.sizes(4096).is_err());
    }
}
