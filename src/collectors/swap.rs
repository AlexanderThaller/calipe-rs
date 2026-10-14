//! Swap devices and paging traffic.
//!
//! FreeBSD sources: `vm.swap_info.N` (one `struct xswdev` per device, read
//! until `ENOENT`, like swapinfo(8)) and the `vm.stats.vm.v_swappgs{in,out}`
//! page counters.
//!
//! Device sizes are the raw `xsw_nblks`, matching swapinfo(8) and
//! gopsutil/Telegraf. (libkvm's `kvm_getswapinfo` subtracts `vm.dmmax` per
//! device; swapinfo doesn't use it.)

// The helpers are only used by the FreeBSD implementation (and tests).
#![cfg_attr(
    not(target_os = "freebsd"),
    expect(dead_code, reason = "used by the FreeBSD implementation")
)]

use std::time::Duration;

use metrics::{describe_counter, describe_gauge};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
}

pub fn describe() {
    describe_gauge!("swap_total_bytes", "Size of the swap device.");
    describe_gauge!("swap_used_bytes", "Swap space in use on the device.");
    describe_counter!("swap_in_bytes_total", "Bytes paged in from swap.");
    describe_counter!("swap_out_bytes_total", "Bytes paged out to swap.");
}

/// `struct xswdev` from `sys/vm/vm_param.h`, `XSWDEV_VERSION` 2 (FreeBSD 12+).
/// Sizes are in pages.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct XswDev {
    version: u32,
    dev: u64,
    flags: i32,
    nblks: i32,
    used: i32,
}

const XSWDEV_VERSION: u32 = 2;

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

freebsd_only!(Swap, "swap");

#[cfg(target_os = "freebsd")]
pub use freebsd::Swap;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::ffi::CStr;
    use std::io;

    use anyhow::{Context, Result, anyhow};
    use metrics::{counter, gauge};

    use super::{Config, XswDev, describe};
    use crate::collector::Collector;
    use crate::sys::freebsd::{Mib, Plain, Uint};

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
        // SAFETY: devname_r returned a NUL-terminated string (in `buf` or static).
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

#[cfg(test)]
mod tests {
    use super::*;

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
