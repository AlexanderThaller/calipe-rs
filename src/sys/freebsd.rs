//! FreeBSD sysctl access.
//!
//! Names are resolved to MIBs once ([`Mib::new`]); collection then reads by
//! MIB, which skips the kernel's name lookup on every call.

// Most helpers are used by the sysctl collectors added in later milestones.
#![allow(dead_code)]

use std::ffi::CString;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::ptr;

use libc::c_int;

/// Maximum MIB depth (`CTL_MAXNAME` in `sys/sysctl.h`).
const CTL_MAXNAME: usize = 24;

/// Types that are valid for every bit pattern and contain no pointers that we
/// dereference, so they can be filled directly from sysctl output.
///
/// # Safety
///
/// Implementors must be `repr(C)` (or primitive) and valid for any bytes.
pub unsafe trait Plain: Copy {}

// SAFETY: primitive integers are valid for every bit pattern.
unsafe impl Plain for i32 {}
unsafe impl Plain for u32 {}
unsafe impl Plain for i64 {}
unsafe impl Plain for u64 {}
// SAFETY: arrays of plain types are plain.
unsafe impl<T: Plain, const N: usize> Plain for [T; N] {}
// SAFETY: kinfo_proc is a repr(C) struct of integers, arrays and raw pointers
// (never dereferenced by us).
unsafe impl Plain for libc::kinfo_proc {}
// SAFETY: repr(C) struct of integers.
unsafe impl Plain for libc::timeval {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mib(Vec<c_int>);

impl Mib {
    /// Resolves a sysctl name like `kern.cp_times` to its MIB.
    pub fn new(name: &str) -> io::Result<Self> {
        let cname = CString::new(name).map_err(io::Error::other)?;
        let mut mib = [0 as c_int; CTL_MAXNAME];
        let mut len = mib.len();
        // SAFETY: `mib` has room for `len` entries; the name is NUL-terminated.
        if unsafe { libc::sysctlnametomib(cname.as_ptr(), mib.as_mut_ptr(), &raw mut len) } != 0 {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(err.kind(), format!("sysctl {name}: {err}")));
        }
        Ok(Self(mib[..len].to_vec()))
    }

    /// Builds a MIB from raw components, e.g. `[CTL_KERN, KERN_PROC, ...]`.
    pub fn from_raw(parts: &[c_int]) -> Self {
        Self(parts.to_vec())
    }

    /// Returns this MIB with `extra` components appended (e.g. an index).
    pub fn with(&self, extra: &[c_int]) -> Self {
        let mut parts = self.0.clone();
        parts.extend_from_slice(extra);
        Self(parts)
    }

    /// Calls sysctl(3). `old` may be null to query the size.
    ///
    /// # Safety
    ///
    /// `old` must be null or valid for writes of `*len` bytes.
    unsafe fn raw(&self, old: *mut libc::c_void, len: &mut usize) -> io::Result<()> {
        // MIBs are at most CTL_MAXNAME (24) long.
        let depth = libc::c_uint::try_from(self.0.len()).map_err(io::Error::other)?;
        // SAFETY: forwarded from the caller; the MIB slice is valid.
        let rc = unsafe { libc::sysctl(self.0.as_ptr(), depth, old, len, ptr::null(), 0) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Reads a variable-length value into `buf`, growing it as needed. `buf`
    /// is reused across calls to avoid reallocating on every collection.
    pub fn read_into(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        loop {
            let mut len = 0;
            // SAFETY: a null `old` pointer only queries the size.
            unsafe { self.raw(ptr::null_mut(), &mut len)? };
            // The size can grow between the two calls (e.g. new processes).
            let want = len + len / 8 + 64;
            buf.clear();
            buf.reserve(want);
            let mut len = buf.capacity();
            // SAFETY: `buf` has capacity for `len` bytes.
            match unsafe { self.raw(buf.as_mut_ptr().cast(), &mut len) } {
                Ok(()) => {
                    // SAFETY: the kernel initialized the first `len` bytes.
                    unsafe { buf.set_len(len) };
                    return Ok(());
                }
                Err(err) if err.raw_os_error() == Some(libc::ENOMEM) => {}
                Err(err) => return Err(err),
            }
        }
    }

    /// Reads a fixed-size value. Fails if the kernel's size differs from
    /// `size_of::<T>()`, which catches ABI mismatches instead of misreading.
    pub fn read<T: Plain>(&self) -> io::Result<T> {
        let mut value = MaybeUninit::<T>::uninit();
        let mut len = size_of::<T>();
        // SAFETY: `value` is valid for `len` bytes.
        unsafe { self.raw(value.as_mut_ptr().cast(), &mut len)? };
        if len != size_of::<T>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sysctl returned {len} bytes, expected {}", size_of::<T>()),
            ));
        }
        // SAFETY: fully initialized, and `T: Plain` is valid for any bytes.
        Ok(unsafe { value.assume_init() })
    }
}

/// Reinterprets a byte buffer as a slice of `T` (e.g. `kern.cp_times`).
/// Fails if the length isn't a multiple of `size_of::<T>()`.
pub fn cast_slice<T: Plain>(bytes: &[u8]) -> io::Result<Vec<T>> {
    let size = size_of::<T>();
    if size == 0 || !bytes.len().is_multiple_of(size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "sysctl returned {} bytes, not a multiple of {size}",
                bytes.len()
            ),
        ));
    }
    Ok(bytes
        .chunks_exact(size)
        // SAFETY: each chunk has exactly `size_of::<T>()` bytes; `T: Plain`.
        .map(|chunk| unsafe { ptr::read_unaligned(chunk.as_ptr().cast::<T>()) })
        .collect())
}

/// Reads this process's `kinfo_proc` and returns its RSS.
pub fn self_rss_bytes() -> io::Result<u64> {
    let mib = Mib::from_raw(&[
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        c_int::try_from(std::process::id()).map_err(io::Error::other)?,
    ]);
    let proc: libc::kinfo_proc = mib.read()?;
    Ok(u64::try_from(proc.ki_rssize).unwrap_or(0) * super::page_size())
}
