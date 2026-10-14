//! FreeBSD sysctl access.
//!
//! Names are resolved to MIBs once ([`Mib::new`]); collection then reads by
//! MIB, which skips the kernel's name lookup on every call.

#![expect(
    unsafe_code,
    reason = "safe wrappers around sysctl(3); each unsafe block states its invariant"
)]

use std::{
    ffi::CString,
    io,
    mem::{
        MaybeUninit,
        size_of,
    },
    ptr,
};

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
// SAFETY: as above.
unsafe impl Plain for u32 {}
// SAFETY: as above.
unsafe impl Plain for i64 {}
// SAFETY: as above.
unsafe impl Plain for u64 {}
// SAFETY: arrays of plain types are plain.
unsafe impl<T: Plain, const N: usize> Plain for [T; N] {}
// SAFETY: kinfo_proc is a repr(C) struct of integers, arrays and raw pointers
// (never dereferenced by us).
unsafe impl Plain for libc::kinfo_proc {}
// SAFETY: repr(C) structs of integers.
unsafe impl Plain for libc::timeval {}
// SAFETY: as above.
unsafe impl Plain for libc::clockinfo {}

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

    /// Returns the OID's format string (e.g. `"IK"`, `"LU"`, `"S,clockinfo"`),
    /// via the undocumented `{CTL_SYSCTL, CTL_SYSCTL_OIDFMT}` node that
    /// sysctl(8) uses too.
    pub fn format(&self) -> io::Result<String> {
        Ok(self.kind_and_format()?.1)
    }

    /// Returns the OID's `CTLTYPE_*` kind and format string.
    pub fn kind_and_format(&self) -> io::Result<(u32, String)> {
        let mut buf = Vec::new();
        Self::from_raw(&[libc::CTL_SYSCTL, libc::CTL_SYSCTL_OIDFMT])
            .with(&self.0)
            .read_into(&mut buf)?;
        // Layout: u_int kind, then the NUL-terminated format string.
        let kind = buf
            .get(..4)
            .map(|b| u32::from_ne_bytes(b.try_into().unwrap_or_default()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short OIDFMT reply"))?;
        let fmt = buf.get(size_of::<u32>()..).unwrap_or_default();
        let fmt = fmt.split(|&b| b == 0).next().unwrap_or_default();
        Ok((kind, String::from_utf8_lossy(fmt).into_owned()))
    }

    /// Reads a string sysctl, without the trailing NUL (and newline, which
    /// some kstats append).
    pub fn read_string(&self) -> io::Result<String> {
        let mut buf = Vec::new();
        self.read_into(&mut buf)?;
        let text = buf.split(|&b| b == 0).next().unwrap_or_default();
        Ok(String::from_utf8_lossy(text).trim_end().to_owned())
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
                    // sysctl never reports more than it was given room for.
                    assert!(len <= buf.capacity(), "sysctl overran its buffer");
                    // SAFETY: the kernel initialized the first `len` bytes,
                    // which fit in the capacity.
                    unsafe { buf.set_len(len) };
                    return Ok(());
                }
                Err(err) if err.raw_os_error() == Some(libc::ENOMEM) => {}
                Err(err) => return Err(err),
            }
        }
    }

    /// Fills `buf` with the first bytes of a (possibly larger) value and
    /// returns how many were written. sysctl(3) copies as much as fits and
    /// reports `ENOMEM` for the rest, which is not an error here.
    pub fn read_prefix(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut len = buf.len();
        // SAFETY: `buf` is valid for `len` bytes.
        match unsafe { self.raw(buf.as_mut_ptr().cast(), &mut len) } {
            Ok(()) => Ok(len),
            Err(err) if err.raw_os_error() == Some(libc::ENOMEM) => Ok(buf.len()),
            Err(err) => Err(err),
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

impl Mib {
    /// Reads a signed integer that may be 32- or 64-bit, sign-extending
    /// 32-bit values.
    pub fn read_int(&self) -> io::Result<i64> {
        let mut buf = [0u8; 8];
        let mut len = buf.len();
        // SAFETY: `buf` is valid for `len` bytes.
        unsafe { self.raw(buf.as_mut_ptr().cast(), &mut len)? };
        match len {
            4 => Ok(i64::from(i32::from_ne_bytes(
                buf[..4].try_into().unwrap_or_default(),
            ))),
            8 => Ok(i64::from_ne_bytes(buf)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sysctl returned {len} bytes, expected 4 or 8"),
            )),
        }
    }

    /// Reads an unsigned integer that may be 32- or 64-bit depending on the
    /// sysctl (e.g. `u_int` page counts vs. `uint64_t` counters).
    pub fn read_uint(&self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        let mut len = buf.len();
        // SAFETY: `buf` is valid for `len` bytes.
        unsafe { self.raw(buf.as_mut_ptr().cast(), &mut len)? };
        match len {
            4 => Ok(u64::from(u32::from_ne_bytes(
                buf[..4].try_into().unwrap_or_default(),
            ))),
            8 => Ok(u64::from_ne_bytes(buf)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sysctl returned {len} bytes, expected 4 or 8"),
            )),
        }
    }
}

/// A leaf found by [`walk`].
#[derive(Debug, Clone)]
pub struct Leaf {
    /// Full dotted name, e.g. `kstat.zfs.misc.arcstats.hits`.
    pub name: String,
    pub mib: Mib,
    /// `CTLTYPE_*` value (kind & `CTLTYPE`).
    pub kind: c_int,
}

/// Lists all leaf sysctls below `prefix` (in kernel order), using the same
/// `{CTL_SYSCTL, CTL_SYSCTL_NEXT}` iteration as `sysctl -a`.
pub fn walk(prefix: &str) -> io::Result<Vec<Leaf>> {
    let root = Mib::new(prefix)?;
    let mut leaves = Vec::new();
    let mut current = root.clone();
    let mut buf = Vec::new();
    loop {
        match Mib::from_raw(&[libc::CTL_SYSCTL, libc::CTL_SYSCTL_NEXT])
            .with(&current.0)
            .read_into(&mut buf)
        {
            Ok(()) => {}
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => break,
            Err(err) => return Err(err),
        }
        let next = Mib(cast_slice::<i32>(&buf)?);
        if !next.0.starts_with(&root.0) {
            break;
        }
        let mut name = Vec::new();
        Mib::from_raw(&[libc::CTL_SYSCTL, libc::CTL_SYSCTL_NAME])
            .with(&next.0)
            .read_into(&mut name)?;
        let name = String::from_utf8_lossy(name.split(|&b| b == 0).next().unwrap_or_default())
            .into_owned();
        let (kind, _) = next.kind_and_format()?;
        // The high bits are CTLFLAG_* flags (CTLFLAG_RD is 0x80000000), so
        // mask before converting.
        let kind = c_int::try_from(kind & 0xf).expect("4 bits fit");
        leaves.push(Leaf {
            name,
            mib: next.clone(),
            kind,
        });
        current = next;
    }
    Ok(leaves)
}

/// A sysctl resolved at startup by name and read as an unsigned integer, with
/// the name in error messages.
pub struct Uint {
    name: &'static str,
    mib: Mib,
}

impl Uint {
    pub fn new(name: &'static str) -> io::Result<Self> {
        Ok(Self {
            name,
            mib: Mib::new(name)?,
        })
    }

    pub fn read(&self) -> io::Result<u64> {
        self.mib
            .read_uint()
            .map_err(|err| io::Error::new(err.kind(), format!("reading {}: {err}", self.name)))
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

/// Views a fixed-size C `char` array (e.g. `statfs::f_mntonname`) as bytes.
pub fn c_chars_as_bytes(chars: &[libc::c_char]) -> &[u8] {
    // SAFETY: c_char and u8 have the same size and alignment, and every bit
    // pattern is valid for both.
    unsafe { &*(ptr::from_ref(chars) as *const [u8]) }
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
