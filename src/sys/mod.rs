//! Platform-specific system access. FreeBSD is the deployment target; Linux
//! support exists only where cheap, so the agent can be run during development.

#[cfg(target_os = "freebsd")]
pub mod freebsd;
#[cfg(target_os = "linux")]
mod linux;

use std::{
    ffi::CStr,
    io,
};

/// Resident set size of this process in bytes.
pub fn self_rss_bytes() -> io::Result<u64> {
    #[cfg(target_os = "freebsd")]
    return freebsd::self_rss_bytes();
    #[cfg(target_os = "linux")]
    return linux::self_rss_bytes();
    #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// User and system CPU time consumed by this process, in seconds.
#[expect(unsafe_code, reason = "getrusage(2) FFI")]
pub fn self_cpu_seconds() -> io::Result<(f64, f64)> {
    // SAFETY: `rusage` is plain data, so all-zero bytes are a valid value.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is valid for writes; getrusage fills it on success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((timeval_secs(usage.ru_utime), timeval_secs(usage.ru_stime)))
}

pub fn timeval_secs(tv: libc::timeval) -> f64 {
    tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6
}

#[expect(unsafe_code, reason = "gethostname(3) FFI")]
pub fn hostname() -> io::Result<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for `buf.len()` bytes; we keep the last byte
    // as NUL.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let name = CStr::from_bytes_until_nul(&buf).map_err(io::Error::other)?;
    Ok(name.to_string_lossy().into_owned())
}

#[expect(unsafe_code, reason = "sysconf(3) FFI")]
pub fn page_size() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(size).unwrap_or(4096)
}
