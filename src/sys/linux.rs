//! Linux system access: procfs and sysfs files, netlink.

pub mod netlink;

use std::{
    io::{
        self,
        Read,
    },
    path::Path,
};

pub fn self_rss_bytes() -> io::Result<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm")?;
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc/self/statm"))?;
    Ok(pages * super::page_size())
}

/// Reads a procfs/sysfs file into `buf`, reusing its allocation. procfs
/// files report a size of 0, so this reads until EOF.
pub fn read_into(path: impl AsRef<Path>, buf: &mut String) -> io::Result<()> {
    buf.clear();
    std::fs::File::open(path)?.read_to_string(buf)?;
    Ok(())
}
