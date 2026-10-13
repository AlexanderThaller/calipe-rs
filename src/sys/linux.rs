use std::io;

pub fn self_rss_bytes() -> io::Result<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm")?;
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc/self/statm"))?;
    Ok(pages * super::page_size())
}
