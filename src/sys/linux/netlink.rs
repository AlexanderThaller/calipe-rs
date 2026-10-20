//! Minimal netlink client for dump requests (rtnetlink, `sock_diag`).
//!
//! A dump is one request with `NLM_F_DUMP`, answered by a series of
//! datagrams with any number of messages each, ended by `NLMSG_DONE`. The
//! kernel produces the next datagram when the previous one is read, so a dump
//! is always read to its end: abandoning one would make the next request on
//! the socket fail with `EBUSY`.

use std::{
    io,
    os::fd::{
        AsRawFd,
        FromRawFd,
        OwnedFd,
    },
};

/// `sizeof (struct nlmsghdr)`.
const NLMSG_HDRLEN: usize = 16;
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
/// Dump datagrams are at most 32 KiB (`netlink_dump`); larger leaves room.
const RECV_BUF: usize = 64 << 10;

/// One message: `nlmsg_type`, `nlmsg_seq` and the payload after the header.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Message<'a> {
    pub kind: u16,
    pub seq: u32,
    pub payload: &'a [u8],
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Splits a datagram into messages (each padded to 4 bytes).
pub fn messages(mut buf: &[u8]) -> Result<Vec<Message<'_>>, String> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let len = u32_at(buf, 0).ok_or("truncated netlink header")? as usize;
        if len < NLMSG_HDRLEN || len > buf.len() {
            return Err(format!("bad netlink message length {len}"));
        }
        out.push(Message {
            kind: u16_at(buf, 4).ok_or("truncated netlink header")?,
            seq: u32_at(buf, 8).ok_or("truncated netlink header")?,
            payload: &buf[NLMSG_HDRLEN..len],
        });
        buf = buf.get(len.next_multiple_of(4)..).unwrap_or_default();
    }
    Ok(out)
}

/// Splits route attributes (`struct nlattr`/`rtattr`, padded to 4 bytes)
/// into (type, payload) pairs. The nested and byte-order flags are masked
/// off the type. Stops at the first malformed attribute.
pub fn attributes(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let len = usize::from(u16_at(buf, 0)?);
        let kind = u16_at(buf, 2)? & 0x3fff;
        let payload = buf.get(4..len)?;
        buf = buf.get(len.next_multiple_of(4)..).unwrap_or_default();
        Some((kind, payload))
    })
}

#[derive(Debug)]
pub struct Socket {
    fd: OwnedFd,
    seq: u32,
    buf: Vec<u8>,
}

impl Socket {
    #[expect(unsafe_code, reason = "socket(2) FFI")]
    pub fn new(protocol: libc::c_int) -> io::Result<Self> {
        // SAFETY: socket(2) has no memory preconditions.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: `fd` is a fresh descriptor nothing else owns.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            seq: 0,
            buf: vec![0; RECV_BUF],
        })
    }

    /// Sends a dump request of type `kind` with `request` as its payload and
    /// calls `on_message(type, payload)` for every reply until the dump ends.
    /// Messages left over from an earlier dump are skipped by sequence number.
    #[expect(unsafe_code, reason = "send(2)/recv(2) FFI")]
    pub fn dump(
        &mut self,
        kind: u16,
        request: &[u8],
        mut on_message: impl FnMut(u16, &[u8]),
    ) -> io::Result<()> {
        self.seq = self.seq.wrapping_add(1);
        let len = NLMSG_HDRLEN + request.len();
        let mut req = Vec::with_capacity(len);
        req.extend_from_slice(&u32::try_from(len).map_err(io::Error::other)?.to_ne_bytes());
        req.extend_from_slice(&kind.to_ne_bytes());
        req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req.extend_from_slice(&self.seq.to_ne_bytes());
        req.extend_from_slice(&0u32.to_ne_bytes());
        req.extend_from_slice(request);
        loop {
            // SAFETY: `req` is valid for reads of `req.len()` bytes.
            let n = unsafe { libc::send(self.fd.as_raw_fd(), req.as_ptr().cast(), req.len(), 0) };
            if n >= 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }

        loop {
            // SAFETY: `buf` is valid for writes of `buf.len()` bytes. With
            // MSG_TRUNC the return value is the full datagram length.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                    libc::MSG_TRUNC,
                )
            };
            let Ok(n) = usize::try_from(n) else {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            };
            if n > self.buf.len() {
                return Err(io::Error::other(format!(
                    "netlink datagram of {n} bytes exceeds the buffer"
                )));
            }
            for msg in messages(&self.buf[..n]).map_err(io::Error::other)? {
                if msg.seq != self.seq {
                    continue;
                }
                match msg.kind {
                    NLMSG_DONE => return Ok(()),
                    NLMSG_ERROR => {
                        let errno = u32_at(msg.payload, 0).map_or(0, u32::cast_signed);
                        if errno != 0 {
                            return Err(io::Error::from_raw_os_error(-errno));
                        }
                    }
                    NLMSG_NOOP => {}
                    kind => on_message(kind, msg.payload),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(NLMSG_HDRLEN + payload.len()).unwrap();
        let mut m = [
            &len.to_ne_bytes()[..],
            &kind.to_ne_bytes(),
            &0u16.to_ne_bytes(),
            &seq.to_ne_bytes(),
            &0u32.to_ne_bytes(),
            payload,
        ]
        .concat();
        m.resize(m.len().next_multiple_of(4), 0);
        m
    }

    #[test]
    fn splits_padded_messages() {
        let buf = [message(16, 7, b"abcde"), message(NLMSG_DONE, 7, &[0; 4])].concat();
        let msgs = messages(&buf).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].kind, 16);
        assert_eq!(msgs[0].seq, 7);
        assert_eq!(msgs[0].payload, b"abcde");
        assert_eq!(msgs[1].kind, NLMSG_DONE);
        assert!(messages(&buf[..10]).is_err());
        assert!(
            messages(&[8, 0, 0, 0, 0, 0, 0, 0]).is_err(),
            "shorter than a header"
        );
    }

    #[test]
    fn splits_attributes() {
        // IFLA_IFNAME "lo\0" (padded), then a nested attribute.
        let buf = [7, 0, 3, 0, b'l', b'o', 0, 0, 4, 0, 0x12, 0x80];
        let attrs: Vec<_> = attributes(&buf).collect();
        assert_eq!(attrs, [(3, &b"lo\0"[..]), (0x12, &[][..])]);
        assert_eq!(attributes(&[9, 0, 1, 0]).count(), 0, "truncated");
    }

    #[test]
    fn dumps_links_from_the_kernel() {
        let mut socket = Socket::new(libc::NETLINK_ROUTE).unwrap();
        for _ in 0..2 {
            let mut links = 0;
            // RTM_GETLINK with an all-zero ifinfomsg.
            socket
                .dump(18, &[0; 16], |kind, _| {
                    assert_eq!(kind, 16, "RTM_NEWLINK");
                    links += 1;
                })
                .unwrap();
            assert!(links >= 1, "at least lo");
        }
    }
}
