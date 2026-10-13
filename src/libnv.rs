//! Decoder for FreeBSD libnv packed nvlists (`nvlist_pack(3)`), as returned by
//! pf's `*NV` ioctls. Not to be confused with ZFS's nvpair format
//! ([`crate::nvlist`]).
//!
//! Layout (`sys/contrib/libnv`, native byte order unless `NV_FLAG_BIG_ENDIAN`):
//!
//! ```text
//! header  u8 magic 0x6c, u8 version 0, u8 flags, u64 descriptors, u64 size  (packed)
//! pair    u8 type, u16 namesize, u64 datasize, u64 nitems  (packed), name\0, data
//! nvlist  value: the nested list's header and pairs follow inline and end
//!         with an NVLIST_UP (255) pair
//! ```
//!
//! nvlist arrays are not needed by any caller and are rejected.

// Used by the FreeBSD pf collector (and tests).
#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

use std::fmt;

const MAGIC: u8 = 0x6c;
const VERSION: u8 = 0;
const FLAG_BIG_ENDIAN: u8 = 0x80;
const HEADER_LEN: usize = 19;
const MAX_DEPTH: usize = 32;

const TYPE_NULL: u8 = 1;
const TYPE_BOOL: u8 = 2;
const TYPE_NUMBER: u8 = 3;
const TYPE_STRING: u8 = 4;
const TYPE_NVLIST: u8 = 5;
const TYPE_BINARY: u8 = 7;
const TYPE_BOOL_ARRAY: u8 = 8;
const TYPE_NUMBER_ARRAY: u8 = 9;
const TYPE_STRING_ARRAY: u8 = 10;
const TYPE_NVLIST_UP: u8 = 255;

#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    Null,
    Bool(bool),
    Number(u64),
    String(&'a str),
    Binary(&'a [u8]),
    BoolArray(Vec<bool>),
    NumberArray(Vec<u64>),
    StringArray(Vec<&'a str>),
    NvList(NvList<'a>),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NvList<'a> {
    pairs: Vec<(&'a str, Value<'a>)>,
}

impl<'a> NvList<'a> {
    pub fn get(&self, name: &str) -> Option<&Value<'a>> {
        self.pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
    }

    pub fn get_number(&self, name: &str) -> Option<u64> {
        match self.get(name)? {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn get_bool(&self, name: &str) -> Option<bool> {
        match self.get(name)? {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn get_str(&self, name: &str) -> Option<&'a str> {
        match self.get(name)? {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn get_list(&self, name: &str) -> Option<&NvList<'a>> {
        match self.get(name)? {
            Value::NvList(l) => Some(l),
            _ => None,
        }
    }

    pub fn get_numbers(&self, name: &str) -> Option<&[u64]> {
        match self.get(name)? {
            Value::NumberArray(v) => Some(v),
            _ => None,
        }
    }

    pub fn get_strings(&self, name: &str) -> Option<&[&'a str]> {
        match self.get(name)? {
            Value::StringArray(v) => Some(v),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed libnv nvlist: {}", self.0)
    }
}

impl std::error::Error for Error {}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

pub fn unpack(buf: &[u8]) -> Result<NvList<'_>, Error> {
    let mut reader = Reader {
        buf,
        pos: 0,
        big_endian: false,
    };
    let size = reader.list_header()?;
    let end = HEADER_LEN.checked_add(size).filter(|&e| e <= buf.len());
    if end.is_none() {
        return err("size exceeds buffer");
    }
    reader.pairs(0, true)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    big_endian: bool,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).filter(|&e| e <= self.buf.len());
        let Some(end) = end else {
            return err(format!("truncated at offset {}", self.pos));
        };
        let bytes = &self.buf[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b: [u8; 2] = self.take(2)?.try_into().expect("2");
        Ok(if self.big_endian {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let b: [u8; 8] = self.take(8)?.try_into().expect("8");
        Ok(if self.big_endian {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    }

    fn usize(&mut self) -> Result<usize, Error> {
        usize::try_from(self.u64()?).map_err(|_| Error("size overflows usize".into()))
    }

    /// Reads an nvlist header and returns its payload size.
    fn list_header(&mut self) -> Result<usize, Error> {
        let head = self.take(3)?;
        if head[0] != MAGIC || head[1] != VERSION {
            return err(format!(
                "bad header magic {:#x} version {}",
                head[0], head[1]
            ));
        }
        self.big_endian = head[2] & FLAG_BIG_ENDIAN != 0;
        let _descriptors = self.u64()?;
        self.usize()
    }

    /// Reads pairs until the end of the buffer (top level) or an `NVLIST_UP`
    /// marker (nested lists).
    fn pairs(&mut self, depth: usize, top: bool) -> Result<NvList<'a>, Error> {
        if depth > MAX_DEPTH {
            return err("nested too deeply");
        }
        let mut list = NvList::default();
        loop {
            if top && self.pos == self.buf.len() {
                return Ok(list);
            }
            let typ = self.take(1)?[0];
            let namesize = usize::from(self.u16()?);
            let datasize = self.usize()?;
            let nitems = self.usize()?;
            let name = cstr(self.take(namesize)?)?;
            if typ == TYPE_NVLIST_UP {
                if top {
                    return err("NVLIST_UP at top level");
                }
                return Ok(list);
            }
            let value = match typ {
                TYPE_NULL => Value::Null,
                TYPE_BOOL => Value::Bool(self.take(1)?[0] != 0),
                TYPE_NUMBER => Value::Number(self.u64()?),
                TYPE_STRING => Value::String(cstr(self.take(datasize)?)?),
                TYPE_BINARY => Value::Binary(self.take(datasize)?),
                TYPE_BOOL_ARRAY => {
                    Value::BoolArray(self.take(nitems)?.iter().map(|&b| b != 0).collect())
                }
                TYPE_NUMBER_ARRAY => {
                    if datasize != nitems.saturating_mul(8) {
                        return err("number array size mismatch");
                    }
                    Value::NumberArray((0..nitems).map(|_| self.u64()).collect::<Result<_, _>>()?)
                }
                TYPE_STRING_ARRAY => {
                    let mut data = self.take(datasize)?;
                    let mut strings = Vec::with_capacity(nitems);
                    for _ in 0..nitems {
                        let s = cstr(data)?;
                        data = &data[s.len() + 1..];
                        strings.push(s);
                    }
                    Value::StringArray(strings)
                }
                TYPE_NVLIST => {
                    let _size = self.list_header()?;
                    Value::NvList(self.pairs(depth + 1, false)?)
                }
                other => return err(format!("unsupported value type {other} for {name:?}")),
            };
            list.pairs.push((name, value));
        }
    }
}

fn cstr(bytes: &[u8]) -> Result<&str, Error> {
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error("unterminated string".into()))?;
    std::str::from_utf8(&bytes[..end]).map_err(|_| Error("string is not UTF-8".into()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Encoder mirroring `nvlist_xpack` (little endian), for tests.
    pub enum Enc<'a> {
        Bool(bool),
        Num(u64),
        Str(&'a str),
        Bin(&'a [u8]),
        Nums(&'a [u64]),
        Strs(&'a [&'a str]),
        List(Vec<(&'a str, Enc<'a>)>),
    }

    fn header(out: &mut Vec<u8>, size: u64) {
        out.extend([MAGIC, VERSION, 0]);
        out.extend(0u64.to_le_bytes());
        out.extend(size.to_le_bytes());
    }

    fn pair(out: &mut Vec<u8>, typ: u8, name: &str, datasize: usize, nitems: usize) {
        out.push(typ);
        out.extend(u16::try_from(name.len() + 1).unwrap().to_le_bytes());
        out.extend((datasize as u64).to_le_bytes());
        out.extend((nitems as u64).to_le_bytes());
        out.extend(name.as_bytes());
        out.push(0);
    }

    fn pairs(out: &mut Vec<u8>, items: &[(&str, Enc<'_>)]) {
        for (name, value) in items {
            match value {
                Enc::Bool(b) => {
                    pair(out, TYPE_BOOL, name, 1, 0);
                    out.push(u8::from(*b));
                }
                Enc::Num(n) => {
                    pair(out, TYPE_NUMBER, name, 8, 0);
                    out.extend(n.to_le_bytes());
                }
                Enc::Str(s) => {
                    pair(out, TYPE_STRING, name, s.len() + 1, 0);
                    out.extend(s.as_bytes());
                    out.push(0);
                }
                Enc::Bin(b) => {
                    pair(out, TYPE_BINARY, name, b.len(), 0);
                    out.extend(*b);
                }
                Enc::Nums(ns) => {
                    pair(out, TYPE_NUMBER_ARRAY, name, ns.len() * 8, ns.len());
                    ns.iter().for_each(|n| out.extend(n.to_le_bytes()));
                }
                Enc::Strs(ss) => {
                    let size: usize = ss.iter().map(|s| s.len() + 1).sum();
                    pair(out, TYPE_STRING_ARRAY, name, size, ss.len());
                    for s in *ss {
                        out.extend(s.as_bytes());
                        out.push(0);
                    }
                }
                Enc::List(inner) => {
                    pair(out, TYPE_NVLIST, name, 0, 0);
                    header(out, 0);
                    pairs(out, inner);
                    pair(out, TYPE_NVLIST_UP, "", 0, 0);
                }
            }
        }
    }

    pub fn pack(items: &[(&str, Enc<'_>)]) -> Vec<u8> {
        let mut body = Vec::new();
        pairs(&mut body, items);
        let mut out = Vec::new();
        header(&mut out, body.len() as u64);
        out.extend(body);
        out
    }

    #[test]
    fn decodes_pf_shaped_list() {
        let buf = pack(&[
            ("running", Enc::Bool(true)),
            ("states", Enc::Num(42)),
            (
                "fcounters",
                Enc::List(vec![
                    ("counters", Enc::Nums(&[10, 20, 30])),
                    ("names", Enc::Strs(&["searches", "inserts", "removals"])),
                    ("ids", Enc::Nums(&[0, 1, 2])),
                ]),
            ),
            ("ifname", Enc::Str("")),
            ("chksum", Enc::Bin(&[1, 2, 3])),
            ("after", Enc::Num(7)),
        ]);
        let list = unpack(&buf).unwrap();
        assert_eq!(list.get_bool("running"), Some(true));
        assert_eq!(list.get_number("states"), Some(42));
        let f = list.get_list("fcounters").unwrap();
        assert_eq!(f.get_numbers("counters"), Some(&[10, 20, 30][..]));
        assert_eq!(
            f.get_strings("names"),
            Some(&["searches", "inserts", "removals"][..])
        );
        assert_eq!(list.get_str("ifname"), Some(""));
        assert_eq!(
            list.get_number("after"),
            Some(7),
            "pairs after a nested list"
        );
    }

    #[test]
    fn rejects_malformed_input() {
        let good = pack(&[("a", Enc::Num(1))]);
        let mut bad_magic = good.clone();
        bad_magic[0] = 0x6d;
        assert!(unpack(&bad_magic).is_err());
        assert!(unpack(&good[..good.len() - 1]).is_err());
        assert!(unpack(&[]).is_err());
    }
}
