//! Decoder for packed nvlists in `NV_ENCODE_NATIVE` encoding, as returned by
//! ZFS ioctls (`fnvlist_pack` in OpenZFS `module/nvpair/nvpair.c`).
//!
//! Stream layout:
//!
//! ```text
//! header   u8 encoding (0 = native), u8 endian (1 = little), u8, u8
//! nvlist   i32 nvl_version (0), u32 nvl_nvflag     (top level only)
//! pairs    each an `nvpair_t` copied verbatim, nvp_size bytes:
//!            i32 size, i16 name_sz (incl. NUL), i16 reserved,
//!            i32 nelem, i32 type, name, value at align8(16 + name_sz)
//!          an NVLIST value is followed by the embedded list's pairs,
//!          an NVLIST_ARRAY value by each element's pairs, in order
//! end      i32 0                                    (closes every list)
//! ```
//!
//! Only decoding is supported. Values are borrowed from the input buffer.

// Used by the ZFS collector (and tests).
#![cfg_attr(
    not(any(target_os = "freebsd", target_os = "linux")),
    expect(dead_code, reason = "used by the FreeBSD and Linux implementations")
)]

use std::fmt;

/// `nvpair_max_recursion` in OpenZFS is 20; be a little more lenient.
const MAX_DEPTH: usize = 32;

const NV_ENCODE_NATIVE: u8 = 0;
const NV_VERSION: i32 = 0;
/// `sizeof (nvpair_t)` without the name.
const NVP_HEADER: usize = 16;
/// `sizeof (nvlist_t)`.
const NVLIST_SIZE: usize = 24;

#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    /// `DATA_TYPE_BOOLEAN` (presence only) and `DATA_TYPE_BOOLEAN_VALUE`.
    Bool(bool),
    /// All unsigned integer types and `HRTIME`.
    Uint(u64),
    /// All signed integer types.
    Int(i64),
    Double(f64),
    String(&'a str),
    UintArray(Vec<u64>),
    IntArray(Vec<i64>),
    StringArray(Vec<&'a str>),
    NvList(NvList<'a>),
    NvListArray(Vec<NvList<'a>>),
    /// Byte and boolean arrays; not needed by any caller yet.
    Unsupported(u32),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NvList<'a> {
    pairs: Vec<(&'a str, Value<'a>)>,
}

impl<'a> NvList<'a> {
    pub fn get(&self, name: &str) -> Option<&Value<'a>> {
        self.pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &Value<'a>)> {
        self.pairs.iter().map(|(n, v)| (*n, v))
    }

    pub fn get_uint(&self, name: &str) -> Option<u64> {
        match self.get(name)? {
            Value::Uint(v) => Some(*v),
            Value::Int(v) => u64::try_from(*v).ok(),
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed nvlist: {}", self.0)
    }
}

impl std::error::Error for Error {}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

/// Decodes a packed native nvlist.
pub fn unpack(buf: &[u8]) -> Result<NvList<'_>, Error> {
    let Some(header) = buf.get(..4) else {
        return err("shorter than its header");
    };
    if header[0] != NV_ENCODE_NATIVE {
        return err(format!("encoding {} is not native", header[0]));
    }
    let little = u8::from(cfg!(target_endian = "little"));
    if header[1] != little {
        return err("endianness differs from this host");
    }
    let mut reader = Reader { buf, pos: 4 };
    let version = reader.i32()?;
    let _nvflag = reader.u32()?;
    if version != NV_VERSION {
        return err(format!("nvlist version {version}"));
    }
    reader.pairs(0)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
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

    fn i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_ne_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_ne_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn peek_i32(&self) -> Result<i32, Error> {
        match self.buf.get(self.pos..self.pos + 4) {
            Some(b) => Ok(i32::from_ne_bytes(b.try_into().expect("4 bytes"))),
            None => err(format!("truncated at offset {}", self.pos)),
        }
    }

    /// Reads pairs up to and including the terminating zero size.
    fn pairs(&mut self, depth: usize) -> Result<NvList<'a>, Error> {
        if depth > MAX_DEPTH {
            return err("nested too deeply");
        }
        let mut list = NvList::default();
        loop {
            let size = self.peek_i32()?;
            if size == 0 {
                self.pos += 4;
                return Ok(list);
            }
            let size = usize::try_from(size)
                .ok()
                .filter(|&s| s >= NVP_HEADER)
                .ok_or_else(|| Error(format!("pair size {size} at offset {}", self.pos)))?;
            let pair = self.take(size)?;
            let (name, value) = self.pair(pair, depth)?;
            list.pairs.push((name, value));
        }
    }

    /// Decodes one pair. Embedded lists are read from the stream after it.
    fn pair(&mut self, pair: &'a [u8], depth: usize) -> Result<(&'a str, Value<'a>), Error> {
        let field = |off: usize| i32::from_ne_bytes(pair[off..off + 4].try_into().expect("4"));
        let name_sz = usize::try_from(i16::from_ne_bytes([pair[4], pair[5]]))
            .ok()
            .filter(|&n| n >= 1)
            .ok_or_else(|| Error("bad name size".into()))?;
        let nelem =
            usize::try_from(field(8)).map_err(|_| Error("negative element count".into()))?;
        let typ = u32::try_from(field(12)).map_err(|_| Error("negative type".into()))?;

        let name_bytes = pair
            .get(NVP_HEADER..NVP_HEADER + name_sz)
            .ok_or_else(|| Error("name exceeds pair".into()))?;
        let name = cstr(name_bytes)?;
        let value = pair.get(align8(NVP_HEADER + name_sz)..).unwrap_or_default();

        let value = match typ {
            // BOOLEAN: the pair's presence is the value.
            1 => Value::Bool(true),
            // BYTE, UINT8
            2 | 23 => Value::Uint(u64::from(fixed::<1>(value)?[0])),
            22 => Value::Int(i64::from(i8::from_ne_bytes(fixed::<1>(value)?))),
            3 => Value::Int(i64::from(i16::from_ne_bytes(fixed(value)?))),
            4 => Value::Uint(u64::from(u16::from_ne_bytes(fixed(value)?))),
            5 => Value::Int(i64::from(i32::from_ne_bytes(fixed(value)?))),
            6 => Value::Uint(u64::from(u32::from_ne_bytes(fixed(value)?))),
            7 => Value::Int(i64::from_ne_bytes(fixed(value)?)),
            // UINT64, HRTIME
            8 | 18 => Value::Uint(u64::from_ne_bytes(fixed(value)?)),
            9 => Value::String(cstr(value)?),
            11 | 13 | 15 => Value::IntArray(int_array(value, typ, nelem)?),
            12 | 14 | 16 => Value::UintArray(uint_array(value, typ, nelem)?),
            17 => {
                // nelem pointer slots, then the strings back to back.
                let mut rest = value.get(nelem * 8..).unwrap_or_default();
                let mut strings = Vec::with_capacity(nelem);
                for _ in 0..nelem {
                    let s = cstr(rest)?;
                    rest = &rest[s.len() + 1..];
                    strings.push(s);
                }
                Value::StringArray(strings)
            }
            19 => {
                check_embedded(value, 0)?;
                Value::NvList(self.pairs(depth + 1)?)
            }
            20 => {
                // nelem pointer slots, then nelem nvlist_t structs; the
                // elements' pairs follow in the stream.
                for i in 0..nelem {
                    check_embedded(value, nelem * 8 + i * NVLIST_SIZE)?;
                }
                let lists = (0..nelem)
                    .map(|_| self.pairs(depth + 1))
                    .collect::<Result<_, _>>()?;
                Value::NvListArray(lists)
            }
            21 => Value::Bool(i32::from_ne_bytes(fixed(value)?) != 0),
            27 => Value::Double(f64::from_ne_bytes(fixed(value)?)),
            other => Value::Unsupported(other),
        };
        Ok((name, value))
    }
}

/// Embedded `nvlist_t` structs carry the list version; reject others like the
/// kernel's decoder does.
fn check_embedded(value: &[u8], offset: usize) -> Result<(), Error> {
    match value.get(offset..offset + 4) {
        Some(b) if i32::from_ne_bytes(b.try_into().expect("4")) == NV_VERSION => Ok(()),
        Some(_) => err("embedded nvlist has unknown version"),
        None => err("embedded nvlist header truncated"),
    }
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], Error> {
    value
        .get(..N)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error("value truncated".into()))
}

fn cstr(bytes: &[u8]) -> Result<&str, Error> {
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error("unterminated string".into()))?;
    std::str::from_utf8(&bytes[..end]).map_err(|_| Error("string is not UTF-8".into()))
}

fn elem_width(typ: u32) -> usize {
    match typ {
        11 | 12 => 2,
        13 | 14 => 4,
        _ => 8,
    }
}

fn uint_array(value: &[u8], typ: u32, nelem: usize) -> Result<Vec<u64>, Error> {
    let width = elem_width(typ);
    let bytes = value
        .get(..nelem * width)
        .ok_or_else(|| Error("array truncated".into()))?;
    Ok(bytes
        .chunks_exact(width)
        .map(|c| match width {
            2 => u64::from(u16::from_ne_bytes([c[0], c[1]])),
            4 => u64::from(u32::from_ne_bytes(c.try_into().expect("4"))),
            _ => u64::from_ne_bytes(c.try_into().expect("8")),
        })
        .collect())
}

fn int_array(value: &[u8], typ: u32, nelem: usize) -> Result<Vec<i64>, Error> {
    let width = elem_width(typ);
    let bytes = value
        .get(..nelem * width)
        .ok_or_else(|| Error("array truncated".into()))?;
    Ok(bytes
        .chunks_exact(width)
        .map(|c| match width {
            2 => i64::from(i16::from_ne_bytes([c[0], c[1]])),
            4 => i64::from(i32::from_ne_bytes(c.try_into().expect("4"))),
            _ => i64::from_ne_bytes(c.try_into().expect("8")),
        })
        .collect())
}

#[cfg(test)]
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "test fixtures are tiny; the casts can't truncate"
)]
pub(crate) mod tests {
    use super::*;

    /// Minimal encoder following `nvs_native_nvp_op`/`nvs_embedded`, to
    /// produce test streams.
    pub enum Enc<'a> {
        U64(u64),
        I32(i32),
        Str(&'a str),
        U64s(&'a [u64]),
        Strs(&'a [&'a str]),
        List(Vec<(&'a str, Enc<'a>)>),
        Lists(Vec<Vec<(&'a str, Enc<'a>)>>),
        Bool,
    }

    pub fn pack(pairs: &[(&str, Enc<'_>)]) -> Vec<u8> {
        let mut out = vec![
            NV_ENCODE_NATIVE,
            u8::from(cfg!(target_endian = "little")),
            0,
            0,
        ];
        out.extend(0i32.to_ne_bytes());
        out.extend(0u32.to_ne_bytes());
        encode_pairs(&mut out, pairs);
        out
    }

    fn encode_pairs(out: &mut Vec<u8>, pairs: &[(&str, Enc<'_>)]) {
        for (name, value) in pairs {
            let (typ, nelem, data): (i32, i32, Vec<u8>) = match value {
                Enc::U64(v) => (8, 1, v.to_ne_bytes().to_vec()),
                Enc::I32(v) => (5, 1, v.to_ne_bytes().to_vec()),
                Enc::Str(s) => (9, 1, [s.as_bytes(), &[0]].concat()),
                Enc::U64s(vs) => (
                    16,
                    vs.len() as i32,
                    vs.iter().flat_map(|v| v.to_ne_bytes()).collect(),
                ),
                Enc::Strs(ss) => {
                    let mut d = vec![0u8; ss.len() * 8];
                    for s in *ss {
                        d.extend(s.as_bytes());
                        d.push(0);
                    }
                    (17, ss.len() as i32, d)
                }
                Enc::List(_) => (19, 1, nvlist_struct()),
                Enc::Lists(ls) => {
                    let mut d = vec![0u8; ls.len() * 8];
                    for _ in ls {
                        d.extend(nvlist_struct());
                    }
                    (20, ls.len() as i32, d)
                }
                Enc::Bool => (1, 0, Vec::new()),
            };
            let name_sz = name.len() + 1;
            let size = align8(NVP_HEADER + name_sz) + align8(data.len());
            let start = out.len();
            out.extend((size as i32).to_ne_bytes());
            out.extend((name_sz as i16).to_ne_bytes());
            out.extend(0i16.to_ne_bytes());
            out.extend(nelem.to_ne_bytes());
            out.extend(typ.to_ne_bytes());
            out.extend(name.as_bytes());
            out.push(0);
            out.resize(start + align8(NVP_HEADER + name_sz), 0);
            out.extend(&data);
            out.resize(start + size, 0);
            match value {
                Enc::List(inner) => encode_pairs(out, inner),
                Enc::Lists(ls) => ls.iter().for_each(|inner| encode_pairs(out, inner)),
                _ => {}
            }
        }
        out.extend(0i32.to_ne_bytes());
    }

    fn nvlist_struct() -> Vec<u8> {
        vec![0u8; NVLIST_SIZE]
    }

    #[test]
    fn decodes_scalars_and_nesting() {
        let buf = pack(&[
            ("size", Enc::U64(1 << 40)),
            ("name", Enc::Str("zroot")),
            ("neg", Enc::I32(-5)),
            ("flag", Enc::Bool),
            (
                "health",
                Enc::List(vec![("value", Enc::U64(7)), ("source", Enc::U64(0))]),
            ),
            ("arr", Enc::U64s(&[1, 2, 3])),
            ("strs", Enc::Strs(&["a", "bc"])),
            (
                "children",
                Enc::Lists(vec![
                    vec![("type", Enc::Str("disk"))],
                    vec![("type", Enc::Str("file")), ("x", Enc::List(vec![]))],
                ]),
            ),
            ("after", Enc::U64(42)),
        ]);
        let list = unpack(&buf).unwrap();
        assert_eq!(list.get_uint("size"), Some(1 << 40));
        assert_eq!(list.get_str("name"), Some("zroot"));
        assert_eq!(list.get("neg"), Some(&Value::Int(-5)));
        assert_eq!(list.get("flag"), Some(&Value::Bool(true)));
        assert_eq!(list.get_list("health").unwrap().get_uint("value"), Some(7));
        assert_eq!(list.get("arr"), Some(&Value::UintArray(vec![1, 2, 3])));
        assert_eq!(list.get("strs"), Some(&Value::StringArray(vec!["a", "bc"])));
        let Some(Value::NvListArray(children)) = list.get("children") else {
            panic!()
        };
        assert_eq!(children.len(), 2);
        assert_eq!(children[1].get_str("type"), Some("file"));
        // Pairs after embedded lists are still found at the right offset.
        assert_eq!(list.get_uint("after"), Some(42));
    }

    #[test]
    fn rejects_malformed_input() {
        let good = pack(&[("a", Enc::U64(1))]);
        assert!(
            unpack(&good[..good.len() - 1]).is_err(),
            "missing terminator"
        );
        assert!(unpack(&good[..10]).is_err(), "truncated pair");
        let mut xdr = good.clone();
        xdr[0] = 1;
        assert!(unpack(&xdr).is_err(), "XDR encoding");
        let mut bad_size = good.clone();
        bad_size[12..16].copy_from_slice(&3i32.to_ne_bytes());
        assert!(unpack(&bad_size).is_err(), "pair smaller than header");
        assert!(unpack(&[]).is_err());
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let mut inner = vec![("leaf", Enc::U64(1))];
        for _ in 0..40 {
            inner = vec![("n", Enc::List(inner))];
        }
        assert!(unpack(&pack(&inner)).is_err());
    }
}
