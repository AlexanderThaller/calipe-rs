//! chronyd tracking state over chrony's command protocol (what `chronyc
//! tracking` does), without running `chronyc`.
//!
//! Protocol (chrony `candm.h`, version 6, unchanged since chrony 2.x): a
//! `REQ_TRACKING` request is a 20-byte header padded to the length of its
//! reply (chronyd rejects shorter requests to prevent amplification); the
//! `RPY_TRACKING` reply is a 28-byte header followed by the tracking data.
//! All integers are big-endian; the offsets and frequencies use chrony's
//! 32-bit `Float` (7-bit exponent, 25-bit coefficient).
//!
//! chronyd answers unauthenticated tracking requests from localhost on UDP
//! port 323 (`cmdport`) by default.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use metrics::describe_gauge;
use serde::Deserialize;
use tokio::net::UdpSocket;

use crate::collector::Collector;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
    /// chronyd's command socket.
    #[serde(default = "default_server")]
    pub server: SocketAddr,
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

fn default_server() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 323))
}

fn default_timeout() -> Duration {
    Duration::from_secs(1)
}

pub fn describe() {
    describe_gauge!(
        "chrony_system_time_correction_seconds",
        "Correction chronyd is slewing in (chronyc 'System time'); positive means the clock is slow."
    );
    describe_gauge!(
        "chrony_last_offset_seconds",
        "Estimated local offset at the last clock update."
    );
    describe_gauge!(
        "chrony_rms_offset_seconds",
        "Long-term average of the offset."
    );
    describe_gauge!(
        "chrony_frequency_ppm",
        "Rate at which the system clock would drift without chronyd; negative means slow (chronyc -c sign)."
    );
    describe_gauge!(
        "chrony_residual_frequency_ppm",
        "Residual frequency of the reference source."
    );
    describe_gauge!("chrony_skew_ppm", "Estimated error bound of the frequency.");
    describe_gauge!(
        "chrony_root_delay_seconds",
        "Total network path delay to the stratum-1 source."
    );
    describe_gauge!(
        "chrony_root_dispersion_seconds",
        "Total dispersion accumulated to the stratum-1 source."
    );
    describe_gauge!(
        "chrony_update_interval_seconds",
        "Interval between the last two clock updates."
    );
    describe_gauge!(
        "chrony_reference_time_seconds",
        "Unix time of the last measurement from the reference."
    );
    describe_gauge!(
        "chrony_stratum",
        "Stratum of this host (reference stratum + 1)."
    );
    describe_gauge!(
        "chrony_synchronized",
        "1 if chronyd is synchronized (leap status not 'not synchronised')."
    );
    describe_gauge!(
        "chrony_tracking_info",
        "Always 1; labels give the reference ID, its address and the leap status."
    );
}

const PROTO_VERSION: u8 = 6;
const PKT_TYPE_CMD_REQUEST: u8 = 1;
const PKT_TYPE_CMD_REPLY: u8 = 2;
const REQ_TRACKING: u16 = 33;
const RPY_TRACKING: u16 = 5;
const STT_SUCCESS: u16 = 0;
/// `offsetof(CMD_Reply, data.tracking.EOR)`; requests are padded to this.
const TRACKING_REPLY_LEN: usize = 28 + 76;
/// `TV_NOHIGHSEC`: marks `tv_sec_high` as unused.
const TV_NOHIGHSEC: u32 = 0x7fff_ffff;

pub fn request(sequence: u32) -> [u8; TRACKING_REPLY_LEN] {
    let mut req = [0u8; TRACKING_REPLY_LEN];
    req[0] = PROTO_VERSION;
    req[1] = PKT_TYPE_CMD_REQUEST;
    req[4..6].copy_from_slice(&REQ_TRACKING.to_be_bytes());
    // attempt (6..8) stays 0
    req[8..12].copy_from_slice(&sequence.to_be_bytes());
    req
}

/// `UTI_FloatNetworkToHost()`.
pub fn decode_float(raw: u32) -> f64 {
    const EXP_BITS: u32 = 7;
    const COEF_BITS: u32 = 32 - EXP_BITS;
    let mut exp = i32::try_from(raw >> COEF_BITS).expect("7 bits");
    if exp >= 1 << (EXP_BITS - 1) {
        exp -= 1 << EXP_BITS;
    }
    let mut coef = i32::try_from(raw % (1 << COEF_BITS)).expect("25 bits");
    if coef >= 1 << (COEF_BITS - 1) {
        coef -= 1 << COEF_BITS;
    }
    f64::from(coef) * 2f64.powi(exp - i32::try_from(COEF_BITS).expect("small"))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tracking {
    pub reference_id: String,
    pub reference_ip: String,
    pub stratum: u16,
    pub leap_status: &'static str,
    pub reference_time: f64,
    pub correction: f64,
    pub last_offset: f64,
    pub rms_offset: f64,
    pub frequency: f64,
    pub residual_frequency: f64,
    pub skew: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub update_interval: f64,
}

pub fn parse_reply(buf: &[u8], sequence: u32) -> Result<Tracking> {
    if buf.len() < TRACKING_REPLY_LEN {
        bail!(
            "reply is {} bytes, expected {TRACKING_REPLY_LEN}",
            buf.len()
        );
    }
    let u16_at = |at: usize| u16::from_be_bytes([buf[at], buf[at + 1]]);
    let u32_at = |at: usize| u32::from_be_bytes(buf[at..at + 4].try_into().expect("4"));
    if buf[0] != PROTO_VERSION || buf[1] != PKT_TYPE_CMD_REPLY {
        bail!(
            "not a protocol {PROTO_VERSION} reply (version {}, type {})",
            buf[0],
            buf[1]
        );
    }
    let status = u16_at(8);
    if status != STT_SUCCESS {
        bail!("chronyd returned status {status} (2 = unauthorized: check cmdallow)");
    }
    if u16_at(4) != REQ_TRACKING || u16_at(6) != RPY_TRACKING {
        bail!(
            "unexpected reply type {} for command {}",
            u16_at(6),
            u16_at(4)
        );
    }
    if u32_at(16) != sequence {
        bail!(
            "reply sequence {} does not match request {sequence}",
            u32_at(16)
        );
    }

    let d = 28;
    let reference_id = u32_at(d);
    // IPAddr: 16 address bytes, u16 family, u16 padding.
    let addr = &buf[d + 4..d + 20];
    let address = match u16_at(d + 20) {
        1 => std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string(),
        2 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(addr).expect("16")).to_string(),
        _ => String::new(),
    };
    let stratum = u16_at(d + 24);
    let leap_status = match u16_at(d + 26) {
        0 => "normal",
        1 => "insert_second",
        2 => "delete_second",
        _ => "not_synchronised",
    };
    let sec_high = match u32_at(d + 28) {
        TV_NOHIGHSEC => 0,
        high => u64::from(high),
    };
    let reference_time =
        ((sec_high << 32) | u64::from(u32_at(d + 32))) as f64 + f64::from(u32_at(d + 36)) / 1e9;
    let float = |i: usize| decode_float(u32_at(d + 40 + 4 * i));
    Ok(Tracking {
        reference_id: format!("{reference_id:08X}"),
        reference_ip: address,
        stratum,
        leap_status,
        reference_time,
        correction: float(0),
        last_offset: float(1),
        rms_offset: float(2),
        frequency: float(3),
        residual_frequency: float(4),
        skew: float(5),
        root_delay: float(6),
        root_dispersion: float(7),
        update_interval: float(8),
    })
}

pub struct Chrony {
    config: Config,
    sequence: u32,
}

impl Chrony {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            // Random-ish start so restarts don't reuse sequence numbers.
            sequence: std::process::id().wrapping_mul(2_654_435_761),
        })
    }

    async fn query(&mut self) -> Result<Tracking> {
        let bind: SocketAddr = if self.config.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .expect("valid address");
        let socket = UdpSocket::bind(bind).await.context("binding UDP socket")?;
        socket
            .connect(self.config.server)
            .await
            .context("connecting to chronyd")?;
        self.sequence = self.sequence.wrapping_add(1);
        socket
            .send(&request(self.sequence))
            .await
            .context("sending request")?;
        let mut buf = [0u8; 1500];
        let n = tokio::time::timeout(self.config.timeout, socket.recv(&mut buf))
            .await
            .with_context(|| {
                format!(
                    "no reply from chronyd at {} within {:?}",
                    self.config.server, self.config.timeout
                )
            })?
            .context("receiving reply")?;
        parse_reply(&buf[..n], self.sequence)
    }
}

impl Collector for Chrony {
    fn name(&self) -> &'static str {
        "chrony"
    }

    fn describe(&self) {
        describe();
    }

    async fn collect(&mut self) -> Result<()> {
        use metrics::gauge;
        let t = self.query().await?;
        gauge!("chrony_system_time_correction_seconds").set(t.correction);
        gauge!("chrony_last_offset_seconds").set(t.last_offset);
        gauge!("chrony_rms_offset_seconds").set(t.rms_offset);
        gauge!("chrony_frequency_ppm").set(t.frequency);
        gauge!("chrony_residual_frequency_ppm").set(t.residual_frequency);
        gauge!("chrony_skew_ppm").set(t.skew);
        gauge!("chrony_root_delay_seconds").set(t.root_delay);
        gauge!("chrony_root_dispersion_seconds").set(t.root_dispersion);
        gauge!("chrony_update_interval_seconds").set(t.update_interval);
        gauge!("chrony_reference_time_seconds").set(t.reference_time);
        gauge!("chrony_stratum").set(f64::from(t.stratum));
        gauge!("chrony_synchronized").set(f64::from(u8::from(t.leap_status != "not_synchronised")));
        gauge!(
            "chrony_tracking_info",
            "reference_id" => t.reference_id,
            "reference_ip" => t.reference_ip,
            "leap_status" => t.leap_status
        )
        .set(1.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inverse of [`decode_float`] for exact test values: coef * 2^(exp-25).
    fn encode(exp: i32, coef: i32) -> u32 {
        ((exp.cast_unsigned() & 0x7f) << 25) | (coef.cast_unsigned() & 0x1ff_ffff)
    }

    #[test]
    fn decodes_chrony_floats() {
        assert_eq!(decode_float(encode(25, 1)), 1.0);
        assert_eq!(decode_float(encode(25, -1)), -1.0);
        assert_eq!(decode_float(encode(0, 1 << 23)), 0.25);
        assert_eq!(decode_float(encode(-10, 3)), 3.0 * 2f64.powi(-35));
        assert_eq!(decode_float(0), 0.0);
    }

    #[test]
    fn builds_padded_request() {
        let req = request(0x0102_0304);
        assert_eq!(req.len(), 104);
        assert_eq!(&req[..12], &[6, 1, 0, 0, 0, 33, 0, 0, 1, 2, 3, 4]);
        assert!(req[12..].iter().all(|&b| b == 0));
    }

    fn reply(sequence: u32, status: u16) -> Vec<u8> {
        let mut r = vec![0u8; 104];
        r[0] = 6;
        r[1] = 2;
        r[4..6].copy_from_slice(&33u16.to_be_bytes());
        r[6..8].copy_from_slice(&5u16.to_be_bytes());
        r[8..10].copy_from_slice(&status.to_be_bytes());
        r[16..20].copy_from_slice(&sequence.to_be_bytes());
        let d = 28;
        r[d..d + 4].copy_from_slice(&0x83BC_03DEu32.to_be_bytes());
        r[d + 4..d + 8].copy_from_slice(&[131, 188, 3, 222]);
        r[d + 20..d + 22].copy_from_slice(&1u16.to_be_bytes());
        r[d + 24..d + 26].copy_from_slice(&2u16.to_be_bytes());
        r[d + 28..d + 32].copy_from_slice(&TV_NOHIGHSEC.to_be_bytes());
        r[d + 32..d + 36].copy_from_slice(&1_791_000_000u32.to_be_bytes());
        r[d + 36..d + 40].copy_from_slice(&500_000_000u32.to_be_bytes());
        r[d + 40..d + 44].copy_from_slice(&encode(25, 1).to_be_bytes()); // correction 1.0
        r[d + 52..d + 56].copy_from_slice(&encode(25, -3).to_be_bytes()); // frequency -3.0
        r
    }

    #[test]
    fn parses_tracking_reply() {
        let t = parse_reply(&reply(7, 0), 7).unwrap();
        assert_eq!(t.reference_id, "83BC03DE");
        assert_eq!(t.reference_ip, "131.188.3.222");
        assert_eq!(t.stratum, 2);
        assert_eq!(t.leap_status, "normal");
        assert_eq!(t.reference_time, 1_791_000_000.5);
        assert_eq!(t.correction, 1.0);
        assert_eq!(t.frequency, -3.0);
        assert_eq!(t.root_delay, 0.0);
    }

    #[test]
    fn rejects_bad_replies() {
        assert!(parse_reply(&reply(7, 0), 8).is_err(), "wrong sequence");
        assert!(parse_reply(&reply(7, 2), 7).is_err(), "unauthorized");
        assert!(parse_reply(&reply(7, 0)[..50], 7).is_err(), "short");
    }
}
