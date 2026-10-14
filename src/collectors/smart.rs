//! Disk health (S.M.A.R.T.) for SATA and NVMe drives, read natively instead
//! of running smartctl.
//!
//! * SATA (`adaN`): ATA commands sent through CAM (libcam's `cam_open_device` +
//!   `CAMIOCOMMAND` with an `XPT_ATA_IO` CCB, as smartctl's FreeBSD backend
//!   does): IDENTIFY DEVICE, CHECK POWER MODE, SMART RETURN STATUS, SMART READ
//!   DATA and READ THRESHOLDS.
//! * NVMe (`nvmeN`): `NVME_PASSTHROUGH_CMD` on the controller device: IDENTIFY
//!   CONTROLLER and the SMART / Health Information log page (0x02).
//!
//! Struct layouts (`union ccb`, `struct ata_cmd`/`ata_res`,
//! `struct nvme_pt_command`) were taken from the 14.5 and 15.1 headers with
//! clang's `offsetof` and are identical on both.
//!
//! With `nocheck = "standby"` (the default, like Telegraf), a SATA disk in
//! standby is not read, so monitoring doesn't spin it up.
//!
//! SMART values are device state (lifetime totals of the physical disk), so
//! they're exported as gauges: a replaced disk starts over.

// The helpers are only used by the FreeBSD implementation (and tests).
#![cfg_attr(
    not(target_os = "freebsd"),
    expect(dead_code, reason = "used by the FreeBSD implementation")
)]

use std::time::Duration;

use metrics::describe_gauge;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Default 60s: SMART data changes slowly, and drives log every query.
    #[serde(default, with = "humantime_serde")]
    pub interval: Option<Duration>,
    /// Devices to read (e.g. `["ada0", "nvme0"]`); empty means all found.
    #[serde(default)]
    pub devices: Vec<String>,
    /// Devices to skip; `/dev/` prefixes are ignored.
    #[serde(default)]
    pub excludes: Vec<String>,
    /// `"standby"`: skip SATA disks in standby; `"never"`: always read.
    #[serde(default = "default_nocheck")]
    pub nocheck: String,
    /// Export the full SATA attribute table, not just the summary metrics.
    #[serde(default = "yes")]
    pub attributes: bool,
}

fn default_nocheck() -> String {
    "standby".to_owned()
}

fn yes() -> bool {
    true
}

pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

pub fn describe() {
    describe_gauge!(
        "smart_device_info",
        "Always 1; labels carry model, serial, firmware and type."
    );
    describe_gauge!(
        "smart_device_healthy",
        "1 if the drive reports no failure (ATA SMART RETURN STATUS / NVMe critical warning 0)."
    );
    describe_gauge!(
        "smart_device_standby",
        "1 if the SATA disk was in standby and therefore not read."
    );
    describe_gauge!("smart_temperature_celsius", "Drive temperature.");
    describe_gauge!("smart_power_on_seconds", "Power-on time.");
    describe_gauge!("smart_power_cycles", "Power cycles.");
    describe_gauge!("smart_attribute_value", "Normalized SATA attribute value.");
    describe_gauge!(
        "smart_attribute_worst",
        "Worst normalized SATA attribute value."
    );
    describe_gauge!(
        "smart_attribute_threshold",
        "Failure threshold of the SATA attribute."
    );
    describe_gauge!(
        "smart_attribute_raw",
        "48-bit raw SATA attribute value (vendor-specific encoding)."
    );
    describe_gauge!(
        "smart_nvme_critical_warning",
        "NVMe critical warning bits (0 = none)."
    );
    describe_gauge!(
        "smart_nvme_available_spare_ratio",
        "Remaining spare capacity (0-1)."
    );
    describe_gauge!(
        "smart_nvme_available_spare_threshold_ratio",
        "Spare capacity alarm threshold (0-1)."
    );
    describe_gauge!(
        "smart_nvme_percentage_used_ratio",
        "Estimated endurance used; can exceed 1."
    );
    describe_gauge!(
        "smart_nvme_data_read_bytes",
        "Lifetime bytes read by the host."
    );
    describe_gauge!(
        "smart_nvme_data_written_bytes",
        "Lifetime bytes written by the host."
    );
    describe_gauge!("smart_nvme_host_read_commands", "Lifetime read commands.");
    describe_gauge!("smart_nvme_host_write_commands", "Lifetime write commands.");
    describe_gauge!(
        "smart_nvme_controller_busy_seconds",
        "Lifetime time the controller was busy."
    );
    describe_gauge!("smart_nvme_unsafe_shutdowns", "Unsafe shutdowns.");
    describe_gauge!(
        "smart_nvme_media_errors",
        "Unrecovered data integrity errors."
    );
    describe_gauge!(
        "smart_nvme_error_log_entries",
        "Error log entries over the drive's life."
    );
    describe_gauge!(
        "smart_nvme_warning_temperature_seconds",
        "Time above the warning composite temperature threshold."
    );
    describe_gauge!(
        "smart_nvme_critical_temperature_seconds",
        "Time above the critical composite temperature threshold."
    );
}

impl Config {
    pub fn wants(&self, device: &str) -> bool {
        let strip = |d: &str| d.strip_prefix("/dev/").unwrap_or(d).to_owned();
        let device = strip(device);
        (self.devices.is_empty() || self.devices.iter().any(|d| strip(d) == device))
            && !self.excludes.iter().any(|d| strip(d) == device)
    }
}

/// Identity strings of a drive.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Identity {
    pub model: String,
    pub serial: String,
    pub firmware: String,
}

/// ATA strings are stored as 16-bit words with the two bytes swapped.
fn ata_string(words: &[u8]) -> String {
    let swapped: Vec<u8> = words
        .as_chunks::<2>()
        .0
        .iter()
        .flat_map(|w| [w[1], w[0]])
        .collect();
    String::from_utf8_lossy(&swapped).trim().to_owned()
}

/// Parses IDENTIFY DEVICE data (ATA8-ACS words 10-19, 23-26, 27-46).
pub fn ata_identity(data: &[u8; 512]) -> Identity {
    Identity {
        serial: ata_string(&data[20..40]),
        firmware: ata_string(&data[46..54]),
        model: ata_string(&data[54..94]),
    }
}

/// Whether IDENTIFY says SMART is supported (word 82 bit 0) and enabled
/// (word 85 bit 0).
pub fn ata_smart_enabled(data: &[u8; 512]) -> bool {
    let word = |n: usize| u16::from_le_bytes([data[n * 2], data[n * 2 + 1]]);
    word(82) & 1 != 0 && word(85) & 1 != 0
}

/// One entry of the SMART attribute table.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Attribute {
    pub id: u8,
    pub value: u8,
    pub worst: u8,
    pub threshold: Option<u8>,
    pub raw: u64,
}

/// Parses SMART READ DATA and READ THRESHOLDS: 30 entries of 12 bytes from
/// offset 2 (`id, flags:u16, value, worst, raw[6], reserved` and
/// `id, threshold, reserved[10]`).
pub fn ata_attributes(data: &[u8; 512], thresholds: Option<&[u8; 512]>) -> Vec<Attribute> {
    let threshold_of = |id: u8| {
        thresholds.and_then(|t| {
            t[2..2 + 30 * 12]
                .as_chunks::<12>()
                .0
                .iter()
                .find(|e| e[0] == id)
                .map(|e| e[1])
        })
    };
    data[2..2 + 30 * 12]
        .as_chunks::<12>()
        .0
        .iter()
        .filter(|e| e[0] != 0)
        .map(|e| {
            let mut raw = [0u8; 8];
            raw[..6].copy_from_slice(&e[5..11]);
            Attribute {
                id: e[0],
                value: e[3],
                worst: e[4],
                threshold: threshold_of(e[0]),
                raw: u64::from_le_bytes(raw),
            }
        })
        .collect()
}

/// smartctl's default attribute names for common IDs.
pub fn attribute_name(id: u8) -> &'static str {
    match id {
        1 => "Raw_Read_Error_Rate",
        2 => "Throughput_Performance",
        3 => "Spin_Up_Time",
        4 => "Start_Stop_Count",
        5 => "Reallocated_Sector_Ct",
        7 => "Seek_Error_Rate",
        8 => "Seek_Time_Performance",
        9 => "Power_On_Hours",
        10 => "Spin_Retry_Count",
        11 => "Calibration_Retry_Count",
        12 => "Power_Cycle_Count",
        22 => "Helium_Level",
        23 => "Helium_Condition_Lower",
        24 => "Helium_Condition_Upper",
        // Toshiba MAMR drives (MG10 and later), as named in smartctl's drivedb.
        27 => "MAMR_Health_Monitor",
        170 | 232 => "Available_Reservd_Space",
        171 => "Program_Fail_Count",
        172 => "Erase_Fail_Count",
        173 => "Ave_Block-Erase_Count",
        174 => "Unexpect_Power_Loss_Ct",
        177 => "Wear_Leveling_Count",
        179 => "Used_Rsvd_Blk_Cnt_Tot",
        181 => "Program_Fail_Cnt_Total",
        182 => "Erase_Fail_Count_Total",
        183 => "Runtime_Bad_Block",
        184 => "End-to-End_Error",
        187 => "Reported_Uncorrect",
        188 => "Command_Timeout",
        189 => "High_Fly_Writes",
        190 => "Airflow_Temperature_Cel",
        191 => "G-Sense_Error_Rate",
        192 => "Power-Off_Retract_Count",
        193 => "Load_Cycle_Count",
        194 => "Temperature_Celsius",
        195 => "Hardware_ECC_Recovered",
        196 => "Reallocated_Event_Count",
        197 => "Current_Pending_Sector",
        198 => "Offline_Uncorrectable",
        199 => "UDMA_CRC_Error_Count",
        200 => "Multi_Zone_Error_Rate",
        220 => "Disk_Shift",
        222 => "Loaded_Hours",
        223 => "Load_Retry_Count",
        224 => "Load_Friction",
        226 => "Load-in_Time",
        231 => "SSD_Life_Left",
        233 => "Media_Wearout_Indicator",
        240 => "Head_Flying_Hours",
        241 => "Total_LBAs_Written",
        242 => "Total_LBAs_Read",
        254 => "Free_Fall_Sensor",
        _ => "Unknown_Attribute",
    }
}

/// Summary values derived from the attribute table with the common raw
/// encodings: temperature in the low byte (194, else 190), power-on hours
/// and power cycles in the low 32 bits.
pub fn ata_summary(attrs: &[Attribute]) -> (Option<f64>, Option<f64>, Option<f64>) {
    let raw = |id: u8| attrs.iter().find(|a| a.id == id).map(|a| a.raw);
    let temperature = raw(194).or_else(|| raw(190)).map(|r| (r & 0xff) as f64);
    let power_on = raw(9).map(|r| (r & 0xffff_ffff) as f64 * 3600.0);
    let cycles = raw(12).map(|r| (r & 0xffff_ffff) as f64);
    (temperature, power_on, cycles)
}

/// SMART RETURN STATUS result in LBA mid/high: 4F/C2 = OK, F4/2C = a
/// threshold was exceeded. Anything else means the status is unknown.
pub fn ata_health(lba_mid: u8, lba_high: u8) -> Option<bool> {
    match (lba_mid, lba_high) {
        (0x4f, 0xc2) => Some(true),
        (0xf4, 0x2c) => Some(false),
        _ => None,
    }
}

/// Parses IDENTIFY CONTROLLER data (serial 4..24, model 24..64, fw 64..72).
pub fn nvme_identity(data: &[u8]) -> Identity {
    let text = |r: std::ops::Range<usize>| String::from_utf8_lossy(&data[r]).trim().to_owned();
    Identity {
        serial: text(4..24),
        model: text(24..64),
        firmware: text(64..72),
    }
}

/// The NVMe SMART / Health Information log page (NVMe base spec, log 0x02).
#[derive(Debug, Clone, PartialEq)]
pub struct NvmeHealth {
    pub critical_warning: u8,
    pub temperature_celsius: f64,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    pub controller_busy_minutes: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
    pub error_log_entries: u128,
    pub warning_temp_minutes: u32,
    pub critical_temp_minutes: u32,
}

pub fn nvme_health(page: &[u8; 512]) -> NvmeHealth {
    let u128_at = |at: usize| u128::from_le_bytes(page[at..at + 16].try_into().expect("16"));
    let u32_at = |at: usize| u32::from_le_bytes(page[at..at + 4].try_into().expect("4"));
    let kelvin = u16::from_le_bytes([page[1], page[2]]);
    NvmeHealth {
        critical_warning: page[0],
        temperature_celsius: f64::from(kelvin) - 273.0,
        available_spare: page[3],
        available_spare_threshold: page[4],
        percentage_used: page[5],
        data_units_read: u128_at(32),
        data_units_written: u128_at(48),
        host_read_commands: u128_at(64),
        host_write_commands: u128_at(80),
        controller_busy_minutes: u128_at(96),
        power_cycles: u128_at(112),
        power_on_hours: u128_at(128),
        unsafe_shutdowns: u128_at(144),
        media_errors: u128_at(160),
        error_log_entries: u128_at(176),
        warning_temp_minutes: u32_at(192),
        critical_temp_minutes: u32_at(196),
    }
}

freebsd_only!(Smart, "smart");

#[cfg(target_os = "freebsd")]
pub use freebsd::Smart;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::{
        collections::HashMap,
        ffi::{
            CString,
            c_char,
            c_int,
            c_void,
        },
        fs::File,
        io,
        os::fd::AsRawFd,
    };

    use anyhow::{
        Context,
        Result,
        anyhow,
    };
    use metrics::gauge;

    use super::{
        Config,
        Identity,
        ata_attributes,
        ata_health,
        ata_identity,
        ata_smart_enabled,
        ata_summary,
        attribute_name,
        describe,
        nvme_health,
        nvme_identity,
    };
    use crate::{
        collector::Collector,
        sys::freebsd::Mib,
    };

    #[expect(unsafe_code, reason = "libcam FFI declarations")]
    #[link(name = "cam")]
    unsafe extern "C" {
        fn cam_open_device(path: *const c_char, flags: c_int) -> *mut c_void;
        fn cam_close_device(dev: *mut c_void);
        fn cam_send_ccb(dev: *mut c_void, ccb: *mut c_void) -> c_int;
    }

    /// `union ccb` layout (identical in 14.5 and 15.1 headers).
    mod ccb {
        pub const SIZE: usize = 1248;
        pub const RETRY_COUNT: usize = 64;
        pub const FUNC_CODE: usize = 80;
        pub const STATUS: usize = 84;
        pub const FLAGS: usize = 112;
        pub const TIMEOUT: usize = 176;
        pub const CMD: usize = 208;
        pub const RES: usize = 222;
        pub const DATA_PTR: usize = 240;
        pub const DXFER_LEN: usize = 248;
        pub const ATA_FLAGS: usize = 256;
        pub const XPT_ATA_IO: u32 = 0x918;
        pub const CAM_DIR_IN: u32 = 0x40;
        pub const CAM_DIR_NONE: u32 = 0xc0;
        pub const CAM_DEV_QFRZDIS: u32 = 0x400;
        pub const CAM_REQ_CMP: u32 = 0x1;
        pub const CAM_STATUS_MASK: u32 = 0x3f;
        pub const CAM_ATAIO_NEEDRESULT: u8 = 0x08;
    }

    /// `struct nvme_pt_command` layout and `NVME_PASSTHROUGH_CMD`.
    mod nvme {
        pub const SIZE: usize = 104;
        pub const OPC: usize = 0;
        pub const NSID: usize = 4;
        pub const CDW10: usize = 40;
        pub const CPL_STATUS: usize = 64 + 14;
        pub const BUF: usize = 80;
        pub const LEN: usize = 88;
        pub const IS_READ: usize = 92;
        pub const PASSTHROUGH_CMD: libc::c_ulong = 0xc068_6e00;
        pub const OPC_GET_LOG_PAGE: u8 = 0x02;
        pub const OPC_IDENTIFY: u8 = 0x06;
    }

    const ATA_TIMEOUT_MS: u32 = 15_000;

    /// Byte buffer with the alignment of the pointer-bearing kernel structs
    /// (`union ccb`, `struct nvme_pt_command`) built in it.
    #[repr(C, align(8))]
    struct Aligned<const N: usize>([u8; N]);

    /// Register values returned by an ATA command.
    struct AtaResult {
        lba_mid: u8,
        lba_high: u8,
        sector_count: u8,
    }

    struct AtaDevice {
        cam: *mut c_void,
    }

    // SAFETY: the CAM handle is only used by one thread at a time (moved
    // into the blocking task and back).
    #[expect(unsafe_code, reason = "raw CAM handle")]
    unsafe impl Send for AtaDevice {}

    #[expect(unsafe_code, reason = "cam_close_device FFI")]
    impl Drop for AtaDevice {
        fn drop(&mut self) {
            // SAFETY: `cam` came from cam_open_device and is closed once.
            unsafe { cam_close_device(self.cam) };
        }
    }

    #[expect(unsafe_code, reason = "cam_open_device and cam_send_ccb FFI")]
    impl AtaDevice {
        fn open(name: &str) -> io::Result<Self> {
            let path = CString::new(name).map_err(io::Error::other)?;
            // SAFETY: valid C string; returns NULL on failure.
            let cam = unsafe { cam_open_device(path.as_ptr(), libc::O_RDWR) };
            if cam.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { cam })
        }

        /// Sends one PIO data-in (512 bytes) or non-data ATA command.
        fn command(
            &mut self,
            command: u8,
            features: u8,
            lba_mid: u8,
            lba_high: u8,
            data: Option<&mut [u8; 512]>,
        ) -> io::Result<AtaResult> {
            let mut buf = Aligned([0u8; ccb::SIZE]);
            let c: &mut [u8] = &mut buf.0;
            let put32 =
                |c: &mut [u8], at: usize, v: u32| c[at..at + 4].copy_from_slice(&v.to_ne_bytes());
            let (dir, ptr, len) = match data {
                Some(d) => (ccb::CAM_DIR_IN, d.as_mut_ptr(), 512u32),
                None => (ccb::CAM_DIR_NONE, std::ptr::null_mut(), 0),
            };
            // cam_fill_ataio()
            put32(c, ccb::FUNC_CODE, ccb::XPT_ATA_IO);
            put32(c, ccb::FLAGS, dir | ccb::CAM_DEV_QFRZDIS);
            c[ccb::RETRY_COUNT..ccb::RETRY_COUNT + 2].copy_from_slice(&0u16.to_ne_bytes());
            put32(c, ccb::TIMEOUT, ATA_TIMEOUT_MS);
            c[ccb::DATA_PTR..ccb::DATA_PTR + 8].copy_from_slice(&(ptr as u64).to_ne_bytes());
            put32(c, ccb::DXFER_LEN, len);
            c[ccb::ATA_FLAGS] = 0;
            // struct ata_cmd
            let cmd = &mut c[ccb::CMD..ccb::CMD + 14];
            cmd[0] = ccb::CAM_ATAIO_NEEDRESULT;
            cmd[1] = command;
            cmd[2] = features;
            cmd[4] = lba_mid;
            cmd[5] = lba_high;
            cmd[6] = 0x40; // device: LBA mode
            cmd[11] = u8::from(len > 0); // sector count
            // SAFETY: the CCB buffer and the data buffer outlive the call.
            if unsafe { cam_send_ccb(self.cam, c.as_mut_ptr().cast()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let status = u32::from_ne_bytes(c[ccb::STATUS..ccb::STATUS + 4].try_into().expect("4"));
            if status & ccb::CAM_STATUS_MASK != ccb::CAM_REQ_CMP {
                return Err(io::Error::other(format!(
                    "ATA command {command:#x} failed (CAM status {status:#x})"
                )));
            }
            let res = &c[ccb::RES..ccb::RES + 12];
            Ok(AtaResult {
                lba_mid: res[4],
                lba_high: res[5],
                sector_count: res[10],
            })
        }
    }

    struct NvmeDevice {
        file: File,
    }

    impl NvmeDevice {
        fn open(name: &str) -> io::Result<Self> {
            Ok(Self {
                file: File::options()
                    .read(true)
                    .write(true)
                    .open(format!("/dev/{name}"))?,
            })
        }

        #[expect(unsafe_code, reason = "NVMe passthrough ioctl")]
        fn admin(&self, opc: u8, nsid: u32, cdw10: u32, buf: &mut [u8]) -> io::Result<()> {
            let mut pt = Aligned([0u8; nvme::SIZE]);
            let p: &mut [u8] = &mut pt.0;
            p[nvme::OPC] = opc;
            p[nvme::NSID..nvme::NSID + 4].copy_from_slice(&nsid.to_le_bytes());
            p[nvme::CDW10..nvme::CDW10 + 4].copy_from_slice(&cdw10.to_le_bytes());
            p[nvme::BUF..nvme::BUF + 8].copy_from_slice(&(buf.as_mut_ptr() as u64).to_ne_bytes());
            let len = u32::try_from(buf.len()).map_err(io::Error::other)?;
            p[nvme::LEN..nvme::LEN + 4].copy_from_slice(&len.to_ne_bytes());
            p[nvme::IS_READ..nvme::IS_READ + 4].copy_from_slice(&1u32.to_ne_bytes());
            // SAFETY: `pt` is a valid nvme_pt_command and `buf` outlives the
            // call.
            if unsafe { libc::ioctl(self.file.as_raw_fd(), nvme::PASSTHROUGH_CMD, p.as_mut_ptr()) }
                != 0
            {
                return Err(io::Error::last_os_error());
            }
            let status = u16::from_le_bytes([p[nvme::CPL_STATUS], p[nvme::CPL_STATUS + 1]]);
            // nvme_completion_is_error(): status code (bits 1-8) or type
            // (9-11).
            if (status >> 1) & 0xff != 0 || (status >> 9) & 0x7 != 0 {
                return Err(io::Error::other(format!(
                    "NVMe admin command {opc:#x} failed (status {status:#x})"
                )));
            }
            Ok(())
        }
    }

    enum Device {
        Ata(AtaDevice),
        Nvme(NvmeDevice),
    }

    pub struct Smart {
        config: Config,
        devices: HashMap<String, Device>,
    }

    impl Smart {
        pub fn new(config: &Config) -> Result<Self> {
            if !matches!(config.nocheck.as_str(), "standby" | "never") {
                anyhow::bail!(
                    "smart nocheck must be \"standby\" or \"never\", not {:?}",
                    config.nocheck
                );
            }
            Ok(Self {
                config: config.clone(),
                devices: HashMap::new(),
            })
        }
    }

    /// SATA disks from `kern.disks`, NVMe controllers from `/dev/nvmeN`.
    fn discover() -> Result<Vec<String>> {
        let disks = Mib::new("kern.disks")?.read_string()?;
        let mut names: Vec<String> = disks
            .split_whitespace()
            .filter(|d| d.starts_with("ada"))
            .map(str::to_owned)
            .collect();
        for entry in std::fs::read_dir("/dev")? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name
                .strip_prefix("nvme")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }

    /// Everything read from one device in one collection.
    enum Reading {
        Standby,
        Ata {
            identity: Identity,
            healthy: Option<bool>,
            attrs: Vec<super::Attribute>,
        },
        Nvme {
            identity: Identity,
            health: super::NvmeHealth,
        },
    }

    fn read_ata(dev: &mut AtaDevice, nocheck_standby: bool) -> io::Result<Reading> {
        if nocheck_standby {
            // CHECK POWER MODE: count 0x00 (or 0x01) = standby.
            let mode = dev.command(0xe5, 0, 0, 0, None)?;
            if mode.sector_count <= 0x01 {
                return Ok(Reading::Standby);
            }
        }
        let mut id_data = [0u8; 512];
        dev.command(0xec, 0, 0, 0, Some(&mut id_data))?;
        let identity = ata_identity(&id_data);
        if !ata_smart_enabled(&id_data) {
            return Ok(Reading::Ata {
                identity,
                healthy: None,
                attrs: Vec::new(),
            });
        }
        // SMART RETURN STATUS / READ DATA / READ THRESHOLDS (B0h, LBA
        // 0xC24F00).
        let status = dev.command(0xb0, 0xda, 0x4f, 0xc2, None)?;
        let mut data = [0u8; 512];
        dev.command(0xb0, 0xd0, 0x4f, 0xc2, Some(&mut data))?;
        let mut thresholds = [0u8; 512];
        // Thresholds are obsolete in ACS-3; don't fail without them.
        let thresholds = dev
            .command(0xb0, 0xd1, 0x4f, 0xc2, Some(&mut thresholds))
            .ok()
            .map(|_| thresholds);
        Ok(Reading::Ata {
            identity,
            healthy: ata_health(status.lba_mid, status.lba_high),
            attrs: ata_attributes(&data, thresholds.as_ref()),
        })
    }

    fn read_nvme(dev: &NvmeDevice) -> io::Result<Reading> {
        let mut identify = vec![0u8; 4096];
        dev.admin(nvme::OPC_IDENTIFY, 0, 1, &mut identify)?; // CNS 1: controller
        let mut page = [0u8; 512];
        // Log page 0x02, global namespace, NUMDL = 512/4 - 1.
        dev.admin(
            nvme::OPC_GET_LOG_PAGE,
            0xffff_ffff,
            (127 << 16) | 0x02,
            &mut page,
        )?;
        Ok(Reading::Nvme {
            identity: nvme_identity(&identify),
            health: nvme_health(&page),
        })
    }

    /// Opens (or reuses) and reads every wanted device. Runs on the
    /// blocking pool: ATA commands can take tens of milliseconds.
    fn gather(
        config: &Config,
        devices: &mut HashMap<String, Device>,
    ) -> Result<Vec<(String, Result<Reading>)>> {
        let names: Vec<String> = discover()?
            .into_iter()
            .filter(|n| config.wants(n))
            .collect();
        devices.retain(|name, _| names.contains(name));
        let standby = config.nocheck == "standby";
        let mut out = Vec::new();
        for name in names {
            let result = (|| -> Result<Reading> {
                if !devices.contains_key(&name) {
                    let dev = if name.starts_with("nvme") {
                        Device::Nvme(
                            NvmeDevice::open(&name)
                                .with_context(|| format!("opening /dev/{name}"))?,
                        )
                    } else {
                        Device::Ata(
                            AtaDevice::open(&name)
                                .with_context(|| format!("opening {name} via CAM"))?,
                        )
                    };
                    devices.insert(name.clone(), dev);
                }
                let reading = match devices.get_mut(&name).expect("inserted above") {
                    Device::Ata(dev) => read_ata(dev, standby),
                    Device::Nvme(dev) => read_nvme(dev),
                };
                if reading.is_err() {
                    // Reopen next time, e.g. after the device was re-attached.
                    devices.remove(&name);
                }
                Ok(reading?)
            })();
            out.push((name, result));
        }
        Ok(out)
    }

    fn export(device: &str, reading: &Reading, attributes: bool) {
        let d = || device.to_owned();
        let info = |typ: &'static str, id: &Identity| {
            gauge!("smart_device_info", "device" => d(), "type" => typ, "model" => id.model.clone(),
                "serial" => id.serial.clone(), "firmware" => id.firmware.clone())
            .set(1.0);
        };
        match reading {
            Reading::Standby => gauge!("smart_device_standby", "device" => d()).set(1.0),
            Reading::Ata {
                identity,
                healthy,
                attrs,
            } => {
                gauge!("smart_device_standby", "device" => d()).set(0.0);
                info("ata", identity);
                if let Some(ok) = healthy {
                    gauge!("smart_device_healthy", "device" => d()).set(f64::from(u8::from(*ok)));
                }
                let (temperature, power_on, cycles) = ata_summary(attrs);
                if let Some(t) = temperature {
                    gauge!("smart_temperature_celsius", "device" => d()).set(t);
                }
                if let Some(s) = power_on {
                    gauge!("smart_power_on_seconds", "device" => d()).set(s);
                }
                if let Some(c) = cycles {
                    gauge!("smart_power_cycles", "device" => d()).set(c);
                }
                if attributes {
                    for a in attrs {
                        let labels = [
                            ("device", d()),
                            ("id", a.id.to_string()),
                            ("name", attribute_name(a.id).to_owned()),
                        ];
                        gauge!("smart_attribute_value", &labels).set(f64::from(a.value));
                        gauge!("smart_attribute_worst", &labels).set(f64::from(a.worst));
                        if let Some(t) = a.threshold {
                            gauge!("smart_attribute_threshold", &labels).set(f64::from(t));
                        }
                        gauge!("smart_attribute_raw", &labels).set(a.raw as f64);
                    }
                }
            }
            Reading::Nvme {
                identity,
                health: h,
            } => {
                info("nvme", identity);
                let set = |name: &'static str, v: f64| gauge!(name, "device" => d()).set(v);
                set(
                    "smart_device_healthy",
                    f64::from(u8::from(h.critical_warning == 0)),
                );
                set("smart_temperature_celsius", h.temperature_celsius);
                set("smart_power_on_seconds", h.power_on_hours as f64 * 3600.0);
                set("smart_power_cycles", h.power_cycles as f64);
                set("smart_nvme_critical_warning", f64::from(h.critical_warning));
                set(
                    "smart_nvme_available_spare_ratio",
                    f64::from(h.available_spare) / 100.0,
                );
                set(
                    "smart_nvme_available_spare_threshold_ratio",
                    f64::from(h.available_spare_threshold) / 100.0,
                );
                set(
                    "smart_nvme_percentage_used_ratio",
                    f64::from(h.percentage_used) / 100.0,
                );
                // A data unit is 1000 512-byte blocks.
                set(
                    "smart_nvme_data_read_bytes",
                    h.data_units_read as f64 * 512_000.0,
                );
                set(
                    "smart_nvme_data_written_bytes",
                    h.data_units_written as f64 * 512_000.0,
                );
                set("smart_nvme_host_read_commands", h.host_read_commands as f64);
                set(
                    "smart_nvme_host_write_commands",
                    h.host_write_commands as f64,
                );
                set(
                    "smart_nvme_controller_busy_seconds",
                    h.controller_busy_minutes as f64 * 60.0,
                );
                set("smart_nvme_unsafe_shutdowns", h.unsafe_shutdowns as f64);
                set("smart_nvme_media_errors", h.media_errors as f64);
                set("smart_nvme_error_log_entries", h.error_log_entries as f64);
                set(
                    "smart_nvme_warning_temperature_seconds",
                    f64::from(h.warning_temp_minutes) * 60.0,
                );
                set(
                    "smart_nvme_critical_temperature_seconds",
                    f64::from(h.critical_temp_minutes) * 60.0,
                );
            }
        }
    }

    impl Collector for Smart {
        fn name(&self) -> &'static str {
            "smart"
        }

        fn describe(&self) {
            describe();
        }

        async fn collect(&mut self) -> Result<()> {
            let config = self.config.clone();
            let mut devices = std::mem::take(&mut self.devices);
            let (devices, result) = tokio::task::spawn_blocking(move || {
                let result = gather(&config, &mut devices);
                (devices, result)
            })
            .await?;
            self.devices = devices;
            let mut first_error = None;
            for (name, reading) in result? {
                match reading {
                    Ok(reading) => export(&name, &reading, self.config.attributes),
                    Err(err) => {
                        first_error.get_or_insert_with(|| anyhow!("{name}: {err:#}"));
                    }
                }
            }
            first_error.map_or(Ok(()), Err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identify() -> [u8; 512] {
        let mut d = [0u8; 512];
        let put = |d: &mut [u8; 512], at: usize, s: &str, len: usize| {
            let mut padded = s.as_bytes().to_vec();
            padded.resize(len, b' ');
            for (i, w) in padded.as_chunks::<2>().0.iter().enumerate() {
                d[at + 2 * i] = w[1];
                d[at + 2 * i + 1] = w[0];
            }
        };
        put(&mut d, 20, "SATA0001", 20);
        put(&mut d, 46, "2.5+", 8);
        put(&mut d, 54, "TOSHIBA MG10AFA22TEY", 40);
        d[164] = 1; // word 82: SMART supported
        d[170] = 1; // word 85: SMART enabled
        d
    }

    #[test]
    fn parses_ata_identify() {
        let id = ata_identity(&identify());
        assert_eq!(
            id,
            Identity {
                model: "TOSHIBA MG10AFA22TEY".into(),
                serial: "SATA0001".into(),
                firmware: "2.5+".into()
            }
        );
        assert!(ata_smart_enabled(&identify()));
        assert!(!ata_smart_enabled(&[0; 512]));
    }

    fn attribute(table: &mut [u8; 512], slot: usize, id: u8, value: u8, worst: u8, raw: u64) {
        let e = &mut table[2 + slot * 12..2 + slot * 12 + 12];
        e[0] = id;
        e[3] = value;
        e[4] = worst;
        e[5..11].copy_from_slice(&raw.to_le_bytes()[..6]);
    }

    #[test]
    fn parses_attribute_table() {
        let mut data = [0u8; 512];
        attribute(&mut data, 0, 9, 99, 99, 12_345);
        attribute(&mut data, 1, 194, 100, 100, 0x0028_0012_0022); // 34 °C, min/max in high bytes
        attribute(&mut data, 2, 5, 100, 100, 0);
        attribute(&mut data, 3, 12, 100, 100, 42);
        let mut thresholds = [0u8; 512];
        thresholds[2 + 24] = 5; // slot 2: id 5
        thresholds[2 + 25] = 50;
        let attrs = ata_attributes(&data, Some(&thresholds));
        assert_eq!(attrs.len(), 4);
        assert_eq!(
            attrs[0],
            Attribute {
                id: 9,
                value: 99,
                worst: 99,
                threshold: None,
                raw: 12_345
            }
        );
        assert_eq!(attrs[2].threshold, Some(50));
        let (temp, power_on, cycles) = ata_summary(&attrs);
        assert_eq!(temp, Some(34.0));
        assert_eq!(power_on, Some(12_345.0 * 3600.0));
        assert_eq!(cycles, Some(42.0));
        assert_eq!(attribute_name(197), "Current_Pending_Sector");
        assert_eq!(attribute_name(27), "MAMR_Health_Monitor");
    }

    #[test]
    fn maps_return_status() {
        assert_eq!(ata_health(0x4f, 0xc2), Some(true));
        assert_eq!(ata_health(0xf4, 0x2c), Some(false));
        assert_eq!(ata_health(0, 0), None);
    }

    #[test]
    fn parses_nvme_health_page() {
        let mut p = [0u8; 512];
        p[0] = 0;
        p[1..3].copy_from_slice(&311u16.to_le_bytes()); // 311 K = 38 °C
        p[3] = 100;
        p[4] = 10;
        p[5] = 3;
        p[32..48].copy_from_slice(&1000u128.to_le_bytes());
        p[128..144].copy_from_slice(&5000u128.to_le_bytes());
        p[192..196].copy_from_slice(&7u32.to_le_bytes());
        let h = nvme_health(&p);
        assert_eq!(h.temperature_celsius, 38.0);
        assert_eq!(
            (
                h.available_spare,
                h.available_spare_threshold,
                h.percentage_used
            ),
            (100, 10, 3)
        );
        assert_eq!(h.data_units_read, 1000);
        assert_eq!(h.power_on_hours, 5000);
        assert_eq!(h.warning_temp_minutes, 7);
    }

    #[test]
    fn filters_devices() {
        let c: Config = toml::from_str("excludes = ['/dev/ses0', 'ada3']").unwrap();
        assert!(c.wants("ada0"));
        assert!(!c.wants("ada3"));
        let only: Config = toml::from_str("devices = ['/dev/nvme0']").unwrap();
        assert!(only.wants("nvme0") && !only.wants("ada0"));
    }
}
