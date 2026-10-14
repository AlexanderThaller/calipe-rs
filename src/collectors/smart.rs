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
//! On Linux the same commands take other transports (as smartctl's Linux
//! backend does):
//!
//! * SATA (`sdX` whose SCSI vendor is `ATA`, i.e. behind libata or a SAT
//!   capable HBA): `SG_IO` on the block device with ATA PASS-THROUGH (16) CDBs.
//!   Commands whose result is in the registers (CHECK POWER MODE, SMART RETURN
//!   STATUS) set `CK_COND`, and the registers come back in the sense data (ATA
//!   Status Return descriptor, or fixed format as libata sends by default).
//!   Needs `CAP_SYS_RAWIO`, as `ATA_16` isn't on the kernel's list of
//!   unprivileged SCSI commands.
//! * NVMe (`nvmeN`): `NVME_IOCTL_ADMIN_CMD` on the controller character device.
//!   Needs `CAP_SYS_ADMIN`.
//!
//! With `nocheck = "standby"` (the default, like Telegraf), a SATA disk in
//! standby is not read, so monitoring doesn't spin it up.
//!
//! SMART values are device state (lifetime totals of the physical disk), so
//! they're exported as gauges: a replaced disk starts over.

// The helpers are only used by the FreeBSD and Linux implementations (and
// tests).
#![cfg_attr(
    not(any(target_os = "freebsd", target_os = "linux")),
    expect(dead_code, reason = "used by the FreeBSD and Linux implementations")
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
    /// Devices to read (e.g. `["ada0", "nvme0"]`, on Linux `["sda", "nvme0"]`);
    /// empty means all found.
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

/// SCSI/ATA Translation (SAT): ATA PASS-THROUGH (16) CDBs and the ATA
/// registers in the sense data.
#[cfg(any(target_os = "linux", test))]
mod sat {
    /// ATA registers returned by the SATL.
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Registers {
        pub error: u8,
        pub status: u8,
        pub sector_count: u8,
        pub lba_mid: u8,
        pub lba_high: u8,
    }

    /// SCSI status CHECK CONDITION.
    const CHECK_CONDITION: u8 = 0x02;
    /// ASC/ASCQ 00h/1Dh: ATA PASS-THROUGH INFORMATION AVAILABLE.
    const ATA_INFO_AVAILABLE: (u8, u8) = (0x00, 0x1d);
    /// ATA status ERR bit.
    const ATA_STATUS_ERR: u8 = 0x01;

    /// ATA PASS-THROUGH (16) for a 28-bit command: PIO data-in of one
    /// 512-byte block, or non-data. `ck_cond` asks for the registers in the
    /// sense data.
    pub fn pass_through_16(
        command: u8,
        features: u8,
        lba_mid: u8,
        lba_high: u8,
        data_in: bool,
        ck_cond: bool,
    ) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = 0x85;
        // PROTOCOL: 4 = PIO data-in, 3 = non-data.
        cdb[1] = if data_in { 4 << 1 } else { 3 << 1 };
        // T_DIR = from device, BYTE_BLOCK = blocks, T_LENGTH = in COUNT.
        cdb[2] = if data_in { 0x0e } else { 0 } | if ck_cond { 0x20 } else { 0 };
        cdb[4] = features;
        cdb[6] = u8::from(data_in); // sector count
        cdb[10] = lba_mid;
        cdb[12] = lba_high;
        cdb[13] = 0x40; // device: LBA mode
        cdb[14] = command;
        cdb
    }

    /// The ATA registers from sense data: the ATA Status Return descriptor
    /// (09h) of descriptor-format sense, or fixed-format sense with ASC/ASCQ
    /// 00h/1Dh, which libata sends unless descriptor sense is enabled.
    pub fn registers(sense: &[u8]) -> Option<Registers> {
        match sense.first()? & 0x7f {
            0x72 | 0x73 => {
                let len = usize::from(*sense.get(7)?);
                let mut descs = sense.get(8..(8 + len).min(sense.len()))?;
                while let [code, len, ..] = *descs {
                    let d = descs.get(..2 + usize::from(len))?;
                    if code == 0x09 && d.len() >= 14 {
                        return Some(Registers {
                            error: d[3],
                            sector_count: d[5],
                            lba_mid: d[9],
                            lba_high: d[11],
                            status: d[13],
                        });
                    }
                    descs = &descs[d.len()..];
                }
                None
            }
            0x70 | 0x71 => {
                let s = sense.get(..14)?;
                ((s[12], s[13]) == ATA_INFO_AVAILABLE).then_some(Registers {
                    error: s[3],
                    status: s[4],
                    sector_count: s[6],
                    lba_mid: s[10],
                    lba_high: s[11],
                })
            }
            _ => None,
        }
    }

    /// Sense key, ASC and ASCQ.
    fn sense_code(sense: &[u8]) -> Option<(u8, u8, u8)> {
        match sense.first()? & 0x7f {
            0x72 | 0x73 => Some((sense.get(1)? & 0x0f, *sense.get(2)?, *sense.get(3)?)),
            0x70 | 0x71 => Some((sense.get(2)? & 0x0f, *sense.get(12)?, *sense.get(13)?)),
            _ => None,
        }
    }

    /// Interprets the SCSI status and sense data of a pass-through command.
    /// `Ok(None)`: success without registers (GOOD status, nothing in the
    /// sense buffer).
    pub fn outcome(scsi_status: u8, sense: &[u8]) -> Result<Option<Registers>, String> {
        let regs = registers(sense);
        match scsi_status & 0x7e {
            0 => {}
            CHECK_CONDITION => {
                // NO SENSE or RECOVERED ERROR carry the registers of a
                // completed command; anything else is a failure.
                let code = sense_code(sense);
                if !matches!(code, Some((0 | 1, ..))) || regs.is_none() {
                    return Err(match code {
                        Some((key, asc, ascq)) => format!(
                            "check condition (sense key {key:#x}, ASC/ASCQ {asc:#04x}/{ascq:#04x})"
                        ),
                        None => "check condition without sense data".to_owned(),
                    });
                }
            }
            status => return Err(format!("SCSI status {status:#x}")),
        }
        match regs {
            Some(r) if r.status & ATA_STATUS_ERR != 0 => Err(format!(
                "ATA error (status {:#x}, error {:#x})",
                r.status, r.error
            )),
            regs => Ok(regs),
        }
    }
}

native_only!(Smart, "smart");

#[cfg(any(target_os = "freebsd", target_os = "linux"))]
pub use native::Smart;

#[cfg(target_os = "freebsd")]
use freebsd as platform;
#[cfg(target_os = "linux")]
use linux as platform;

/// Reading and exporting, shared by the platforms; [`platform`] supplies
/// device discovery and the command transports.
#[cfg(any(target_os = "freebsd", target_os = "linux"))]
mod native {
    use std::{
        collections::HashMap,
        io,
    };

    use anyhow::{
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
        platform::{
            AtaDevice,
            NvmeDevice,
            discover,
        },
    };
    use crate::collector::Collector;

    /// Register values returned by an ATA command.
    pub struct AtaResult {
        pub lba_mid: u8,
        pub lba_high: u8,
        pub sector_count: u8,
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
        let mut identify = Box::new([0u8; 4096]);
        dev.identify_controller(&mut identify)?;
        let mut page = [0u8; 512];
        dev.health_log(&mut page)?;
        Ok(Reading::Nvme {
            identity: nvme_identity(&identify[..]),
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
                        Device::Nvme(NvmeDevice::open(&name)?)
                    } else {
                        Device::Ata(AtaDevice::open(&name)?)
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

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::{
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
    };

    use super::native::AtaResult;
    use crate::sys::freebsd::Mib;

    #[expect(unsafe_code, reason = "libcam FFI declarations")]
    #[link(name = "cam")]
    unsafe extern "C" {
        fn cam_open_device(path: *const c_char, flags: c_int) -> *mut c_void;
        fn cam_close_device(dev: *mut c_void);
        fn cam_send_ccb(dev: *mut c_void, ccb: *mut c_void) -> c_int;
    }

    /// `union ccb` layout (identical in 14.5 and 15.1 headers).
    mod ccb {
        /// `sizeof(union ccb)`.
        pub const SIZE: usize = 1248;
        /// The CCB buffer we pass. `CAMIOCOMMAND` copies the *installed*
        /// libcam's `sizeof(union ccb)` in and out, so a newer release with a
        /// larger CCB must not overrun our buffer.
        pub const BUF_SIZE: usize = 4096;
        const _: () = assert!(SIZE <= BUF_SIZE);
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

    pub struct AtaDevice {
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
        pub fn open(name: &str) -> Result<Self> {
            let open = || {
                let path = CString::new(name).map_err(io::Error::other)?;
                // SAFETY: valid C string; returns NULL on failure.
                let cam = unsafe { cam_open_device(path.as_ptr(), libc::O_RDWR) };
                if cam.is_null() {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self { cam })
            };
            open().with_context(|| format!("opening {name} via CAM"))
        }

        /// Sends one PIO data-in (512 bytes) or non-data ATA command.
        pub fn command(
            &mut self,
            command: u8,
            features: u8,
            lba_mid: u8,
            lba_high: u8,
            data: Option<&mut [u8; 512]>,
        ) -> io::Result<AtaResult> {
            let mut buf = Aligned([0u8; ccb::BUF_SIZE]);
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

    pub struct NvmeDevice {
        file: File,
    }

    impl NvmeDevice {
        pub fn open(name: &str) -> Result<Self> {
            Ok(Self {
                file: File::options()
                    .read(true)
                    .write(true)
                    .open(format!("/dev/{name}"))
                    .with_context(|| format!("opening /dev/{name}"))?,
            })
        }

        /// IDENTIFY with CNS 1 (controller), which always returns 4 KiB.
        #[expect(unsafe_code, reason = "calls the unsafe admin()")]
        pub fn identify_controller(&self, buf: &mut [u8; 4096]) -> io::Result<()> {
            // SAFETY: the controller data structure is exactly 4096 bytes.
            unsafe { self.admin(nvme::OPC_IDENTIFY, 0, 1, buf) }
        }

        /// GET LOG PAGE 02h (SMART / health), global namespace.
        #[expect(unsafe_code, reason = "calls the unsafe admin()")]
        pub fn health_log(&self, buf: &mut [u8; 512]) -> io::Result<()> {
            // NUMDL: dwords to transfer minus one, for the 512-byte `buf`.
            const NUMDL: u32 = 512 / 4 - 1;
            // SAFETY: NUMDL requests exactly `buf.len()` bytes.
            unsafe {
                self.admin(
                    nvme::OPC_GET_LOG_PAGE,
                    0xffff_ffff,
                    (NUMDL << 16) | 0x02,
                    buf,
                )
            }
        }

        /// Runs a data-in admin command into `buf`.
        ///
        /// # Safety
        ///
        /// The command must transfer at most `buf.len()` bytes. The kernel
        /// only maps `buf.len()` bytes, but the device's transfer size comes
        /// from `opc`/`cdw10`, and a larger transfer can DMA past `buf`.
        #[expect(unsafe_code, reason = "NVMe passthrough ioctl")]
        unsafe fn admin(&self, opc: u8, nsid: u32, cdw10: u32, buf: &mut [u8]) -> io::Result<()> {
            let mut pt = Aligned([0u8; nvme::SIZE]);
            let p: &mut [u8] = &mut pt.0;
            p[nvme::OPC] = opc;
            p[nvme::NSID..nvme::NSID + 4].copy_from_slice(&nsid.to_le_bytes());
            p[nvme::CDW10..nvme::CDW10 + 4].copy_from_slice(&cdw10.to_le_bytes());
            p[nvme::BUF..nvme::BUF + 8].copy_from_slice(&(buf.as_mut_ptr() as u64).to_ne_bytes());
            let len = u32::try_from(buf.len()).map_err(io::Error::other)?;
            p[nvme::LEN..nvme::LEN + 4].copy_from_slice(&len.to_ne_bytes());
            p[nvme::IS_READ..nvme::IS_READ + 4].copy_from_slice(&1u32.to_ne_bytes());
            // SAFETY: `pt` is a valid nvme_pt_command, `buf` outlives the call,
            // and the caller guarantees the transfer fits in `buf`.
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

    /// SATA disks from `kern.disks`, NVMe controllers from `/dev/nvmeN`.
    pub fn discover() -> Result<Vec<String>> {
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
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        ffi::c_void,
        fs::File,
        io,
        os::{
            fd::AsRawFd,
            unix::fs::OpenOptionsExt,
        },
    };

    use anyhow::{
        Context,
        Result,
    };

    use super::{
        native::AtaResult,
        sat,
    };

    /// `struct sg_io_hdr` from `<scsi/sg.h>`.
    #[repr(C)]
    struct SgIoHdr {
        interface_id: i32,
        dxfer_direction: i32,
        cmd_len: u8,
        mx_sb_len: u8,
        iovec_count: u16,
        dxfer_len: u32,
        dxferp: *mut c_void,
        cmdp: *const u8,
        sbp: *mut u8,
        timeout: u32,
        flags: u32,
        pack_id: i32,
        usr_ptr: *mut c_void,
        status: u8,
        masked_status: u8,
        msg_status: u8,
        sb_len_wr: u8,
        host_status: u16,
        driver_status: u16,
        resid: i32,
        duration: u32,
        info: u32,
    }

    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(size_of::<SgIoHdr>() == 88);

    const SG_IO: libc::c_ulong = 0x2285;
    const SG_DXFER_NONE: i32 = -1;
    const SG_DXFER_FROM_DEV: i32 = -3;
    /// `driver_status` bits other than `DRIVER_SENSE` (0x08) mean the
    /// request failed in the driver.
    const DRIVER_STATUS_MASK: u16 = 0x0f;
    const DRIVER_SENSE: u16 = 0x08;

    /// `struct nvme_passthru_cmd` (`nvme_admin_cmd`) from
    /// `<linux/nvme_ioctl.h>`.
    #[repr(C)]
    #[derive(Default)]
    struct NvmePassthruCmd {
        opcode: u8,
        flags: u8,
        rsvd1: u16,
        nsid: u32,
        cdw2: u32,
        cdw3: u32,
        metadata: u64,
        addr: u64,
        metadata_len: u32,
        data_len: u32,
        cdw10: u32,
        cdw11: u32,
        cdw12: u32,
        cdw13: u32,
        cdw14: u32,
        cdw15: u32,
        timeout_ms: u32,
        result: u32,
    }

    const _: () = assert!(size_of::<NvmePassthruCmd>() == 72);

    /// `_IOWR('N', 0x41, struct nvme_admin_cmd)`.
    const NVME_IOCTL_ADMIN_CMD: libc::c_ulong = 0xc048_4e41;
    const OPC_GET_LOG_PAGE: u8 = 0x02;
    const OPC_IDENTIFY: u8 = 0x06;

    const ATA_TIMEOUT_MS: u32 = 15_000;

    pub struct AtaDevice {
        file: File,
    }

    impl AtaDevice {
        pub fn open(name: &str) -> Result<Self> {
            // O_NONBLOCK: don't wait for removable media, like sg_utils.
            let file = File::options()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(format!("/dev/{name}"))
                .with_context(|| format!("opening /dev/{name}"))?;
            Ok(Self { file })
        }

        /// Sends one PIO data-in (512 bytes) or non-data ATA command as ATA
        /// PASS-THROUGH (16). Non-data commands ask for the registers.
        #[expect(unsafe_code, reason = "SG_IO ioctl")]
        pub fn command(
            &mut self,
            command: u8,
            features: u8,
            lba_mid: u8,
            lba_high: u8,
            data: Option<&mut [u8; 512]>,
        ) -> io::Result<AtaResult> {
            let data_in = data.is_some();
            let cdb = sat::pass_through_16(command, features, lba_mid, lba_high, data_in, !data_in);
            let mut sense = [0u8; 64];
            let (direction, ptr, len) = match data {
                Some(d) => (SG_DXFER_FROM_DEV, d.as_mut_ptr().cast(), 512),
                None => (SG_DXFER_NONE, std::ptr::null_mut(), 0),
            };
            let mut hdr = SgIoHdr {
                interface_id: i32::from(b'S'),
                dxfer_direction: direction,
                cmd_len: 16,
                mx_sb_len: 64,
                iovec_count: 0,
                dxfer_len: len,
                dxferp: ptr,
                cmdp: cdb.as_ptr(),
                sbp: sense.as_mut_ptr(),
                timeout: ATA_TIMEOUT_MS,
                flags: 0,
                pack_id: 0,
                usr_ptr: std::ptr::null_mut(),
                status: 0,
                masked_status: 0,
                msg_status: 0,
                sb_len_wr: 0,
                host_status: 0,
                driver_status: 0,
                resid: 0,
                duration: 0,
                info: 0,
            };
            // SAFETY: `hdr` is a valid sg_io_hdr; the CDB, sense and data
            // buffers it points to outlive the call and have the lengths
            // given in it.
            if unsafe { libc::ioctl(self.file.as_raw_fd(), SG_IO, &raw mut hdr) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let failed =
                |what: String| io::Error::other(format!("ATA command {command:#x} failed: {what}"));
            if hdr.host_status != 0 {
                return Err(failed(format!("host status {:#x}", hdr.host_status)));
            }
            let driver = hdr.driver_status & DRIVER_STATUS_MASK;
            if driver != 0 && driver != DRIVER_SENSE {
                return Err(failed(format!("driver status {:#x}", hdr.driver_status)));
            }
            let sense = &sense[..usize::from(hdr.sb_len_wr).min(sense.len())];
            let regs = sat::outcome(hdr.status, sense).map_err(failed)?;
            match regs {
                Some(r) => Ok(AtaResult {
                    lba_mid: r.lba_mid,
                    lba_high: r.lba_high,
                    sector_count: r.sector_count,
                }),
                None if data_in => Ok(AtaResult {
                    lba_mid: 0,
                    lba_high: 0,
                    sector_count: 0,
                }),
                None => Err(failed("no ATA registers returned".to_owned())),
            }
        }
    }

    pub struct NvmeDevice {
        file: File,
    }

    impl NvmeDevice {
        pub fn open(name: &str) -> Result<Self> {
            Ok(Self {
                file: File::open(format!("/dev/{name}"))
                    .with_context(|| format!("opening /dev/{name}"))?,
            })
        }

        /// IDENTIFY with CNS 1 (controller), which always returns 4 KiB.
        #[expect(unsafe_code, reason = "calls the unsafe admin()")]
        pub fn identify_controller(&self, buf: &mut [u8; 4096]) -> io::Result<()> {
            // SAFETY: the controller data structure is exactly 4096 bytes.
            unsafe { self.admin(OPC_IDENTIFY, 0, 1, buf) }
        }

        /// GET LOG PAGE 02h (SMART / health), global namespace.
        #[expect(unsafe_code, reason = "calls the unsafe admin()")]
        pub fn health_log(&self, buf: &mut [u8; 512]) -> io::Result<()> {
            // NUMDL: dwords to transfer minus one, for the 512-byte `buf`.
            const NUMDL: u32 = 512 / 4 - 1;
            // SAFETY: NUMDL requests exactly `buf.len()` bytes.
            unsafe { self.admin(OPC_GET_LOG_PAGE, 0xffff_ffff, (NUMDL << 16) | 0x02, buf) }
        }

        /// Runs a data-in admin command into `buf`.
        ///
        /// # Safety
        ///
        /// The command must transfer at most `buf.len()` bytes: the device's
        /// transfer size comes from `opc`/`cdw10`, not from `data_len`.
        #[expect(unsafe_code, reason = "NVMe admin ioctl")]
        unsafe fn admin(&self, opc: u8, nsid: u32, cdw10: u32, buf: &mut [u8]) -> io::Result<()> {
            let mut cmd = NvmePassthruCmd {
                opcode: opc,
                nsid,
                addr: buf.as_mut_ptr() as u64,
                data_len: u32::try_from(buf.len()).map_err(io::Error::other)?,
                cdw10,
                ..NvmePassthruCmd::default()
            };
            // SAFETY: `cmd` is a valid nvme_passthru_cmd, `buf` outlives the
            // call, and the caller guarantees the transfer fits in `buf`.
            let ret =
                unsafe { libc::ioctl(self.file.as_raw_fd(), NVME_IOCTL_ADMIN_CMD, &raw mut cmd) };
            match ret {
                0 => Ok(()),
                // A positive return is the NVMe status field of the completion.
                status if status > 0 => Err(io::Error::other(format!(
                    "NVMe admin command {opc:#x} failed (status {status:#x})"
                ))),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    /// SATA disks (SCSI disks whose vendor is `ATA`, i.e. behind libata or a
    /// SATL) from `/sys/block`, NVMe controllers from `/sys/class/nvme`.
    pub fn discover() -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir("/sys/block").context("listing /sys/block")? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with("sd")
                && std::fs::read_to_string(format!("/sys/block/{name}/device/vendor"))
                    .is_ok_and(|vendor| vendor.trim() == "ATA")
            {
                names.push(name);
            }
        }
        match std::fs::read_dir("/sys/class/nvme") {
            Ok(dir) => {
                for entry in dir {
                    let name = entry?.file_name().to_string_lossy().into_owned();
                    if name
                        .strip_prefix("nvme")
                        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                    {
                        names.push(name);
                    }
                }
            }
            // No NVMe driver loaded.
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("listing /sys/class/nvme"),
        }
        names.sort();
        Ok(names)
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
    fn builds_ata_pass_through_cdbs() {
        // SMART READ DATA: PIO data-in, one block, LBA mid/high 4F/C2.
        assert_eq!(
            sat::pass_through_16(0xb0, 0xd0, 0x4f, 0xc2, true, false),
            [
                0x85, 0x08, 0x0e, 0, 0xd0, 0, 1, 0, 0, 0, 0x4f, 0, 0xc2, 0x40, 0xb0, 0
            ]
        );
        // CHECK POWER MODE: non-data with CK_COND.
        assert_eq!(
            sat::pass_through_16(0xe5, 0, 0, 0, false, true),
            [
                0x85, 0x06, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0xe5, 0
            ]
        );
    }

    /// Sense data as libata builds it for a `CK_COND` command: recovered
    /// error, ASC/ASCQ 00h/1Dh.
    fn descriptor_sense(count: u8, mid: u8, high: u8, status: u8) -> Vec<u8> {
        let mut s = vec![0x72, 0x01, 0x00, 0x1d, 0, 0, 0, 14];
        s.extend([
            0x09, 0x0c, 0, 0, 0, count, 0, 0, 0, mid, 0, high, 0x40, status,
        ]);
        s
    }

    fn fixed_sense(count: u8, mid: u8, high: u8, status: u8) -> Vec<u8> {
        let mut s = vec![0xf0, 0, 0x01, 0, status, 0x40, count, 10, 0, 0, mid, high];
        s.extend([0x00, 0x1d, 0, 0, 0, 0]);
        s
    }

    #[test]
    fn reads_registers_from_sense() {
        let ok = sat::Registers {
            error: 0,
            status: 0x50,
            sector_count: 0xff,
            lba_mid: 0x4f,
            lba_high: 0xc2,
        };
        for sense in [
            descriptor_sense(0xff, 0x4f, 0xc2, 0x50),
            fixed_sense(0xff, 0x4f, 0xc2, 0x50),
        ] {
            assert_eq!(sat::registers(&sense), Some(ok));
            assert_eq!(sat::outcome(0x02, &sense), Ok(Some(ok)));
        }
        // An unrelated descriptor before the ATA one is skipped.
        let mut skip = descriptor_sense(0, 0xf4, 0x2c, 0x50);
        skip.splice(8..8, [0x00, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        skip[7] += 12;
        assert_eq!(
            sat::registers(&skip).map(|r| (r.lba_mid, r.lba_high)),
            Some((0xf4, 0x2c))
        );
        // Truncated or other sense data carries no registers.
        assert_eq!(sat::registers(&descriptor_sense(0, 0, 0, 0)[..12]), None);
        let mut other = fixed_sense(0, 0, 0, 0);
        other[13] = 0;
        assert_eq!(sat::registers(&other), None);
        assert_eq!(sat::registers(&[]), None);
    }

    #[test]
    fn interprets_pass_through_outcome() {
        assert_eq!(sat::outcome(0, &[]), Ok(None), "GOOD without sense");
        // The command failed: ATA status ERR, error ABRT.
        let mut aborted = descriptor_sense(0, 0, 0, 0x51);
        aborted[11] = 0x04;
        assert!(sat::outcome(0x02, &aborted).is_err_and(|e| e.contains("error 0x4")));
        // ILLEGAL REQUEST, e.g. a SATL without ATA pass-through.
        let illegal = [0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x20, 0x00];
        assert!(sat::outcome(0x02, &illegal).is_err_and(|e| e.contains("sense key 0x5")));
        assert!(sat::outcome(0x02, &[]).is_err());
        assert!(sat::outcome(0x18, &[]).is_err(), "reservation conflict");
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
