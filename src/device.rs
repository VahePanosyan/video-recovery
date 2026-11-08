//! Windows physical drive read-only access and safety checks.
//!
//! Provides strictly read-only access to Windows physical disk devices (`\\.\PhysicalDriveN`),
//! queries device identity and storage bus geometry, enforces source safety preflight rules,
//! checks volume physical extents to prevent writing to the source disk, and implements
//! robust sector-aligned reading with 1 sector-level retry on failures.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(windows)]
use std::sync::{Mutex, OnceLock};

use crate::error::RecoveryError;
use crate::types::{BusType, DeviceIdentity, ReadSource};

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, BOOL, GENERIC_READ, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, SetFilePointerEx, FILE_BEGIN, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
    STORAGE_BUS_TYPE,
};
#[cfg(windows)]
use windows::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT};
#[cfg(windows)]
use windows::Win32::System::Ioctl::{
    PropertyStandardQuery, RemovableMedia, StorageDeviceProperty, DISK_GEOMETRY_EX,
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_PROPERTY_QUERY,
};
#[cfg(windows)]
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
#[cfg(windows)]
use windows::Win32::System::IO::DeviceIoControl;

/// Masks a raw serial number so the full serial is never exposed in `report.json`.
///
/// Rules:
/// - Trims leading and trailing whitespace, control characters, and null bytes.
/// - If the trimmed string is empty, returns `None`.
/// - If the character count is greater than 4, returns `"****"` concatenated with
///   the last 4 characters (respecting character boundaries safely).
/// - If the character count is 4 or fewer, returns `"****"`.
#[must_use]
pub fn mask_serial(raw_serial: &str) -> Option<String> {
    let trimmed =
        raw_serial.trim_matches(|c: char| c.is_whitespace() || c.is_control() || c == '\0');
    if trimmed.is_empty() {
        return None;
    }
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() > 4 {
        let last4: String = chars[chars.len() - 4..].iter().collect();
        Some(format!("****{last4}"))
    } else {
        Some("****".to_string())
    }
}

/// Enforces source device safety preflight validation before any scan or recovery attempt.
///
/// # Safety Rules
/// 1. Windows system/boot disk is strictly refused (`RecoveryError::SafetyPreflight`).
/// 2. Only SD, MMC, or USB card readers are permitted (`bus_type.is_sd_or_usb()`). Non-SD/MMC/USB
///    buses (such as internal SATA, NVMe, RAID, SCSI) are unconditionally rejected.
/// 3. If media is reported as non-removable (`!device.removable`), it is only allowed if
///    the bus type is USB, SD, or MMC AND `allow_fixed` is explicitly set to `true`.
///
/// # Errors
/// Returns [`RecoveryError::SafetyPreflight`] if any safety condition is violated.
pub fn validate_source_device_safety(
    device: &DeviceIdentity,
    allow_fixed: bool,
) -> Result<(), RecoveryError> {
    if device.is_system_disk {
        return Err(RecoveryError::SafetyPreflight(format!(
            "refusing to access Windows system disk (PhysicalDrive{})",
            device.disk_number
        )));
    }
    if !device.bus_type.is_sd_or_usb() {
        return Err(RecoveryError::SafetyPreflight(format!(
            "refusing non-SD/MMC/USB bus {} for PhysicalDrive{}; only SD, MMC, or USB card readers are supported",
            device.bus_type.label(),
            device.disk_number
        )));
    }
    if !device.removable {
        if matches!(device.bus_type, BusType::Usb | BusType::Sd | BusType::Mmc) && allow_fixed {
            return Ok(());
        }
        return Err(RecoveryError::SafetyPreflight(format!(
            "PhysicalDrive{} reports non-removable media; --allow-fixed is required for fixed-media USB/SD readers",
            device.disk_number
        )));
    }
    Ok(())
}

/// Validates that none of the destination volume's physical disks match `source_disk`.
///
/// # Errors
/// Returns [`RecoveryError::SafetyPreflight`] if `output_disk_numbers` is empty or contains `source_disk`.
pub fn validate_same_disk_numbers(
    source_disk: u32,
    output_disk_numbers: &[u32],
) -> Result<(), RecoveryError> {
    if output_disk_numbers.is_empty() {
        return Err(RecoveryError::SafetyPreflight(
            "could not determine physical disk extents for output directory".to_string(),
        ));
    }
    if output_disk_numbers.contains(&source_disk) {
        return Err(RecoveryError::SafetyPreflight(format!(
            "output directory resides on source physical disk {source_disk}; refusing same-disk output"
        )));
    }
    Ok(())
}

/// Verifies that the given output directory does not reside on `source_disk`.
///
/// Queries the volume physical disk numbers for `output_dir` and validates them against `source_disk`.
///
/// # Errors
/// Returns [`RecoveryError::SafetyPreflight`] on resolution failure or same-disk collision.
pub fn check_output_not_on_source_disk(
    source_disk: u32,
    output_dir: &std::path::Path,
) -> Result<Vec<u32>, RecoveryError> {
    let disk_numbers = get_volume_disk_numbers(output_dir)?;
    validate_same_disk_numbers(source_disk, &disk_numbers)?;
    Ok(disk_numbers)
}

/// Helper that safely extracts a null-terminated ASCII/UTF-8 C-string from a byte slice at `offset`.
#[must_use]
pub fn extract_cstring(buf: &[u8], offset: usize) -> Option<String> {
    if offset == 0 || offset >= buf.len() {
        return None;
    }
    let end = buf[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|pos| offset + pos)
        .unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[offset..end])
        .trim()
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Formats vendor and product strings into a unified device model string.
#[must_use]
pub fn format_model(vendor: Option<&str>, product: Option<&str>, disk_number: u32) -> String {
    match (vendor, product) {
        (Some(v), Some(p)) => {
            let combined = format!("{v} {p}").trim().to_string();
            if combined.is_empty() {
                format!("PhysicalDrive{disk_number}")
            } else {
                combined
            }
        }
        (Some(v), None) => {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                format!("PhysicalDrive{disk_number}")
            } else {
                trimmed.to_string()
            }
        }
        (None, Some(p)) => {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                format!("PhysicalDrive{disk_number}")
            } else {
                trimmed.to_string()
            }
        }
        (None, None) => format!("PhysicalDrive{disk_number}"),
    }
}

/// Maps raw integer `STORAGE_BUS_TYPE` to domain [`BusType`].
#[must_use]
pub fn map_bus_type_raw(bus_type: i32) -> BusType {
    match bus_type {
        12 => BusType::Sd,
        13 => BusType::Mmc,
        7 => BusType::Usb,
        11 => BusType::Sata,
        17 => BusType::Nvme,
        1 | 10 => BusType::Scsi,
        8 => BusType::Raid,
        14 | 15 => BusType::Virtual,
        other => BusType::Other(format!("bus_{other}")),
    }
}

#[cfg(windows)]
/// Maps Windows SDK [`STORAGE_BUS_TYPE`] to domain [`BusType`].
#[must_use]
pub fn map_bus_type(bus_type: STORAGE_BUS_TYPE) -> BusType {
    map_bus_type_raw(bus_type.0)
}

/// Parses physical disk numbers from raw `VOLUME_DISK_EXTENTS` payload bytes.
#[must_use]
pub fn parse_volume_disk_extents(buf: &[u8]) -> Vec<u32> {
    if buf.len() < 8 {
        return Vec::new();
    }
    let num_extents = u32::from_ne_bytes(buf[0..4].try_into().unwrap_or([0; 4])) as usize;
    let mut disks = Vec::new();
    for i in 0..num_extents {
        let offset = 8 + i * 24;
        if offset + 4 <= buf.len() {
            let disk_num = u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap_or([0; 4]));
            if !disks.contains(&disk_num) {
                disks.push(disk_num);
            }
        }
    }
    disks
}

/// Parsed descriptor tuple: `(bus_type, removable, vendor, product, serial)`.
pub type ParsedDeviceDescriptor = (
    BusType,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Parses device descriptor properties from a `STORAGE_DEVICE_DESCRIPTOR` byte buffer.
///
/// Returns `(bus_type, removable, vendor, product, serial)`.
#[must_use]
pub fn parse_device_descriptor_bytes(buf: &[u8]) -> Option<ParsedDeviceDescriptor> {
    if buf.len() < 36 {
        return None;
    }
    let removable = buf[10] != 0;
    let vendor_offset = u32::from_ne_bytes(buf[12..16].try_into().ok()?) as usize;
    let product_offset = u32::from_ne_bytes(buf[16..20].try_into().ok()?) as usize;
    let serial_offset = u32::from_ne_bytes(buf[24..28].try_into().ok()?) as usize;
    let bus_type_val = i32::from_ne_bytes(buf[28..32].try_into().ok()?);
    let bus_type = map_bus_type_raw(bus_type_val);
    let vendor = extract_cstring(buf, vendor_offset);
    let product = extract_cstring(buf, product_offset);
    let serial = extract_cstring(buf, serial_offset);
    Some((bus_type, removable, vendor, product, serial))
}

// ---------------------------------------------------------------------------
// Windows Implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
/// RAII wrapper for a Win32 `HANDLE`, guaranteeing `CloseHandle` on drop.
#[derive(Debug)]
pub struct HandleGuard(pub HANDLE);

#[cfg(windows)]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: self.0 is an exclusively owned, open Win32 handle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
unsafe impl Send for HandleGuard {}
#[cfg(windows)]
unsafe impl Sync for HandleGuard {}

#[cfg(windows)]
/// Queries physical disk numbers for the volume underlying `path`.
///
/// # Errors
/// Returns [`RecoveryError::SafetyPreflight`] if the drive letter cannot be found or IOCTL fails.
pub fn get_volume_disk_numbers(path: &std::path::Path) -> Result<Vec<u32>, RecoveryError> {
    let mut current = path.to_path_buf();
    let mut canon_opt = None;
    loop {
        if let Ok(c) = std::fs::canonicalize(&current) {
            canon_opt = Some(c);
            break;
        }
        if !current.pop() {
            break;
        }
    }
    let p_str = if let Some(canon) = canon_opt {
        canon.to_string_lossy().to_string()
    } else if let Ok(abs) = std::path::absolute(path) {
        abs.to_string_lossy().to_string()
    } else {
        path.to_string_lossy().to_string()
    };

    let stripped = p_str.strip_prefix(r"\\?\").unwrap_or(&p_str);
    let bytes = stripped.as_bytes();
    let volume_path = if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = (bytes[0] as char).to_ascii_uppercase();
        format!(r"\\.\{drive}:")
    } else if stripped.starts_with(r"\\.\") {
        stripped.to_string()
    } else {
        return Err(RecoveryError::SafetyPreflight(format!(
            "could not determine drive letter for volume path: {}",
            path.display()
        )));
    };

    let wide_path: Vec<u16> = volume_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Open volume handle with 0 desired access (query metadata without elevation requirement),
    // falling back to GENERIC_READ.0. Under NO circumstances is GENERIC_WRITE passed.
    // SAFETY: wide_path is null-terminated UTF-16; no write permissions requested.
    let handle_res = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default(),
        )
    };
    let handle = match handle_res {
        Ok(h) => HandleGuard(h),
        Err(_) => {
            // SAFETY: fallback with GENERIC_READ.0
            let fallback = unsafe {
                CreateFileW(
                    PCWSTR(wide_path.as_ptr()),
                    GENERIC_READ.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    HANDLE::default(),
                )
            };
            match fallback {
                Ok(h) => HandleGuard(h),
                Err(e) => {
                    return Err(RecoveryError::SafetyPreflight(format!(
                        "cannot open volume {volume_path} to query disk numbers: {e}"
                    )));
                }
            }
        }
    };

    let mut buf = [0u8; 512];
    let mut bytes_returned = 0u32;
    // SAFETY: handle is valid; buf is 512-byte stack buffer.
    let ok = unsafe {
        DeviceIoControl(
            handle.0,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            0,
            Some(buf.as_mut_ptr() as *mut _),
            buf.len() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };
    if let Err(e) = ok {
        return Err(RecoveryError::SafetyPreflight(format!(
            "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS failed for {volume_path}: {e}"
        )));
    }

    let disks = parse_volume_disk_extents(&buf[..bytes_returned as usize]);
    if disks.is_empty() {
        return Err(RecoveryError::SafetyPreflight(format!(
            "no physical disk extents found for volume {volume_path}"
        )));
    }
    Ok(disks)
}

#[cfg(windows)]
/// Determines the physical disk numbers of the Windows system drive (`%SystemDrive%` / `C:`).
///
/// Falls back to `[0]` if the volume cannot be queried (e.g. non-elevated).
#[must_use]
pub fn get_system_disk_numbers() -> Vec<u32> {
    let drive_str = if let Ok(sys_drive) = std::env::var("SystemDrive") {
        let trimmed = sys_drive.trim();
        if !trimmed.is_empty() {
            trimmed.to_string()
        } else {
            "C:".to_string()
        }
    } else {
        let mut buf = [0u16; 260];
        // SAFETY: buf is a valid stack buffer of 260 u16 elements.
        let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
        if len > 0 && (len as usize) < buf.len() {
            let path_str = String::from_utf16_lossy(&buf[..len as usize]);
            if let Some(colon_idx) = path_str.find(':') {
                if colon_idx > 0 {
                    path_str[..=colon_idx].to_string()
                } else {
                    "C:".to_string()
                }
            } else {
                "C:".to_string()
            }
        } else {
            "C:".to_string()
        }
    };

    let p = std::path::Path::new(&drive_str);
    match get_volume_disk_numbers(p) {
        Ok(disks) if !disks.is_empty() => disks,
        _ => vec![0],
    }
}

#[cfg(windows)]
/// Queries physical drive identity and geometry for `\\.\PhysicalDrive{disk_number}` strictly read-only.
///
/// # Errors
/// Returns [`RecoveryError::SourceIo`] if opening or querying geometry and storage properties fails.
pub fn query_device_identity(disk_number: u32) -> Result<DeviceIdentity, RecoveryError> {
    let device_path = format!(r"\\.\PhysicalDrive{disk_number}");
    let wide_path: Vec<u16> = device_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Try opening with GENERIC_READ.0 first; fall back to 0 (query access) so `list` works
    // even without administrator elevation if the driver allows metadata queries.
    // SAFETY: strictly read-only access.
    let handle_res = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default(),
        )
    };
    let handle = match handle_res {
        Ok(h) => HandleGuard(h),
        Err(_) => {
            // SAFETY: fallback with query access 0.
            let fallback = unsafe {
                CreateFileW(
                    PCWSTR(wide_path.as_ptr()),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    HANDLE::default(),
                )
            };
            match fallback {
                Ok(h) => HandleGuard(h),
                Err(e) => {
                    return Err(RecoveryError::SourceIo {
                        offset: None,
                        message: format!("cannot open physical drive {disk_number}: {e}"),
                    });
                }
            }
        }
    };

    // 1. Query IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
    let mut geom_buf = [0u8; 256];
    let mut geom_returned = 0u32;
    // SAFETY: handle is valid; geom_buf is a valid stack buffer.
    let geom_ok = unsafe {
        DeviceIoControl(
            handle.0,
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            None,
            0,
            Some(geom_buf.as_mut_ptr() as *mut _),
            geom_buf.len() as u32,
            Some(&mut geom_returned),
            None,
        )
    };

    let (size_bytes, sector_size, geom_removable) =
        if geom_ok.is_ok() && (geom_returned as usize) >= std::mem::size_of::<DISK_GEOMETRY_EX>() {
            let geom_ex = unsafe { &*(geom_buf.as_ptr() as *const DISK_GEOMETRY_EX) };
            let size = if geom_ex.DiskSize > 0 {
                geom_ex.DiskSize as u64
            } else {
                0
            };
            let sector = if geom_ex.Geometry.BytesPerSector > 0 {
                geom_ex.Geometry.BytesPerSector
            } else {
                512
            };
            let removable = geom_ex.Geometry.MediaType == RemovableMedia;
            (size, sector, removable)
        } else {
            (0u64, 512u32, false)
        };

    // 2. Query IOCTL_STORAGE_QUERY_PROPERTY
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    let mut desc_buf = vec![0u8; 1024];
    let mut desc_returned = 0u32;
    // SAFETY: query is a valid STORAGE_PROPERTY_QUERY; desc_buf is a heap buffer.
    let prop_res = unsafe {
        DeviceIoControl(
            handle.0,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const _),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(desc_buf.as_mut_ptr() as *mut _),
            desc_buf.len() as u32,
            Some(&mut desc_returned),
            None,
        )
    };

    if geom_ok.is_err() && prop_res.is_err() {
        return Err(RecoveryError::SourceIo {
            offset: None,
            message: format!(
                "failed to query drive geometry and storage properties for PhysicalDrive{disk_number}"
            ),
        });
    }

    if prop_res.is_ok()
        && (desc_returned as usize) >= std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>()
    {
        let needed_size =
            unsafe { (*(desc_buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR)).Size as usize };
        if needed_size > desc_buf.len() && needed_size <= 65536 {
            desc_buf.resize(needed_size, 0);
            // SAFETY: re-query with appropriately sized buffer.
            let _ = unsafe {
                DeviceIoControl(
                    handle.0,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    Some(&query as *const _ as *const _),
                    std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                    Some(desc_buf.as_mut_ptr() as *mut _),
                    desc_buf.len() as u32,
                    Some(&mut desc_returned),
                    None,
                )
            };
        }
    }

    let (bus_type, desc_removable, vendor, product, serial) = if prop_res.is_ok()
        && (desc_returned as usize) >= std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>()
    {
        let valid_slice = &desc_buf[..desc_returned as usize];
        parse_device_descriptor_bytes(valid_slice).unwrap_or_else(|| {
            (
                BusType::Other("unknown".to_string()),
                false,
                None,
                None,
                None,
            )
        })
    } else {
        (
            BusType::Other("unknown".to_string()),
            false,
            None,
            None,
            None,
        )
    };

    let removable = desc_removable || geom_removable;
    let model = format_model(vendor.as_deref(), product.as_deref(), disk_number);
    let masked_serial = serial.as_deref().and_then(mask_serial);
    let system_disks = get_system_disk_numbers();
    let is_system_disk = system_disks.contains(&disk_number);

    Ok(DeviceIdentity {
        disk_number,
        device_path,
        model,
        size_bytes,
        sector_size,
        bus_type,
        removable,
        is_system_disk,
        masked_serial,
    })
}

#[cfg(windows)]
/// Enumerates all detectable physical drives from `0..64`.
#[must_use]
pub fn enumerate_physical_drives() -> Vec<DeviceIdentity> {
    let mut drives = Vec::new();
    for disk_number in 0..64 {
        if let Ok(identity) = query_device_identity(disk_number) {
            drives.push(identity);
        }
    }
    drives
}

#[cfg(windows)]
/// A read-only handle to a Windows physical drive implementing [`ReadSource`].
pub struct PhysicalDriveReader {
    handle: HandleGuard,
    identity: DeviceIdentity,
}

#[cfg(windows)]
impl PhysicalDriveReader {
    /// Returns the device identity metadata for this physical drive.
    #[must_use]
    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }
}

#[cfg(windows)]
unsafe impl Send for PhysicalDriveReader {}
#[cfg(windows)]
unsafe impl Sync for PhysicalDriveReader {}

#[cfg(windows)]
/// Performs a single sector/chunk read via `SetFilePointerEx` followed by `ReadFile`.
unsafe fn do_single_read(handle: HANDLE, offset: u64, buf: &mut [u8]) -> Result<usize, String> {
    if offset > i64::MAX as u64 {
        return Err(format!("offset {offset} exceeds i64::MAX"));
    }
    let mut new_pos = 0i64;
    let seek_res = SetFilePointerEx(handle, offset as i64, Some(&mut new_pos), FILE_BEGIN);
    if let Err(e) = seek_res {
        return Err(format!("SetFilePointerEx to {offset} failed: {e}"));
    }
    let mut bytes_read = 0u32;
    let read_res = ReadFile(handle, Some(buf), Some(&mut bytes_read), None);
    match read_res {
        Ok(()) => Ok(bytes_read as usize),
        Err(e) => Err(format!("ReadFile at {offset} failed: {e}")),
    }
}

#[cfg(windows)]
impl ReadSource for PhysicalDriveReader {
    fn size_bytes(&self) -> u64 {
        self.identity.size_bytes
    }

    fn sector_size(&self) -> u32 {
        self.identity.sector_size
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, RecoveryError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.identity.size_bytes > 0 && offset >= self.identity.size_bytes {
            return Ok(0);
        }

        let sector = self.identity.sector_size.max(512) as u64;
        let max_available = if self.identity.size_bytes > 0 {
            self.identity.size_bytes.saturating_sub(offset)
        } else {
            buf.len() as u64
        };
        let bytes_to_read = (buf.len() as u64).min(max_available) as usize;
        if bytes_to_read == 0 {
            return Ok(0);
        }

        let end_offset =
            offset
                .checked_add(bytes_to_read as u64)
                .ok_or_else(|| RecoveryError::SourceIo {
                    offset: Some(offset),
                    message: "read offset overflow".to_string(),
                })?;

        let aligned_start = (offset / sector) * sector;
        let aligned_end = match end_offset.checked_add(sector - 1) {
            Some(val) => (val / sector) * sector,
            None => (u64::MAX / sector) * sector,
        };

        const MAX_CHUNK_BYTES: u64 = 64 * 1024;
        let mut cur_offset = aligned_start;
        let mut bytes_copied = 0usize;

        while cur_offset < aligned_end {
            let remaining_aligned = aligned_end - cur_offset;
            let chunk_bytes = remaining_aligned.min(MAX_CHUNK_BYTES);
            let chunk_sectors = (chunk_bytes / sector).max(1);
            let chunk_len = (chunk_sectors * sector) as usize;

            let mut chunk_buf = vec![0u8; chunk_len];

            // SAFETY: self.handle.0 is a valid open read-only HANDLE; chunk_buf is aligned in length.
            let chunk_res = unsafe { do_single_read(self.handle.0, cur_offset, &mut chunk_buf) };

            let read_ok = matches!(chunk_res, Ok(n) if n == chunk_len);

            if !read_ok {
                // Chunk read failed: drop down to sector-by-sector reading with retry
                for s in 0..chunk_sectors {
                    let sec_offset = cur_offset + s * sector;
                    let sec_buf_slice =
                        &mut chunk_buf[(s * sector) as usize..((s + 1) * sector) as usize];

                    // Attempt 1 for this sector
                    // SAFETY: read of single sector into sec_buf_slice.
                    let first_res =
                        unsafe { do_single_read(self.handle.0, sec_offset, sec_buf_slice) };

                    let sec_ok = matches!(first_res, Ok(n) if n == sector as usize);

                    if !sec_ok {
                        // Attempt 2: exactly 1 sector-level retry
                        // SAFETY: retry attempt on failing sector.
                        let retry_res =
                            unsafe { do_single_read(self.handle.0, sec_offset, sec_buf_slice) };
                        match retry_res {
                            Ok(n) if n == sector as usize => {
                                // Retry succeeded!
                            }
                            Ok(n) => {
                                return Err(RecoveryError::SourceIo {
                                    offset: Some(sec_offset),
                                    message: format!(
                                        "short sector read at offset {sec_offset} after 1 retry: expected {sector}, got {n}"
                                    ),
                                });
                            }
                            Err(e) => {
                                return Err(RecoveryError::SourceIo {
                                    offset: Some(sec_offset),
                                    message: format!(
                                        "persistent sector read error at offset {sec_offset} after 1 retry: {e}"
                                    ),
                                });
                            }
                        }
                    }
                }
            }

            // Copy overlapping chunk bytes into caller's buf
            let chunk_start = cur_offset;
            let chunk_end = cur_offset + chunk_len as u64;
            let overlap_start = offset.max(chunk_start);
            let overlap_end = end_offset.min(chunk_end);

            if overlap_start < overlap_end {
                let src_start = (overlap_start - chunk_start) as usize;
                let src_end = (overlap_end - chunk_start) as usize;
                let dst_start = (overlap_start - offset) as usize;
                let dst_end = (overlap_end - offset) as usize;
                buf[dst_start..dst_end].copy_from_slice(&chunk_buf[src_start..src_end]);
                bytes_copied += (overlap_end - overlap_start) as usize;
            }

            cur_offset += chunk_len as u64;
        }

        Ok(bytes_copied)
    }
}

#[cfg(windows)]
/// Opens `\\.\PhysicalDrive{disk_number}` strictly read-only for recovery extraction.
///
/// Under NO circumstances is write access requested or granted.
///
/// # Errors
/// Returns [`RecoveryError::SourceIo`] if opening the drive fails.
pub fn open_physical_drive(disk_number: u32) -> Result<PhysicalDriveReader, RecoveryError> {
    let identity = query_device_identity(disk_number)?;
    let device_path = format!(r"\\.\PhysicalDrive{disk_number}");
    let wide_path: Vec<u16> = device_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Must be opened strictly read-only with GENERIC_READ.0!
    // SAFETY: wide_path is null-terminated UTF-16; access is strictly GENERIC_READ; no write flags.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            HANDLE::default(),
        )
    };

    let handle = match handle {
        Ok(h) => HandleGuard(h),
        Err(e) => {
            return Err(RecoveryError::SourceIo {
                offset: None,
                message: format!("failed to open PhysicalDrive{disk_number} for reading: {e}"),
            });
        }
    };

    Ok(PhysicalDriveReader { handle, identity })
}

#[cfg(windows)]
static CTRL_C_FLAG: OnceLock<Mutex<Option<Arc<AtomicBool>>>> = OnceLock::new();

#[cfg(windows)]
unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> BOOL {
    if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT {
        if let Some(mutex) = CTRL_C_FLAG.get() {
            if let Ok(guard) = mutex.lock() {
                if let Some(flag) = guard.as_ref() {
                    flag.store(true, Ordering::SeqCst);
                    return BOOL(1);
                }
            }
        }
    }
    BOOL(0)
}

#[cfg(windows)]
/// Registers a Windows console control handler that sets `flag` to `true` on Ctrl+C or Ctrl+Break.
///
/// # Errors
/// Returns [`RecoveryError::SafetyPreflight`] if handler registration fails.
pub fn install_ctrlc_handler(flag: Arc<AtomicBool>) -> Result<(), RecoveryError> {
    let mutex = CTRL_C_FLAG.get_or_init(|| Mutex::new(None));
    if let Ok(mut guard) = mutex.lock() {
        *guard = Some(flag);
    }
    // SAFETY: console_ctrl_handler matches PHANDLER_ROUTINE signature and safely sets an AtomicBool.
    let res = unsafe { SetConsoleCtrlHandler(Some(console_ctrl_handler), true) };
    if let Err(e) = res {
        return Err(RecoveryError::SafetyPreflight(format!(
            "failed to register Windows console Ctrl+C handler: {e}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Non-Windows Fallback Stubs
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub fn get_volume_disk_numbers(_path: &std::path::Path) -> Result<Vec<u32>, RecoveryError> {
    Err(RecoveryError::SafetyPreflight(
        "device layer is only supported on Windows".to_string(),
    ))
}

#[cfg(not(windows))]
#[must_use]
pub fn get_system_disk_numbers() -> Vec<u32> {
    vec![0]
}

#[cfg(not(windows))]
pub fn query_device_identity(disk_number: u32) -> Result<DeviceIdentity, RecoveryError> {
    Err(RecoveryError::SourceIo {
        offset: None,
        message: format!(
            "Windows physical drives not supported on this platform (PhysicalDrive{disk_number})"
        ),
    })
}

#[cfg(not(windows))]
#[must_use]
pub fn enumerate_physical_drives() -> Vec<DeviceIdentity> {
    Vec::new()
}

#[cfg(not(windows))]
pub struct PhysicalDriveReader {
    identity: DeviceIdentity,
}

#[cfg(not(windows))]
impl PhysicalDriveReader {
    #[must_use]
    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }
}

#[cfg(not(windows))]
impl ReadSource for PhysicalDriveReader {
    fn size_bytes(&self) -> u64 {
        self.identity.size_bytes
    }
    fn sector_size(&self) -> u32 {
        self.identity.sector_size
    }
    fn read_at(&mut self, _offset: u64, _buf: &mut [u8]) -> Result<usize, RecoveryError> {
        Err(RecoveryError::SourceIo {
            offset: None,
            message: "Windows physical drives not supported on this platform".to_string(),
        })
    }
}

#[cfg(not(windows))]
pub fn open_physical_drive(disk_number: u32) -> Result<PhysicalDriveReader, RecoveryError> {
    Err(RecoveryError::SourceIo {
        offset: None,
        message: format!(
            "Windows physical drives not supported on this platform (PhysicalDrive{disk_number})"
        ),
    })
}

#[cfg(not(windows))]
pub fn install_ctrlc_handler(_flag: Arc<AtomicBool>) -> Result<(), RecoveryError> {
    Err(RecoveryError::SafetyPreflight(
        "console control handler is only supported on Windows".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BusType;

    fn sample_identity(bus_type: BusType, removable: bool, is_system: bool) -> DeviceIdentity {
        DeviceIdentity {
            disk_number: 2,
            device_path: r"\\.\PhysicalDrive2".to_string(),
            model: "Test SD Reader".to_string(),
            size_bytes: 64 * 1024 * 1024 * 1024,
            sector_size: 512,
            bus_type,
            removable,
            is_system_disk: is_system,
            masked_serial: Some("****1234".to_string()),
        }
    }

    #[test]
    fn test_mask_serial_empty_and_whitespace() {
        assert_eq!(mask_serial(""), None);
        assert_eq!(mask_serial("   \t\r\n"), None);
        assert_eq!(mask_serial("\0\0\0\0"), None);
        assert_eq!(mask_serial("  \0  \0  "), None);
    }

    #[test]
    fn test_mask_serial_short_lengths() {
        assert_eq!(mask_serial("1"), Some("****".to_string()));
        assert_eq!(mask_serial("12"), Some("****".to_string()));
        assert_eq!(mask_serial("123"), Some("****".to_string()));
        assert_eq!(mask_serial("1234"), Some("****".to_string()));
        assert_eq!(mask_serial("  AB \0 "), Some("****".to_string()));
    }

    #[test]
    fn test_mask_serial_long_lengths() {
        assert_eq!(mask_serial("12345"), Some("****2345".to_string()));
        assert_eq!(mask_serial("ABCDEFGH"), Some("****EFGH".to_string()));
        assert_eq!(
            mask_serial("  SN-987654321 \0 "),
            Some("****4321".to_string())
        );
    }

    #[test]
    fn test_mask_serial_unicode_multibyte() {
        // Armenian "տեսագրություն" is 13 Unicode characters > 4. Last 4 are "յուն".
        assert_eq!(mask_serial("տեսագրություն"), Some("****յուն".to_string()));
        // "հայ" is 3 Unicode characters <= 4.
        assert_eq!(mask_serial("հայ"), Some("****".to_string()));
    }

    #[test]
    fn test_validate_source_device_safety_system_disk() {
        let dev = sample_identity(BusType::Sd, true, true);
        let res = validate_source_device_safety(&dev, false);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Windows system disk"));

        let dev_usb = sample_identity(BusType::Usb, true, true);
        let res_usb = validate_source_device_safety(&dev_usb, true);
        assert!(res_usb.is_err());
        assert!(res_usb
            .unwrap_err()
            .to_string()
            .contains("Windows system disk"));
    }

    #[test]
    fn test_validate_source_device_safety_buses() {
        // SD, MMC, USB allowed if removable
        assert!(
            validate_source_device_safety(&sample_identity(BusType::Sd, true, false), false)
                .is_ok()
        );
        assert!(
            validate_source_device_safety(&sample_identity(BusType::Mmc, true, false), false)
                .is_ok()
        );
        assert!(
            validate_source_device_safety(&sample_identity(BusType::Usb, true, false), false)
                .is_ok()
        );

        // Internal SATA, NVMe, SCSI, RAID, Virtual, Other refused
        let buses = [
            BusType::Sata,
            BusType::Nvme,
            BusType::Scsi,
            BusType::Raid,
            BusType::Virtual,
            BusType::Other("PCIe".to_string()),
        ];
        for b in buses {
            let res = validate_source_device_safety(&sample_identity(b, true, false), false);
            assert!(res.is_err());
            assert!(res
                .unwrap_err()
                .to_string()
                .contains("refusing non-SD/MMC/USB bus"));
        }
    }

    #[test]
    fn test_validate_source_device_safety_removable_vs_fixed() {
        // USB reader reporting fixed media: refused without allow_fixed, allowed with allow_fixed
        let fixed_usb = sample_identity(BusType::Usb, false, false);
        assert!(validate_source_device_safety(&fixed_usb, false).is_err());
        assert!(validate_source_device_safety(&fixed_usb, true).is_ok());

        // SD reader reporting fixed media: refused without allow_fixed, allowed with allow_fixed
        let fixed_sd = sample_identity(BusType::Sd, false, false);
        assert!(validate_source_device_safety(&fixed_sd, false).is_err());
        assert!(validate_source_device_safety(&fixed_sd, true).is_ok());

        // Non-SD/USB bus with allow_fixed must STILL be rejected!
        let fixed_nvme = sample_identity(BusType::Nvme, false, false);
        assert!(validate_source_device_safety(&fixed_nvme, true).is_err());
    }

    #[test]
    fn test_validate_same_disk_numbers() {
        // Empty output numbers
        let res_empty = validate_same_disk_numbers(2, &[]);
        assert!(res_empty.is_err());
        assert!(res_empty
            .unwrap_err()
            .to_string()
            .contains("could not determine"));

        // Output resides on same disk
        let res_same = validate_same_disk_numbers(2, &[2]);
        assert!(res_same.is_err());
        assert!(res_same
            .unwrap_err()
            .to_string()
            .contains("refusing same-disk output"));

        let res_same_multi = validate_same_disk_numbers(2, &[0, 2, 3]);
        assert!(res_same_multi.is_err());

        // Output on different disk
        assert!(validate_same_disk_numbers(2, &[0]).is_ok());
        assert!(validate_same_disk_numbers(2, &[0, 1]).is_ok());
    }

    #[test]
    fn test_extract_cstring() {
        assert_eq!(extract_cstring(&[], 0), None);
        assert_eq!(extract_cstring(b"hello", 10), None);
        assert_eq!(extract_cstring(b"\0hello", 0), None);

        let buf = b"\0\0SanDisk Ultra\0Product\0";
        assert_eq!(extract_cstring(buf, 2), Some("SanDisk Ultra".to_string()));
        assert_eq!(extract_cstring(buf, 16), Some("Product".to_string()));

        // Unterminated string at end of buffer
        let buf2 = b"\0\0EndString";
        assert_eq!(extract_cstring(buf2, 2), Some("EndString".to_string()));

        // Whitespace trimmed
        let buf3 = b"\0\0  Spaced  \0";
        assert_eq!(extract_cstring(buf3, 2), Some("Spaced".to_string()));
    }

    #[test]
    fn test_format_model() {
        assert_eq!(
            format_model(Some("SanDisk"), Some("Extreme PRO"), 1),
            "SanDisk Extreme PRO"
        );
        assert_eq!(format_model(Some("SanDisk"), None, 1), "SanDisk");
        assert_eq!(format_model(None, Some("Card Reader"), 1), "Card Reader");
        assert_eq!(format_model(None, None, 1), "PhysicalDrive1");
        assert_eq!(format_model(Some(" "), Some(" "), 3), "PhysicalDrive3");
    }

    #[test]
    fn test_map_bus_type_raw_variants() {
        assert_eq!(map_bus_type_raw(12), BusType::Sd);
        assert_eq!(map_bus_type_raw(13), BusType::Mmc);
        assert_eq!(map_bus_type_raw(7), BusType::Usb);
        assert_eq!(map_bus_type_raw(11), BusType::Sata);
        assert_eq!(map_bus_type_raw(17), BusType::Nvme);
        assert_eq!(map_bus_type_raw(1), BusType::Scsi);
        assert_eq!(map_bus_type_raw(10), BusType::Scsi);
        assert_eq!(map_bus_type_raw(8), BusType::Raid);
        assert_eq!(map_bus_type_raw(14), BusType::Virtual);
        assert_eq!(map_bus_type_raw(15), BusType::Virtual);
        assert_eq!(map_bus_type_raw(99), BusType::Other("bus_99".to_string()));
    }

    #[test]
    fn test_parse_synthetic_storage_device_descriptor() {
        let mut buf = vec![0u8; 128];
        // RemovableMedia at offset 10 = 1
        buf[10] = 1;
        // VendorIdOffset at offset 12..16 = 36
        buf[12..16].copy_from_slice(&(36u32).to_ne_bytes());
        // ProductIdOffset at offset 16..20 = 48
        buf[16..20].copy_from_slice(&(48u32).to_ne_bytes());
        // SerialNumberOffset at offset 24..28 = 64
        buf[24..28].copy_from_slice(&(64u32).to_ne_bytes());
        // BusType at offset 28..32 = 7 (BusTypeUsb)
        buf[28..32].copy_from_slice(&(7i32).to_ne_bytes());

        // Strings
        buf[36..44].copy_from_slice(b"SanDisk\0");
        buf[48..60].copy_from_slice(b"Extreme PRO\0");
        buf[64..74].copy_from_slice(b"987654321\0");

        let parsed = parse_device_descriptor_bytes(&buf);
        assert!(parsed.is_some());
        let (bus, removable, vendor, product, serial) = parsed.unwrap();
        assert_eq!(bus, BusType::Usb);
        assert!(removable);
        assert_eq!(vendor.as_deref(), Some("SanDisk"));
        assert_eq!(product.as_deref(), Some("Extreme PRO"));
        assert_eq!(serial.as_deref(), Some("987654321"));

        let model = format_model(vendor.as_deref(), product.as_deref(), 2);
        assert_eq!(model, "SanDisk Extreme PRO");

        let masked = serial.as_deref().and_then(mask_serial);
        assert_eq!(masked, Some("****4321".to_string()));
    }

    #[test]
    fn test_parse_volume_disk_extents() {
        // Empty / truncated buffer
        assert!(parse_volume_disk_extents(&[]).is_empty());
        assert!(parse_volume_disk_extents(&[0u8; 4]).is_empty());

        // 1 extent with DiskNumber 3
        let mut buf1 = vec![0u8; 64];
        buf1[0..4].copy_from_slice(&(1u32).to_ne_bytes());
        buf1[8..12].copy_from_slice(&(3u32).to_ne_bytes());
        assert_eq!(parse_volume_disk_extents(&buf1), vec![3]);

        // 2 extents with DiskNumber 1 and 2
        let mut buf2 = vec![0u8; 64];
        buf2[0..4].copy_from_slice(&(2u32).to_ne_bytes());
        buf2[8..12].copy_from_slice(&(1u32).to_ne_bytes());
        buf2[32..36].copy_from_slice(&(2u32).to_ne_bytes());
        assert_eq!(parse_volume_disk_extents(&buf2), vec![1, 2]);

        // Duplicate disk numbers deduplicated
        let mut buf3 = vec![0u8; 64];
        buf3[0..4].copy_from_slice(&(2u32).to_ne_bytes());
        buf3[8..12].copy_from_slice(&(1u32).to_ne_bytes());
        buf3[32..36].copy_from_slice(&(1u32).to_ne_bytes());
        assert_eq!(parse_volume_disk_extents(&buf3), vec![1]);
    }
}
