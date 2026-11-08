//! Core domain types and read-only block/byte source abstractions.

use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::RecoveryError;

/// Supported user-interface and report summary languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    /// English (`en`).
    #[default]
    En,
    /// Armenian (`hy`).
    Hy,
}

impl Language {
    /// ISO language code (`"en"` or `"hy"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Hy => "hy",
        }
    }
}

/// Recovery scan phase mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    /// Run filesystem metadata recovery first, then full raw carving.
    #[default]
    All,
    /// Run only filesystem metadata recovery (FAT32 / exFAT).
    Filesystem,
    /// Run only deep sequential raw carving for MP4/MOV boxes.
    Deep,
}

impl ScanMode {
    /// String representation for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Filesystem => "filesystem",
            Self::Deep => "deep",
        }
    }
}

/// Storage bus type reported by Windows `STORAGE_BUS_TYPE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusType {
    /// Secure Digital (`BusTypeSd`).
    Sd,
    /// MultiMediaCard (`BusTypeMmc`).
    Mmc,
    /// USB storage reader (`BusTypeUsb`).
    Usb,
    /// SATA internal/external bus.
    Sata,
    /// NVMe internal/external bus.
    Nvme,
    /// SCSI / SAS bus.
    Scsi,
    /// RAID bus.
    Raid,
    /// Virtual / file-backed disk.
    Virtual,
    /// Unknown or other bus type.
    Other(String),
}

impl BusType {
    /// Whether this bus is an eligible SD/MMC/USB card reader bus.
    #[must_use]
    pub const fn is_sd_or_usb(&self) -> bool {
        matches!(self, Self::Sd | Self::Mmc | Self::Usb)
    }

    /// Human-readable label.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Sd => "SD",
            Self::Mmc => "MMC",
            Self::Usb => "USB",
            Self::Sata => "SATA",
            Self::Nvme => "NVMe",
            Self::Scsi => "SCSI",
            Self::Raid => "RAID",
            Self::Virtual => "Virtual",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// Physical disk identity and geometry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Physical disk index `N` (`\\.\PhysicalDriveN`).
    pub disk_number: u32,
    /// Win32 device path (`\\.\PhysicalDriveN`).
    pub device_path: String,
    /// Vendor + product model string.
    pub model: String,
    /// Total disk capacity in bytes.
    pub size_bytes: u64,
    /// Logical bytes per sector (e.g., 512 or 4096).
    pub sector_size: u32,
    /// Storage bus type.
    pub bus_type: BusType,
    /// Whether Windows reports the media as removable.
    pub removable: bool,
    /// Whether this disk contains the Windows system/boot volume.
    pub is_system_disk: bool,
    /// Masked serial number (e.g., `"****ABCD"`), never exposing the full raw serial.
    pub masked_serial: Option<String>,
}

/// Partition table scheme on a disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionScheme {
    /// Master Boot Record.
    Mbr,
    /// GUID Partition Table.
    Gpt,
    /// Unpartitioned volume ("superfloppy") starting at LBA 0.
    Superfloppy,
    /// Unrecognized layout.
    Unknown,
}

/// Filesystem detected on a partition or volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilesystemKind {
    /// FAT32 filesystem.
    Fat32,
    /// exFAT filesystem.
    ExFat,
    /// Unknown or unformatted raw space.
    Unknown,
}

impl FilesystemKind {
    /// Display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fat32 => "FAT32",
            Self::ExFat => "exFAT",
            Self::Unknown => "Unknown",
        }
    }
}

/// A parsed partition or volume region on the source disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionInfo {
    /// 0-based partition index.
    pub index: u32,
    /// Partition table scheme.
    pub scheme: PartitionScheme,
    /// Starting byte offset on the physical disk.
    pub byte_offset: u64,
    /// Length in bytes.
    pub byte_len: u64,
    /// Partition type identifier (MBR hex code or GPT type GUID).
    pub type_id: String,
    /// Optional partition name/label.
    pub name: Option<String>,
    /// Detected filesystem inside the partition.
    pub filesystem: FilesystemKind,
}

/// A contiguous byte range on the physical disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Extent {
    /// Absolute byte offset on the source disk.
    pub byte_offset: u64,
    /// Length in bytes (`> 0`).
    pub byte_len: u64,
}

impl Extent {
    /// Creates a new extent.
    #[must_use]
    pub const fn new(byte_offset: u64, byte_len: u64) -> Self {
        Self {
            byte_offset,
            byte_len,
        }
    }

    /// Exclusive end byte offset (`byte_offset + byte_len`), using checked addition.
    #[must_use]
    pub const fn end_offset(&self) -> Option<u64> {
        self.byte_offset.checked_add(self.byte_len)
    }

    /// Whether two extents overlap in byte space.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        if self.byte_len == 0 || other.byte_len == 0 {
            return false;
        }
        let Some(self_end) = self.end_offset() else {
            return true;
        };
        let Some(other_end) = other.end_offset() else {
            return true;
        };
        self.byte_offset < other_end && other.byte_offset < self_end
    }
}

/// How a recovery candidate was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryMethod {
    /// Recovered from FAT32 directory/FAT metadata.
    FilesystemFat32,
    /// Recovered from exFAT directory/bitmap/FAT metadata.
    FilesystemExFat,
    /// Carve-recovered from raw sequential scan of ISO-BMFF boxes.
    RawCarve,
}

impl RecoveryMethod {
    /// Whether this candidate came from filesystem metadata (higher priority than raw carving).
    #[must_use]
    pub const fn is_filesystem(self) -> bool {
        matches!(self, Self::FilesystemFat32 | Self::FilesystemExFat)
    }
}

/// Recovery confidence level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Low confidence (e.g., partial/truncated stream or lost cluster chain with anomalies).
    Low,
    /// Medium confidence (e.g., contiguous heuristic or raw carve without metadata).
    Medium,
    /// High confidence (e.g., intact chain/NoFatChain or complete MP4 structure verified by ffprobe/ffmpeg).
    High,
}

/// Final validation and extraction status of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    /// Validated video stream (placed in `validated/`).
    Validated,
    /// Partial/incomplete video data (placed in `partial/`).
    Partial,
    /// Rejected (no valid video stream or corrupt beyond partial recovery).
    Rejected,
    /// Extraction stopped due to persistent source read error after retry.
    IoError,
}

/// A candidate video file discovered during filesystem or raw carving phases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// Stable candidate identifier within the session (e.g. `"cand-0001"`).
    pub id: String,
    /// Physical byte extents on the source disk that make up the candidate file.
    pub extents: Vec<Extent>,
    /// Expected file size in bytes.
    pub expected_size: u64,
    /// Discovery method.
    pub recovery_method: RecoveryMethod,
    /// Original filename from FAT32/exFAT directory entry, if available.
    pub original_name: Option<String>,
    /// Assigned output filename (e.g., `"cand-0001_GOPR0001.MP4"`).
    pub recovered_name: Option<String>,
    /// Relative or absolute path in the session directory where the file was saved.
    pub output_path: Option<String>,
    /// Confidence level.
    pub confidence: Confidence,
    /// Validation/extraction status.
    pub status: CandidateStatus,
    /// Whether the exact cluster allocation mapping was preserved (`true` for intact FAT chain,
    /// exFAT `NoFatChain`, or single-cluster file; `false` when FAT chain was zeroed on deletion
    /// and a contiguous fallback was assumed).
    pub chain_preserved: bool,
    /// Whether the file is known or detected to be physically fragmented or structurally truncated.
    pub is_fragmented: bool,
    /// Error or rejection reason if `status != Validated`.
    pub error_reason: Option<String>,
    /// Source byte offset where an I/O error occurred, if `status == IoError`.
    pub error_offset: Option<u64>,
}

impl Candidate {
    /// Starting byte offset of the first extent, if any.
    #[must_use]
    pub fn primary_offset(&self) -> Option<u64> {
        self.extents.first().map(|e| e.byte_offset)
    }

    /// Total bytes across all extents using checked arithmetic.
    #[must_use]
    pub fn total_extent_bytes(&self) -> u64 {
        self.extents
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.byte_len))
    }
}

/// Configuration for a recovery session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Physical disk number `N`.
    pub disk_number: u32,
    /// Base output directory requested by the user.
    pub output_dir: PathBuf,
    /// Scan mode (`all`, `filesystem`, `deep`).
    pub mode: ScanMode,
    /// Optional explicit path to `ffprobe`.
    pub ffprobe_path: Option<PathBuf>,
    /// Optional explicit path to `ffmpeg`.
    pub ffmpeg_path: Option<PathBuf>,
    /// Whether `--full-verify` full video stream decode is enabled.
    pub full_verify: bool,
    /// Whether `--allow-fixed` was passed for fixed-media USB readers.
    pub allow_fixed: bool,
    /// Active UI/report language.
    pub lang: Language,
}

/// Read-only byte/sector source trait.
///
/// Implementations NEVER expose write methods.
pub trait ReadSource {
    /// Total size of this source in bytes.
    fn size_bytes(&self) -> u64;

    /// Logical sector size in bytes (e.g., 512 or 4096).
    fn sector_size(&self) -> u32;

    /// Reads bytes starting at `offset` into `buf`.
    ///
    /// Returns the number of bytes read (`0` at EOF).
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::SourceIo`] if the underlying device fails after retry,
    /// or if `offset` overflows.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, RecoveryError>;

    /// Reads the exact number of bytes to fill `buf` at `offset`, or returns an error on short read.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::SourceIo`] or [`RecoveryError::Parse`] if EOF is reached early.
    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), RecoveryError> {
        let mut total = 0usize;
        while total < buf.len() {
            let cur_offset = offset.checked_add(total as u64).ok_or_else(|| {
                RecoveryError::Parse("arithmetic overflow in read_exact_at".to_string())
            })?;
            let n = self.read_at(cur_offset, &mut buf[total..])?;
            if n == 0 {
                return Err(RecoveryError::Parse(format!(
                    "unexpected EOF at offset {cur_offset} (wanted {} bytes, got {total})",
                    buf.len()
                )));
            }
            total += n;
        }
        Ok(())
    }
}

/// A bounded view into a [`ReadSource`] representing a single partition or slice.
pub struct PartitionSlice<'a, R: ReadSource + ?Sized> {
    inner: &'a mut R,
    base_offset: u64,
    byte_len: u64,
}

impl<'a, R: ReadSource + ?Sized> PartitionSlice<'a, R> {
    /// Creates a new bounded slice starting at `base_offset` with length `byte_len`.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Parse`] if `base_offset + byte_len` overflows or exceeds the parent source size.
    pub fn new(inner: &'a mut R, base_offset: u64, byte_len: u64) -> Result<Self, RecoveryError> {
        let end = base_offset
            .checked_add(byte_len)
            .ok_or_else(|| RecoveryError::Parse("partition slice offset overflow".to_string()))?;
        if end > inner.size_bytes() {
            return Err(RecoveryError::Parse(format!(
                "partition slice end {end} exceeds disk size {}",
                inner.size_bytes()
            )));
        }
        Ok(Self {
            inner,
            base_offset,
            byte_len,
        })
    }

    /// Base offset of this partition on the physical disk.
    #[must_use]
    pub const fn base_offset(&self) -> u64 {
        self.base_offset
    }
}

impl<R: ReadSource + ?Sized> ReadSource for PartitionSlice<'_, R> {
    fn size_bytes(&self) -> u64 {
        self.byte_len
    }

    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, RecoveryError> {
        if offset >= self.byte_len || buf.is_empty() {
            return Ok(0);
        }
        let available = (self.byte_len - offset).min(buf.len() as u64) as usize;
        let abs_offset = self.base_offset.checked_add(offset).ok_or_else(|| {
            RecoveryError::Parse("partition slice read offset overflow".to_string())
        })?;
        self.inner.read_at(abs_offset, &mut buf[..available])
    }
}

/// In-memory [`ReadSource`] for unit and synthetic disk integration tests, supporting
/// optional sector-level fault injection and retry tracking.
#[derive(Debug, Clone)]
pub struct MemorySource {
    data: Vec<u8>,
    sector_size: u32,
    failing_offsets: HashSet<u64>,
    transient_offsets: HashSet<u64>,
    read_attempts: Vec<u64>,
}

impl MemorySource {
    /// Creates a new in-memory read source with a 512-byte sector size.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            sector_size: 512,
            failing_offsets: HashSet::new(),
            transient_offsets: HashSet::new(),
            read_attempts: Vec::new(),
        }
    }

    /// Creates a new in-memory read source with a custom sector size.
    #[must_use]
    pub fn with_sector_size(data: Vec<u8>, sector_size: u32) -> Self {
        Self {
            data,
            sector_size: sector_size.max(512),
            failing_offsets: HashSet::new(),
            transient_offsets: HashSet::new(),
            read_attempts: Vec::new(),
        }
    }

    /// Injects a persistent read failure at the sector containing `byte_offset`.
    pub fn inject_persistent_failure(&mut self, byte_offset: u64) {
        let aligned = (byte_offset / u64::from(self.sector_size)) * u64::from(self.sector_size);
        self.failing_offsets.insert(aligned);
    }

    /// Injects a transient (fail-once, succeed-on-retry) failure at the sector containing `byte_offset`.
    pub fn inject_transient_failure(&mut self, byte_offset: u64) {
        let aligned = (byte_offset / u64::from(self.sector_size)) * u64::from(self.sector_size);
        self.transient_offsets.insert(aligned);
    }

    /// Returns all recorded read offsets.
    #[must_use]
    pub fn read_attempts(&self) -> &[u64] {
        &self.read_attempts
    }

    /// Underlying byte slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl ReadSource for MemorySource {
    fn size_bytes(&self) -> u64 {
        self.data.len() as u64
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, RecoveryError> {
        self.read_attempts.push(offset);
        if offset >= self.data.len() as u64 || buf.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .unwrap_or(self.data.len() as u64)
            .min(self.data.len() as u64);

        let sector = u64::from(self.sector_size);
        let first_sec = (offset / sector) * sector;
        let last_sec = ((end.saturating_sub(1)) / sector) * sector;
        let mut cur_sec = first_sec;
        while cur_sec <= last_sec {
            if self.transient_offsets.remove(&cur_sec) {
                // First attempt fails, but retry will succeed unless also in failing_offsets.
                // Simulate the 1 sector-level retry inside the reader:
                self.read_attempts.push(cur_sec);
            }
            if self.failing_offsets.contains(&cur_sec) {
                if cur_sec != offset {
                    self.read_attempts.push(cur_sec);
                }
                // Record the single retry attempt and return error with the exact failing offset.
                self.read_attempts.push(cur_sec);
                return Err(RecoveryError::SourceIo {
                    offset: Some(cur_sec),
                    message: format!(
                        "persistent sector read error at offset {cur_sec} after 1 retry"
                    ),
                });
            }
            match cur_sec.checked_add(sector) {
                Some(next) if next > cur_sec => cur_sec = next,
                _ => break,
            }
        }

        let start_usize = offset as usize;
        let end_usize = end as usize;
        let count = end_usize - start_usize;
        buf[..count].copy_from_slice(&self.data[start_usize..end_usize]);
        Ok(count)
    }
}
