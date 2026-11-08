//! Versioned JSON report and localized summary generation.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::RecoveryError;
use crate::types::{
    BusType, Candidate, CandidateStatus, Confidence, DeviceIdentity, Language, PartitionInfo,
    RecoveryMethod, ScanConfig, ScanMode,
};

/// Current version of the JSON recovery session report contract.
pub const REPORT_VERSION: u32 = 1;

/// Masked identity of the source storage device for reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskedDeviceReport {
    /// Physical disk number `N`.
    pub disk_number: u32,
    /// Win32 device path (e.g. `\\.\PhysicalDrive1`).
    pub device_path: String,
    /// Product model string.
    pub model: String,
    /// Total capacity in bytes.
    pub size_bytes: u64,
    /// Sector size in bytes.
    pub sector_size: u32,
    /// Storage bus type.
    pub bus_type: BusType,
    /// Removable media flag.
    pub removable: bool,
    /// Masked serial number (never full serial).
    pub masked_serial: Option<String>,
}

impl From<&DeviceIdentity> for MaskedDeviceReport {
    fn from(d: &DeviceIdentity) -> Self {
        Self {
            disk_number: d.disk_number,
            device_path: d.device_path.clone(),
            model: d.model.clone(),
            size_bytes: d.size_bytes,
            sector_size: d.sector_size,
            bus_type: d.bus_type.clone(),
            removable: d.removable,
            masked_serial: d.masked_serial.clone(),
        }
    }
}

impl From<DeviceIdentity> for MaskedDeviceReport {
    fn from(d: DeviceIdentity) -> Self {
        Self::from(&d)
    }
}

/// Recovery configuration captured in session report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfigReport {
    /// Scan mode (`all`, `filesystem`, `deep`).
    pub mode: ScanMode,
    /// Whether `--full-verify` video decode was enabled.
    pub full_verify: bool,
    /// Whether `--allow-fixed` was granted for fixed-disk USB readers.
    pub allow_fixed: bool,
    /// UI/report language.
    pub lang: Language,
    /// Output directory.
    pub output_dir: String,
}

impl From<&ScanConfig> for ScanConfigReport {
    fn from(c: &ScanConfig) -> Self {
        Self {
            mode: c.mode,
            full_verify: c.full_verify,
            allow_fixed: c.allow_fixed,
            lang: c.lang,
            output_dir: c.output_dir.to_string_lossy().into_owned(),
        }
    }
}

impl From<ScanConfig> for ScanConfigReport {
    fn from(c: ScanConfig) -> Self {
        Self::from(&c)
    }
}

/// Candidate count breakdown by status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportCounts {
    /// Total candidates discovered.
    pub total_candidates: usize,
    /// Successfully validated video files.
    pub validated: usize,
    /// Incomplete or damaged video streams saved to `partial/`.
    pub partial: usize,
    /// Corrupt, invalid, or non-video items rejected.
    pub rejected: usize,
    /// Extraction aborted due to unrecoverable read failure.
    pub io_error: usize,
}

impl ReportCounts {
    /// Tallies candidate statuses across a slice of candidates.
    #[must_use]
    pub fn from_candidates(candidates: &[Candidate]) -> Self {
        let mut counts = Self {
            total_candidates: candidates.len(),
            validated: 0,
            partial: 0,
            rejected: 0,
            io_error: 0,
        };
        for c in candidates {
            match c.status {
                CandidateStatus::Validated => counts.validated += 1,
                CandidateStatus::Partial => counts.partial += 1,
                CandidateStatus::Rejected => counts.rejected += 1,
                CandidateStatus::IoError => counts.io_error += 1,
            }
        }
        counts
    }
}

/// Comprehensive session recovery report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReport {
    /// Contract report version (must be `1`).
    pub report_version: u32,
    /// Session folder identifier.
    pub session_id: String,
    /// Unix millisecond timestamp when scan started.
    pub started_at_unix_ms: u64,
    /// Unix millisecond timestamp when session concluded.
    pub finished_at_unix_ms: u64,
    /// Duration of scan in milliseconds.
    pub duration_ms: u64,
    /// Whether scan was halted by user interrupt (Ctrl+C).
    pub interrupted: bool,
    /// Masked device properties.
    pub device: MaskedDeviceReport,
    /// Scan options used.
    pub scan_config: ScanConfigReport,
    /// Partitions and filesystems detected on source.
    pub filesystems: Vec<PartitionInfo>,
    /// All evaluated candidates.
    pub candidates: Vec<Candidate>,
    /// Summary totals.
    pub counts: ReportCounts,
}

impl SessionReport {
    /// Constructs a new [`SessionReport`] and computes [`ReportCounts`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: String,
        started_at_unix_ms: u64,
        finished_at_unix_ms: u64,
        interrupted: bool,
        device: MaskedDeviceReport,
        scan_config: ScanConfigReport,
        filesystems: Vec<PartitionInfo>,
        candidates: Vec<Candidate>,
    ) -> Self {
        let counts = ReportCounts::from_candidates(&candidates);
        let duration_ms = finished_at_unix_ms.saturating_sub(started_at_unix_ms);
        Self {
            report_version: REPORT_VERSION,
            session_id,
            started_at_unix_ms,
            finished_at_unix_ms,
            duration_ms,
            interrupted,
            device,
            scan_config,
            filesystems,
            candidates,
            counts,
        }
    }
}

fn format_bytes_en(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!(
            "{bytes} bytes ({:.2} GiB)",
            bytes as f64 / (1024.0 * 1024.0 * 1024.0)
        )
    } else if bytes >= 1024 * 1024 {
        format!(
            "{bytes} bytes ({:.2} MiB)",
            bytes as f64 / (1024.0 * 1024.0)
        )
    } else if bytes >= 1024 {
        format!("{bytes} bytes ({:.2} KiB)", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} bytes")
    }
}

fn format_bytes_hy(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!(
            "{bytes} բայթ ({:.2} ԳԲ)",
            bytes as f64 / (1024.0 * 1024.0 * 1024.0)
        )
    } else if bytes >= 1024 * 1024 {
        format!("{bytes} բայթ ({:.2} ՄԲ)", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{bytes} բայթ ({:.2} ԿԲ)", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} բայթ")
    }
}

fn status_label(status: CandidateStatus, lang: Language) -> &'static str {
    match (status, lang) {
        (CandidateStatus::Validated, Language::En) => "Validated",
        (CandidateStatus::Validated, Language::Hy) => "Վավերացված",
        (CandidateStatus::Partial, Language::En) => "Partial",
        (CandidateStatus::Partial, Language::Hy) => "Մասնակի",
        (CandidateStatus::Rejected, Language::En) => "Rejected",
        (CandidateStatus::Rejected, Language::Hy) => "Մերժված",
        (CandidateStatus::IoError, Language::En) => "I/O Error",
        (CandidateStatus::IoError, Language::Hy) => "I/O Սխալ",
    }
}

fn confidence_label(confidence: Confidence, lang: Language) -> &'static str {
    match (confidence, lang) {
        (Confidence::High, Language::En) => "High",
        (Confidence::High, Language::Hy) => "Բարձր",
        (Confidence::Medium, Language::En) => "Medium",
        (Confidence::Medium, Language::Hy) => "Միջին",
        (Confidence::Low, Language::En) => "Low",
        (Confidence::Low, Language::Hy) => "Ցածր",
    }
}

fn recovery_method_label(method: RecoveryMethod, lang: Language) -> &'static str {
    match (method, lang) {
        (RecoveryMethod::FilesystemFat32, Language::En) => "FAT32 Metadata",
        (RecoveryMethod::FilesystemFat32, Language::Hy) => "FAT32 մետատվյալներ",
        (RecoveryMethod::FilesystemExFat, Language::En) => "exFAT Metadata",
        (RecoveryMethod::FilesystemExFat, Language::Hy) => "exFAT մետատվյալներ",
        (RecoveryMethod::RawCarve, Language::En) => "Raw Carve",
        (RecoveryMethod::RawCarve, Language::Hy) => "Ուղիղ քարվինգ (Raw Carve)",
    }
}

/// Generates a detailed human-readable summary in English (`Language::En`) or Armenian (`Language::Hy`).
#[must_use]
pub fn format_summary_text(report: &SessionReport, lang: Language) -> String {
    let mut out = String::with_capacity(4096);

    match lang {
        Language::En => {
            out.push_str("================================================================================\n");
            out.push_str("sd-video-recovery Session Summary\n");
            out.push_str("================================================================================\n");
            out.push_str(&format!("Session ID:         {}\n", report.session_id));
            out.push_str(&format!("Report Version:     {}\n", report.report_version));
            out.push_str(&format!(
                "Status:             {}\n",
                if report.interrupted {
                    "INTERRUPTED (Ctrl+C)"
                } else {
                    "COMPLETED"
                }
            ));
            out.push_str(&format!(
                "Duration:           {} ms (started: {}, finished: {})\n\n",
                report.duration_ms, report.started_at_unix_ms, report.finished_at_unix_ms
            ));

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str("Source Device\n");
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Disk Number:        PhysicalDrive{}\n",
                report.device.disk_number
            ));
            out.push_str(&format!(
                "Device Path:        {}\n",
                report.device.device_path
            ));
            out.push_str(&format!("Model:              {}\n", report.device.model));
            out.push_str(&format!(
                "Capacity:           {}\n",
                format_bytes_en(report.device.size_bytes)
            ));
            out.push_str(&format!(
                "Sector Size:        {} bytes\n",
                report.device.sector_size
            ));
            out.push_str(&format!(
                "Bus Type:           {}\n",
                report.device.bus_type.label()
            ));
            out.push_str(&format!(
                "Removable:          {}\n",
                report.device.removable
            ));
            out.push_str(&format!(
                "Masked Serial:      {}\n\n",
                report.device.masked_serial.as_deref().unwrap_or("N/A")
            ));

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str("Scan Configuration\n");
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Scan Mode:          {}\n",
                report.scan_config.mode.as_str()
            ));
            out.push_str(&format!(
                "Full Verify:        {}\n",
                report.scan_config.full_verify
            ));
            out.push_str(&format!(
                "Allow Fixed:        {}\n",
                report.scan_config.allow_fixed
            ));
            out.push_str(&format!(
                "Output Directory:   {}\n",
                report.scan_config.output_dir
            ));
            out.push_str(&format!(
                "Language:           {}\n\n",
                report.scan_config.lang.as_str()
            ));

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Partitions & Filesystems ({})\n",
                report.filesystems.len()
            ));
            out.push_str("--------------------------------------------------------------------------------\n");
            if report.filesystems.is_empty() {
                out.push_str("  (No partitions detected)\n");
            } else {
                for p in &report.filesystems {
                    out.push_str(&format!(
                        "  [Partition #{}] Filesystem: {:?} | Scheme: {:?} | Offset: {} | Length: {} | Type: {}\n",
                        p.index,
                        p.filesystem.as_str(),
                        p.scheme,
                        p.byte_offset,
                        p.byte_len,
                        p.type_id
                    ));
                }
            }
            out.push('\n');

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str("Recovery Results\n");
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Total Candidates:   {}\n",
                report.counts.total_candidates
            ));
            out.push_str(&format!(
                "  Validated:        {}\n",
                report.counts.validated
            ));
            out.push_str(&format!("  Partial:          {}\n", report.counts.partial));
            out.push_str(&format!("  Rejected:         {}\n", report.counts.rejected));
            out.push_str(&format!(
                "  I/O Errors:       {}\n\n",
                report.counts.io_error
            ));

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Candidate Details ({})\n",
                report.candidates.len()
            ));
            out.push_str("--------------------------------------------------------------------------------\n");
            if report.candidates.is_empty() {
                out.push_str("  (No video candidates found)\n");
            } else {
                for c in &report.candidates {
                    let display_name = c
                        .recovered_name
                        .as_deref()
                        .or(c.original_name.as_deref())
                        .unwrap_or("unnamed");
                    out.push_str(&format!("- [{}] {}\n", c.id, display_name));
                    out.push_str(&format!(
                        "    Status: {} | Confidence: {} | Size: {}\n",
                        status_label(c.status, Language::En),
                        confidence_label(c.confidence, Language::En),
                        format_bytes_en(c.expected_size)
                    ));
                    out.push_str(&format!(
                        "    Method: {} | Chain Preserved: {} | Fragmented: {}\n",
                        recovery_method_label(c.recovery_method, Language::En),
                        c.chain_preserved,
                        c.is_fragmented
                    ));
                    if let Some(ref orig) = c.original_name {
                        out.push_str(&format!("    Original Name:    {}\n", orig));
                    }
                    if let Some(ref out_path) = c.output_path {
                        out.push_str(&format!("    Output File:      {}\n", out_path));
                    }
                    if let Some(ref err) = c.error_reason {
                        if let Some(offset) = c.error_offset {
                            out.push_str(&format!(
                                "    Error:            {} (at offset {})\n",
                                err, offset
                            ));
                        } else {
                            out.push_str(&format!("    Error:            {}\n", err));
                        }
                    }
                    out.push_str(&format!("    Extents ({}):       ", c.extents.len()));
                    let ext_str: Vec<String> = c
                        .extents
                        .iter()
                        .map(|e| {
                            let end = e.end_offset().unwrap_or(u64::MAX);
                            format!("[{}..{}, len {}]", e.byte_offset, end, e.byte_len)
                        })
                        .collect();
                    out.push_str(&ext_str.join(", "));
                    out.push('\n');
                }
            }
        }
        Language::Hy => {
            out.push_str("================================================================================\n");
            out.push_str("sd-video-recovery Սեսիայի Ամփոփում\n");
            out.push_str("================================================================================\n");
            out.push_str(&format!("Սեսիայի ID:         {}\n", report.session_id));
            out.push_str(&format!(
                "Հաշվետվության տարբերակ: {}\n",
                report.report_version
            ));
            out.push_str(&format!(
                "Կարգավիճակ:         {}\n",
                if report.interrupted {
                    "ԸՆԴՀԱՏՎԱԾ Է (Ctrl+C)"
                } else {
                    "ԱՎԱՐՏՎԱԾ"
                }
            ));
            out.push_str(&format!(
                "Տևողություն:        {} մվ (սկիզբ: {}, ավարտ: {})\n\n",
                report.duration_ms, report.started_at_unix_ms, report.finished_at_unix_ms
            ));

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str("Աղբյուր Սարք\n");
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Սկավառակի համարը:   PhysicalDrive{}\n",
                report.device.disk_number
            ));
            out.push_str(&format!(
                "Սարքի ուղին:        {}\n",
                report.device.device_path
            ));
            out.push_str(&format!("Մոդել:              {}\n", report.device.model));
            out.push_str(&format!(
                "Տարողություն:       {}\n",
                format_bytes_hy(report.device.size_bytes)
            ));
            out.push_str(&format!(
                "Սեկտորի չափը:       {} բայթ\n",
                report.device.sector_size
            ));
            out.push_str(&format!(
                "Շինայի տեսակը:      {}\n",
                report.device.bus_type.label()
            ));
            out.push_str(&format!(
                "Շարժական կրիչ:      {}\n",
                if report.device.removable {
                    "Այո"
                } else {
                    "Ոչ"
                }
            ));
            out.push_str(&format!(
                "Սերիական համար:      {}\n\n",
                report.device.masked_serial.as_deref().unwrap_or("Անհայտ")
            ));

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str("Սկանի Կարգավորումներ\n");
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Սկանի ռեժիմ:        {}\n",
                report.scan_config.mode.as_str()
            ));
            out.push_str(&format!(
                "Ամբողջական ստուգում: {}\n",
                if report.scan_config.full_verify {
                    "Այո"
                } else {
                    "Ոչ"
                }
            ));
            out.push_str(&format!(
                "Թույլատրել ֆիքսված: {}\n",
                if report.scan_config.allow_fixed {
                    "Այո"
                } else {
                    "Ոչ"
                }
            ));
            out.push_str(&format!(
                "Ելքային պանակ:      {}\n",
                report.scan_config.output_dir
            ));
            out.push_str(&format!(
                "Լեզու:              {}\n\n",
                report.scan_config.lang.as_str()
            ));

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Բաժիններ և Ֆայլային Համակարգեր ({})\n",
                report.filesystems.len()
            ));
            out.push_str("--------------------------------------------------------------------------------\n");
            if report.filesystems.is_empty() {
                out.push_str("  (Բաժիններ չեն հայտնաբերվել)\n");
            } else {
                for p in &report.filesystems {
                    out.push_str(&format!(
                        "  [Բաժին #{}] Ֆայլային համակարգ: {:?} | Սխեմա: {:?} | Սկիզբ: {} | Երկարություն: {} | Տիպ: {}\n",
                        p.index,
                        p.filesystem.as_str(),
                        p.scheme,
                        p.byte_offset,
                        p.byte_len,
                        p.type_id
                    ));
                }
            }
            out.push('\n');

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str("Վերականգնման Արդյունքներ\n");
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Ընդհանուր թեկնածուներ: {}\n",
                report.counts.total_candidates
            ));
            out.push_str(&format!(
                "  Վավերացված:         {}\n",
                report.counts.validated
            ));
            out.push_str(&format!(
                "  Մասնակի:            {}\n",
                report.counts.partial
            ));
            out.push_str(&format!(
                "  Մերժված:            {}\n",
                report.counts.rejected
            ));
            out.push_str(&format!(
                "  I/O Սխալներ:        {}\n\n",
                report.counts.io_error
            ));

            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!(
                "Թեկնածուների Մանրամասներ ({})\n",
                report.candidates.len()
            ));
            out.push_str("--------------------------------------------------------------------------------\n");
            if report.candidates.is_empty() {
                out.push_str("  (Վիդեո թեկնածուներ չեն գտնվել)\n");
            } else {
                for c in &report.candidates {
                    let display_name = c
                        .recovered_name
                        .as_deref()
                        .or(c.original_name.as_deref())
                        .unwrap_or("անանուն");
                    out.push_str(&format!("- [{}] {}\n", c.id, display_name));
                    out.push_str(&format!(
                        "    Կարգավիճակ: {} | Վստահություն: {} | Չափ: {}\n",
                        status_label(c.status, Language::Hy),
                        confidence_label(c.confidence, Language::Hy),
                        format_bytes_hy(c.expected_size)
                    ));
                    out.push_str(&format!(
                        "    Մեթոդ: {} | Շղթան պահպանված: {} | Ֆրագմենտավորված: {}\n",
                        recovery_method_label(c.recovery_method, Language::Hy),
                        if c.chain_preserved { "Այո" } else { "Ոչ" },
                        if c.is_fragmented { "Այո" } else { "Ոչ" }
                    ));
                    if let Some(ref orig) = c.original_name {
                        out.push_str(&format!("    Սկզբնական անուն:   {}\n", orig));
                    }
                    if let Some(ref out_path) = c.output_path {
                        out.push_str(&format!("    Ելքային ֆայլ:      {}\n", out_path));
                    }
                    if let Some(ref err) = c.error_reason {
                        if let Some(offset) = c.error_offset {
                            out.push_str(&format!(
                                "    Սխալ:              {} (օֆսեթում՝ {})\n",
                                err, offset
                            ));
                        } else {
                            out.push_str(&format!("    Սխալ:              {}\n", err));
                        }
                    }
                    out.push_str(&format!("    Հատվածներ ({}):     ", c.extents.len()));
                    let ext_str: Vec<String> = c
                        .extents
                        .iter()
                        .map(|e| {
                            let end = e.end_offset().unwrap_or(u64::MAX);
                            format!("[{}..{}, երկ.` {}]", e.byte_offset, end, e.byte_len)
                        })
                        .collect();
                    out.push_str(&ext_str.join(", "));
                    out.push('\n');
                }
            }
        }
    }

    out
}

/// Serializes the session report to JSON and writes the human-readable summary text file.
///
/// Both files are written using `create_new(true)` semantics, ensuring that existing files
/// are NEVER overwritten.
///
/// # Errors
///
/// Returns [`RecoveryError::OutputIo`] if file creation, serialization, or write fails.
pub fn write_session_reports(
    report_json_path: &Path,
    summary_txt_path: &Path,
    report: &SessionReport,
    lang: Language,
) -> Result<(), RecoveryError> {
    let json_bytes = serde_json::to_string_pretty(report)
        .map_err(|e| RecoveryError::OutputIo(format!("failed to serialize report to JSON: {e}")))?;

    {
        let mut json_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(report_json_path)
            .map_err(|e| {
                RecoveryError::OutputIo(format!(
                    "failed to create report JSON file '{}': {e}",
                    report_json_path.display()
                ))
            })?;
        json_file.write_all(json_bytes.as_bytes()).map_err(|e| {
            RecoveryError::OutputIo(format!(
                "failed to write report JSON to '{}': {e}",
                report_json_path.display()
            ))
        })?;
        json_file.sync_all().map_err(|e| {
            RecoveryError::OutputIo(format!(
                "failed to sync report JSON file '{}': {e}",
                report_json_path.display()
            ))
        })?;
    }

    let summary_text = format_summary_text(report, lang);
    {
        let mut txt_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(summary_txt_path)
            .map_err(|e| {
                RecoveryError::OutputIo(format!(
                    "failed to create summary text file '{}': {e}",
                    summary_txt_path.display()
                ))
            })?;
        txt_file.write_all(summary_text.as_bytes()).map_err(|e| {
            RecoveryError::OutputIo(format!(
                "failed to write summary text to '{}': {e}",
                summary_txt_path.display()
            ))
        })?;
        txt_file.sync_all().map_err(|e| {
            RecoveryError::OutputIo(format!(
                "failed to sync summary text file '{}': {e}",
                summary_txt_path.display()
            ))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Extent, FilesystemKind, PartitionScheme};
    use std::path::PathBuf;

    fn sample_report() -> SessionReport {
        let device = MaskedDeviceReport {
            disk_number: 2,
            device_path: r"\\.\PhysicalDrive2".to_string(),
            model: "SanDisk Extreme PRO".to_string(),
            size_bytes: 64_000_000_000,
            sector_size: 512,
            bus_type: BusType::Usb,
            removable: true,
            masked_serial: Some("****A1B2".to_string()),
        };

        let scan_config = ScanConfigReport {
            mode: ScanMode::All,
            full_verify: true,
            allow_fixed: false,
            lang: Language::En,
            output_dir: r"D:\Recovered".to_string(),
        };

        let filesystems = vec![PartitionInfo {
            index: 0,
            scheme: PartitionScheme::Mbr,
            byte_offset: 1_048_576,
            byte_len: 63_998_951_424,
            type_id: "0x07".to_string(),
            name: Some("SD_CARD".to_string()),
            filesystem: FilesystemKind::ExFat,
        }];

        let candidates = vec![
            Candidate {
                id: "cand-0001".to_string(),
                extents: vec![Extent::new(2_097_152, 10_000_000)],
                expected_size: 10_000_000,
                recovery_method: RecoveryMethod::FilesystemExFat,
                original_name: Some("GOPR0001.MP4".to_string()),
                recovered_name: Some("cand-0001_GOPR0001.MP4".to_string()),
                output_path: Some(
                    r"D:\Recovered\session-1\validated\cand-0001_GOPR0001.MP4".to_string(),
                ),
                confidence: Confidence::High,
                status: CandidateStatus::Validated,
                chain_preserved: true,
                is_fragmented: false,
                error_reason: None,
                error_offset: None,
            },
            Candidate {
                id: "cand-0002".to_string(),
                extents: vec![Extent::new(20_000_000, 5_000_000)],
                expected_size: 5_000_000,
                recovery_method: RecoveryMethod::RawCarve,
                original_name: None,
                recovered_name: Some("cand-0002_carved.mp4".to_string()),
                output_path: Some(
                    r"D:\Recovered\session-1\partial\cand-0002_carved.mp4".to_string(),
                ),
                confidence: Confidence::Medium,
                status: CandidateStatus::Partial,
                chain_preserved: false,
                is_fragmented: true,
                error_reason: Some("truncated moov atom".to_string()),
                error_offset: None,
            },
            Candidate {
                id: "cand-0003".to_string(),
                extents: vec![Extent::new(30_000_000, 1_000_000)],
                expected_size: 1_000_000,
                recovery_method: RecoveryMethod::RawCarve,
                original_name: None,
                recovered_name: Some("cand-0003_carved.mp4".to_string()),
                output_path: None,
                confidence: Confidence::Low,
                status: CandidateStatus::Rejected,
                chain_preserved: false,
                is_fragmented: false,
                error_reason: Some("no valid video elementary stream found".to_string()),
                error_offset: None,
            },
            Candidate {
                id: "cand-0004".to_string(),
                extents: vec![Extent::new(40_000_000, 2_000_000)],
                expected_size: 2_000_000,
                recovery_method: RecoveryMethod::FilesystemExFat,
                original_name: Some("GOPR0002.MP4".to_string()),
                recovered_name: Some("cand-0004_GOPR0002.MP4".to_string()),
                output_path: None,
                confidence: Confidence::Low,
                status: CandidateStatus::IoError,
                chain_preserved: true,
                is_fragmented: false,
                error_reason: Some("persistent sector read error".to_string()),
                error_offset: Some(40_500_000),
            },
        ];

        SessionReport::new(
            "session-1710000000000".to_string(),
            1710000000000,
            1710000005000,
            false,
            device,
            scan_config,
            filesystems,
            candidates,
        )
    }

    #[test]
    fn test_report_counts_and_new() {
        let rep = sample_report();
        assert_eq!(rep.report_version, 1);
        assert_eq!(rep.session_id, "session-1710000000000");
        assert_eq!(rep.duration_ms, 5000);
        assert!(!rep.interrupted);
        assert_eq!(rep.counts.total_candidates, 4);
        assert_eq!(rep.counts.validated, 1);
        assert_eq!(rep.counts.partial, 1);
        assert_eq!(rep.counts.rejected, 1);
        assert_eq!(rep.counts.io_error, 1);
    }

    #[test]
    fn test_format_summary_text_english() {
        let rep = sample_report();
        let summary = format_summary_text(&rep, Language::En);

        assert!(summary.contains("sd-video-recovery Session Summary"));
        assert!(summary.contains("Session ID:         session-1710000000000"));
        assert!(summary.contains("Status:             COMPLETED"));
        assert!(summary.contains("PhysicalDrive2"));
        assert!(summary.contains("SanDisk Extreme PRO"));
        assert!(summary.contains("Total Candidates:   4"));
        assert!(summary.contains("Validated:        1"));
        assert!(summary.contains("Partial:          1"));
        assert!(summary.contains("Rejected:         1"));
        assert!(summary.contains("I/O Errors:       1"));
        assert!(summary.contains("cand-0001"));
        assert!(summary.contains("cand-0002"));
        assert!(summary.contains("cand-0003"));
        assert!(summary.contains("cand-0004"));
        assert!(summary.contains("40500000"));
    }

    #[test]
    fn test_format_summary_text_armenian() {
        let rep = sample_report();
        let summary = format_summary_text(&rep, Language::Hy);

        assert!(summary.contains("sd-video-recovery Սեսիայի Ամփոփում"));
        assert!(summary.contains("Սեսիայի ID:         session-1710000000000"));
        assert!(summary.contains("Կարգավիճակ:         ԱՎԱՐՏՎԱԾ"));
        assert!(summary.contains("PhysicalDrive2"));
        assert!(summary.contains("SanDisk Extreme PRO"));
        assert!(summary.contains("Ընդհանուր թեկնածուներ: 4"));
        assert!(summary.contains("Վավերացված:         1"));
        assert!(summary.contains("Մասնակի:            1"));
        assert!(summary.contains("Մերժված:            1"));
        assert!(summary.contains("I/O Սխալներ:        1"));
        assert!(summary.contains("cand-0001"));
        assert!(summary.contains("cand-0002"));
        assert!(summary.contains("cand-0003"));
        assert!(summary.contains("cand-0004"));
    }

    #[test]
    fn test_write_session_reports_create_new_and_roundtrip() {
        let rep = sample_report();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("sd_test_reports_{unique}"));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let json_path = temp_dir.join("report.json");
        let txt_path = temp_dir.join("summary.txt");

        // First write should succeed
        write_session_reports(&json_path, &txt_path, &rep, Language::En).unwrap();

        assert!(json_path.exists());
        assert!(txt_path.exists());

        // Deserialize JSON report back and verify roundtrip
        let json_str = std::fs::read_to_string(&json_path).unwrap();
        let parsed_rep: SessionReport = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed_rep, rep);

        // Second write to the exact same paths MUST fail due to create_new semantics
        let second_write = write_session_reports(&json_path, &txt_path, &rep, Language::En);
        assert!(matches!(second_write, Err(RecoveryError::OutputIo(_))));

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_conversions_from_types() {
        let dev = DeviceIdentity {
            disk_number: 1,
            device_path: r"\\.\PhysicalDrive1".to_string(),
            model: "Generic SD".to_string(),
            size_bytes: 32_000_000_000,
            sector_size: 512,
            bus_type: BusType::Sd,
            removable: true,
            is_system_disk: false,
            masked_serial: Some("****1234".to_string()),
        };

        let masked = MaskedDeviceReport::from(&dev);
        assert_eq!(masked.disk_number, 1);
        assert_eq!(masked.masked_serial.as_deref(), Some("****1234"));

        let cfg = ScanConfig {
            disk_number: 1,
            output_dir: PathBuf::from(r"D:\Out"),
            mode: ScanMode::Deep,
            ffprobe_path: None,
            ffmpeg_path: None,
            full_verify: false,
            allow_fixed: true,
            lang: Language::Hy,
        };

        let cfg_rep = ScanConfigReport::from(&cfg);
        assert_eq!(cfg_rep.mode, ScanMode::Deep);
        assert_eq!(cfg_rep.lang, Language::Hy);
        assert!(cfg_rep.allow_fixed);
    }
}
