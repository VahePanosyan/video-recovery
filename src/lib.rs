//! `sd-video-recovery` library crate.
//!
//! Read-only Windows CLI tool and library for recovering deleted or quick-formatted
//! MP4/MOV video files from FAT32 and exFAT SD cards up to 2 TB.

pub mod carver;
pub mod cli;
pub mod device;
pub mod error;
pub mod exfat;
pub mod extractor;
pub mod fat32;
pub mod i18n;
pub mod partition;
pub mod report;
pub mod types;
pub mod validator;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::RecoveryError;
use crate::extractor::SessionPaths;
use crate::i18n::texts;
use crate::report::{MaskedDeviceReport, ScanConfigReport, SessionReport};
use crate::types::{
    CandidateStatus, DeviceIdentity, FilesystemKind, Language, PartitionInfo, ReadSource,
    ScanConfig, ScanMode,
};

struct FileReadSource {
    file: File,
    len: u64,
}

impl FileReadSource {
    fn open(path: &Path) -> Result<Self, RecoveryError> {
        let file = File::open(path).map_err(|e| {
            RecoveryError::OutputIo(format!(
                "failed to open extracted candidate file '{}': {e}",
                path.display()
            ))
        })?;
        let len = file
            .metadata()
            .map_err(|e| {
                RecoveryError::OutputIo(format!(
                    "failed to query metadata for '{}': {e}",
                    path.display()
                ))
            })?
            .len();
        Ok(Self { file, len })
    }
}

impl ReadSource for FileReadSource {
    fn size_bytes(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, RecoveryError> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| RecoveryError::OutputIo(format!("seek error at offset {offset}: {e}")))?;
        self.file
            .read(buf)
            .map_err(|e| RecoveryError::OutputIo(format!("read error at offset {offset}: {e}")))
    }
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Executes the `list` subcommand, returning formatted output (table or JSON).
///
/// # Errors
///
/// Returns [`RecoveryError::Parse`] if JSON serialization fails.
pub fn run_list_command(lang: Language, as_json: bool) -> Result<String, RecoveryError> {
    let devices = device::enumerate_physical_drives();
    cli::format_device_list(&devices, lang, as_json)
}

/// Executes the `doctor` subcommand, checking `ffprobe` and `ffmpeg` readiness.
///
/// # Errors
///
/// Returns [`RecoveryError::ExternalTool`] if `ffprobe` is missing or broken.
pub fn run_doctor_command(
    ffprobe_path: Option<&Path>,
    ffmpeg_path: Option<&Path>,
    lang: Language,
) -> Result<String, RecoveryError> {
    let t = texts(lang);
    let ffprobe_status = validator::check_tool("ffprobe", ffprobe_path);
    let ffmpeg_status = validator::check_tool("ffmpeg", ffmpeg_path);

    let mut out = String::new();
    out.push_str(
        "================================================================================\n",
    );
    out.push_str(t.doctor_title);
    out.push_str(
        "\n================================================================================\n",
    );
    out.push_str(&format!(
        "{:<10} {:<12} {:<30} {}\n",
        t.doctor_tool, t.doctor_status, t.doctor_path, t.doctor_version
    ));
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );

    for status in [&ffprobe_status, &ffmpeg_status] {
        let state_str = if status.available {
            t.doctor_available
        } else {
            t.doctor_missing
        };
        let details = status
            .version_line
            .as_deref()
            .or(status.error.as_deref())
            .unwrap_or("-");
        out.push_str(&format!(
            "{:<10} {:<12} {:<30} {}\n",
            status.name,
            state_str,
            status.resolved_path.display(),
            details
        ));
    }
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );

    if !ffprobe_status.available {
        out.push_str(t.doctor_ffprobe_missing_warning);
        out.push('\n');
        return Err(RecoveryError::ExternalTool {
            tool: "ffprobe".to_string(),
            message: out,
        });
    }

    if !ffmpeg_status.available {
        out.push_str(t.doctor_ffmpeg_missing_warning);
        out.push('\n');
    } else {
        out.push_str(t.doctor_all_ok);
        out.push('\n');
    }

    Ok(out)
}

/// Executes the recovery pipeline on any [`ReadSource`] (physical drive or synthetic memory image).
///
/// Handles:
/// - Phase 1: FAT32 / exFAT filesystem metadata discovery
/// - Phase 2: Sequential raw ISO-BMFF carving (`ftyp`, `moov`, `mdat`, `moof`)
/// - Candidate deduplication (prioritizing filesystem metadata over raw carving)
/// - Phase 3: `.part` extraction, single-sector retry error capture, `ffprobe`/`ffmpeg` validation,
///   atomic rename to `validated/` or `partial/`, and `Ctrl+C` cleanup
/// - Writing `report.json` (`report_version: 1`) and localized `summary.txt`
///
/// # Errors
///
/// Returns [`RecoveryError`] if session directory creation fails, if the user interrupts via `Ctrl+C`
/// ([`RecoveryError::Interrupted`]), or if a persistent source I/O failure occurs ([`RecoveryError::SourceIo`]).
pub fn execute_recovery_on_source<R: ReadSource + ?Sized>(
    source: &mut R,
    device: &DeviceIdentity,
    config: &ScanConfig,
    partitions: &[PartitionInfo],
    interrupted: &AtomicBool,
) -> Result<(SessionReport, SessionPaths), RecoveryError> {
    let started_at_unix_ms = current_unix_ms();
    let session_paths = extractor::create_session_dirs(&config.output_dir)?;
    let mut raw_candidates = Vec::new();
    let mut fatal_source_io: Option<RecoveryError> = None;

    // Phase 1: Filesystem metadata recovery
    if matches!(config.mode, ScanMode::All | ScanMode::Filesystem)
        && !interrupted.load(Ordering::SeqCst)
    {
        for part in partitions {
            if interrupted.load(Ordering::SeqCst) {
                break;
            }
            let res = match part.filesystem {
                FilesystemKind::Fat32 => {
                    fat32::recover_fat32_candidates(source, part.byte_offset, part.byte_len)
                }
                FilesystemKind::ExFat => {
                    exfat::recover_exfat_candidates(source, part.byte_offset, part.byte_len)
                }
                FilesystemKind::Unknown => Ok(Vec::new()),
            };

            match res {
                Ok(mut cands) => raw_candidates.append(&mut cands),
                Err(e @ RecoveryError::SourceIo { .. }) => {
                    fatal_source_io = Some(e);
                    break;
                }
                Err(RecoveryError::Parse(_)) => {
                    // If filesystem metadata is corrupted, continue so other partitions or raw carver can run.
                }
                Err(other) => return Err(other),
            }
        }
    }

    // Phase 2: Deep raw carving
    if fatal_source_io.is_none()
        && matches!(config.mode, ScanMode::All | ScanMode::Deep)
        && !interrupted.load(Ordering::SeqCst)
    {
        let disk_size = source.size_bytes();
        if disk_size >= 8 {
            match carver::carve_mp4_candidates(source, 0, disk_size) {
                Ok(mut carved) => raw_candidates.append(&mut carved),
                Err(e @ RecoveryError::SourceIo { .. }) => {
                    fatal_source_io = Some(e);
                }
                Err(RecoveryError::Parse(_)) => {}
                Err(other) => return Err(other),
            }
        }
    }

    let mut candidates = extractor::deduplicate_candidates(raw_candidates);
    let mut active_part: Option<PathBuf> = None;

    let ffprobe_bin = config
        .ffprobe_path
        .as_deref()
        .unwrap_or_else(|| Path::new("ffprobe"));
    let ffmpeg_bin = config
        .ffmpeg_path
        .as_deref()
        .or_else(|| Some(Path::new("ffmpeg")));
    let verify_timeout = if config.full_verify {
        Duration::from_secs(300)
    } else {
        Duration::from_secs(30)
    };

    // Phase 3: Extraction and validation
    if fatal_source_io.is_none() {
        for cand in &mut candidates {
            if interrupted.load(Ordering::SeqCst) {
                extractor::cleanup_active_part(&mut active_part);
                break;
            }

            match extractor::extract_candidate_to_part(
                source,
                cand,
                &session_paths,
                interrupted,
                &mut active_part,
            ) {
                Ok(part_path) => {
                    if interrupted.load(Ordering::SeqCst) {
                        extractor::cleanup_active_part(&mut active_part);
                        break;
                    }

                    let (structure_complete, has_video_header) =
                        match FileReadSource::open(&part_path)
                            .and_then(|mut fs| carver::inspect_mp4_structure(&mut fs))
                        {
                            Ok(info) => (
                                info.is_complete_video_container(),
                                info.has_ftyp || info.has_moov || info.has_mdat || info.has_moof,
                            ),
                            Err(_) => (false, false),
                        };

                    if let Err(e) = validator::validate_extracted_candidate(
                        cand,
                        &part_path,
                        ffprobe_bin,
                        ffmpeg_bin,
                        config.full_verify,
                        verify_timeout,
                        structure_complete,
                        has_video_header,
                    ) {
                        extractor::cleanup_active_part(&mut active_part);
                        return Err(e);
                    }

                    extractor::finalize_candidate_file(
                        &part_path,
                        cand,
                        &session_paths,
                        &mut active_part,
                    )?;
                }
                Err(RecoveryError::Interrupted) => {
                    extractor::cleanup_active_part(&mut active_part);
                    break;
                }
                Err(e @ RecoveryError::SourceIo { .. }) => {
                    extractor::cleanup_active_part(&mut active_part);
                    fatal_source_io = Some(e);
                    break;
                }
                Err(other) => {
                    extractor::cleanup_active_part(&mut active_part);
                    return Err(other);
                }
            }
        }
    }

    extractor::cleanup_active_part(&mut active_part);

    let was_interrupted = interrupted.load(Ordering::SeqCst);
    let finished_at_unix_ms = current_unix_ms();

    let report = SessionReport::new(
        session_paths.session_id.clone(),
        started_at_unix_ms,
        finished_at_unix_ms,
        was_interrupted,
        MaskedDeviceReport::from(device),
        ScanConfigReport::from(config),
        partitions.to_vec(),
        candidates,
    );

    report::write_session_reports(
        &session_paths.report_json_path,
        &session_paths.summary_txt_path,
        &report,
        config.lang,
    )?;

    if was_interrupted {
        return Err(RecoveryError::Interrupted);
    }

    if let Some(io_err) = fatal_source_io {
        return Err(io_err);
    }

    Ok((report, session_paths))
}

/// Runs the interactive `recover` CLI workflow against a Windows physical drive.
///
/// # Errors
///
/// Returns [`RecoveryError`] if tool verification, safety preflight checks, user confirmation,
/// or source recovery fails.
pub fn run_recover_command(
    config: &ScanConfig,
) -> Result<(SessionReport, SessionPaths), RecoveryError> {
    let t = texts(config.lang);

    // 1. Verify required external tools (ffprobe, and ffmpeg if --full-verify)
    validator::require_tools(
        config.ffprobe_path.as_deref(),
        config.ffmpeg_path.as_deref(),
        config.full_verify,
    )?;

    // 2. Query source device identity (read-only metadata)
    let identity = device::query_device_identity(config.disk_number)?;

    // 3. Enforce source device safety (refuse system disk, refuse non-SD/MMC/USB, require --allow-fixed for fixed media)
    device::validate_source_device_safety(&identity, config.allow_fixed)?;

    // 4. Enforce separate physical disk for output directory
    device::check_output_not_on_source_disk(config.disk_number, &config.output_dir)?;

    // 5. Open source physical drive strictly read-only
    let mut reader = device::open_physical_drive(config.disk_number)?;

    // 6. Parse partition layout for pre-scan confirmation banner
    let partitions = match partition::parse_partitions(&mut reader) {
        Ok(parts) => parts,
        Err(e @ RecoveryError::SourceIo { .. }) => return Err(e),
        Err(RecoveryError::Parse(_)) if config.mode != ScanMode::Filesystem => Vec::new(),
        Err(e) => return Err(e),
    };

    // 6. Display pre-scan target device summary and require user to type exact disk number
    let banner = cli::format_confirmation_prompt(&identity, &partitions, config.lang);
    print!("{banner}");
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    cli::confirm_disk_selection(config.disk_number, &mut stdin_lock, config.lang)?;

    // 7. Install Ctrl+C handler
    let interrupted = Arc::new(AtomicBool::new(false));
    device::install_ctrlc_handler(Arc::clone(&interrupted))?;

    if matches!(config.mode, ScanMode::All | ScanMode::Filesystem) {
        println!("{}", t.phase_filesystem_start);
    }
    if matches!(config.mode, ScanMode::All | ScanMode::Deep) {
        println!("{}", t.phase_deep_start);
    }
    println!("{}", t.phase_validation_start);

    // 8. Run recovery pipeline
    let (report, session_paths) =
        execute_recovery_on_source(&mut reader, &identity, config, &partitions, &interrupted)?;

    let recovered_bytes: u64 = report
        .candidates
        .iter()
        .filter(|c| {
            matches!(
                c.status,
                CandidateStatus::Validated | CandidateStatus::Partial
            )
        })
        .map(|c| c.expected_size)
        .sum();

    println!("\n{}", t.session_complete_summary);
    println!(
        "  {}: {} (validated: {}, partial: {})",
        t.session_files_recovered,
        report.counts.validated + report.counts.partial,
        report.counts.validated,
        report.counts.partial
    );
    println!(
        "  {}: {}",
        t.session_bytes_recovered,
        cli::format_bytes(recovered_bytes)
    );
    println!(
        "  {}: {}",
        t.session_report_saved,
        session_paths.report_json_path.display()
    );

    Ok((report, session_paths))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BusType, MemorySource, PartitionScheme};

    #[test]
    fn test_execute_recovery_on_empty_memory_source() {
        let mut source = MemorySource::new(vec![0u8; 4096]);
        let device = DeviceIdentity {
            disk_number: 2,
            device_path: r"\\.\PhysicalDrive2".to_string(),
            model: "Test Reader".to_string(),
            size_bytes: 4096,
            sector_size: 512,
            bus_type: BusType::Usb,
            removable: true,
            is_system_disk: false,
            masked_serial: Some("****1234".to_string()),
        };
        let temp_dir =
            std::env::temp_dir().join(format!("sd_video_lib_test_{}", current_unix_ms()));
        let config = ScanConfig {
            disk_number: 2,
            output_dir: temp_dir.clone(),
            mode: ScanMode::Deep,
            ffprobe_path: None,
            ffmpeg_path: None,
            full_verify: false,
            allow_fixed: false,
            lang: Language::En,
        };
        let parts = vec![PartitionInfo {
            index: 0,
            scheme: PartitionScheme::Superfloppy,
            byte_offset: 0,
            byte_len: 4096,
            type_id: "Superfloppy".to_string(),
            name: None,
            filesystem: FilesystemKind::Unknown,
        }];
        let interrupted = AtomicBool::new(false);

        let (report, paths) =
            execute_recovery_on_source(&mut source, &device, &config, &parts, &interrupted)
                .expect("recovery on empty source should succeed");
        assert_eq!(report.report_version, 1);
        assert_eq!(report.counts.total_candidates, 0);
        assert!(paths.report_json_path.exists());
        assert!(paths.summary_txt_path.exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
