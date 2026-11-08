//! Candidate deduplication, .part extraction, atomic rename, and Ctrl+C cleanup.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::RecoveryError;
use crate::types::{Candidate, CandidateStatus, Confidence, ReadSource};

/// Paths to session-specific output directories and report files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPaths {
    /// Unique session identifier (e.g. `"session-1710000000000"`).
    pub session_id: String,
    /// Absolute or relative path to the session root directory.
    pub session_dir: PathBuf,
    /// Output directory for validated video files (`<session_dir>/validated`).
    pub validated_dir: PathBuf,
    /// Output directory for partial/incomplete video files (`<session_dir>/partial`).
    pub partial_dir: PathBuf,
    /// Path to the JSON report file (`<session_dir>/report.json`).
    pub report_json_path: PathBuf,
    /// Path to the human-readable summary text file (`<session_dir>/summary.txt`).
    pub summary_txt_path: PathBuf,
}

/// Creates a brand-new timestamped session directory with `create_new` semantics,
/// along with `validated/` and `partial/` subdirectories.
///
/// # Errors
///
/// Returns [`RecoveryError::OutputIo`] if directory creation fails or if collision resolution exhausts.
pub fn create_session_dirs(base_output: &Path) -> Result<SessionPaths, RecoveryError> {
    if !base_output.exists() {
        std::fs::create_dir_all(base_output).map_err(|e| {
            RecoveryError::OutputIo(format!(
                "failed to create base output directory '{}': {e}",
                base_output.display()
            ))
        })?;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let (session_id, session_dir) = {
        let initial_id = format!("session-{now_ms}");
        let initial_path = base_output.join(&initial_id);
        match std::fs::create_dir(&initial_path) {
            Ok(()) => (initial_id, initial_path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut counter = 1u32;
                loop {
                    let cand_id = format!("session-{now_ms}-{counter}");
                    let cand_path = base_output.join(&cand_id);
                    match std::fs::create_dir(&cand_path) {
                        Ok(()) => break (cand_id, cand_path),
                        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                            counter += 1;
                            if counter > 10_000 {
                                return Err(RecoveryError::OutputIo(
                                    "too many session directory collisions".to_string(),
                                ));
                            }
                        }
                        Err(err) => {
                            return Err(RecoveryError::OutputIo(format!(
                                "failed to create session directory '{}': {err}",
                                cand_path.display()
                            )));
                        }
                    }
                }
            }
            Err(e) => {
                return Err(RecoveryError::OutputIo(format!(
                    "failed to create session directory '{}': {e}",
                    initial_path.display()
                )));
            }
        }
    };

    let validated_dir = session_dir.join("validated");
    std::fs::create_dir(&validated_dir).map_err(|e| {
        RecoveryError::OutputIo(format!(
            "failed to create validated directory '{}': {e}",
            validated_dir.display()
        ))
    })?;

    let partial_dir = session_dir.join("partial");
    std::fs::create_dir(&partial_dir).map_err(|e| {
        RecoveryError::OutputIo(format!(
            "failed to create partial directory '{}': {e}",
            partial_dir.display()
        ))
    })?;

    let report_json_path = session_dir.join("report.json");
    let summary_txt_path = session_dir.join("summary.txt");

    Ok(SessionPaths {
        session_id,
        session_dir,
        validated_dir,
        partial_dir,
        report_json_path,
        summary_txt_path,
    })
}

/// Sanitizes a raw filename component against directory traversal, Windows reserved names,
/// and invalid characters, ensuring an `.mp4` or `.mov` extension and prefixing with `cand_id`.
#[must_use]
pub fn sanitize_filename(cand_id: &str, raw_name: Option<&str>) -> String {
    let raw = raw_name.unwrap_or("").trim();

    // Strip leading path components by splitting on both forward and backward slashes.
    let base = raw
        .split(['/', '\\'])
        .rfind(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .unwrap_or("carved.mp4");

    // Replace Windows prohibited characters (< > : " / \ | ? * and ASCII control chars < 32) with '_'.
    let mut cleaned: String = base
        .chars()
        .map(|c| {
            if c < ' ' || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();

    // Trim trailing spaces and dots (prohibited on Windows).
    while cleaned.ends_with(' ') || cleaned.ends_with('.') {
        cleaned.pop();
    }

    if cleaned.is_empty() {
        cleaned = "carved.mp4".to_string();
    }

    // Determine extension: preserve .mov or .mp4 (case-insensitive), or default to .mp4.
    let lower = cleaned.to_lowercase();
    let has_mp4 = lower.ends_with(".mp4");
    let has_mov = lower.ends_with(".mov");

    let final_leaf = if has_mp4 || has_mov {
        let stem = &cleaned[..cleaned.len() - 4];
        let ext = &cleaned[cleaned.len() - 4..];

        // Check Windows reserved device names on the stem.
        let stem_upper = stem.to_ascii_uppercase();
        let is_reserved = matches!(
            stem_upper.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        );
        if is_reserved {
            format!("file_{stem}{ext}")
        } else {
            cleaned
        }
    } else {
        // Non-mp4/mov extension: strip existing extension and enforce .mp4.
        let stem = if let Some(dot_idx) = cleaned.rfind('.') {
            &cleaned[..dot_idx]
        } else {
            &cleaned
        };
        let stem = stem.trim_end_matches([' ', '.']);
        let stem = if stem.is_empty() { "carved" } else { stem };
        let stem_upper = stem.to_ascii_uppercase();
        let is_reserved = matches!(
            stem_upper.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        );
        if is_reserved {
            format!("file_{stem}.mp4")
        } else {
            format!("{stem}.mp4")
        }
    };

    // Prefix with cand_id unless already prefixed.
    let prefix = format!("{cand_id}_");
    if final_leaf.starts_with(&prefix)
        || final_leaf == format!("{cand_id}.mp4")
        || final_leaf == format!("{cand_id}.mov")
    {
        final_leaf
    } else {
        format!("{prefix}{final_leaf}")
    }
}

/// Deduplicates candidates from the same source extent, giving priority to filesystem
/// candidates (FAT32 and exFAT) over raw carving (`RawCarve`).
///
/// Sequential identifiers (`cand-0001`, `cand-0002`, ...) are assigned and output filenames
/// are sanitized against path traversal and reserved Windows names.
#[must_use]
pub fn deduplicate_candidates(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    // Stable sort: all filesystem candidates come first, keeping relative order.
    candidates.sort_by_key(|c| {
        if c.recovery_method.is_filesystem() {
            0
        } else {
            1
        }
    });

    let mut accepted: Vec<Candidate> = Vec::new();

    for cand in candidates {
        let is_duplicate = accepted.iter().any(|acc| {
            // Check identical primary starting offset.
            if let (Some(cand_off), Some(acc_off)) = (cand.primary_offset(), acc.primary_offset()) {
                if cand_off == acc_off {
                    return true;
                }
            }

            // Check if any extent of this candidate overlaps the first extent of an already accepted filesystem candidate.
            if acc.recovery_method.is_filesystem() {
                if let Some(acc_first) = acc.extents.first() {
                    if cand.extents.iter().any(|e| e.overlaps(acc_first)) {
                        return true;
                    }
                }
            }

            false
        });

        if !is_duplicate {
            accepted.push(cand);
        }
    }

    // Assign sequential IDs and sanitize recovered_name.
    for (i, cand) in accepted.iter_mut().enumerate() {
        let id = format!("cand-{:04}", i + 1);
        cand.id = id.clone();
        let raw_name = cand
            .recovered_name
            .as_deref()
            .or(cand.original_name.as_deref());
        cand.recovered_name = Some(sanitize_filename(&id, raw_name));
    }

    accepted
}

/// Extracts candidate extents from `source` into a temporary `.part` file in the session directory.
///
/// Uses 64 KiB chunk copying, respects `interrupted`, updates `active_part`, and handles
/// source I/O errors by recording the exact failure offset on the candidate before returning.
///
/// # Errors
///
/// Returns [`RecoveryError::Interrupted`] on SIGINT/Ctrl+C.
/// Returns [`RecoveryError::SourceIo`] on read failure.
/// Returns [`RecoveryError::OutputIo`] on destination write failure.
pub fn extract_candidate_to_part<R: ReadSource + ?Sized>(
    source: &mut R,
    candidate: &mut Candidate,
    session: &SessionPaths,
    interrupted: &AtomicBool,
    active_part: &mut Option<PathBuf>,
) -> Result<PathBuf, RecoveryError> {
    // Ensure recovered_name is set and sanitized.
    let rec_name = match candidate.recovered_name.take() {
        Some(name) => sanitize_filename(&candidate.id, Some(&name)),
        None => sanitize_filename(&candidate.id, candidate.original_name.as_deref()),
    };
    candidate.recovered_name = Some(rec_name.clone());

    let part_path = session.session_dir.join(format!("{rec_name}.part"));

    // Open with create_new semantics — NEVER overwrite existing files!
    let file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part_path)
    {
        Ok(f) => f,
        Err(e) => {
            return Err(RecoveryError::OutputIo(format!(
                "failed to create partial extraction file '{}': {e}",
                part_path.display()
            )));
        }
    };

    *active_part = Some(part_path.clone());

    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, file);
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut remaining = candidate.expected_size;

    for extent in &candidate.extents {
        if remaining == 0 {
            break;
        }

        let extent_to_copy = extent.byte_len.min(remaining);
        let mut extent_copied = 0u64;

        while extent_copied < extent_to_copy {
            if interrupted.load(Ordering::SeqCst) {
                drop(writer);
                let _ = std::fs::remove_file(&part_path);
                *active_part = None;
                return Err(RecoveryError::Interrupted);
            }

            let to_read = ((extent_to_copy - extent_copied) as usize).min(CHUNK_SIZE);
            let chunk_offset = match extent.byte_offset.checked_add(extent_copied) {
                Some(off) => off,
                None => {
                    drop(writer);
                    let _ = std::fs::remove_file(&part_path);
                    *active_part = None;
                    return Err(RecoveryError::Parse(
                        "extent byte offset arithmetic overflow during extraction".to_string(),
                    ));
                }
            };

            if let Err(read_err) = source.read_exact_at(chunk_offset, &mut buf[..to_read]) {
                drop(writer);
                let _ = std::fs::remove_file(&part_path);
                *active_part = None;

                candidate.status = CandidateStatus::IoError;
                candidate.confidence = Confidence::Low;
                candidate.output_path = None;

                match read_err {
                    RecoveryError::SourceIo { offset, message } => {
                        let actual_offset = offset.or(Some(chunk_offset));
                        candidate.error_offset = actual_offset;
                        candidate.error_reason = Some(message.clone());
                        return Err(RecoveryError::SourceIo {
                            offset: actual_offset,
                            message,
                        });
                    }
                    other => {
                        let msg = other.to_string();
                        candidate.error_offset = Some(chunk_offset);
                        candidate.error_reason = Some(msg.clone());
                        return Err(RecoveryError::SourceIo {
                            offset: Some(chunk_offset),
                            message: msg,
                        });
                    }
                }
            }

            if let Err(e) = writer.write_all(&buf[..to_read]) {
                drop(writer);
                let _ = std::fs::remove_file(&part_path);
                *active_part = None;
                return Err(RecoveryError::OutputIo(format!(
                    "failed to write to partial extraction file '{}': {e}",
                    part_path.display()
                )));
            }

            extent_copied += to_read as u64;
            remaining -= to_read as u64;
        }
    }

    if let Err(e) = writer.flush() {
        drop(writer);
        let _ = std::fs::remove_file(&part_path);
        *active_part = None;
        return Err(RecoveryError::OutputIo(format!(
            "failed to flush partial extraction file '{}': {e}",
            part_path.display()
        )));
    }

    let file = match writer.into_inner() {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(&part_path);
            *active_part = None;
            return Err(RecoveryError::OutputIo(format!(
                "failed to unwrap buffer for '{}': {e}",
                part_path.display()
            )));
        }
    };

    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = std::fs::remove_file(&part_path);
        *active_part = None;
        return Err(RecoveryError::OutputIo(format!(
            "failed to sync partial extraction file '{}': {e}",
            part_path.display()
        )));
    }

    drop(file);
    Ok(part_path)
}

/// Finalizes an extracted `.part` file by atomically renaming it to its destination directory
/// (`validated/` or `partial/`) or deleting it if the candidate was rejected or suffered an I/O error.
///
/// # Errors
///
/// Returns [`RecoveryError::OutputIo`] if the destination file already exists or renaming fails.
pub fn finalize_candidate_file(
    part_path: &Path,
    candidate: &mut Candidate,
    session: &SessionPaths,
    active_part: &mut Option<PathBuf>,
) -> Result<(), RecoveryError> {
    match candidate.status {
        CandidateStatus::Validated | CandidateStatus::Partial => {
            let target_dir = if candidate.status == CandidateStatus::Validated {
                &session.validated_dir
            } else {
                &session.partial_dir
            };

            let leaf_name = candidate
                .recovered_name
                .as_deref()
                .unwrap_or("recovered.mp4");
            let target_path = target_dir.join(leaf_name);

            if target_path.exists() {
                return Err(RecoveryError::OutputIo(format!(
                    "destination file already exists: '{}'",
                    target_path.display()
                )));
            }

            std::fs::rename(part_path, &target_path).map_err(|e| {
                RecoveryError::OutputIo(format!(
                    "failed to rename '{}' to '{}': {e}",
                    part_path.display(),
                    target_path.display()
                ))
            })?;

            *active_part = None;
            candidate.output_path = Some(target_path.to_string_lossy().into_owned());
            Ok(())
        }
        CandidateStatus::Rejected | CandidateStatus::IoError => {
            if part_path.exists() {
                let _ = std::fs::remove_file(part_path);
            }
            *active_part = None;
            candidate.output_path = None;
            Ok(())
        }
    }
}

/// Cleans up any actively extracting `.part` file upon interruption or failure.
pub fn cleanup_active_part(active_part: &mut Option<PathBuf>) {
    if let Some(path) = active_part.take() {
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Extent, MemorySource, RecoveryMethod};

    #[test]
    fn test_sanitize_filename_traversal_and_reserved() {
        // Path traversal attempts
        assert_eq!(
            sanitize_filename("cand-0001", Some("../../etc/passwd")),
            "cand-0001_passwd.mp4"
        );
        assert_eq!(
            sanitize_filename("cand-0001", Some("..\\..\\Windows\\System32\\cmd.exe")),
            "cand-0001_cmd.mp4"
        );
        assert_eq!(
            sanitize_filename("cand-0001", Some("/var/log/video.mov")),
            "cand-0001_video.mov"
        );

        // Windows reserved names
        assert_eq!(
            sanitize_filename("cand-0001", Some("CON.mp4")),
            "cand-0001_file_CON.mp4"
        );
        assert_eq!(
            sanitize_filename("cand-0001", Some("aux.mov")),
            "cand-0001_file_aux.mov"
        );
        assert_eq!(
            sanitize_filename("cand-0001", Some("NUL")),
            "cand-0001_file_NUL.mp4"
        );
        assert_eq!(
            sanitize_filename("cand-0001", Some("com1.mp4")),
            "cand-0001_file_com1.mp4"
        );

        // Prohibited characters
        assert_eq!(
            sanitize_filename("cand-0001", Some("clip:1*2?3<4>5|6.mp4")),
            "cand-0001_clip_1_2_3_4_5_6.mp4"
        );

        // None and empty fallbacks
        assert_eq!(sanitize_filename("cand-0001", None), "cand-0001_carved.mp4");
        assert_eq!(
            sanitize_filename("cand-0001", Some("")),
            "cand-0001_carved.mp4"
        );
        assert_eq!(
            sanitize_filename("cand-0001", Some("..")),
            "cand-0001_carved.mp4"
        );

        // Already prefixed names
        assert_eq!(
            sanitize_filename("cand-0001", Some("cand-0001_GOPR0001.MP4")),
            "cand-0001_GOPR0001.MP4"
        );
        assert_eq!(
            sanitize_filename("cand-0001", Some("cand-0001.mp4")),
            "cand-0001.mp4"
        );
    }

    #[test]
    fn test_deduplicate_candidates_priority_and_overlap() {
        let c_fs = Candidate {
            id: "old-1".to_string(),
            extents: vec![Extent::new(1000, 500)],
            expected_size: 500,
            recovery_method: RecoveryMethod::FilesystemFat32,
            original_name: Some("FS_FILE.MP4".to_string()),
            recovered_name: None,
            output_path: None,
            confidence: Confidence::High,
            status: CandidateStatus::Validated,
            chain_preserved: true,
            is_fragmented: false,
            error_reason: None,
            error_offset: None,
        };

        // Identical offset raw carve -> should be deduplicated
        let c_carve_same = Candidate {
            id: "old-2".to_string(),
            extents: vec![Extent::new(1000, 500)],
            expected_size: 500,
            recovery_method: RecoveryMethod::RawCarve,
            original_name: None,
            recovered_name: None,
            output_path: None,
            confidence: Confidence::Medium,
            status: CandidateStatus::Validated,
            chain_preserved: false,
            is_fragmented: false,
            error_reason: None,
            error_offset: None,
        };

        // Overlapping offset raw carve -> should be deduplicated
        let c_carve_overlap = Candidate {
            id: "old-3".to_string(),
            extents: vec![Extent::new(1200, 400)],
            expected_size: 400,
            recovery_method: RecoveryMethod::RawCarve,
            original_name: None,
            recovered_name: None,
            output_path: None,
            confidence: Confidence::Medium,
            status: CandidateStatus::Validated,
            chain_preserved: false,
            is_fragmented: false,
            error_reason: None,
            error_offset: None,
        };

        // Distinct non-overlapping raw carve -> should be accepted
        let c_carve_distinct = Candidate {
            id: "old-4".to_string(),
            extents: vec![Extent::new(2000, 300)],
            expected_size: 300,
            recovery_method: RecoveryMethod::RawCarve,
            original_name: None,
            recovered_name: None,
            output_path: None,
            confidence: Confidence::Medium,
            status: CandidateStatus::Validated,
            chain_preserved: false,
            is_fragmented: false,
            error_reason: None,
            error_offset: None,
        };

        // Place raw carves BEFORE filesystem candidate in input vector to verify priority sorting.
        let candidates = vec![c_carve_same, c_carve_overlap, c_fs, c_carve_distinct];

        let result = deduplicate_candidates(candidates);
        assert_eq!(result.len(), 2);

        // First accepted must be the filesystem candidate
        assert_eq!(result[0].id, "cand-0001");
        assert_eq!(result[0].recovery_method, RecoveryMethod::FilesystemFat32);
        assert_eq!(
            result[0].recovered_name.as_deref(),
            Some("cand-0001_FS_FILE.MP4")
        );

        // Second accepted must be the distinct raw carve
        assert_eq!(result[1].id, "cand-0002");
        assert_eq!(result[1].recovery_method, RecoveryMethod::RawCarve);
        assert_eq!(
            result[1].recovered_name.as_deref(),
            Some("cand-0002_carved.mp4")
        );
    }

    #[test]
    fn test_create_session_dirs() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!("sd_test_session_{unique}"));

        let paths = create_session_dirs(&base_dir).expect("session dirs should be created");
        assert!(paths.session_dir.is_dir());
        assert!(paths.validated_dir.is_dir());
        assert!(paths.partial_dir.is_dir());
        assert_eq!(
            paths.report_json_path,
            paths.session_dir.join("report.json")
        );
        assert_eq!(
            paths.summary_txt_path,
            paths.session_dir.join("summary.txt")
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn test_extract_and_finalize_validated() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!("sd_test_extract_val_{unique}"));
        let session = create_session_dirs(&base_dir).unwrap();

        let source_data = vec![0xAB; 128 * 1024];
        let mut source = MemorySource::new(source_data.clone());

        let mut candidate = Candidate {
            id: "cand-0001".to_string(),
            extents: vec![Extent::new(1024, 70_000)],
            expected_size: 70_000,
            recovery_method: RecoveryMethod::FilesystemFat32,
            original_name: Some("GOPR0001.MP4".to_string()),
            recovered_name: None,
            output_path: None,
            confidence: Confidence::High,
            status: CandidateStatus::Validated,
            chain_preserved: true,
            is_fragmented: false,
            error_reason: None,
            error_offset: None,
        };

        let interrupted = AtomicBool::new(false);
        let mut active_part = None;

        let part_path = extract_candidate_to_part(
            &mut source,
            &mut candidate,
            &session,
            &interrupted,
            &mut active_part,
        )
        .expect("extraction should succeed");

        assert!(part_path.exists());
        assert_eq!(active_part, Some(part_path.clone()));

        finalize_candidate_file(&part_path, &mut candidate, &session, &mut active_part)
            .expect("finalize should succeed");

        assert!(!part_path.exists());
        assert!(active_part.is_none());

        let final_path = PathBuf::from(candidate.output_path.as_ref().unwrap());
        assert!(final_path.exists());
        assert_eq!(final_path.parent().unwrap(), session.validated_dir);

        let final_bytes = std::fs::read(&final_path).unwrap();
        assert_eq!(final_bytes.len(), 70_000);
        assert_eq!(final_bytes, &source_data[1024..1024 + 70_000]);

        // Cleanup
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn test_extract_and_finalize_partial() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!("sd_test_extract_part_{unique}"));
        let session = create_session_dirs(&base_dir).unwrap();

        let source_data = vec![0xCD; 64 * 1024];
        let mut source = MemorySource::new(source_data.clone());

        let mut candidate = Candidate {
            id: "cand-0002".to_string(),
            extents: vec![Extent::new(0, 32 * 1024)],
            expected_size: 32 * 1024,
            recovery_method: RecoveryMethod::RawCarve,
            original_name: None,
            recovered_name: None,
            output_path: None,
            confidence: Confidence::Medium,
            status: CandidateStatus::Partial,
            chain_preserved: false,
            is_fragmented: false,
            error_reason: None,
            error_offset: None,
        };

        let interrupted = AtomicBool::new(false);
        let mut active_part = None;

        let part_path = extract_candidate_to_part(
            &mut source,
            &mut candidate,
            &session,
            &interrupted,
            &mut active_part,
        )
        .expect("extraction should succeed");

        finalize_candidate_file(&part_path, &mut candidate, &session, &mut active_part)
            .expect("finalize should succeed");

        let final_path = PathBuf::from(candidate.output_path.as_ref().unwrap());
        assert!(final_path.exists());
        assert_eq!(final_path.parent().unwrap(), session.partial_dir);

        // Cleanup
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn test_finalize_rejected_deletes_part() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!("sd_test_rej_{unique}"));
        let session = create_session_dirs(&base_dir).unwrap();

        let mut source = MemorySource::new(vec![0xAA; 1024]);
        let mut candidate = Candidate {
            id: "cand-0003".to_string(),
            extents: vec![Extent::new(0, 512)],
            expected_size: 512,
            recovery_method: RecoveryMethod::RawCarve,
            original_name: None,
            recovered_name: None,
            output_path: None,
            confidence: Confidence::Low,
            status: CandidateStatus::Rejected,
            chain_preserved: false,
            is_fragmented: false,
            error_reason: Some("no valid video stream".to_string()),
            error_offset: None,
        };

        let interrupted = AtomicBool::new(false);
        let mut active_part = None;

        let part_path = extract_candidate_to_part(
            &mut source,
            &mut candidate,
            &session,
            &interrupted,
            &mut active_part,
        )
        .unwrap();

        assert!(part_path.exists());
        finalize_candidate_file(&part_path, &mut candidate, &session, &mut active_part).unwrap();

        assert!(!part_path.exists());
        assert!(active_part.is_none());
        assert!(candidate.output_path.is_none());

        // Cleanup
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn test_interruption_cleans_up_active_part() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!("sd_test_interrupt_{unique}"));
        let session = create_session_dirs(&base_dir).unwrap();

        let mut source = MemorySource::new(vec![0xFF; 256 * 1024]);
        let mut candidate = Candidate {
            id: "cand-0004".to_string(),
            extents: vec![Extent::new(0, 200 * 1024)],
            expected_size: 200 * 1024,
            recovery_method: RecoveryMethod::RawCarve,
            original_name: None,
            recovered_name: None,
            output_path: None,
            confidence: Confidence::High,
            status: CandidateStatus::Validated,
            chain_preserved: false,
            is_fragmented: false,
            error_reason: None,
            error_offset: None,
        };

        // Pre-set interrupted flag to simulate Ctrl+C before extraction loop starts.
        let interrupted = AtomicBool::new(true);
        let mut active_part = None;

        let result = extract_candidate_to_part(
            &mut source,
            &mut candidate,
            &session,
            &interrupted,
            &mut active_part,
        );

        assert!(matches!(result, Err(RecoveryError::Interrupted)));
        assert!(active_part.is_none());

        let expected_part = session.session_dir.join("cand-0004_carved.mp4.part");
        assert!(!expected_part.exists());

        // Also test cleanup_active_part helper when active_part is Some.
        let dummy_part = session.session_dir.join("dummy.part");
        std::fs::write(&dummy_part, b"dummy").unwrap();
        let mut to_clean = Some(dummy_part.clone());
        cleanup_active_part(&mut to_clean);
        assert!(!dummy_part.exists());
        assert!(to_clean.is_none());

        // Cleanup
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn test_source_io_error_records_offset_and_cleans_up() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!("sd_test_ioerr_{unique}"));
        let session = create_session_dirs(&base_dir).unwrap();

        let mut source = MemorySource::new(vec![0x77; 64 * 1024]);
        // Inject failure at sector starting at offset 1024
        source.inject_persistent_failure(1024);

        let mut candidate = Candidate {
            id: "cand-0005".to_string(),
            extents: vec![Extent::new(0, 10 * 1024)],
            expected_size: 10 * 1024,
            recovery_method: RecoveryMethod::FilesystemFat32,
            original_name: Some("FAULTY.MP4".to_string()),
            recovered_name: None,
            output_path: None,
            confidence: Confidence::High,
            status: CandidateStatus::Validated,
            chain_preserved: true,
            is_fragmented: false,
            error_reason: None,
            error_offset: None,
        };

        let interrupted = AtomicBool::new(false);
        let mut active_part = None;

        let result = extract_candidate_to_part(
            &mut source,
            &mut candidate,
            &session,
            &interrupted,
            &mut active_part,
        );

        assert!(matches!(result, Err(RecoveryError::SourceIo { .. })));
        assert_eq!(candidate.status, CandidateStatus::IoError);
        assert_eq!(candidate.confidence, Confidence::Low);
        assert_eq!(candidate.error_offset, Some(1024));
        assert!(candidate.error_reason.is_some());
        assert!(active_part.is_none());

        let expected_part = session.session_dir.join("cand-0005_FAULTY.MP4.part");
        assert!(!expected_part.exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn test_finalize_destination_collision_fails() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!("sd_test_coll_{unique}"));
        let session = create_session_dirs(&base_dir).unwrap();

        // Pre-create file in validated directory
        let pre_existing = session.validated_dir.join("cand-0006_COLLISION.MP4");
        std::fs::write(&pre_existing, b"already exists").unwrap();

        let dummy_part = session.session_dir.join("cand-0006_COLLISION.MP4.part");
        std::fs::write(&dummy_part, b"new content").unwrap();

        let mut candidate = Candidate {
            id: "cand-0006".to_string(),
            extents: vec![Extent::new(0, 100)],
            expected_size: 100,
            recovery_method: RecoveryMethod::FilesystemFat32,
            original_name: Some("COLLISION.MP4".to_string()),
            recovered_name: Some("cand-0006_COLLISION.MP4".to_string()),
            output_path: None,
            confidence: Confidence::High,
            status: CandidateStatus::Validated,
            chain_preserved: true,
            is_fragmented: false,
            error_reason: None,
            error_offset: None,
        };

        let mut active_part = Some(dummy_part.clone());
        let res = finalize_candidate_file(&dummy_part, &mut candidate, &session, &mut active_part);

        assert!(matches!(res, Err(RecoveryError::OutputIo(_))));
        // Ensure pre-existing file was NOT overwritten
        assert_eq!(std::fs::read(&pre_existing).unwrap(), b"already exists");

        // Cleanup
        let _ = std::fs::remove_dir_all(&base_dir);
    }
}
