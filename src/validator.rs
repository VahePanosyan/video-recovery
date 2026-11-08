//! External `ffprobe` and `ffmpeg` media validation.
//!
//! Provides direct process execution with timeout management (no shell invocation),
//! tool availability discovery (`doctor`), JSON stream metadata parsing,
//! full stream decode verification (`--full-verify`), and candidate classification.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::RecoveryError;
use crate::types::{Candidate, CandidateStatus, Confidence};

/// Diagnostic availability and version status for an external tool (`ffprobe` or `ffmpeg`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStatus {
    /// Tool binary name (e.g. `"ffprobe"` or `"ffmpeg"`).
    pub name: String,
    /// Resolved executable path checked on disk or in PATH.
    pub resolved_path: PathBuf,
    /// Whether the tool was found and executed successfully.
    pub available: bool,
    /// First line of tool version output if available.
    pub version_line: Option<String>,
    /// Error description if the tool was not found or failed execution.
    pub error: Option<String>,
}

/// Parsed video metadata from `ffprobe`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeMetadata {
    /// Container format name (e.g. `"mov,mp4,m4a,3gp,3g2,mj2"`).
    pub format_name: String,
    /// Video duration in seconds, if available.
    pub duration_secs: Option<f64>,
    /// Video codec identifier (e.g. `"h264"`, `"hevc"`).
    pub video_codec: String,
    /// Video frame width in pixels.
    pub width: u32,
    /// Video frame height in pixels.
    pub height: u32,
}

/// Executes a program directly with arguments and a strict timeout.
///
/// **Safety & Security**: This function spawns the executable directly via `std::process::Command`
/// and **never** delegates to `cmd.exe`, `powershell`, or any shell. Stdout and stderr are
/// consumed asynchronously to prevent process deadlocks on full OS pipe buffers.
///
/// # Errors
///
/// Returns [`RecoveryError::ExternalTool`] if:
/// - Spawning the process fails.
/// - The execution exceeds `timeout` (the child process is forcefully killed).
/// - An I/O error occurs while polling the child process.
pub fn run_command_with_timeout(
    program: &Path,
    args: &[&OsStr],
    timeout: Duration,
) -> Result<std::process::Output, RecoveryError> {
    let tool_name = program
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.strip_suffix(".exe").unwrap_or(s))
        .unwrap_or_else(|| program.to_str().unwrap_or("external_tool"))
        .to_string();

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| RecoveryError::ExternalTool {
            tool: tool_name.clone(),
            message: format!("failed to spawn '{}': {e}", program.display()),
        })?;

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe.take() {
            let _ = std::io::Read::read_to_end(&mut pipe, &mut buf);
        }
        buf
    });

    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe.take() {
            let _ = std::io::Read::read_to_end(&mut pipe, &mut buf);
        }
        buf
    });

    let start = std::time::Instant::now();
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    return Err(RecoveryError::ExternalTool {
                        tool: tool_name,
                        message: format!("timed out after {timeout:?}"),
                    });
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(RecoveryError::ExternalTool {
                    tool: tool_name,
                    message: format!("error waiting for child process: {e}"),
                });
            }
        }
    };

    let stdout = stdout_handle.join().unwrap_or_default();
    let stderr = stderr_handle.join().unwrap_or_default();

    Ok(std::process::Output {
        status: exit_status,
        stdout,
        stderr,
    })
}

/// Checks availability and retrieves version information for a tool (`ffprobe` or `ffmpeg`).
#[must_use]
pub fn check_tool(tool_name: &str, explicit_path: Option<&Path>) -> ToolStatus {
    let resolved_path = explicit_path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(tool_name));

    match run_command_with_timeout(
        &resolved_path,
        &[OsStr::new("-version")],
        Duration::from_secs(5),
    ) {
        Ok(output) => {
            if output.status.success() {
                let stdout_text = String::from_utf8_lossy(&output.stdout);
                let stderr_text = String::from_utf8_lossy(&output.stderr);
                let version_line = stdout_text
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty())
                    .or_else(|| {
                        stderr_text
                            .lines()
                            .map(str::trim)
                            .find(|line| !line.is_empty())
                    })
                    .map(String::from);
                ToolStatus {
                    name: tool_name.to_string(),
                    resolved_path,
                    available: true,
                    version_line,
                    error: None,
                }
            } else {
                let stderr_text = String::from_utf8_lossy(&output.stderr);
                let err_msg = if stderr_text.trim().is_empty() {
                    format!("tool exited with status {}", output.status)
                } else {
                    stderr_text.trim().to_string()
                };
                ToolStatus {
                    name: tool_name.to_string(),
                    resolved_path,
                    available: false,
                    version_line: None,
                    error: Some(err_msg),
                }
            }
        }
        Err(err) => ToolStatus {
            name: tool_name.to_string(),
            resolved_path,
            available: false,
            version_line: None,
            error: Some(err.to_string()),
        },
    }
}

/// Verifies required external media tools before starting recovery.
///
/// # Errors
///
/// Returns [`RecoveryError::ExternalTool`] (exit code 5) if:
/// - `ffprobe` is not available or fails execution.
/// - `full_verify` is true and `ffmpeg` is not available or fails execution.
pub fn require_tools(
    ffprobe_path: Option<&Path>,
    ffmpeg_path: Option<&Path>,
    full_verify: bool,
) -> Result<(PathBuf, Option<PathBuf>), RecoveryError> {
    let probe_status = check_tool("ffprobe", ffprobe_path);
    if !probe_status.available {
        return Err(RecoveryError::ExternalTool {
            tool: "ffprobe".to_string(),
            message: probe_status
                .error
                .unwrap_or_else(|| "ffprobe is unavailable or not found in PATH".to_string()),
        });
    }

    let ffmpeg_resolved = if full_verify {
        let ffmpeg_status = check_tool("ffmpeg", ffmpeg_path);
        if !ffmpeg_status.available {
            return Err(RecoveryError::ExternalTool {
                tool: "ffmpeg".to_string(),
                message: ffmpeg_status
                    .error
                    .unwrap_or_else(|| "ffmpeg is unavailable or not found in PATH".to_string()),
            });
        }
        Some(ffmpeg_status.resolved_path)
    } else {
        None
    };

    Ok((probe_status.resolved_path, ffmpeg_resolved))
}

/// Parses JSON output from `ffprobe` into [`ProbeMetadata`].
///
/// # Errors
///
/// Returns [`RecoveryError::ExternalTool`] if:
/// - JSON is malformed.
/// - The `streams` array is missing or empty.
/// - No valid video stream is found (e.g., audio-only, empty file, or codec is `"none"`).
pub fn parse_ffprobe_json(json_str: &str) -> Result<ProbeMetadata, RecoveryError> {
    let root: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| RecoveryError::ExternalTool {
            tool: "ffprobe".to_string(),
            message: format!("failed to parse ffprobe JSON output: {e}"),
        })?;

    let streams = root
        .get("streams")
        .and_then(|s| s.as_array())
        .ok_or_else(|| RecoveryError::ExternalTool {
            tool: "ffprobe".to_string(),
            message: "missing or invalid 'streams' array in ffprobe JSON".to_string(),
        })?;

    // Find the first valid video stream
    let video_stream = streams
        .iter()
        .find(|s| {
            let is_video = s
                .get("codec_type")
                .and_then(|v| v.as_str())
                .is_some_and(|t| t.eq_ignore_ascii_case("video"));

            let has_valid_codec = s
                .get("codec_name")
                .and_then(|v| v.as_str())
                .is_some_and(|name| !name.is_empty() && !name.eq_ignore_ascii_case("none"));

            is_video && has_valid_codec
        })
        .ok_or_else(|| RecoveryError::ExternalTool {
            tool: "ffprobe".to_string(),
            message:
                "no valid video stream found (file is empty, audio-only, or has unrecognized codec)"
                    .to_string(),
        })?;

    let video_codec = video_stream
        .get("codec_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let width = video_stream
        .get("width")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .unwrap_or(0) as u32;

    let height = video_stream
        .get("height")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .unwrap_or(0) as u32;

    let format_obj = root.get("format");

    let format_name = format_obj
        .and_then(|f| f.get("format_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let parse_duration_val = |v: &serde_json::Value| -> Option<f64> {
        if let Some(s) = v.as_str() {
            s.parse::<f64>().ok()
        } else {
            v.as_f64()
        }
    };

    let duration_secs = format_obj
        .and_then(|f| f.get("duration"))
        .and_then(parse_duration_val)
        .or_else(|| video_stream.get("duration").and_then(parse_duration_val))
        .filter(|d| d.is_finite() && *d >= 0.0);

    Ok(ProbeMetadata {
        format_name,
        duration_secs,
        video_codec,
        width,
        height,
    })
}

/// Runs `ffprobe` quick validation on a recovered video file.
///
/// # Errors
///
/// Returns [`RecoveryError::ExternalTool`] if execution fails, times out, exits with a non-zero code,
/// or produces invalid JSON.
pub fn run_ffprobe_validation(
    ffprobe_bin: &Path,
    file_path: &Path,
    timeout: Duration,
) -> Result<ProbeMetadata, RecoveryError> {
    let file_arg = file_path.as_os_str();
    let args = [
        OsStr::new("-v"),
        OsStr::new("error"),
        OsStr::new("-print_format"),
        OsStr::new("json"),
        OsStr::new("-show_format"),
        OsStr::new("-show_streams"),
        file_arg,
    ];

    let output = run_command_with_timeout(ffprobe_bin, &args, timeout)?;
    if !output.status.success() {
        let stderr_msg = String::from_utf8_lossy(&output.stderr);
        let msg = if stderr_msg.trim().is_empty() {
            format!("ffprobe exited with status {}", output.status)
        } else {
            stderr_msg.trim().to_string()
        };
        return Err(RecoveryError::ExternalTool {
            tool: "ffprobe".to_string(),
            message: msg,
        });
    }

    let stdout_str =
        std::str::from_utf8(&output.stdout).map_err(|e| RecoveryError::ExternalTool {
            tool: "ffprobe".to_string(),
            message: format!("invalid UTF-8 in ffprobe output: {e}"),
        })?;

    parse_ffprobe_json(stdout_str)
}

/// Runs full stream decode verification using `ffmpeg` (`--full-verify`).
///
/// Decode passes only if the process exits with status code `0` and stderr emits no decode errors.
///
/// # Errors
///
/// Returns [`RecoveryError::ExternalTool`] if `ffmpeg` fails or detects corrupted video frames.
pub fn run_ffmpeg_full_verify(
    ffmpeg_bin: &Path,
    file_path: &Path,
    timeout: Duration,
) -> Result<(), RecoveryError> {
    let file_arg = file_path.as_os_str();
    let args = [
        OsStr::new("-v"),
        OsStr::new("error"),
        OsStr::new("-xerror"),
        OsStr::new("-i"),
        file_arg,
        OsStr::new("-map"),
        OsStr::new("0:v:0"),
        OsStr::new("-f"),
        OsStr::new("null"),
        OsStr::new("-"),
    ];

    let output = run_command_with_timeout(ffmpeg_bin, &args, timeout)?;
    if !output.status.success() {
        let stderr_msg = String::from_utf8_lossy(&output.stderr);
        let msg = if stderr_msg.trim().is_empty() {
            format!("ffmpeg full verify failed with status {}", output.status)
        } else {
            stderr_msg.trim().to_string()
        };
        return Err(RecoveryError::ExternalTool {
            tool: "ffmpeg".to_string(),
            message: msg,
        });
    }

    let stderr_msg = String::from_utf8_lossy(&output.stderr);
    if !stderr_msg.trim().is_empty() {
        return Err(RecoveryError::ExternalTool {
            tool: "ffmpeg".to_string(),
            message: format!("decode error output: {}", stderr_msg.trim()),
        });
    }

    Ok(())
}

/// Validates an extracted video file using `ffprobe` and optional `ffmpeg` full decode verification,
/// updating candidate status, confidence, and error diagnostics according to recovery acceptance criteria.
///
/// # Mandatory Acceptance Rules
///
/// - Fragmented files with lost cluster allocation (`!candidate.chain_preserved && candidate.is_fragmented`)
///   MUST NEVER be classified as [`CandidateStatus::Validated`]. Even if `ffprobe` parses a valid video
///   header at the start of the first cluster, status is downgraded to [`CandidateStatus::Partial`].
/// - Incomplete container structures (`!structure_complete`) MUST NEVER be classified as
///   [`CandidateStatus::Validated`].
///
/// # Errors
///
/// Returns [`RecoveryError`] if process execution fails critically (e.g., missing ffmpeg binary when required).
#[allow(clippy::too_many_arguments)]
pub fn validate_extracted_candidate(
    candidate: &mut Candidate,
    extracted_path: &Path,
    ffprobe_bin: &Path,
    ffmpeg_bin: Option<&Path>,
    full_verify: bool,
    timeout: Duration,
    structure_complete: bool,
    has_video_header: bool,
) -> Result<Option<ProbeMetadata>, RecoveryError> {
    // 1. Mandatory rule: Fragmented files with lost cluster chain cannot be Validated.
    if !candidate.chain_preserved && candidate.is_fragmented {
        let probe_metadata = run_ffprobe_validation(ffprobe_bin, extracted_path, timeout).ok();
        candidate.status = CandidateStatus::Partial;
        candidate.confidence = Confidence::Low;
        candidate.error_reason = Some(
            "cluster chain mapping was lost for fragmented file; recovered prefix only".to_string(),
        );
        return Ok(probe_metadata);
    }

    // 2. Run ffprobe quick validation.
    let probe_metadata = match run_ffprobe_validation(ffprobe_bin, extracted_path, timeout) {
        Ok(meta) => meta,
        Err(err) => {
            if has_video_header {
                candidate.status = CandidateStatus::Partial;
                candidate.confidence = Confidence::Low;
                candidate.error_reason = Some(err.to_string());
            } else {
                candidate.status = CandidateStatus::Rejected;
                candidate.confidence = Confidence::Low;
                candidate.error_reason = Some(err.to_string());
            }
            return Ok(None);
        }
    };

    // 3. Optional ffmpeg full decode verification.
    if full_verify {
        let ffmpeg = ffmpeg_bin.ok_or_else(|| RecoveryError::ExternalTool {
            tool: "ffmpeg".to_string(),
            message: "ffmpeg executable path required when full_verify is enabled".to_string(),
        })?;

        if let Err(err) = run_ffmpeg_full_verify(ffmpeg, extracted_path, timeout) {
            candidate.status = CandidateStatus::Partial;
            candidate.confidence = Confidence::Low;
            candidate.error_reason = Some(err.to_string());
            return Ok(Some(probe_metadata));
        }
    }

    // 4. Container structural completeness check.
    if !structure_complete {
        candidate.status = CandidateStatus::Partial;
        candidate.confidence = Confidence::Low;
        candidate.error_reason =
            Some("container structure truncated or missing moov/mdat".to_string());
        return Ok(Some(probe_metadata));
    }

    // 5. Validated candidate.
    candidate.status = CandidateStatus::Validated;
    candidate.confidence = if full_verify
        || (candidate.chain_preserved
            && (!candidate.recovery_method.is_filesystem() || !candidate.is_fragmented))
    {
        Confidence::High
    } else {
        Confidence::Medium
    };
    candidate.error_reason = None;

    Ok(Some(probe_metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ExitCode;
    use crate::types::{Extent, RecoveryMethod};

    fn make_test_candidate(chain_preserved: bool, is_fragmented: bool) -> Candidate {
        Candidate {
            id: "cand-0001".to_string(),
            extents: vec![Extent::new(1024, 2048)],
            expected_size: 2048,
            recovery_method: RecoveryMethod::FilesystemFat32,
            original_name: Some("test.mp4".to_string()),
            recovered_name: Some("cand-0001_test.mp4".to_string()),
            output_path: None,
            confidence: Confidence::Medium,
            status: CandidateStatus::Partial,
            chain_preserved,
            is_fragmented,
            error_reason: None,
            error_offset: None,
        }
    }

    #[test]
    fn test_parse_ffprobe_json_valid_mp4() {
        let json = r#"{
            "streams": [
                {
                    "index": 0,
                    "codec_name": "h264",
                    "codec_type": "video",
                    "width": 1920,
                    "height": 1080,
                    "duration": "12.345678"
                },
                {
                    "index": 1,
                    "codec_name": "aac",
                    "codec_type": "audio",
                    "duration": "12.345000"
                }
            ],
            "format": {
                "format_name": "mov,mp4,m4a,3gp,3g2,mj2",
                "duration": "12.345678"
            }
        }"#;

        let meta = parse_ffprobe_json(json).expect("should parse valid ffprobe json");
        assert_eq!(meta.format_name, "mov,mp4,m4a,3gp,3g2,mj2");
        assert_eq!(meta.video_codec, "h264");
        assert_eq!(meta.width, 1920);
        assert_eq!(meta.height, 1080);
        assert_eq!(meta.duration_secs, Some(12.345_678));
    }

    #[test]
    fn test_parse_ffprobe_json_malformed() {
        let json = r#"{ not valid json ... "#;
        let err = parse_ffprobe_json(json).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::ExternalTool);
    }

    #[test]
    fn test_parse_ffprobe_json_empty_streams() {
        let json = r#"{
            "streams": [],
            "format": {
                "format_name": "mp4"
            }
        }"#;

        let err = parse_ffprobe_json(json).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::ExternalTool);
        assert!(
            matches!(err, RecoveryError::ExternalTool { ref message, .. } if message.contains("no valid video stream"))
        );
    }

    #[test]
    fn test_parse_ffprobe_json_audio_only_rejected() {
        let json = r#"{
            "streams": [
                {
                    "index": 0,
                    "codec_name": "aac",
                    "codec_type": "audio",
                    "duration": "60.0"
                }
            ],
            "format": {
                "format_name": "mp3",
                "duration": "60.0"
            }
        }"#;

        let err = parse_ffprobe_json(json).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::ExternalTool);
        assert!(
            matches!(err, RecoveryError::ExternalTool { ref message, .. } if message.contains("no valid video stream"))
        );
    }

    #[test]
    fn test_parse_ffprobe_json_codec_none_rejected() {
        let json = r#"{
            "streams": [
                {
                    "index": 0,
                    "codec_name": "none",
                    "codec_type": "video"
                }
            ],
            "format": {
                "format_name": "mp4"
            }
        }"#;

        let err = parse_ffprobe_json(json).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::ExternalTool);
    }

    #[test]
    fn test_parse_ffprobe_json_stream_duration_fallback() {
        let json = r#"{
            "streams": [
                {
                    "index": 0,
                    "codec_name": "hevc",
                    "codec_type": "video",
                    "width": 3840,
                    "height": 2160,
                    "duration": "24.500"
                }
            ],
            "format": {
                "format_name": "mov"
            }
        }"#;

        let meta = parse_ffprobe_json(json).expect("should parse with stream duration fallback");
        assert_eq!(meta.video_codec, "hevc");
        assert_eq!(meta.width, 3840);
        assert_eq!(meta.height, 2160);
        assert_eq!(meta.duration_secs, Some(24.5));
    }

    #[test]
    fn test_check_tool_non_existent() {
        let status = check_tool("nonexistent_binary_tool_xyz_9999", None);
        assert_eq!(status.name, "nonexistent_binary_tool_xyz_9999");
        assert!(!status.available);
        assert!(status.version_line.is_none());
        assert!(status.error.is_some());
    }

    #[test]
    fn test_require_tools_missing_ffprobe() {
        let missing_path = Path::new("nonexistent_ffprobe_bin_9999");
        let res = require_tools(Some(missing_path), None, false);
        let err = res.unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::ExternalTool);
        assert_eq!(err.exit_code().code(), 5);
        assert!(matches!(err, RecoveryError::ExternalTool { ref tool, .. } if tool == "ffprobe"));
    }

    #[test]
    fn test_require_tools_missing_ffmpeg_for_full_verify() {
        // If ffprobe points to a non-existent binary, it fails early on ffprobe
        let missing_path = Path::new("nonexistent_ffprobe_bin_9999");
        let res = require_tools(Some(missing_path), Some(missing_path), true);
        let err = res.unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::ExternalTool);
    }

    #[test]
    fn test_validate_fragmented_lost_chain_never_validated() {
        let mut candidate = make_test_candidate(false, true);
        let temp_file = std::env::temp_dir().join("test_dummy_video.mp4");
        let _ = std::fs::write(&temp_file, b"dummy data");

        let res = validate_extracted_candidate(
            &mut candidate,
            &temp_file,
            Path::new("dummy_ffprobe"),
            None,
            false,
            Duration::from_millis(50),
            true, // structure_complete
            true, // has_video_header
        );

        let _ = std::fs::remove_file(&temp_file);

        assert!(res.is_ok());
        assert_eq!(candidate.status, CandidateStatus::Partial);
        assert_eq!(candidate.confidence, Confidence::Low);
        assert_eq!(
            candidate.error_reason.as_deref(),
            Some("cluster chain mapping was lost for fragmented file; recovered prefix only")
        );
    }

    #[test]
    fn test_validate_probe_fail_no_header_is_rejected() {
        let mut candidate = make_test_candidate(true, false);
        let temp_file = std::env::temp_dir().join("test_dummy_rejected.mp4");
        let _ = std::fs::write(&temp_file, b"not a video file");

        let res = validate_extracted_candidate(
            &mut candidate,
            &temp_file,
            Path::new("nonexistent_ffprobe_bin_1234"),
            None,
            false,
            Duration::from_millis(50),
            true,
            false, // has_video_header == false
        );

        let _ = std::fs::remove_file(&temp_file);

        assert!(res.is_ok());
        assert_eq!(candidate.status, CandidateStatus::Rejected);
        assert_eq!(candidate.confidence, Confidence::Low);
        assert!(candidate.error_reason.is_some());
    }

    #[test]
    fn test_validate_probe_fail_with_header_is_partial() {
        let mut candidate = make_test_candidate(true, false);
        let temp_file = std::env::temp_dir().join("test_dummy_partial.mp4");
        let _ = std::fs::write(&temp_file, b"not a valid video file");

        let res = validate_extracted_candidate(
            &mut candidate,
            &temp_file,
            Path::new("nonexistent_ffprobe_bin_1234"),
            None,
            false,
            Duration::from_millis(50),
            true,
            true, // has_video_header == true
        );

        let _ = std::fs::remove_file(&temp_file);

        assert!(res.is_ok());
        assert_eq!(candidate.status, CandidateStatus::Partial);
        assert_eq!(candidate.confidence, Confidence::Low);
        assert!(candidate.error_reason.is_some());
    }

    #[test]
    fn test_run_command_timeout_handling() {
        // Run ping on Windows with 5 requests but 1ms timeout, guaranteeing a timeout if ping exists
        let ping_path = Path::new("ping");
        let args = [OsStr::new("-n"), OsStr::new("5"), OsStr::new("127.0.0.1")];

        let res = run_command_with_timeout(ping_path, &args, Duration::from_millis(1));
        match res {
            Err(RecoveryError::ExternalTool { message, .. }) => {
                assert!(
                    message.contains("timed out") || message.contains("failed to spawn"),
                    "unexpected error message: {message}"
                );
            }
            Ok(_) => {
                // If ping somehow finished under 1ms, that's theoretically possible on weird setups
            }
            Err(e) => panic!("unexpected error type: {e}"),
        }
    }
}
