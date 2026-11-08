//! Validator edge cases, CLI argument parsing, and localization integration tests.
//!
//! Tests:
//! 1. Validator edge cases:
//!    - Missing `ffprobe` path returns `RecoveryError::ExternalTool` with exit code `5`.
//!    - Missing `ffmpeg` path with `full_verify == true` returns `RecoveryError::ExternalTool` with exit code `5`.
//!    - Non-existent tool returns `ToolStatus.available == false`.
//!    - Malformed `ffprobe` JSON returns `RecoveryError::ExternalTool`.
//!    - Audio-only (no video stream) JSON is rejected.
//!    - Valid video stream JSON parses `ProbeMetadata` accurately.
//!    - Real `ffprobe` and `ffmpeg` execution (if installed on the host system) on both a valid
//!      generated 1-second video and a truncated/corrupted copy.
//!    - `validate_extracted_candidate` enforcing the mandatory rule that lost cluster mapping on
//!      a fragmented candidate is NEVER classified as `CandidateStatus::Validated`.
//! 2. CLI argument parser and exit codes:
//!    - `list`, `doctor`, `recover`, and invalid arguments returning `ExitCode::InvalidArgs` (`2`).
//! 3. Localization (`en` and `hy`):
//!    - Language parsing and tag detection.
//!    - English and Armenian `format_device_list`, `format_confirmation_prompt`,
//!      `confirm_disk_selection`, and `format_summary_text`.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sd_video_recovery::cli::{
    confirm_disk_selection, format_confirmation_prompt, format_device_list, parse_cli_args,
    CliCommand,
};
use sd_video_recovery::error::ExitCode;
use sd_video_recovery::i18n::{detect_language_from_tag, detect_system_language, parse_language};
use sd_video_recovery::report::{
    format_summary_text, MaskedDeviceReport, ScanConfigReport, SessionReport,
};
use sd_video_recovery::types::{
    BusType, Candidate, CandidateStatus, Confidence, DeviceIdentity, Extent, FilesystemKind,
    Language, PartitionInfo, PartitionScheme, RecoveryMethod, ScanMode,
};
use sd_video_recovery::validator::{
    check_tool, parse_ffprobe_json, require_tools, run_ffmpeg_full_verify, run_ffprobe_validation,
    validate_extracted_candidate,
};

// ============================================================================
// 1. Validator Edge Case Tests
// ============================================================================

#[test]
fn test_missing_tool_status() {
    let status = check_tool("nonexistent_binary_xyz_12345", None);
    assert!(
        !status.available,
        "non-existent tool must report available = false"
    );
    assert!(status.version_line.is_none());
    assert!(status.error.is_some());
}

#[test]
fn test_require_tools_missing_ffprobe() {
    let missing_path = Path::new("C:\\nonexistent_dir\\ffprobe_fake.exe");
    let res = require_tools(Some(missing_path), None, false);
    assert!(res.is_err(), "must fail when ffprobe is missing");
    let err = res.unwrap_err();
    assert_eq!(
        err.exit_code(),
        ExitCode::ExternalTool,
        "missing ffprobe must return exit code ExternalTool (5)"
    );
    assert_eq!(ExitCode::ExternalTool.code(), 5);
}

#[test]
fn test_require_tools_missing_ffmpeg_with_full_verify() {
    // When full_verify is true, missing ffmpeg must fail with exit code 5
    let missing_ffmpeg = Path::new("C:\\nonexistent_dir\\ffmpeg_fake.exe");
    let res = require_tools(None, Some(missing_ffmpeg), true);
    assert!(
        res.is_err(),
        "must fail when ffmpeg is missing and full_verify is requested"
    );
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::ExternalTool);
}

#[test]
fn test_parse_ffprobe_json_malformed() {
    let bad_json = "{ this is not valid json";
    let res = parse_ffprobe_json(bad_json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::ExternalTool);
}

#[test]
fn test_parse_ffprobe_json_missing_streams() {
    let json = r#"{"format":{"format_name":"mov,mp4"}}"#;
    let res = parse_ffprobe_json(json);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::ExternalTool);
}

#[test]
fn test_parse_ffprobe_json_audio_only_rejected() {
    // Audio-only file must be rejected because recovery target is MP4/MOV video
    let audio_json = r#"{
        "streams": [
            {
                "index": 0,
                "codec_name": "aac",
                "codec_type": "audio",
                "sample_rate": "44100",
                "channels": 2
            }
        ],
        "format": {
            "format_name": "mp3",
            "duration": "180.5"
        }
    }"#;

    let res = parse_ffprobe_json(audio_json);
    assert!(
        res.is_err(),
        "audio-only file must be rejected with no valid video stream"
    );
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::ExternalTool);
    let msg = err.to_string();
    assert!(msg.contains("no valid video stream found"));
}

#[test]
fn test_parse_ffprobe_json_valid_video() {
    let valid_json = r#"{
        "streams": [
            {
                "index": 0,
                "codec_name": "h264",
                "codec_type": "video",
                "width": 1920,
                "height": 1080,
                "duration": "15.500000"
            },
            {
                "index": 1,
                "codec_name": "aac",
                "codec_type": "audio"
            }
        ],
        "format": {
            "format_name": "mov,mp4,m4a,3gp,3g2,mj2",
            "duration": "15.500000"
        }
    }"#;

    let meta = parse_ffprobe_json(valid_json).expect("valid video stream must parse successfully");
    assert_eq!(meta.video_codec, "h264");
    assert_eq!(meta.width, 1920);
    assert_eq!(meta.height, 1080);
    assert_eq!(meta.duration_secs, Some(15.5));
    assert!(meta.format_name.contains("mp4"));
}

#[test]
fn test_validate_extracted_candidate_lost_cluster_mapping_downgrade() {
    // Mandatory Acceptance Rule (PLAN.md line 72):
    // A fragmented file with lost cluster mapping (!chain_preserved && is_fragmented)
    // MUST NEVER be classified as CandidateStatus::Validated!
    let mut candidate = Candidate {
        id: "cand-0001".to_string(),
        extents: vec![Extent::new(1024, 2048), Extent::new(5120, 2048)],
        expected_size: 4096,
        recovery_method: RecoveryMethod::FilesystemFat32,
        original_name: Some("GOPR0001.MP4".to_string()),
        recovered_name: Some("cand-0001_GOPR0001.MP4".to_string()),
        output_path: None,
        confidence: Confidence::High,
        status: CandidateStatus::Partial,
        chain_preserved: false, // LOST mapping
        is_fragmented: true,    // Fragmented
        error_reason: None,
        error_offset: None,
    };

    let dummy_path = Path::new("dummy_recovered.mp4");
    let dummy_ffprobe = Path::new("ffprobe.exe");

    let _ = validate_extracted_candidate(
        &mut candidate,
        dummy_path,
        dummy_ffprobe,
        None,
        false,
        Duration::from_secs(1),
        true, // structure_complete
        true, // has_video_header
    );

    assert_eq!(
        candidate.status,
        CandidateStatus::Partial,
        "fragmented file with lost mapping must be CandidateStatus::Partial"
    );
    assert_ne!(
        candidate.status,
        CandidateStatus::Validated,
        "fragmented file with lost mapping must NEVER be Validated"
    );
    assert_eq!(candidate.confidence, Confidence::Low);
    assert!(candidate
        .error_reason
        .as_ref()
        .unwrap()
        .contains("cluster chain mapping was lost"));
}

/// Optional live verification with real `ffprobe` and `ffmpeg` if present in the system environment.
#[test]
fn test_real_ffprobe_ffmpeg_if_available() {
    let ffprobe_status = check_tool("ffprobe", None);
    let ffmpeg_status = check_tool("ffmpeg", None);

    if !ffprobe_status.available || !ffmpeg_status.available {
        // Skip real execution if tools are not installed in the current environment
        return;
    }

    let temp_dir = std::env::temp_dir().join(format!(
        "sd_validator_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);

    let valid_mp4_path = temp_dir.join("valid_test.mp4");
    let corrupted_mp4_path = temp_dir.join("corrupted_test.mp4");

    // 1. Generate a tiny valid 1-second 64x64 test MP4 video using ffmpeg
    let gen_status = Command::new(&ffmpeg_status.resolved_path)
        .args([
            "-f",
            "lavfi",
            "-i",
            "testsrc=duration=1:size=64x64:rate=10",
            "-pix_fmt",
            "yuv420p",
            "-y",
            valid_mp4_path.to_str().unwrap(),
        ])
        .output();

    if let Ok(gen_out) = gen_status {
        if gen_out.status.success() && valid_mp4_path.exists() {
            // A. Test run_ffprobe_validation on valid MP4
            let probe_res = run_ffprobe_validation(
                &ffprobe_status.resolved_path,
                &valid_mp4_path,
                Duration::from_secs(10),
            );
            assert!(probe_res.is_ok(), "ffprobe must validate valid test video");
            let meta = probe_res.unwrap();
            assert_eq!(meta.width, 64);
            assert_eq!(meta.height, 64);

            // B. Test run_ffmpeg_full_verify on valid MP4
            let verify_res = run_ffmpeg_full_verify(
                &ffmpeg_status.resolved_path,
                &valid_mp4_path,
                Duration::from_secs(10),
            );
            assert!(
                verify_res.is_ok(),
                "ffmpeg full verify must pass on valid test video"
            );

            // C. Create a corrupted copy by truncating the file to 40 bytes
            let mut file_bytes = std::fs::read(&valid_mp4_path).unwrap();
            file_bytes.truncate(40);
            std::fs::write(&corrupted_mp4_path, &file_bytes).unwrap();

            // D. run_ffmpeg_full_verify on corrupted copy must fail
            let corrupt_verify_res = run_ffmpeg_full_verify(
                &ffmpeg_status.resolved_path,
                &corrupted_mp4_path,
                Duration::from_secs(10),
            );
            assert!(
                corrupt_verify_res.is_err(),
                "ffmpeg full verify must reject truncated corrupted video"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// 2. CLI Argument Parsing & Exit Code Tests
// ============================================================================

#[test]
fn test_cli_parse_list_defaults() {
    let args = ["sd-video-recovery", "list"];
    let cmd = parse_cli_args(args).expect("parsing 'list' should succeed");
    assert_eq!(
        cmd,
        CliCommand::List {
            lang: None,
            json: false
        }
    );
}

#[test]
fn test_cli_parse_list_with_flags() {
    let args = ["sd-video-recovery", "list", "--lang", "hy", "--json"];
    let cmd = parse_cli_args(args).expect("parsing 'list' with flags should succeed");
    assert_eq!(
        cmd,
        CliCommand::List {
            lang: Some(Language::Hy),
            json: true,
        }
    );
}

#[test]
fn test_cli_parse_doctor() {
    let args = [
        "sd-video-recovery",
        "doctor",
        "--ffprobe-path",
        "C:\\bin\\ffprobe.exe",
        "--ffmpeg-path=C:\\bin\\ffmpeg.exe",
        "--lang=en",
    ];
    let cmd = parse_cli_args(args).expect("parsing 'doctor' should succeed");
    assert_eq!(
        cmd,
        CliCommand::Doctor {
            ffprobe_path: Some(PathBuf::from("C:\\bin\\ffprobe.exe")),
            ffmpeg_path: Some(PathBuf::from("C:\\bin\\ffmpeg.exe")),
            lang: Some(Language::En),
        }
    );
}

#[test]
fn test_cli_parse_recover_all_flags() {
    let args = [
        "sd-video-recovery",
        "recover",
        "--disk",
        "3",
        "--output",
        "E:\\RecoveredVideos",
        "--mode",
        "deep",
        "--full-verify",
        "--allow-fixed",
        "--lang",
        "hy",
    ];
    let cmd = parse_cli_args(args).expect("parsing 'recover' should succeed");
    assert_eq!(
        cmd,
        CliCommand::Recover {
            disk: 3,
            output: PathBuf::from("E:\\RecoveredVideos"),
            mode: ScanMode::Deep,
            ffprobe_path: None,
            ffmpeg_path: None,
            full_verify: true,
            allow_fixed: true,
            lang: Some(Language::Hy),
        }
    );
}

#[test]
fn test_cli_parse_invalid_subcommand() {
    let args = ["sd-video-recovery", "unsupported_command"];
    let res = parse_cli_args(args);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::InvalidArgs);
    assert_eq!(ExitCode::InvalidArgs.code(), 2);
}

#[test]
fn test_cli_parse_recover_missing_disk() {
    let args = ["sd-video-recovery", "recover", "--output", "E:\\Out"];
    let res = parse_cli_args(args);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().exit_code(), ExitCode::InvalidArgs);
}

#[test]
fn test_cli_parse_recover_missing_output() {
    let args = ["sd-video-recovery", "recover", "--disk", "1"];
    let res = parse_cli_args(args);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().exit_code(), ExitCode::InvalidArgs);
}

#[test]
fn test_cli_parse_recover_invalid_disk_number() {
    let args = [
        "sd-video-recovery",
        "recover",
        "--disk",
        "not_a_number",
        "--output",
        "E:\\Out",
    ];
    let res = parse_cli_args(args);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().exit_code(), ExitCode::InvalidArgs);
}

#[test]
fn test_cli_parse_recover_invalid_mode() {
    let args = [
        "sd-video-recovery",
        "recover",
        "--disk",
        "1",
        "--output",
        "E:\\Out",
        "--mode",
        "turbo",
    ];
    let res = parse_cli_args(args);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().exit_code(), ExitCode::InvalidArgs);
}

// ============================================================================
// 3. Localization & Formatting Tests (English & Armenian)
// ============================================================================

#[test]
fn test_language_parsing() {
    assert_eq!(parse_language("en").unwrap(), Language::En);
    assert_eq!(parse_language("ENG").unwrap(), Language::En);
    assert_eq!(parse_language("en-US").unwrap(), Language::En);

    assert_eq!(parse_language("hy").unwrap(), Language::Hy);
    assert_eq!(parse_language("arm").unwrap(), Language::Hy);
    assert_eq!(parse_language("hy-AM").unwrap(), Language::Hy);

    let err = parse_language("french").unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::InvalidArgs);
}

#[test]
fn test_language_tag_detection() {
    assert_eq!(detect_language_from_tag("hy-AM"), Language::Hy);
    assert_eq!(detect_language_from_tag("hy_AM"), Language::Hy);
    assert_eq!(detect_language_from_tag("hy"), Language::Hy);

    assert_eq!(detect_language_from_tag("en-US"), Language::En);
    assert_eq!(detect_language_from_tag("de-DE"), Language::En);
    assert_eq!(detect_language_from_tag(""), Language::En);
}

#[test]
fn test_detect_system_language() {
    let lang = detect_system_language();
    assert!(matches!(lang, Language::En | Language::Hy));
}

#[test]
fn test_format_device_list_en_and_hy() {
    let devices = vec![
        DeviceIdentity {
            disk_number: 1,
            device_path: "\\\\.\\PhysicalDrive1".to_string(),
            model: "SanDisk Extreme PRO 128GB".to_string(),
            size_bytes: 128 * 1000 * 1000 * 1000,
            sector_size: 512,
            bus_type: BusType::Sd,
            removable: true,
            is_system_disk: false,
            masked_serial: Some("****5678".to_string()),
        },
        DeviceIdentity {
            disk_number: 0,
            device_path: "\\\\.\\PhysicalDrive0".to_string(),
            model: "Samsung SSD 980 PRO 1TB".to_string(),
            size_bytes: 1000 * 1000 * 1000 * 1000,
            sector_size: 512,
            bus_type: BusType::Nvme,
            removable: false,
            is_system_disk: true,
            masked_serial: Some("****ABCD".to_string()),
        },
    ];

    // English list output
    let en_out = format_device_list(&devices, Language::En, false).unwrap();
    assert!(en_out.contains("Disk"));
    assert!(en_out.contains("Model"));
    assert!(en_out.contains("SanDisk"));
    assert!(en_out.contains("[SYSTEM DISK - BLOCKED]"));

    // Armenian list output
    let hy_out = format_device_list(&devices, Language::Hy, false).unwrap();
    assert!(hy_out.contains("Սկավ."));
    assert!(hy_out.contains("Մոդել"));
    assert!(hy_out.contains("[ՀԱՄԱԿԱՐԳԱՅԻՆ - ԱՐԳԵԼՎԱԾ]"));

    // JSON output
    let json_out = format_device_list(&devices, Language::En, true).unwrap();
    assert!(json_out.contains("\"disk_number\": 1"));
    assert!(json_out.contains("\"is_system_disk\": true"));
}

#[test]
fn test_format_confirmation_prompt_en_and_hy() {
    let device = DeviceIdentity {
        disk_number: 2,
        device_path: "\\\\.\\PhysicalDrive2".to_string(),
        model: "Lexar Professional 64GB".to_string(),
        size_bytes: 64 * 1024 * 1024 * 1024,
        sector_size: 512,
        bus_type: BusType::Usb,
        removable: true,
        is_system_disk: false,
        masked_serial: Some("****9999".to_string()),
    };

    let partitions = vec![PartitionInfo {
        index: 0,
        scheme: PartitionScheme::Mbr,
        byte_offset: 1_048_576,
        byte_len: 64 * 1024 * 1024 * 1024 - 1_048_576,
        type_id: "0x0C".to_string(),
        name: None,
        filesystem: FilesystemKind::Fat32,
    }];

    // English confirmation prompt
    let en_prompt = format_confirmation_prompt(&device, &partitions, Language::En);
    assert!(en_prompt.contains("Lexar"));
    assert!(en_prompt.contains("PhysicalDrive2"));
    assert!(en_prompt.contains("type the disk number (2)"));

    // Armenian confirmation prompt
    let hy_prompt = format_confirmation_prompt(&device, &partitions, Language::Hy);
    assert!(hy_prompt.contains("Lexar"));
    assert!(hy_prompt.contains("PhysicalDrive2"));
    assert!(hy_prompt.contains("մուտքագրեք սկավառակի համարը (2)"));
}

#[test]
fn test_confirm_disk_selection_matching() {
    let mut input = Cursor::new(b"2\n");
    let res = confirm_disk_selection(2, &mut input, Language::En);
    assert!(res.is_ok(), "matching disk ID must be accepted");

    let mut input_hy = Cursor::new(b"  5  \r\n");
    let res_hy = confirm_disk_selection(5, &mut input_hy, Language::Hy);
    assert!(
        res_hy.is_ok(),
        "matching disk ID with whitespace must be accepted"
    );
}

#[test]
fn test_confirm_disk_selection_mismatch() {
    let mut input = Cursor::new(b"3\n");
    let res = confirm_disk_selection(2, &mut input, Language::En);
    assert!(res.is_err(), "mismatching disk ID must be rejected");
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::SafetyPreflight);
}

#[test]
fn test_confirm_disk_selection_eof() {
    let mut empty_input = Cursor::new(b"");
    let res = confirm_disk_selection(2, &mut empty_input, Language::En);
    assert!(res.is_err(), "EOF must be rejected");
    assert_eq!(res.unwrap_err().exit_code(), ExitCode::SafetyPreflight);
}

#[test]
fn test_format_summary_text_en_and_hy() {
    let device_report = MaskedDeviceReport {
        disk_number: 2,
        device_path: "\\\\.\\PhysicalDrive2".to_string(),
        model: "Kingston Canvas Go! Plus".to_string(),
        size_bytes: 32 * 1024 * 1024 * 1024,
        sector_size: 512,
        bus_type: BusType::Sd,
        removable: true,
        masked_serial: Some("****7777".to_string()),
    };

    let scan_config = ScanConfigReport {
        mode: ScanMode::All,
        full_verify: false,
        allow_fixed: false,
        lang: Language::En,
        output_dir: "D:\\RecoverySession".to_string(),
    };

    let candidate = Candidate {
        id: "cand-0001".to_string(),
        extents: vec![Extent::new(1048576, 5242880)],
        expected_size: 5242880,
        recovery_method: RecoveryMethod::FilesystemFat32,
        original_name: Some("GOPR0001.MP4".to_string()),
        recovered_name: Some("cand-0001_GOPR0001.MP4".to_string()),
        output_path: Some("D:\\RecoverySession\\validated\\cand-0001_GOPR0001.MP4".to_string()),
        confidence: Confidence::High,
        status: CandidateStatus::Validated,
        chain_preserved: true,
        is_fragmented: false,
        error_reason: None,
        error_offset: None,
    };

    let report = SessionReport::new(
        "session-1710000000000".to_string(),
        1710000000000,
        1710000030000,
        false,
        device_report,
        scan_config,
        Vec::new(),
        vec![candidate],
    );

    // English summary
    let summary_en = format_summary_text(&report, Language::En);
    assert!(summary_en.contains("sd-video-recovery Session Summary"));
    assert!(summary_en.contains("Session ID:         session-1710000000000"));
    assert!(summary_en.contains("Total Candidates:   1"));
    assert!(summary_en.contains("Validated:        1"));
    assert!(summary_en.contains("GOPR0001.MP4"));

    // Armenian summary
    let summary_hy = format_summary_text(&report, Language::Hy);
    assert!(summary_hy.contains("sd-video-recovery Սեսիայի Ամփոփում"));
    assert!(summary_hy.contains("Սեսիայի ID:         session-1710000000000"));
    assert!(summary_hy.contains("Ընդհանուր թեկնածուներ: 1"));
    assert!(summary_hy.contains("Վավերացված:         1"));
    assert!(summary_hy.contains("GOPR0001.MP4"));
}
