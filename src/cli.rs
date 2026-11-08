//! CLI argument parser and interactive confirmation banner.

use std::io::BufRead;
use std::path::PathBuf;

use crate::error::RecoveryError;
use crate::i18n::{detect_system_language, parse_language, texts};
use crate::types::{DeviceIdentity, Language, PartitionInfo, ScanMode};

/// Parsed CLI commands for `sd-video-recovery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    /// List connected physical drives.
    List {
        /// Optional UI language override.
        lang: Option<Language>,
        /// Whether to output machine-readable JSON.
        json: bool,
    },
    /// Verify external tools (`ffprobe`, `ffmpeg`) readiness.
    Doctor {
        /// Optional explicit path to `ffprobe`.
        ffprobe_path: Option<PathBuf>,
        /// Optional explicit path to `ffmpeg`.
        ffmpeg_path: Option<PathBuf>,
        /// Optional UI language override.
        lang: Option<Language>,
    },
    /// Perform read-only video recovery from a physical drive.
    Recover {
        /// Physical disk number `N` (`\\.\PhysicalDriveN`).
        disk: u32,
        /// Destination directory on a different physical drive.
        output: PathBuf,
        /// Scan phase mode (`all`, `filesystem`, or `deep`).
        mode: ScanMode,
        /// Optional explicit path to `ffprobe`.
        ffprobe_path: Option<PathBuf>,
        /// Optional explicit path to `ffmpeg`.
        ffmpeg_path: Option<PathBuf>,
        /// Whether to run full video stream decode via `ffmpeg`.
        full_verify: bool,
        /// Whether to allow scanning fixed-media USB card readers.
        allow_fixed: bool,
        /// Optional UI language override.
        lang: Option<Language>,
    },
    /// Display general or command help.
    Help {
        /// Language for the help message.
        lang: Language,
    },
}

/// Parses command-line arguments into a strongly-typed [`CliCommand`].
///
/// Skips `args[0]` (the executable name).
///
/// Supports both `--key VALUE` and `--key=VALUE` syntax.
///
/// # Errors
///
/// Returns [`RecoveryError::InvalidArgs`] if an unknown subcommand, unknown flag,
/// or invalid/missing argument is encountered.
pub fn parse_cli_args<I, S>(args: I) -> Result<CliCommand, RecoveryError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let all_args: Vec<String> = args.into_iter().map(Into::into).collect();
    let tokens: Vec<String> = if all_args.is_empty() {
        Vec::new()
    } else {
        all_args.into_iter().skip(1).collect()
    };

    // If no arguments or help flag requested anywhere, show help
    if tokens.is_empty() {
        return Ok(CliCommand::Help {
            lang: detect_system_language(),
        });
    }

    if tokens
        .iter()
        .any(|t| t == "-h" || t == "--help" || t == "help")
    {
        let mut selected_lang = None;
        let mut i = 0;
        while i < tokens.len() {
            let t = &tokens[i];
            if let Some(val) = t.strip_prefix("--lang=") {
                selected_lang = Some(parse_language(val)?);
                i += 1;
            } else if t == "--lang" {
                if i + 1 < tokens.len() {
                    selected_lang = Some(parse_language(&tokens[i + 1])?);
                    i += 2;
                } else {
                    return Err(RecoveryError::InvalidArgs(
                        "missing value for flag '--lang'".to_string(),
                    ));
                }
            } else {
                i += 1;
            }
        }
        return Ok(CliCommand::Help {
            lang: selected_lang.unwrap_or_else(detect_system_language),
        });
    }

    match tokens[0].as_str() {
        "list" => parse_list_command(&tokens[1..]),
        "doctor" => parse_doctor_command(&tokens[1..]),
        "recover" => parse_recover_command(&tokens[1..]),
        other => Err(RecoveryError::InvalidArgs(format!(
            "unknown subcommand '{other}'; use 'sd-video-recovery --help' for usage"
        ))),
    }
}

fn parse_list_command(tokens: &[String]) -> Result<CliCommand, RecoveryError> {
    let mut lang = None;
    let mut json = false;

    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        if t == "--json" {
            json = true;
            i += 1;
        } else if let Some(val) = t.strip_prefix("--lang=") {
            lang = Some(parse_language(val)?);
            i += 1;
        } else if t == "--lang" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--lang'".to_string(),
                ));
            }
            lang = Some(parse_language(&tokens[i + 1])?);
            i += 2;
        } else {
            return Err(RecoveryError::InvalidArgs(format!(
                "unknown flag or argument '{t}' for subcommand 'list'"
            )));
        }
    }

    Ok(CliCommand::List { lang, json })
}

fn parse_doctor_command(tokens: &[String]) -> Result<CliCommand, RecoveryError> {
    let mut ffprobe_path = None;
    let mut ffmpeg_path = None;
    let mut lang = None;

    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        if let Some(val) = t.strip_prefix("--ffprobe-path=") {
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--ffprobe-path cannot be empty".to_string(),
                ));
            }
            ffprobe_path = Some(PathBuf::from(val));
            i += 1;
        } else if t == "--ffprobe-path" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--ffprobe-path'".to_string(),
                ));
            }
            let val = &tokens[i + 1];
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--ffprobe-path cannot be empty".to_string(),
                ));
            }
            ffprobe_path = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = t.strip_prefix("--ffmpeg-path=") {
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--ffmpeg-path cannot be empty".to_string(),
                ));
            }
            ffmpeg_path = Some(PathBuf::from(val));
            i += 1;
        } else if t == "--ffmpeg-path" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--ffmpeg-path'".to_string(),
                ));
            }
            let val = &tokens[i + 1];
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--ffmpeg-path cannot be empty".to_string(),
                ));
            }
            ffmpeg_path = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = t.strip_prefix("--lang=") {
            lang = Some(parse_language(val)?);
            i += 1;
        } else if t == "--lang" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--lang'".to_string(),
                ));
            }
            lang = Some(parse_language(&tokens[i + 1])?);
            i += 2;
        } else {
            return Err(RecoveryError::InvalidArgs(format!(
                "unknown flag or argument '{t}' for subcommand 'doctor'"
            )));
        }
    }

    Ok(CliCommand::Doctor {
        ffprobe_path,
        ffmpeg_path,
        lang,
    })
}

fn parse_recover_command(tokens: &[String]) -> Result<CliCommand, RecoveryError> {
    let mut disk = None;
    let mut output = None;
    let mut mode = ScanMode::All;
    let mut ffprobe_path = None;
    let mut ffmpeg_path = None;
    let mut full_verify = false;
    let mut allow_fixed = false;
    let mut lang = None;

    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        if let Some(val) = t.strip_prefix("--disk=") {
            let d = val.parse::<u32>().map_err(|_| {
                RecoveryError::InvalidArgs(format!(
                    "invalid disk number '{val}': expected non-negative integer"
                ))
            })?;
            disk = Some(d);
            i += 1;
        } else if t == "--disk" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--disk'".to_string(),
                ));
            }
            let val = &tokens[i + 1];
            let d = val.parse::<u32>().map_err(|_| {
                RecoveryError::InvalidArgs(format!(
                    "invalid disk number '{val}': expected non-negative integer"
                ))
            })?;
            disk = Some(d);
            i += 2;
        } else if let Some(val) = t.strip_prefix("--output=") {
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--output path cannot be empty".to_string(),
                ));
            }
            output = Some(PathBuf::from(val));
            i += 1;
        } else if t == "--output" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--output'".to_string(),
                ));
            }
            let val = &tokens[i + 1];
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--output path cannot be empty".to_string(),
                ));
            }
            output = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = t.strip_prefix("--mode=") {
            mode = parse_scan_mode(val)?;
            i += 1;
        } else if t == "--mode" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--mode'".to_string(),
                ));
            }
            mode = parse_scan_mode(&tokens[i + 1])?;
            i += 2;
        } else if let Some(val) = t.strip_prefix("--ffprobe-path=") {
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--ffprobe-path cannot be empty".to_string(),
                ));
            }
            ffprobe_path = Some(PathBuf::from(val));
            i += 1;
        } else if t == "--ffprobe-path" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--ffprobe-path'".to_string(),
                ));
            }
            let val = &tokens[i + 1];
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--ffprobe-path cannot be empty".to_string(),
                ));
            }
            ffprobe_path = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = t.strip_prefix("--ffmpeg-path=") {
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--ffmpeg-path cannot be empty".to_string(),
                ));
            }
            ffmpeg_path = Some(PathBuf::from(val));
            i += 1;
        } else if t == "--ffmpeg-path" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--ffmpeg-path'".to_string(),
                ));
            }
            let val = &tokens[i + 1];
            if val.is_empty() {
                return Err(RecoveryError::InvalidArgs(
                    "--ffmpeg-path cannot be empty".to_string(),
                ));
            }
            ffmpeg_path = Some(PathBuf::from(val));
            i += 2;
        } else if t == "--full-verify" {
            full_verify = true;
            i += 1;
        } else if t == "--allow-fixed" {
            allow_fixed = true;
            i += 1;
        } else if let Some(val) = t.strip_prefix("--lang=") {
            lang = Some(parse_language(val)?);
            i += 1;
        } else if t == "--lang" {
            if i + 1 >= tokens.len() {
                return Err(RecoveryError::InvalidArgs(
                    "missing value for flag '--lang'".to_string(),
                ));
            }
            lang = Some(parse_language(&tokens[i + 1])?);
            i += 2;
        } else {
            return Err(RecoveryError::InvalidArgs(format!(
                "unknown flag or argument '{t}' for subcommand 'recover'"
            )));
        }
    }

    let disk = disk.ok_or_else(|| {
        RecoveryError::InvalidArgs("missing required flag '--disk <N>'".to_string())
    })?;

    let output = output.ok_or_else(|| {
        RecoveryError::InvalidArgs("missing required flag '--output <DIRECTORY>'".to_string())
    })?;

    Ok(CliCommand::Recover {
        disk,
        output,
        mode,
        ffprobe_path,
        ffmpeg_path,
        full_verify,
        allow_fixed,
        lang,
    })
}

fn parse_scan_mode(input: &str) -> Result<ScanMode, RecoveryError> {
    match input.trim().to_ascii_lowercase().as_str() {
        "all" => Ok(ScanMode::All),
        "filesystem" => Ok(ScanMode::Filesystem),
        "deep" => Ok(ScanMode::Deep),
        other => Err(RecoveryError::InvalidArgs(format!(
            "unsupported scan mode '{other}'; expected 'all', 'filesystem', or 'deep'"
        ))),
    }
}

/// Formats a list of physical devices for console output or JSON output.
///
/// # Errors
///
/// Returns [`RecoveryError::Parse`] if JSON serialization fails.
pub fn format_device_list(
    devices: &[DeviceIdentity],
    lang: Language,
    as_json: bool,
) -> Result<String, RecoveryError> {
    if as_json {
        return serde_json::to_string_pretty(devices)
            .map_err(|e| RecoveryError::Parse(format!("JSON serialization error: {e}")));
    }

    let t = texts(lang);
    if devices.is_empty() {
        return Ok(t.list_no_devices.to_string());
    }

    let mut out = String::new();
    out.push_str(&format!(
        "{:<5} {:<22} {:<30} {:<18} {:<8} {:<12} {}\n",
        t.list_header_disk,
        t.list_header_path,
        t.list_header_model,
        t.list_header_size,
        t.list_header_bus,
        t.list_header_type,
        t.list_header_system,
    ));
    out.push_str(&"-".repeat(110));
    out.push('\n');

    for d in devices {
        let size_str = format_bytes(d.size_bytes);
        let bus_str = d.bus_type.label();
        let media_str = if d.removable {
            t.list_removable
        } else {
            t.list_fixed
        };
        let sys_str = if d.is_system_disk {
            t.list_system_disk_warning
        } else {
            t.list_not_system
        };

        let model_display = if d.model.chars().count() > 29 {
            let mut s: String = d.model.chars().take(26).collect();
            s.push_str("...");
            s
        } else {
            d.model.clone()
        };

        out.push_str(&format!(
            "{:<5} {:<22} {:<30} {:<18} {:<8} {:<12} {}\n",
            d.disk_number, d.device_path, model_display, size_str, bus_str, media_str, sys_str,
        ));
    }

    Ok(out)
}

/// Formats a detailed pre-scan verification banner for user confirmation.
#[must_use]
pub fn format_confirmation_prompt(
    device: &DeviceIdentity,
    partitions: &[PartitionInfo],
    lang: Language,
) -> String {
    let t = texts(lang);
    let size_str = format_bytes(device.size_bytes);
    let bus_str = device.bus_type.label();
    let media_type = if device.removable {
        t.list_removable
    } else {
        t.list_fixed
    };

    let mut out = String::new();
    out.push_str(
        "================================================================================\n",
    );
    out.push_str(t.prescan_title);
    out.push_str(
        "\n================================================================================\n",
    );
    out.push_str(&format!(
        "{}: {} (PhysicalDrive{})\n",
        t.prescan_target_device, device.device_path, device.disk_number
    ));
    out.push_str(&format!("{}: {}\n", t.prescan_model, device.model));
    out.push_str(&format!("{}: {}\n", t.prescan_size, size_str));
    out.push_str(&format!(
        "{}: {} ({})\n",
        t.prescan_bus, bus_str, media_type
    ));

    if device.is_system_disk {
        out.push_str(&format!("\n*** {} ***\n", t.list_system_disk_warning));
    }

    out.push_str(&format!("\n{}:\n", t.prescan_partitions_header));
    if partitions.is_empty() {
        out.push_str(&format!("  {}\n", t.prescan_no_partitions));
    } else {
        for p in partitions {
            let part_size = format_bytes(p.byte_len);
            let name_str = p.name.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "  [{}] Offset: {} ({}), Size: {} ({}), FS: {}, Scheme: {:?}, Name: {}\n",
                p.index,
                p.byte_offset,
                format_bytes(p.byte_offset),
                p.byte_len,
                part_size,
                p.filesystem.as_str(),
                p.scheme,
                name_str,
            ));
        }
    }
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );
    let instruction = t
        .confirm_prompt_instruction
        .replace("{N}", &device.disk_number.to_string());
    out.push_str(&instruction);
    out
}

/// Reads a line from `reader`, trims it, and verifies that it matches `expected_disk`.
///
/// # Errors
///
/// Returns [`RecoveryError::SafetyPreflight`] if:
/// - The input does not match `expected_disk`.
/// - End-of-file (EOF) is encountered before input is given.
pub fn confirm_disk_selection<R: BufRead>(
    expected_disk: u32,
    reader: &mut R,
    lang: Language,
) -> Result<(), RecoveryError> {
    let t = texts(lang);
    let mut line = String::new();
    let bytes_read = reader
        .read_line(&mut line)
        .map_err(|e| RecoveryError::SafetyPreflight(format!("{}: {e}", t.confirm_eof_error)))?;

    if bytes_read == 0 {
        return Err(RecoveryError::SafetyPreflight(
            t.confirm_eof_error.to_string(),
        ));
    }

    let trimmed = line.trim();
    let expected_str = expected_disk.to_string();
    if trimmed != expected_str {
        return Err(RecoveryError::SafetyPreflight(format!(
            "{}: entered '{trimmed}', expected '{expected_str}'",
            t.confirm_mismatch_error
        )));
    }

    Ok(())
}

/// Formats byte count into a human-readable string (`B`, `KB`, `MB`, `GB`, `TB`).
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB ({} B)", bytes as f64 / TB as f64, bytes)
    } else if bytes >= GB {
        format!("{:.1} GB ({} B)", bytes as f64 / GB as f64, bytes)
    } else if bytes >= MB {
        format!("{:.1} MB ({} B)", bytes as f64 / MB as f64, bytes)
    } else if bytes >= KB {
        format!("{:.1} KB ({} B)", bytes as f64 / KB as f64, bytes)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ExitCode;
    use crate::types::{BusType, FilesystemKind, PartitionScheme};

    #[test]
    fn test_parse_cli_empty_shows_help() {
        let args: Vec<&str> = vec!["sd-video-recovery"];
        let cmd = parse_cli_args(args).unwrap();
        assert!(matches!(cmd, CliCommand::Help { .. }));
    }

    #[test]
    fn test_parse_cli_help_flags() {
        for flag in ["-h", "--help", "help"] {
            let args = vec!["sd-video-recovery", flag];
            let cmd = parse_cli_args(args).unwrap();
            assert!(matches!(cmd, CliCommand::Help { .. }));
        }

        let args_hy = vec!["sd-video-recovery", "--help", "--lang", "hy"];
        let cmd_hy = parse_cli_args(args_hy).unwrap();
        assert_eq!(cmd_hy, CliCommand::Help { lang: Language::Hy });

        let args_en = vec!["sd-video-recovery", "help", "--lang=en"];
        let cmd_en = parse_cli_args(args_en).unwrap();
        assert_eq!(cmd_en, CliCommand::Help { lang: Language::En });
    }

    #[test]
    fn test_parse_cli_list_command() {
        let args = vec!["sd-video-recovery", "list"];
        assert_eq!(
            parse_cli_args(args).unwrap(),
            CliCommand::List {
                lang: None,
                json: false
            }
        );

        let args_json = vec!["sd-video-recovery", "list", "--json"];
        assert_eq!(
            parse_cli_args(args_json).unwrap(),
            CliCommand::List {
                lang: None,
                json: true
            }
        );

        let args_lang = vec!["sd-video-recovery", "list", "--lang", "hy", "--json"];
        assert_eq!(
            parse_cli_args(args_lang).unwrap(),
            CliCommand::List {
                lang: Some(Language::Hy),
                json: true
            }
        );

        let args_lang_eq = vec!["sd-video-recovery", "list", "--lang=en"];
        assert_eq!(
            parse_cli_args(args_lang_eq).unwrap(),
            CliCommand::List {
                lang: Some(Language::En),
                json: false
            }
        );

        let args_invalid = vec!["sd-video-recovery", "list", "--invalid"];
        assert!(parse_cli_args(args_invalid).is_err());
    }

    #[test]
    fn test_parse_cli_doctor_command() {
        let args = vec!["sd-video-recovery", "doctor"];
        assert_eq!(
            parse_cli_args(args).unwrap(),
            CliCommand::Doctor {
                ffprobe_path: None,
                ffmpeg_path: None,
                lang: None,
            }
        );

        let args_paths = vec![
            "sd-video-recovery",
            "doctor",
            "--ffprobe-path",
            r"C:\bin\ffprobe.exe",
            "--ffmpeg-path",
            r"C:\bin\ffmpeg.exe",
            "--lang=hy",
        ];
        assert_eq!(
            parse_cli_args(args_paths).unwrap(),
            CliCommand::Doctor {
                ffprobe_path: Some(PathBuf::from(r"C:\bin\ffprobe.exe")),
                ffmpeg_path: Some(PathBuf::from(r"C:\bin\ffmpeg.exe")),
                lang: Some(Language::Hy),
            }
        );

        let args_eq = vec![
            "sd-video-recovery",
            "doctor",
            r"--ffprobe-path=C:\probe.exe",
            r"--ffmpeg-path=C:\ffmpeg.exe",
        ];
        assert_eq!(
            parse_cli_args(args_eq).unwrap(),
            CliCommand::Doctor {
                ffprobe_path: Some(PathBuf::from(r"C:\probe.exe")),
                ffmpeg_path: Some(PathBuf::from(r"C:\ffmpeg.exe")),
                lang: None,
            }
        );

        let args_invalid = vec!["sd-video-recovery", "doctor", "--extra"];
        assert!(parse_cli_args(args_invalid).is_err());
    }

    #[test]
    fn test_parse_cli_recover_command() {
        let args = vec![
            "sd-video-recovery",
            "recover",
            "--disk",
            "2",
            "--output",
            r"D:\Recovered",
        ];
        assert_eq!(
            parse_cli_args(args).unwrap(),
            CliCommand::Recover {
                disk: 2,
                output: PathBuf::from(r"D:\Recovered"),
                mode: ScanMode::All,
                ffprobe_path: None,
                ffmpeg_path: None,
                full_verify: false,
                allow_fixed: false,
                lang: None,
            }
        );

        let args_full = vec![
            "sd-video-recovery",
            "recover",
            "--disk=3",
            r"--output=D:\Out",
            "--mode=deep",
            r"--ffprobe-path=C:\probe.exe",
            r"--ffmpeg-path=C:\ffmpeg.exe",
            "--full-verify",
            "--allow-fixed",
            "--lang=hy",
        ];
        assert_eq!(
            parse_cli_args(args_full).unwrap(),
            CliCommand::Recover {
                disk: 3,
                output: PathBuf::from(r"D:\Out"),
                mode: ScanMode::Deep,
                ffprobe_path: Some(PathBuf::from(r"C:\probe.exe")),
                ffmpeg_path: Some(PathBuf::from(r"C:\ffmpeg.exe")),
                full_verify: true,
                allow_fixed: true,
                lang: Some(Language::Hy),
            }
        );

        let args_fs = vec![
            "sd-video-recovery",
            "recover",
            "--disk",
            "1",
            "--output",
            r"E:\Dump",
            "--mode",
            "filesystem",
        ];
        assert_eq!(
            parse_cli_args(args_fs).unwrap(),
            CliCommand::Recover {
                disk: 1,
                output: PathBuf::from(r"E:\Dump"),
                mode: ScanMode::Filesystem,
                ffprobe_path: None,
                ffmpeg_path: None,
                full_verify: false,
                allow_fixed: false,
                lang: None,
            }
        );
    }

    #[test]
    fn test_parse_cli_recover_validation_errors() {
        // Missing --disk
        let err1 =
            parse_cli_args(vec!["sd-video-recovery", "recover", "--output", "D:\\"]).unwrap_err();
        assert!(matches!(err1, RecoveryError::InvalidArgs(_)));
        assert_eq!(err1.exit_code(), ExitCode::InvalidArgs);

        // Missing --output
        let err2 = parse_cli_args(vec!["sd-video-recovery", "recover", "--disk", "1"]).unwrap_err();
        assert!(matches!(err2, RecoveryError::InvalidArgs(_)));
        assert_eq!(err2.exit_code(), ExitCode::InvalidArgs);

        // Invalid disk number
        let err3 = parse_cli_args(vec![
            "sd-video-recovery",
            "recover",
            "--disk",
            "abc",
            "--output",
            "D:\\",
        ])
        .unwrap_err();
        assert!(matches!(err3, RecoveryError::InvalidArgs(_)));

        // Empty output path
        let err4 = parse_cli_args(vec![
            "sd-video-recovery",
            "recover",
            "--disk",
            "1",
            "--output",
            "",
        ])
        .unwrap_err();
        assert!(matches!(err4, RecoveryError::InvalidArgs(_)));

        // Invalid mode
        let err5 = parse_cli_args(vec![
            "sd-video-recovery",
            "recover",
            "--disk",
            "1",
            "--output",
            "D:\\",
            "--mode",
            "unknown",
        ])
        .unwrap_err();
        assert!(matches!(err5, RecoveryError::InvalidArgs(_)));

        // Unknown subcommand
        let err6 = parse_cli_args(vec!["sd-video-recovery", "scan"]).unwrap_err();
        assert!(matches!(err6, RecoveryError::InvalidArgs(_)));
    }

    #[test]
    fn test_format_device_list() {
        let devices = vec![
            DeviceIdentity {
                disk_number: 0,
                device_path: r"\\.\PhysicalDrive0".to_string(),
                model: "Samsung SSD 980 PRO 1TB".to_string(),
                size_bytes: 1_000_204_886_016,
                sector_size: 512,
                bus_type: BusType::Nvme,
                removable: false,
                is_system_disk: true,
                masked_serial: Some("****1234".to_string()),
            },
            DeviceIdentity {
                disk_number: 1,
                device_path: r"\\.\PhysicalDrive1".to_string(),
                model: "SanDisk Extreme PRO 64GB".to_string(),
                size_bytes: 63_864_569_856,
                sector_size: 512,
                bus_type: BusType::Usb,
                removable: true,
                is_system_disk: false,
                masked_serial: None,
            },
        ];

        // English text format
        let en_text = format_device_list(&devices, Language::En, false).unwrap();
        assert!(en_text.contains("Disk"));
        assert!(en_text.contains("Samsung SSD 980 PRO"));
        assert!(en_text.contains("SanDisk Extreme PRO"));
        assert!(en_text.contains("[SYSTEM DISK - BLOCKED]"));

        // Armenian text format
        let hy_text = format_device_list(&devices, Language::Hy, false).unwrap();
        assert!(hy_text.contains("Սկավ."));
        assert!(hy_text.contains("[ՀԱՄԱԿԱՐԳԱՅԻՆ - ԱՐԳԵԼՎԱԾ]"));

        // JSON format
        let json_text = format_device_list(&devices, Language::En, true).unwrap();
        let parsed: Vec<DeviceIdentity> = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].disk_number, 1);

        // Empty devices
        let empty_text = format_device_list(&[], Language::En, false).unwrap();
        assert!(empty_text.contains("No physical drives"));
    }

    #[test]
    fn test_format_confirmation_prompt() {
        let dev = DeviceIdentity {
            disk_number: 2,
            device_path: r"\\.\PhysicalDrive2".to_string(),
            model: "Kingston Canvas Go Plus 128GB".to_string(),
            size_bytes: 128_000_000_000,
            sector_size: 512,
            bus_type: BusType::Sd,
            removable: true,
            is_system_disk: false,
            masked_serial: None,
        };

        let parts = vec![PartitionInfo {
            index: 1,
            scheme: PartitionScheme::Mbr,
            byte_offset: 1_048_576,
            byte_len: 127_998_951_424,
            type_id: "0x07".to_string(),
            name: Some("SD_CARD".to_string()),
            filesystem: FilesystemKind::ExFat,
        }];

        let prompt_en = format_confirmation_prompt(&dev, &parts, Language::En);
        assert!(prompt_en.contains("Kingston Canvas Go Plus"));
        assert!(prompt_en.contains("PhysicalDrive2"));
        assert!(prompt_en.contains("exFAT"));
        assert!(prompt_en.contains("type the disk number (2) and press Enter:"));

        let prompt_hy = format_confirmation_prompt(&dev, &parts, Language::Hy);
        assert!(prompt_hy.contains("Kingston Canvas Go Plus"));
        assert!(prompt_hy.contains("մուտքագրեք սկավառակի համարը (2)"));
    }

    #[test]
    fn test_confirm_disk_selection_matching() {
        let mut input = std::io::Cursor::new(b"2\n");
        assert!(confirm_disk_selection(2, &mut input, Language::En).is_ok());

        let mut input_padded = std::io::Cursor::new(b"  2 \r\n");
        assert!(confirm_disk_selection(2, &mut input_padded, Language::En).is_ok());
    }

    #[test]
    fn test_confirm_disk_selection_mismatch() {
        let mut input = std::io::Cursor::new(b"1\n");
        let err = confirm_disk_selection(2, &mut input, Language::En).unwrap_err();
        assert!(matches!(err, RecoveryError::SafetyPreflight(_)));
        assert_eq!(err.exit_code(), ExitCode::SafetyPreflight);
    }

    #[test]
    fn test_confirm_disk_selection_eof() {
        let mut input = std::io::Cursor::new(b"");
        let err = confirm_disk_selection(2, &mut input, Language::En).unwrap_err();
        assert!(matches!(err, RecoveryError::SafetyPreflight(_)));
        assert_eq!(err.exit_code(), ExitCode::SafetyPreflight);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB (1024 B)");
        assert_eq!(format_bytes(1_048_576), "1.0 MB (1048576 B)");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB (1073741824 B)");
        assert_eq!(format_bytes(1_099_511_627_776), "1.0 TB (1099511627776 B)");
    }
}
