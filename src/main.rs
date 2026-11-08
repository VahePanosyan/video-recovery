//! CLI entry point for `sd-video-recovery`.

use std::process;

use sd_video_recovery::cli::{parse_cli_args, CliCommand};
use sd_video_recovery::error::ExitCode;
use sd_video_recovery::i18n::{detect_system_language, texts};
use sd_video_recovery::types::ScanConfig;
use sd_video_recovery::{run_doctor_command, run_list_command, run_recover_command};

fn main() {
    let code = match run() {
        Ok(()) => ExitCode::Success.code(),
        Err(err) => {
            eprintln!("{err}");
            err.exit_code().code()
        }
    };
    process::exit(code);
}

fn run() -> Result<(), sd_video_recovery::error::RecoveryError> {
    let command = parse_cli_args(std::env::args())?;

    match command {
        CliCommand::Help { lang } => {
            let t = texts(lang);
            print!("{}", t.help_text);
            Ok(())
        }
        CliCommand::List { lang, json } => {
            let active_lang = lang.unwrap_or_else(detect_system_language);
            let output = run_list_command(active_lang, json)?;
            println!("{output}");
            Ok(())
        }
        CliCommand::Doctor {
            ffprobe_path,
            ffmpeg_path,
            lang,
        } => {
            let active_lang = lang.unwrap_or_else(detect_system_language);
            let output =
                run_doctor_command(ffprobe_path.as_deref(), ffmpeg_path.as_deref(), active_lang)?;
            print!("{output}");
            Ok(())
        }
        CliCommand::Recover {
            disk,
            output,
            mode,
            ffprobe_path,
            ffmpeg_path,
            full_verify,
            allow_fixed,
            lang,
        } => {
            let active_lang = lang.unwrap_or_else(detect_system_language);
            let config = ScanConfig {
                disk_number: disk,
                output_dir: output,
                mode,
                ffprobe_path,
                ffmpeg_path,
                full_verify,
                allow_fixed,
                lang: active_lang,
            };
            let _ = run_recover_command(&config)?;
            Ok(())
        }
    }
}
