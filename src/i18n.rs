//! English and Armenian localization messages and Windows locale detection.

use crate::error::RecoveryError;
use crate::types::Language;

/// Parses a language string into a supported [`Language`] variant.
///
/// Supported values (case-insensitive):
/// - `"en"`, `"eng"`, `"en-us"`, `"en_us"` -> [`Language::En`]
/// - `"hy"`, `"arm"`, `"hy-am"`, `"hy_am"` -> [`Language::Hy`]
///
/// # Errors
///
/// Returns [`RecoveryError::InvalidArgs`] if the language tag is unsupported.
pub fn parse_language(input: &str) -> Result<Language, RecoveryError> {
    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case("en")
        || trimmed.eq_ignore_ascii_case("eng")
        || trimmed.eq_ignore_ascii_case("en-us")
        || trimmed.eq_ignore_ascii_case("en_us")
    {
        Ok(Language::En)
    } else if trimmed.eq_ignore_ascii_case("hy")
        || trimmed.eq_ignore_ascii_case("arm")
        || trimmed.eq_ignore_ascii_case("hy-am")
        || trimmed.eq_ignore_ascii_case("hy_am")
    {
        Ok(Language::Hy)
    } else {
        Err(RecoveryError::InvalidArgs(format!(
            "unsupported language '{input}'; expected 'en' or 'hy'"
        )))
    }
}

/// Detects the language variant from a locale tag or identifier.
///
/// Trims and converts `locale_tag` to lowercase. If it begins with `"hy"`,
/// returns [`Language::Hy`]; otherwise defaults to [`Language::En`].
#[must_use]
pub fn detect_language_from_tag(locale_tag: &str) -> Language {
    let tag = locale_tag.trim().to_ascii_lowercase();
    if tag.starts_with("hy") {
        Language::Hy
    } else {
        Language::En
    }
}

/// Detects the active system language.
///
/// Checks the following environment variables in order:
/// 1. `SD_VIDEO_RECOVERY_LANG`
/// 2. `LC_ALL`
/// 3. `LANG`
///
/// On Windows, if no environment variable is set, queries the user default
/// locale name via Win32 `GetUserDefaultLocaleName`.
///
/// Defaults to [`Language::En`] on unsupported or unrecognized locales.
#[must_use]
pub fn detect_system_language() -> Language {
    for var_name in ["SD_VIDEO_RECOVERY_LANG", "LC_ALL", "LANG"] {
        if let Ok(val) = std::env::var(var_name) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return detect_language_from_tag(trimmed);
            }
        }
    }

    #[cfg(windows)]
    {
        let mut buf = [0u16; 85];
        let len = unsafe { windows::Win32::Globalization::GetUserDefaultLocaleName(&mut buf) };
        if len > 1 {
            let valid_len = (len - 1) as usize;
            let locale_str = String::from_utf16_lossy(&buf[..valid_len]);
            return detect_language_from_tag(&locale_str);
        }
    }

    Language::En
}

/// Complete localized text catalog for user-facing CLI messages.
#[derive(Debug, Clone, Copy)]
pub struct Texts {
    /// Active language.
    pub lang: Language,

    // CLI general & help
    pub app_name: &'static str,
    pub app_description: &'static str,
    pub help_text: &'static str,

    // Device list
    pub list_header_disk: &'static str,
    pub list_header_path: &'static str,
    pub list_header_model: &'static str,
    pub list_header_size: &'static str,
    pub list_header_bus: &'static str,
    pub list_header_type: &'static str,
    pub list_header_system: &'static str,
    pub list_no_devices: &'static str,
    pub list_removable: &'static str,
    pub list_fixed: &'static str,
    pub list_system_disk_warning: &'static str,
    pub list_not_system: &'static str,

    // Doctor command
    pub doctor_title: &'static str,
    pub doctor_tool: &'static str,
    pub doctor_status: &'static str,
    pub doctor_path: &'static str,
    pub doctor_version: &'static str,
    pub doctor_available: &'static str,
    pub doctor_missing: &'static str,
    pub doctor_ffprobe_missing_warning: &'static str,
    pub doctor_ffmpeg_missing_warning: &'static str,
    pub doctor_all_ok: &'static str,

    // Pre-scan target device verification & confirmation banner
    pub prescan_title: &'static str,
    pub prescan_target_device: &'static str,
    pub prescan_model: &'static str,
    pub prescan_size: &'static str,
    pub prescan_bus: &'static str,
    pub prescan_partitions_header: &'static str,
    pub prescan_no_partitions: &'static str,
    pub confirm_prompt_instruction: &'static str,
    pub confirm_mismatch_error: &'static str,
    pub confirm_eof_error: &'static str,

    // Safety refusal messages
    pub safety_system_disk_refusal: &'static str,
    pub safety_fixed_disk_refusal: &'static str,
    pub safety_same_disk_refusal: &'static str,
    pub safety_non_sd_usb_refusal: &'static str,

    // Phase progress & completion
    pub phase_filesystem_start: &'static str,
    pub phase_deep_start: &'static str,
    pub phase_validation_start: &'static str,
    pub phase_interrupted: &'static str,
    pub session_complete_summary: &'static str,
    pub session_files_recovered: &'static str,
    pub session_bytes_recovered: &'static str,
    pub session_report_saved: &'static str,
}

static EN_HELP: &str = r#"sd-video-recovery 0.1.0
Read-only Windows CLI tool for recovering deleted or quick-formatted MP4/MOV videos from FAT32 and exFAT SD cards.

USAGE:
    sd-video-recovery <COMMAND> [OPTIONS]

COMMANDS:
    list        List connected physical drives and identify eligible SD card readers
    doctor      Verify external tools (ffprobe, ffmpeg) and report environment readiness
    recover     Perform read-only video recovery from a physical drive to a destination folder
    help        Display this help message

COMMAND 'list':
    sd-video-recovery list [--lang en|hy] [--json]

    Flags:
        --lang <en|hy>   Interface language (default: auto-detected from system)
        --json           Output device list formatted as JSON
    -h, --help           Show help for the list command

COMMAND 'doctor':
    sd-video-recovery doctor [--ffprobe-path FILE] [--ffmpeg-path FILE] [--lang en|hy]

    Flags:
        --ffprobe-path <FILE>  Explicit path to ffprobe executable
        --ffmpeg-path <FILE>   Explicit path to ffmpeg executable
        --lang <en|hy>         Interface language (default: auto-detected from system)
    -h, --help                 Show help for the doctor command

COMMAND 'recover':
    sd-video-recovery recover --disk N --output DIRECTORY [OPTIONS]

    Required Options:
        --disk <N>             Physical disk number (e.g. 1 for \\.\PhysicalDrive1)
        --output <DIRECTORY>   Destination folder on a different drive

    Options:
        --mode <MODE>          Scan mode: 'all' (default), 'filesystem', or 'deep'
        --ffprobe-path <FILE>  Explicit path to ffprobe executable
        --ffmpeg-path <FILE>   Explicit path to ffmpeg executable
        --full-verify          Decode full video streams with ffmpeg (slower, thorough)
        --allow-fixed          Allow scanning fixed-media USB card readers
        --lang <en|hy>         Interface language (default: auto-detected from system)
    -h, --help                 Show help for the recover command

SAFETY:
    - Source drive is opened with read-only access (GENERIC_READ). Never writes to the source.
    - Windows system/boot drive is strictly blocked from recovery.
    - Output directory must be located on a different physical drive.
"#;

static HY_HELP: &str = r#"sd-video-recovery 0.1.0
Windows CLI գործիք՝ FAT32 և exFAT SD քարտերից ջնջված կամ quick-format-ից հետո մնացած MP4/MOV վիդեոների անվտանգ (read-only) վերականգնման համար։

ՕԳՏԱԳՈՐԾՈՒՄ:
    sd-video-recovery <ՀՐԱՄԱՆ> [ԸՆՏՐԱՆՔՆԵՐ]

ՀՐԱՄԱՆՆԵՐ:
    list        Ցուցադրել միացված ֆիզիկական սկավառակները և հայտնաբերել SD reader-ները
    doctor      Ստուգել արտաքին գործիքները (ffprobe, ffmpeg) և միջավայրի պատրաստվածությունը
    recover     Իրականացնել վիդեոների read-only վերականգնում ֆիզիկական սկավառակից դեպի output թղթապանակ
    help        Ցուցադրել այս օգնության տեքստը

ՀՐԱՄԱՆ 'list':
    sd-video-recovery list [--lang en|hy] [--json]

    Դրոշակներ:
        --lang <en|hy>   Միջերեսի լեզուն (լռելյայն՝ համակարգային locale-ից)
        --json           Սարքերի ցուցակը արտածել JSON ձևաչափով
    -h, --help           Ցուցադրել list հրամանի օգնությունը

ՀՐԱՄԱՆ 'doctor':
    sd-video-recovery doctor [--ffprobe-path FILE] [--ffmpeg-path FILE] [--lang en|hy]

    Դրոշակներ:
        --ffprobe-path <FILE>  ffprobe ծրագրի հստակ ուղին
        --ffmpeg-path <FILE>   ffmpeg ծրագրի հստակ ուղին
        --lang <en|hy>         Միջերեսի լեզուն (լռելյայն՝ համակարգային locale-ից)
    -h, --help                 Ցուցադրել doctor հրամանի օգնությունը

ՀՐԱՄԱՆ 'recover':
    sd-video-recovery recover --disk N --output DIRECTORY [ԸՆՏՐԱՆՔՆԵՐ]

    Պարտադիր ընտրանքներ:
        --disk <N>             Ֆիզիկական սկավառակի համարը (օր.՝ 1-ը \\.\PhysicalDrive1-ի համար)
        --output <DIRECTORY>   Արդյունքների թղթապանակը (պարտադիր այլ սկավառակի վրա)

    Լրացուցիչ ընտրանքներ:
        --mode <MODE>          Սկանավորման ռեժիմ՝ 'all' (լռելյայն), 'filesystem' կամ 'deep'
        --ffprobe-path <FILE>  ffprobe ծրագրի հստակ ուղին
        --ffmpeg-path <FILE>   ffmpeg ծրագրի հստակ ուղին
        --full-verify          Ամբողջական վիդեո սթրիմի դեկոդավորում ffmpeg-ով (դանդաղ, բայց մանրակրկիտ)
        --allow-fixed          Թույլատրել fixed-media USB card reader-ների սկանավորումը
        --lang <en|hy>         Միջերեսի լեզուն (լռելյայն՝ համակարգային locale-ից)
    -h, --help                 Ցուցադրել recover հրամանի օգնությունը

ԱՆՎՏԱՆԳՈՒԹՅՈՒՆ:
    - Աղբյուր սկավառակը բացվում է միայն կարդալու իրավունքով (GENERIC_READ)։ Աղբյուրի վրա գրառում ԵՐԲԵՔ չի կատարվում։
    - Համակարգային/boot սկավառակը արգելված է վերականգնման համար։
    - Output թղթապանակը պարտադիր պետք է գտնվի այլ ֆիզիկական սկավառակի վրա։
"#;

static EN_TEXTS: Texts = Texts {
    lang: Language::En,
    app_name: "sd-video-recovery",
    app_description: "Read-only Windows CLI tool for recovering deleted or quick-formatted MP4/MOV videos from FAT32 and exFAT SD cards",
    help_text: EN_HELP,

    list_header_disk: "Disk",
    list_header_path: "Device Path",
    list_header_model: "Model",
    list_header_size: "Size",
    list_header_bus: "Bus",
    list_header_type: "Media Type",
    list_header_system: "System Disk",
    list_no_devices: "No physical drives detected.",
    list_removable: "Removable",
    list_fixed: "Fixed",
    list_system_disk_warning: "[SYSTEM DISK - BLOCKED]",
    list_not_system: "No",

    doctor_title: "sd-video-recovery Environment & Tool Readiness",
    doctor_tool: "Tool",
    doctor_status: "Status",
    doctor_path: "Resolved Path",
    doctor_version: "Version / Details",
    doctor_available: "AVAILABLE",
    doctor_missing: "MISSING",
    doctor_ffprobe_missing_warning: "ERROR: ffprobe is required for video validation. Please install ffmpeg/ffprobe and add to PATH or pass --ffprobe-path.",
    doctor_ffmpeg_missing_warning: "WARNING: ffmpeg is missing. Required only if using --full-verify.",
    doctor_all_ok: "All external tools are available and ready for video recovery.",

    prescan_title: "PRE-SCAN TARGET DEVICE VERIFICATION",
    prescan_target_device: "Target Device",
    prescan_model: "Model",
    prescan_size: "Total Size",
    prescan_bus: "Bus Type",
    prescan_partitions_header: "Partitions / Layout",
    prescan_no_partitions: "No partitions found (superfloppy or raw volume)",
    confirm_prompt_instruction: "To confirm scanning PhysicalDrive{N}, type the disk number ({N}) and press Enter: ",
    confirm_mismatch_error: "Disk number confirmation failed",
    confirm_eof_error: "Disk confirmation was aborted (EOF reached)",

    safety_system_disk_refusal: "Safety check failed: target disk is the Windows system/boot drive. Scanning system drives is blocked to prevent accidents.",
    safety_fixed_disk_refusal: "Safety check failed: target drive is reported as fixed media. If using a fixed-media USB card reader, pass '--allow-fixed' to proceed.",
    safety_same_disk_refusal: "Safety check failed: output directory resides on the same physical drive as the source SD card. Output must be on a different drive.",
    safety_non_sd_usb_refusal: "Safety check failed: target drive bus type is not an eligible SD, MMC, or USB card reader bus.",

    phase_filesystem_start: "[Phase 1/3] Starting filesystem metadata recovery (FAT32/exFAT)...",
    phase_deep_start: "[Phase 2/3] Starting deep raw carving for MP4/MOV boxes...",
    phase_validation_start: "[Phase 3/3] Validating recovered candidate video streams...",
    phase_interrupted: "Recovery interrupted by user (Ctrl+C). Cleaning up partial file and finalizing session report...",
    session_complete_summary: "Recovery session finished.",
    session_files_recovered: "Recovered files",
    session_bytes_recovered: "Recovered bytes",
    session_report_saved: "Session report written to",
};

static HY_TEXTS: Texts = Texts {
    lang: Language::Hy,
    app_name: "sd-video-recovery",
    app_description: "Windows CLI գործիք՝ FAT32 և exFAT SD քարտերից ջնջված կամ quick-format-ից հետո մնացած MP4/MOV վիդեոների անվտանգ (read-only) վերականգնման համար",
    help_text: HY_HELP,

    list_header_disk: "Սկավ.",
    list_header_path: "Սարքի ուղի",
    list_header_model: "Մոդել",
    list_header_size: "Չափ",
    list_header_bus: "Կապուղի",
    list_header_type: "Տեսակ",
    list_header_system: "Համակարգային",
    list_no_devices: "Ֆիզիկական սկավառակներ չեն հայտնաբերվել:",
    list_removable: "Removable (Շարժական)",
    list_fixed: "Fixed (Ամրացված)",
    list_system_disk_warning: "[ՀԱՄԱԿԱՐԳԱՅԻՆ - ԱՐԳԵԼՎԱԾ]",
    list_not_system: "Ոչ",

    doctor_title: "sd-video-recovery Միջավայրի և գործիքների պատրաստվածություն",
    doctor_tool: "Գործիք",
    doctor_status: "Կարգավիճակ",
    doctor_path: "Ուղի",
    doctor_version: "Տարբերակ / Մանրամասներ",
    doctor_available: "ՀԱՍԱՆԵԼԻ Է",
    doctor_missing: "ԲԱՑԱԿԱՅՈՒՄ Է",
    doctor_ffprobe_missing_warning: "ՍԽԱԼ: ffprobe-ը պարտադիր է վիդեոների վալիդացիայի համար: Տեղադրեք ffmpeg/ffprobe-ը կամ փոխանցեք --ffprobe-path:",
    doctor_ffmpeg_missing_warning: "ԶԳՈՒՇԱՑՈՒՄ: ffmpeg-ը բացակայում է: Պահանջվում է միայն --full-verify ընտրանքի դեպքում:",
    doctor_all_ok: "Բոլոր անհրաժեշտ արտաքին գործիքները հասանելի են և պատրաստ աշխատանքի:",

    prescan_title: "ԹԻՐԱԽԱՅԻՆ ՍԱՐՔԻ ՆԱԽՆԱԿԱՆ ՍՏՈՒԳՈՒՄ",
    prescan_target_device: "Թիրախային սարք",
    prescan_model: "Մոդել",
    prescan_size: "Ընդհանուր չափ",
    prescan_bus: "Կապուղու տեսակ",
    prescan_partitions_header: "Բաժիններ / Կառուցվածք",
    prescan_no_partitions: "Բաժիններ չեն գտնվել (superfloppy կամ raw ծավալ)",
    confirm_prompt_instruction: "PhysicalDrive{N}-ի սկանավորումը հաստատելու համար մուտքագրեք սկավառակի համարը ({N}) և սեղմեք Enter: ",
    confirm_mismatch_error: "Սկավառակի համարի հաստատումը ձախողվեց",
    confirm_eof_error: "Հաստատման գործընթացը ընդհատվեց (EOF)",

    safety_system_disk_refusal: "Անվտանգության ստուգումը ձախողվեց. թիրախային սկավառակը Windows համակարգային/boot սկավառակն է: Համակարգային սկավառակների սկանավորումն արգելված է:",
    safety_fixed_disk_refusal: "Անվտանգության ստուգումը ձախողվեց. թիրախային սկավառակը ֆիքսված (fixed) տեսակի է: Եթե օգտագործում եք fixed-media USB reader, փոխանցեք '--allow-fixed':",
    safety_same_disk_refusal: "Անվտանգության ստուգումը ձախողվեց. output թղթապանակը գտնվում է աղբյուր SD քարտի նույն ֆիզիկական սկավառակի վրա: Output-ը պետք է լինի ուրիշ սկավառակի վրա:",
    safety_non_sd_usb_refusal: "Անվտանգության ստուգումը ձախողվեց. թիրախային սկավառակի կապուղին SD, MMC կամ USB card reader չէ:",

    phase_filesystem_start: "[Փուլ 1/3] Ֆայլային համակարգի մետատվյալների վերականգնման մեկնարկ (FAT32/exFAT)...",
    phase_deep_start: "[Փուլ 2/3] MP4/MOV box-երի խորքային raw carving-ի մեկնարկ...",
    phase_validation_start: "[Փուլ 3/3] Վերականգնված վիդեո թեկնածուների վալիդացիա...",
    phase_interrupted: "Վերականգնումը ընդհատվեց օգտատիրոջ կողմից (Ctrl+C): Ընթացիկ .part ֆայլի մաքրում և report-ի պահպանում...",
    session_complete_summary: "Վերականգնման սեսիան ավարտվեց:",
    session_files_recovered: "Վերականգնված ֆայլեր",
    session_bytes_recovered: "Վերականգնված բայթեր",
    session_report_saved: "Սեսիայի հաշվետվությունը պահպանվել է",
};

/// Returns the static localized texts for the given language.
#[must_use]
pub const fn texts(lang: Language) -> &'static Texts {
    match lang {
        Language::En => &EN_TEXTS,
        Language::Hy => &HY_TEXTS,
    }
}

/// Returns the formatted CLI help text for the specified language.
#[must_use]
pub fn help_text(lang: Language) -> &'static str {
    texts(lang).help_text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_language_english() {
        assert_eq!(parse_language("en").unwrap(), Language::En);
        assert_eq!(parse_language("EN").unwrap(), Language::En);
        assert_eq!(parse_language("eng").unwrap(), Language::En);
        assert_eq!(parse_language("en-US").unwrap(), Language::En);
        assert_eq!(parse_language("en_us").unwrap(), Language::En);
    }

    #[test]
    fn test_parse_language_armenian() {
        assert_eq!(parse_language("hy").unwrap(), Language::Hy);
        assert_eq!(parse_language("HY").unwrap(), Language::Hy);
        assert_eq!(parse_language("arm").unwrap(), Language::Hy);
        assert_eq!(parse_language("hy-AM").unwrap(), Language::Hy);
        assert_eq!(parse_language("hy_am").unwrap(), Language::Hy);
    }

    #[test]
    fn test_parse_language_unsupported() {
        let err = parse_language("fr").unwrap_err();
        assert!(matches!(err, RecoveryError::InvalidArgs(_)));
        let err_empty = parse_language("").unwrap_err();
        assert!(matches!(err_empty, RecoveryError::InvalidArgs(_)));
    }

    #[test]
    fn test_detect_language_from_tag() {
        assert_eq!(detect_language_from_tag("hy"), Language::Hy);
        assert_eq!(detect_language_from_tag("hy-AM"), Language::Hy);
        assert_eq!(detect_language_from_tag("hy_am"), Language::Hy);
        assert_eq!(detect_language_from_tag("HY"), Language::Hy);

        assert_eq!(detect_language_from_tag("en"), Language::En);
        assert_eq!(detect_language_from_tag("en-US"), Language::En);
        assert_eq!(detect_language_from_tag("fr-FR"), Language::En);
        assert_eq!(detect_language_from_tag("de"), Language::En);
        assert_eq!(detect_language_from_tag(""), Language::En);
    }

    #[test]
    fn test_detect_system_language_env_override() {
        // Test SD_VIDEO_RECOVERY_LANG env variable precedence
        std::env::set_var("SD_VIDEO_RECOVERY_LANG", "hy-AM");
        assert_eq!(detect_system_language(), Language::Hy);

        std::env::set_var("SD_VIDEO_RECOVERY_LANG", "en-US");
        assert_eq!(detect_system_language(), Language::En);

        std::env::remove_var("SD_VIDEO_RECOVERY_LANG");
    }

    #[test]
    fn test_texts_completeness() {
        for lang in [Language::En, Language::Hy] {
            let t = texts(lang);
            assert_eq!(t.lang, lang);
            assert!(!t.app_name.is_empty());
            assert!(!t.app_description.is_empty());
            assert!(!t.help_text.is_empty());
            assert!(t.help_text.contains("list"));
            assert!(t.help_text.contains("doctor"));
            assert!(t.help_text.contains("recover"));
            assert!(t.help_text.contains("--disk"));
            assert!(t.help_text.contains("--output"));
            assert!(t.help_text.contains("--mode"));
            assert!(t.confirm_prompt_instruction.contains("{N}"));
            assert!(!t.confirm_mismatch_error.is_empty());
            assert!(!t.confirm_eof_error.is_empty());
            assert!(!t.safety_system_disk_refusal.is_empty());
            assert!(!t.safety_fixed_disk_refusal.is_empty());
            assert!(!t.safety_same_disk_refusal.is_empty());
            assert!(!t.safety_non_sd_usb_refusal.is_empty());
            assert!(!t.phase_filesystem_start.is_empty());
            assert!(!t.phase_deep_start.is_empty());
            assert!(!t.phase_validation_start.is_empty());
            assert!(!t.session_complete_summary.is_empty());
            assert_eq!(help_text(lang), t.help_text);
        }
    }
}
