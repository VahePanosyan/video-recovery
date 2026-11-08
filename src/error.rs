//! Error types and CLI exit code mapping for `sd-video-recovery`.

use thiserror::Error;

/// Standardized process exit codes defined by the CLI contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Scan completed (or `list`/`doctor` succeeded).
    Success = 0,
    /// Invalid CLI arguments or flags.
    InvalidArgs = 2,
    /// Safety or preflight check failed (system disk, non-removable without `--allow-fixed`,
    /// same-disk output, disk-ID confirmation mismatch, or output collision).
    SafetyPreflight = 3,
    /// Source device I/O failure.
    SourceIo = 4,
    /// External `ffprobe`/`ffmpeg` missing, unusable, or failed to execute.
    ExternalTool = 5,
    /// Interrupted by `Ctrl+C` (SIGINT).
    Interrupted = 130,
}

impl ExitCode {
    /// Numeric process exit code.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }
}

/// Top-level error type for recovery operations.
#[derive(Debug, Error)]
pub enum RecoveryError {
    /// Invalid CLI arguments (`exit 2`).
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    /// Safety or preflight check failed (`exit 3`).
    #[error("safety/preflight check failed: {0}")]
    SafetyPreflight(String),

    /// Source device I/O error with optional byte offset (`exit 4`).
    #[error("source I/O error at offset {offset:?}: {message}")]
    SourceIo {
        /// Byte offset on the source device where the read error occurred.
        offset: Option<u64>,
        /// Diagnostic description of the error.
        message: String,
    },

    /// Output filesystem I/O or serialization error (`exit 3`).
    #[error("output error: {0}")]
    OutputIo(String),

    /// External `ffprobe` or `ffmpeg` error (`exit 5`).
    #[error("external tool failure ({tool}): {message}")]
    ExternalTool {
        /// Tool name (`ffprobe` or `ffmpeg`).
        tool: String,
        /// Diagnostic description of the error.
        message: String,
    },

    /// Format or structure parsing error (non-fatal during scan, used in parsers).
    #[error("parse error: {0}")]
    Parse(String),

    /// Scan was interrupted via `Ctrl+C` (`exit 130`).
    #[error("operation interrupted by user (Ctrl+C)")]
    Interrupted,
}

impl RecoveryError {
    /// Maps this error to its contract [`ExitCode`].
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidArgs(_) => ExitCode::InvalidArgs,
            Self::SafetyPreflight(_) | Self::OutputIo(_) | Self::Parse(_) => {
                ExitCode::SafetyPreflight
            }
            Self::SourceIo { .. } => ExitCode::SourceIo,
            Self::ExternalTool { .. } => ExitCode::ExternalTool,
            Self::Interrupted => ExitCode::Interrupted,
        }
    }
}
