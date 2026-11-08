# AGENTS.md — Agent Guidelines for `sd-video-recovery`

This document defines architectural standards, safety invariants, workflow rules, and module boundaries for AI coding agents collaborating on the `sd-video-recovery` project.

---

## 1. Engineering Principles & Framework References

This project adheres to the engineering patterns and quality standards defined in the Everything Claude Code (ECC) and Superpowers skillsets:
- **Rust Implementation Standards**: Consult `plugins/ecc/skills/rust-patterns/SKILL.md` for idiomatic Rust, zero-cost abstractions, checked arithmetic, and error handling.
- **Rust Testing & Verification**: Follow `plugins/ecc/skills/rust-testing/SKILL.md` for unit tests, table-driven test cases, in-memory fault injection, and property testing (`proptest`).
- **Security & Preflight Hardening**: Apply `plugins/ecc/skills/security-review/SKILL.md` to prevent device write escalation, path traversal, command injection, and resource exhaustion.
- **Quality Gates & Evidence**: Follow `skills/unlazy/SKILL.md` (no placeholders, TODOs, or mock shortcuts) and `plugins/superpowers/skills/verification-before-completion/SKILL.md` (require fresh execution evidence before reporting completion).

> [!CAUTION]
> **Desktop Path Prohibition**: Never create, copy, or modify any files on `C:\Users\Vahe\Desktop` under any circumstances.

---

## 2. Non-Negotiable Safety Invariants

The primary purpose of `sd-video-recovery` is non-destructive data recovery from potentially fragile or corrupted SD cards. Any violation of these safety invariants is considered a critical defect:

1. **Strictly Read-Only Source Access**:
   - The physical device handle (`\\.\PhysicalDriveN`) must **always** be opened with `GENERIC_READ`, `FILE_SHARE_READ | FILE_SHARE_WRITE`, and `OPEN_EXISTING`.
   - Never request `GENERIC_WRITE`, write permissions, or issue write IOCTLs to the source device under any circumstances.
2. **Physical Disk Separation (Anti-Collision)**:
   - The destination directory where recovered files and reports are written must reside on a **different physical disk** than the source SD card.
   - The application must resolve the physical drive extent of the output volume and abort with exit code `3` if it shares the physical drive index with the source.
3. **Overwrite Prevention (`create_new`)**:
   - Destination files and session directories must use atomic creation semantics (`OpenOptions::new().write(true).create_new(true)`).
   - Existing files must never be overwritten, truncated, or modified in place.
4. **Isolated Extraction with Atomic Rename**:
   - In-flight file extractions must write to a temporary `.part` file (e.g. `cand-0001.MP4.part`).
   - Only after all extents are read without error and pass validation is the file atomically renamed to its final target name.
   - On cancellation (`Ctrl+C`), any in-progress `.part` file must be deleted immediately.
5. **Bounded Read Retries on Media Degradation**:
   - Perform at most **1 sector-level retry** upon encountering an I/O error.
   - If the retry fails, record the failing byte offset in the session report and gracefully terminate or isolate the failure. Never loop indefinitely or stress failing flash memory.
6. **No In-Place Filesystem or Disk Repair**:
   - Never invoke `chkdsk`, format utilities, partition editors, or repair routines on the source media.
7. **Development & Testing Safety**:
   - Never format, write to, or run destructive tests on a user's real SD card.
   - Destructive physical media tests (e.g. format verification) are only permitted on a dedicated sacrificial test card after explicit user confirmation of the exact physical disk number.

---

## 3. Architecture & Module Boundaries

The codebase is organized as a Rust library (`sd_video_recovery`) with an accompanying CLI binary (`sd-video-recovery`):

| Module | Responsibility | Key Invariants |
| :--- | :--- | :--- |
| `src/device.rs` | Windows physical drive enumeration (`\\.\PhysicalDriveN`), IOCTL queries (`IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`, `IOCTL_STORAGE_QUERY_PROPERTY`), bus type detection, system disk filtering, and output drive extent collision checks. | Strictly `GENERIC_READ` handles. Rejects system drive (`C:\`). Disallows fixed media unless `--allow-fixed` is explicitly provided. |
| `src/partition.rs` | Partition table detection and parsing for MBR, GPT, and unpartitioned "superfloppy" volumes. | Uses checked arithmetic for all sector/offset math to prevent integer overflow. |
| `src/fat32.rs` | FAT32 boot sector, directory entry parsing (including deleted entries with `0xE5` marker), cluster chain traversal, and contiguous fallback reconstruction. | Uses `hadris-fat-raw` codec structures in read-only mode. Never issues writes to FAT tables. |
| `src/exfat.rs` | exFAT volume parsing, InUse bitmap checks, stream extension entries, and `NoFatChain` contiguous flag handling per Microsoft exFAT specifications. | Bounded directory traversal; handles secondary directory entries safely. |
| `src/carver.rs` | Single sequential pass deep carver scanning for ISO-BMFF container boxes (`ftyp`, `mdat`, `moov`, `moof`). | Supports 32-bit and 64-bit box sizes; enforces strict box nesting depth limits; validates box bounds against disk boundary. |
| `src/validator.rs` | External tool runner for `ffprobe` (mandatory stream sanity validation) and `ffmpeg` (optional `--full-verify` frame-by-frame decode). | Invokes external processes via direct argument vectors (`std::process::Command`), never through a shell interpreter. |
| `src/extractor.rs` | Orchestrates candidate file dumping from physical extents to disk, atomic `.part` rename, deduplication (prioritizing filesystem metadata over raw carving), and single-sector retry handling. | Cleans up `.part` files on error or `Ctrl+C`. Guarantees byte integrity. |
| `src/report.rs` | Generates the session directory layout (`validated/`, `partial/`), structured `report.json` (v1 schema), and localized human-readable `summary.txt`. | Masked device serial numbers; stable versioned schema (`report_version: 1`). |
| `src/cli.rs` | Command-line argument parsing and interactive confirmation prompt before scan execution. | Prompts user to confirm physical disk number before reading if interactive. |
| `src/i18n.rs` | Localization subsystem providing English (`en`) and Armenian (`hy`) strings for all CLI output, error messages, and summary text. Defaults to Windows UI locale. | Complete parity between English and Armenian message catalogs. |
| `src/types.rs` | Core domain abstractions: `ReadSource`, `MemorySource`, `DeviceIdentity`, `Candidate`, `Extent`, `ScanMode`, `Confidence`, and `CandidateStatus`. | All slice and extent indexing strictly checked. |
| `src/error.rs` | Error hierarchy (`RecoveryError`) and contract-mandated process exit code mapping. | Stable mapping to standardized exit codes. |

---

## 4. Process Exit Codes

All tools and entry points must exit with one of the following standardized codes:

| Exit Code | Constant | Meaning |
| :---: | :--- | :--- |
| `0` | `ExitCode::Success` | Operation completed successfully (`recover` scan completed, `list` printed, or `doctor` passed). |
| `2` | `InvalidArgs` | Invalid command line arguments, flags, or syntax. |
| `3` | `SafetyPreflight` | Safety preflight check failed: target is system disk, internal/fixed disk without `--allow-fixed`, destination on same physical drive, confirmation mismatch, or output collision. |
| `4` | `SourceIo` | Persistent source I/O read failure after 1 sector retry. |
| `5` | `ExternalTool` | External dependency (`ffprobe` or `ffmpeg`) missing, invalid, or returned an unrecoverable failure. |
| `130` | `Interrupted` | User interrupted operation via `Ctrl+C` (SIGINT). |

---

## 5. Standard Verification Commands

Before submitting code, completing tasks, or opening pull requests, agents must execute and verify all of the following commands:

```bash
# 1. Code formatting check
cargo fmt --all -- --check

# 2. Strict linter check (zero warnings tolerated)
cargo clippy --all-targets -- -D warnings

# 3. Unit and integration test suite
cargo test

# 4. Code coverage (must maintain >= 80% line coverage)
cargo llvm-cov --fail-under-lines 80

# 5. Security vulnerability audit
cargo audit

# 6. License and dependency supply chain check
cargo deny check

# 7. Release build verification
cargo build --release --target x86_64-pc-windows-msvc
```
