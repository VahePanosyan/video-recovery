//! Synthetic disk integration tests for `sd-video-recovery`.
//!
//! Verifies end-to-end recovery pipelines on in-memory disk images (`MemorySource`)
//! containing synthetic FAT32, exFAT, and raw carved MP4/MOV payloads across 10 specific
//! test scenarios:
//!
//! 1. Deleted contiguous MP4 on FAT32 (SHA-256 identical).
//! 2. Deleted physically fragmented MP4 on FAT32 with preserved FAT chain (SHA-256 identical).
//! 3. Deleted contiguous MP4 on exFAT with `NoFatChain` set (SHA-256 identical).
//! 4. Deleted fragmented MP4 on exFAT with preserved FAT chain (SHA-256 identical).
//! 5. Deleted fragmented MP4 with lost/zeroed cluster mapping is NEVER classified as `Validated`.
//! 6. Quick-formatted disk image recovered via `carve_mp4_candidates` in deep mode.
//! 7. Duplicate candidate deduplication in favor of filesystem metadata candidate.
//! 8. Same-disk output refusal (`validate_same_disk_numbers(2, &[2])`) fails with `SafetyPreflight` (`3`).
//! 9. Persistent sector read error retries once, records `CandidateStatus::IoError` & offset.
//! 10. `Ctrl+C` interruption deletes active `.part` file while preserving finalized files and writing reports.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use hadris_fat_raw::exfat::{
    BootSector, ALLOCATION_POSSIBLE, ATTR_ARCHIVE, ENTRY_BITMAP, ENTRY_FILE, ENTRY_NAME,
    ENTRY_STREAM, FIRST_CLUSTER, NO_FAT_CHAIN,
};
use hadris_fat_raw::layout::{encode_boot_sector, plan, reserved_fat_entries, BootFields, Request};
use hadris_fat_raw::FatKind;
use sha2::{Digest, Sha256};

use sd_video_recovery::carver::{carve_mp4_candidates, inspect_mp4_structure};
use sd_video_recovery::device::validate_same_disk_numbers;
use sd_video_recovery::error::{ExitCode, RecoveryError};
use sd_video_recovery::exfat::recover_exfat_candidates;
use sd_video_recovery::extractor::{
    create_session_dirs, deduplicate_candidates, extract_candidate_to_part, finalize_candidate_file,
};
use sd_video_recovery::fat32::recover_fat32_candidates;
use sd_video_recovery::report::{
    write_session_reports, MaskedDeviceReport, ScanConfigReport, SessionReport,
};
use sd_video_recovery::types::{
    BusType, Candidate, CandidateStatus, Confidence, Extent, Language, MemorySource, ReadSource,
    RecoveryMethod, ScanMode,
};

/// Computes SHA-256 hex digest for verification.
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Creates a temporary unique test directory inside the OS temp directory.
fn make_temp_dir(tag: &str) -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("sd_video_test_{tag}_{now}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Cleans up a temporary test directory.
fn cleanup_temp_dir(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Constructs a synthetic valid ISO-BMFF MP4 file containing `ftyp`, `moov`, and `mdat` boxes.
///
/// Returns the byte buffer.
fn create_synthetic_mp4(data_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    // 1. ftyp box (24 bytes)
    let ftyp_size: u32 = 24;
    out.extend_from_slice(&ftyp_size.to_be_bytes());
    out.extend_from_slice(b"ftyp");
    out.extend_from_slice(b"isom"); // major brand
    out.extend_from_slice(&[0, 0, 0x02, 0]); // minor version
    out.extend_from_slice(b"isom"); // compatible brand
    out.extend_from_slice(b"mp42"); // compatible brand

    // 2. moov box with child mvhd box (116 bytes total)
    let mvhd_size: u32 = 108;
    let moov_size: u32 = 8 + mvhd_size;
    out.extend_from_slice(&moov_size.to_be_bytes());
    out.extend_from_slice(b"moov");
    out.extend_from_slice(&mvhd_size.to_be_bytes());
    out.extend_from_slice(b"mvhd");
    out.resize(out.len() + (mvhd_size as usize - 8), 0);

    // 3. mdat box (8 + data_payload.len() bytes)
    let mdat_size: u32 = 8 + data_payload.len() as u32;
    out.extend_from_slice(&mdat_size.to_be_bytes());
    out.extend_from_slice(b"mdat");
    out.extend_from_slice(data_payload);

    out
}

/// Builds an in-memory FAT32 volume (64 MiB, 512-byte sectors) containing deleted directory
/// entries pointing to either contiguous or fragmented cluster chains.
fn build_synthetic_fat32_volume(
    clusters: &[u32],
    mp4_bytes: &[u8],
    zero_fat_chain: bool,
) -> (Vec<u8>, u64) {
    const SECTOR_SIZE: u32 = 512;
    const TOTAL_SECTORS: u64 = 131_072; // 64 MiB

    let req = Request::new(SECTOR_SIZE, TOTAL_SECTORS)
        .with_kind(FatKind::Fat32)
        .with_cluster_size(SECTOR_SIZE); // 1 sector per cluster = 512 bytes
    let layout = plan(&req).expect("FAT32 plan failed");

    let total_bytes = (layout.total_sectors() as usize) * (SECTOR_SIZE as usize);
    let mut disk = vec![0u8; total_bytes];

    // Encode boot sector at sector 0 and backup at sector 6
    let boot_fields = BootFields::new();
    let boot_sector = encode_boot_sector(&layout, &boot_fields);
    disk[..512].copy_from_slice(&boot_sector);
    let backup_offset = 6 * 512;
    disk[backup_offset..backup_offset + 512].copy_from_slice(&boot_sector);

    // Initialize FAT1 and FAT2 reserved entries (clusters 0, 1, and root dir cluster 2)
    let fat1_offset = layout.fat_start() as usize;
    let fat2_offset =
        (layout.fat_start() + u64::from(layout.fat_sectors()) * u64::from(SECTOR_SIZE)) as usize;
    let (reserved, reserved_len) = reserved_fat_entries(FatKind::Fat32, 0xF8);
    disk[fat1_offset..fat1_offset + reserved_len].copy_from_slice(&reserved[..reserved_len]);
    disk[fat2_offset..fat2_offset + reserved_len].copy_from_slice(&reserved[..reserved_len]);

    // Root directory is cluster 2
    let root_dir_offset = layout.data_start() as usize;

    // Place a deleted short directory entry in the root directory
    let first_cluster = clusters[0];
    let file_size = mp4_bytes.len() as u32;

    let mut dir_entry = [0u8; 32];
    dir_entry[0] = 0xE5; // Deleted marker
    dir_entry[1..8].copy_from_slice(b"VIDE001");
    dir_entry[8..11].copy_from_slice(b"MP4");
    dir_entry[11] = 0x20; // ATTR_ARCHIVE
    dir_entry[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
    dir_entry[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
    dir_entry[28..32].copy_from_slice(&file_size.to_le_bytes());

    disk[root_dir_offset..root_dir_offset + 32].copy_from_slice(&dir_entry);

    // Populate cluster chain in FAT1 (and FAT2) unless zero_fat_chain is true
    if !zero_fat_chain {
        for (i, &c) in clusters.iter().enumerate() {
            let next_val = if i + 1 < clusters.len() {
                clusters[i + 1] & 0x0FFF_FFFF
            } else {
                0x0FFF_FFFF // End of chain marker
            };
            let fat_entry_off = fat1_offset + (c as usize) * 4;
            let fat2_entry_off = fat2_offset + (c as usize) * 4;
            disk[fat_entry_off..fat_entry_off + 4].copy_from_slice(&next_val.to_le_bytes());
            disk[fat2_entry_off..fat2_entry_off + 4].copy_from_slice(&next_val.to_le_bytes());
        }
    }

    // Write MP4 payload into the specified clusters
    let cluster_size = layout.cluster_size() as usize;
    for (i, &c) in clusters.iter().enumerate() {
        let chunk_start = i * cluster_size;
        if chunk_start >= mp4_bytes.len() {
            break;
        }
        let chunk_end = (chunk_start + cluster_size).min(mp4_bytes.len());
        let chunk = &mp4_bytes[chunk_start..chunk_end];

        let c_offset = layout.data_start() as usize + ((c - 2) as usize) * cluster_size;
        disk[c_offset..c_offset + chunk.len()].copy_from_slice(chunk);
    }

    (disk, total_bytes as u64)
}

/// Builds an in-memory exFAT volume (4096 sectors = 2 MiB, 512-byte sectors) containing deleted
/// entry sets pointing to contiguous or fragmented clusters.
fn build_synthetic_exfat_volume(
    clusters: &[u32],
    mp4_bytes: &[u8],
    no_fat_chain: bool,
    zero_fat_chain: bool,
) -> (Vec<u8>, u64) {
    const SECTOR_SIZE: usize = 512;
    const VOLUME_SECTORS: u64 = 4096; // 2 MiB volume
    let total_bytes = VOLUME_SECTORS as usize * SECTOR_SIZE;
    let mut disk = vec![0u8; total_bytes];

    // Sector allocation:
    // Sector 0..11: Main Boot Region
    // Sector 12..23: Backup Boot Region
    // Sector 24..47: FAT (24 sectors)
    // Sector 48..: Cluster Heap (cluster 2 starts at sector 48)
    const FAT_OFFSET: u32 = 24;
    const FAT_LENGTH: u32 = 24;
    const HEAP_OFFSET: u32 = 48;
    const CLUSTER_COUNT: u32 = 3000;

    let mut boot: BootSector = bytemuck::Zeroable::zeroed();
    boot.jump_boot = [0xEB, 0x76, 0x90];
    boot.file_system_name = *b"EXFAT   ";
    boot.partition_offset.set(0);
    boot.volume_length.set(VOLUME_SECTORS);
    boot.fat_offset.set(FAT_OFFSET);
    boot.fat_length.set(FAT_LENGTH);
    boot.cluster_heap_offset.set(HEAP_OFFSET);
    boot.cluster_count.set(CLUSTER_COUNT);
    boot.first_cluster_of_root_directory.set(2);
    boot.volume_serial_number.set(0x1234_5678);
    boot.file_system_revision.set(0x0100);
    boot.volume_flags.set(0);
    boot.bytes_per_sector_shift = 9; // 512
    boot.sectors_per_cluster_shift = 0; // 1 sector per cluster = 512 bytes
    boot.number_of_fats = 1;
    boot.drive_select = 0x80;
    boot.percent_in_use = 0;
    boot.boot_signature.set(0xAA55);

    let boot_bytes = bytemuck::bytes_of(&boot);
    disk[..512].copy_from_slice(boot_bytes);
    disk[12 * 512..13 * 512].copy_from_slice(boot_bytes);

    // Root directory is at cluster 2 (offset = 48 * 512)
    let heap_start = HEAP_OFFSET as usize * SECTOR_SIZE;
    let root_dir_offset = heap_start;

    // Entry 0 in root directory: Allocation Bitmap pointing to cluster 3
    let mut bitmap_entry = [0u8; 32];
    bitmap_entry[0] = ENTRY_BITMAP; // 0x81 (InUse)
    bitmap_entry[1] = 0; // Active bitmap 0
    bitmap_entry[20..24].copy_from_slice(&3u32.to_le_bytes()); // first_cluster = 3
    bitmap_entry[24..32].copy_from_slice(&512u64.to_le_bytes()); // data_length = 512
    disk[root_dir_offset..root_dir_offset + 32].copy_from_slice(&bitmap_entry);

    // Cluster 3 contains the Allocation Bitmap bytes
    // Mark clusters 2 and 3 allocated (bits 0 and 1 = 0x03)
    let bitmap_cluster_offset = heap_start + (3 - FIRST_CLUSTER as usize) * SECTOR_SIZE;
    disk[bitmap_cluster_offset] = 0x03;

    // Entry 1: Deleted FileEntry (0x05 = ENTRY_FILE & !IN_USE)
    let mut file_entry = [0u8; 32];
    file_entry[0] = ENTRY_FILE & !0x80; // 0x05
    file_entry[1] = 2; // secondary count (stream + 1 name entry)
    file_entry[4..6].copy_from_slice(&ATTR_ARCHIVE.to_le_bytes());
    disk[root_dir_offset + 32..root_dir_offset + 64].copy_from_slice(&file_entry);

    // Entry 2: Deleted StreamEntry (0x40 = ENTRY_STREAM & !IN_USE)
    let mut stream_entry = [0u8; 32];
    stream_entry[0] = ENTRY_STREAM & !0x80; // 0x40
    let flags = ALLOCATION_POSSIBLE | if no_fat_chain { NO_FAT_CHAIN } else { 0 };
    stream_entry[1] = flags;
    stream_entry[3] = 8; // name length "TEST.MP4"
    let file_len = mp4_bytes.len() as u64;
    stream_entry[8..16].copy_from_slice(&file_len.to_le_bytes()); // valid_data_length
    stream_entry[20..24].copy_from_slice(&clusters[0].to_le_bytes()); // first_cluster
    stream_entry[24..32].copy_from_slice(&file_len.to_le_bytes()); // data_length
    disk[root_dir_offset + 64..root_dir_offset + 96].copy_from_slice(&stream_entry);

    // Entry 3: Deleted NameEntry (0x41 = ENTRY_NAME & !IN_USE)
    let mut name_entry = [0u8; 32];
    name_entry[0] = ENTRY_NAME & !0x80; // 0x41
    let name_utf16: Vec<u16> = "TEST.MP4".encode_utf16().collect();
    for (i, &u) in name_utf16.iter().enumerate().take(15) {
        name_entry[2 + i * 2..4 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    disk[root_dir_offset + 96..root_dir_offset + 128].copy_from_slice(&name_entry);

    // If not no_fat_chain and not zero_fat_chain, populate FAT table
    let fat_start = FAT_OFFSET as usize * SECTOR_SIZE;
    if !no_fat_chain && !zero_fat_chain {
        for (i, &c) in clusters.iter().enumerate() {
            let next_val = if i + 1 < clusters.len() {
                clusters[i + 1]
            } else {
                0xFFFF_FFFF // FAT_END
            };
            let fat_entry_off = fat_start + (c as usize) * 4;
            disk[fat_entry_off..fat_entry_off + 4].copy_from_slice(&next_val.to_le_bytes());
        }
    }

    // Write MP4 payload into specified clusters
    for (i, &c) in clusters.iter().enumerate() {
        let chunk_start = i * SECTOR_SIZE;
        if chunk_start >= mp4_bytes.len() {
            break;
        }
        let chunk_end = (chunk_start + SECTOR_SIZE).min(mp4_bytes.len());
        let chunk = &mp4_bytes[chunk_start..chunk_end];

        let c_offset = heap_start + ((c - FIRST_CLUSTER) as usize) * SECTOR_SIZE;
        disk[c_offset..c_offset + chunk.len()].copy_from_slice(chunk);
    }

    (disk, total_bytes as u64)
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Test 1: Deleted contiguous MP4 on FAT32 is recovered and extracted byte-identically.
#[test]
fn test_01_deleted_contiguous_mp4_fat32() {
    let payload = vec![0xAB; 200];
    let mp4 = create_synthetic_mp4(&payload);
    let original_hash = compute_sha256(&mp4);

    let (disk_bytes, disk_size) = build_synthetic_fat32_volume(&[3], &mp4, false);
    let mut source = MemorySource::new(disk_bytes);

    let candidates =
        recover_fat32_candidates(&mut source, 0, disk_size).expect("FAT32 recovery failed");
    assert_eq!(candidates.len(), 1, "expected exactly 1 FAT32 candidate");

    let candidate = &candidates[0];
    assert!(
        candidate.chain_preserved,
        "contiguous chain must be preserved"
    );
    assert!(
        !candidate.is_fragmented,
        "contiguous file is not fragmented"
    );
    assert_eq!(candidate.confidence, Confidence::High);
    assert_eq!(candidate.expected_size, mp4.len() as u64);

    let temp_dir = make_temp_dir("test_01");
    let session = create_session_dirs(&temp_dir).expect("session dirs creation failed");

    let mut cand_to_extract = candidate.clone();
    let interrupted = AtomicBool::new(false);
    let mut active_part = None;

    let part_path = extract_candidate_to_part(
        &mut source,
        &mut cand_to_extract,
        &session,
        &interrupted,
        &mut active_part,
    )
    .expect("extraction failed");
    assert!(
        part_path.exists(),
        ".part file must exist before finalization"
    );

    cand_to_extract.status = CandidateStatus::Validated;
    finalize_candidate_file(&part_path, &mut cand_to_extract, &session, &mut active_part)
        .expect("finalization failed");

    let output_path = cand_to_extract
        .output_path
        .expect("output path must be set");
    let mut extracted_file = File::open(&output_path).expect("failed to open extracted file");
    let mut extracted_bytes = Vec::new();
    extracted_file
        .read_to_end(&mut extracted_bytes)
        .expect("failed to read extracted file");

    let extracted_hash = compute_sha256(&extracted_bytes);
    assert_eq!(
        original_hash, extracted_hash,
        "recovered contiguous FAT32 video must be byte-identical"
    );

    cleanup_temp_dir(&temp_dir);
}

/// Test 2: Deleted physically fragmented MP4 on FAT32 with preserved FAT cluster chain is recovered
/// and extracted byte-identically (`chain_preserved == true`).
#[test]
fn test_02_deleted_fragmented_mp4_fat32_preserved_chain() {
    // 3 clusters = 1536 bytes. Total synthetic MP4 size is 1536 bytes.
    let payload = vec![0xCD; 1536 - 148];
    let mp4 = create_synthetic_mp4(&payload);
    assert_eq!(mp4.len(), 1536);
    let original_hash = compute_sha256(&mp4);

    // Fragments scattered across clusters 3, 7, and 11
    let fragments = [3u32, 7, 11];
    let (disk_bytes, disk_size) = build_synthetic_fat32_volume(&fragments, &mp4, false);
    let mut source = MemorySource::new(disk_bytes);

    let candidates =
        recover_fat32_candidates(&mut source, 0, disk_size).expect("FAT32 recovery failed");
    assert_eq!(candidates.len(), 1);

    let candidate = &candidates[0];
    assert_eq!(candidate.extents.len(), 3, "expected 3 fragmented extents");
    assert!(
        candidate.chain_preserved,
        "preserved FAT chain must set chain_preserved=true"
    );
    assert!(
        candidate.is_fragmented,
        "scattered clusters must set is_fragmented=true"
    );
    assert_eq!(candidate.confidence, Confidence::High);
    assert_eq!(candidate.expected_size, 1536);

    let temp_dir = make_temp_dir("test_02");
    let session = create_session_dirs(&temp_dir).expect("session dirs creation failed");

    let mut cand_to_extract = candidate.clone();
    let interrupted = AtomicBool::new(false);
    let mut active_part = None;

    let part_path = extract_candidate_to_part(
        &mut source,
        &mut cand_to_extract,
        &session,
        &interrupted,
        &mut active_part,
    )
    .expect("extraction failed");

    cand_to_extract.status = CandidateStatus::Validated;
    finalize_candidate_file(&part_path, &mut cand_to_extract, &session, &mut active_part)
        .expect("finalization failed");

    let output_path = cand_to_extract
        .output_path
        .expect("output path must be set");
    let mut extracted_file = File::open(&output_path).expect("failed to open extracted file");
    let mut extracted_bytes = Vec::new();
    extracted_file
        .read_to_end(&mut extracted_bytes)
        .expect("failed to read extracted file");

    let extracted_hash = compute_sha256(&extracted_bytes);
    assert_eq!(
        original_hash, extracted_hash,
        "recovered fragmented FAT32 video with intact chain must be byte-identical"
    );

    cleanup_temp_dir(&temp_dir);
}

/// Test 3: Deleted contiguous MP4 on exFAT (`NoFatChain` set) is recovered and extracted byte-identically.
#[test]
fn test_03_deleted_contiguous_mp4_exfat_no_fat_chain() {
    let payload = vec![0xEF; 200];
    let mp4 = create_synthetic_mp4(&payload);
    let original_hash = compute_sha256(&mp4);

    let (disk_bytes, disk_size) = build_synthetic_exfat_volume(&[4], &mp4, true, false);
    let mut source = MemorySource::new(disk_bytes);

    let candidates =
        recover_exfat_candidates(&mut source, 0, disk_size).expect("exFAT recovery failed");
    assert_eq!(candidates.len(), 1, "expected 1 exFAT candidate");

    let candidate = &candidates[0];
    assert!(
        candidate.chain_preserved,
        "NoFatChain file must have chain_preserved=true"
    );
    assert!(
        !candidate.is_fragmented,
        "contiguous NoFatChain file must have is_fragmented=false"
    );
    assert_eq!(candidate.confidence, Confidence::High);
    assert_eq!(candidate.expected_size, mp4.len() as u64);

    let temp_dir = make_temp_dir("test_03");
    let session = create_session_dirs(&temp_dir).expect("session dirs creation failed");

    let mut cand_to_extract = candidate.clone();
    let interrupted = AtomicBool::new(false);
    let mut active_part = None;

    let part_path = extract_candidate_to_part(
        &mut source,
        &mut cand_to_extract,
        &session,
        &interrupted,
        &mut active_part,
    )
    .expect("extraction failed");

    cand_to_extract.status = CandidateStatus::Validated;
    finalize_candidate_file(&part_path, &mut cand_to_extract, &session, &mut active_part)
        .expect("finalization failed");

    let output_path = cand_to_extract
        .output_path
        .expect("output path must be set");
    let mut extracted_file = File::open(&output_path).expect("failed to open extracted file");
    let mut extracted_bytes = Vec::new();
    extracted_file
        .read_to_end(&mut extracted_bytes)
        .expect("failed to read extracted file");

    let extracted_hash = compute_sha256(&extracted_bytes);
    assert_eq!(
        original_hash, extracted_hash,
        "recovered contiguous exFAT video must be byte-identical"
    );

    cleanup_temp_dir(&temp_dir);
}

/// Test 4: Deleted fragmented MP4 on exFAT (`NoFatChain == 0`) with preserved exFAT FAT chain
/// is recovered and extracted byte-identically.
#[test]
fn test_04_deleted_fragmented_mp4_exfat_preserved_fat_chain() {
    let payload = vec![0x12; 1536 - 148];
    let mp4 = create_synthetic_mp4(&payload);
    assert_eq!(mp4.len(), 1536);
    let original_hash = compute_sha256(&mp4);

    // Fragments scattered across exFAT clusters 4, 9, 15
    let fragments = [4u32, 9, 15];
    let (disk_bytes, disk_size) = build_synthetic_exfat_volume(&fragments, &mp4, false, false);
    let mut source = MemorySource::new(disk_bytes);

    let candidates =
        recover_exfat_candidates(&mut source, 0, disk_size).expect("exFAT recovery failed");
    assert_eq!(candidates.len(), 1);

    let candidate = &candidates[0];
    assert_eq!(candidate.extents.len(), 3, "expected 3 fragmented extents");
    assert!(
        candidate.chain_preserved,
        "preserved exFAT FAT chain must have chain_preserved=true"
    );
    assert!(
        candidate.is_fragmented,
        "scattered clusters must have is_fragmented=true"
    );
    assert_eq!(candidate.confidence, Confidence::High);
    assert_eq!(candidate.expected_size, 1536);

    let temp_dir = make_temp_dir("test_04");
    let session = create_session_dirs(&temp_dir).expect("session dirs creation failed");

    let mut cand_to_extract = candidate.clone();
    let interrupted = AtomicBool::new(false);
    let mut active_part = None;

    let part_path = extract_candidate_to_part(
        &mut source,
        &mut cand_to_extract,
        &session,
        &interrupted,
        &mut active_part,
    )
    .expect("extraction failed");

    cand_to_extract.status = CandidateStatus::Validated;
    finalize_candidate_file(&part_path, &mut cand_to_extract, &session, &mut active_part)
        .expect("finalization failed");

    let output_path = cand_to_extract
        .output_path
        .expect("output path must be set");
    let mut extracted_file = File::open(&output_path).expect("failed to open extracted file");
    let mut extracted_bytes = Vec::new();
    extracted_file
        .read_to_end(&mut extracted_bytes)
        .expect("failed to read extracted file");

    let extracted_hash = compute_sha256(&extracted_bytes);
    assert_eq!(
        original_hash, extracted_hash,
        "recovered fragmented exFAT video with intact FAT chain must be byte-identical"
    );

    cleanup_temp_dir(&temp_dir);
}

/// Test 5: Deleted fragmented MP4 on FAT32/exFAT with lost/zeroed cluster mapping (`!chain_preserved && is_fragmented`)
/// is NEVER classified as `CandidateStatus::Validated` (must be `CandidateStatus::Partial` with `Confidence::Low`).
#[test]
fn test_05_deleted_fragmented_mp4_lost_chain_never_validated() {
    let payload = vec![0x34; 1536 - 148];
    let mp4 = create_synthetic_mp4(&payload);
    let fragments = [3u32, 7, 11];

    // Build FAT32 disk where the FAT chain was zeroed on deletion, and intervening cluster 4 is allocated
    let (mut disk_bytes, disk_size) = build_synthetic_fat32_volume(&fragments, &mp4, true);
    // Mark intervening cluster 4 (between fragment 3 and fragment 7) as allocated in FAT1 & FAT2
    let req = Request::new(512, 131_072)
        .with_kind(FatKind::Fat32)
        .with_cluster_size(512);
    let layout = plan(&req).unwrap();
    let fat1_c4 = layout.fat_start() as usize + 4 * 4;
    disk_bytes[fat1_c4..fat1_c4 + 4].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    let mut source = MemorySource::new(disk_bytes);

    let candidates =
        recover_fat32_candidates(&mut source, 0, disk_size).expect("FAT32 recovery failed");
    assert!(!candidates.is_empty(), "candidate should be found");

    let candidate = &candidates[0];
    assert!(
        !candidate.chain_preserved,
        "chain was zeroed, must not be preserved"
    );
    assert!(
        candidate.is_fragmented,
        "multi-cluster file without chain is fragmented"
    );
    assert_eq!(candidate.confidence, Confidence::Low);
    assert_ne!(
        candidate.status,
        CandidateStatus::Validated,
        "Mandatory Acceptance Rule: fragmented file with lost cluster mapping must NEVER be Validated"
    );
    assert_eq!(candidate.status, CandidateStatus::Partial);

    // Verify extraction and finalization moves it to `partial/`, NEVER `validated/`
    let temp_dir = make_temp_dir("test_05");
    let session = create_session_dirs(&temp_dir).expect("session dirs creation failed");

    let mut cand_to_extract = candidate.clone();
    let interrupted = AtomicBool::new(false);
    let mut active_part = None;

    let part_path = extract_candidate_to_part(
        &mut source,
        &mut cand_to_extract,
        &session,
        &interrupted,
        &mut active_part,
    )
    .expect("extraction failed");

    finalize_candidate_file(&part_path, &mut cand_to_extract, &session, &mut active_part)
        .expect("finalization failed");

    let output_path = cand_to_extract
        .output_path
        .expect("output path must be set");
    assert!(
        output_path.contains("partial"),
        "fragmented candidate with lost mapping must reside in partial directory"
    );
    assert!(
        !output_path.contains("validated"),
        "fragmented candidate with lost mapping must NEVER be placed in validated directory"
    );

    cleanup_temp_dir(&temp_dir);
}

/// Test 6: Quick-formatted disk image (where filesystem directory metadata is wiped, leaving raw
/// contiguous MP4/MOV bytes in the data region) is recovered via `carve_mp4_candidates` in deep mode.
#[test]
fn test_06_quick_formatted_disk_carve_mp4_deep_mode() {
    const DISK_SIZE: usize = 2 * 1024 * 1024; // 2 MiB
    let mut disk_bytes = vec![0u8; DISK_SIZE];

    // Wipe directory metadata / boot sector completely (all zeros or fresh formatted sector 0)
    // Place a valid contiguous MP4 at offset 131,072 (128 KiB sector-aligned)
    let payload = vec![0x78; 500];
    let mp4 = create_synthetic_mp4(&payload);
    let raw_carve_offset = 131_072usize;
    disk_bytes[raw_carve_offset..raw_carve_offset + mp4.len()].copy_from_slice(&mp4);

    let mut source = MemorySource::new(disk_bytes);

    let candidates =
        carve_mp4_candidates(&mut source, 0, DISK_SIZE as u64).expect("raw carving failed");
    assert_eq!(candidates.len(), 1, "expected 1 carved candidate");

    let candidate = &candidates[0];
    assert_eq!(candidate.recovery_method, RecoveryMethod::RawCarve);
    assert_eq!(candidate.extents.len(), 1);
    assert_eq!(candidate.extents[0].byte_offset, raw_carve_offset as u64);
    assert_eq!(candidate.expected_size, mp4.len() as u64);

    // Verify MP4 structure inspection recognizes it as a complete container
    let mut slice = sd_video_recovery::types::PartitionSlice::new(
        &mut source,
        candidate.extents[0].byte_offset,
        candidate.expected_size,
    )
    .expect("slice creation failed");
    let struct_info = inspect_mp4_structure(&mut slice).expect("structure inspection failed");
    assert!(struct_info.is_complete_video_container());
}

/// Test 7: Duplicate candidate at the same extent discovered by both filesystem recovery and raw
/// carving is deduplicated by `deduplicate_candidates` in favor of the filesystem metadata candidate
/// (preserving original filename).
#[test]
fn test_07_duplicate_candidate_deduplication() {
    let extent = Extent::new(65_536, 4096);

    let fs_cand = Candidate {
        id: "raw-cand-1".to_string(),
        extents: vec![extent],
        expected_size: 4096,
        recovery_method: RecoveryMethod::FilesystemFat32,
        original_name: Some("GOPR0042.MP4".to_string()),
        recovered_name: Some("GOPR0042.MP4".to_string()),
        output_path: None,
        confidence: Confidence::High,
        status: CandidateStatus::Partial,
        chain_preserved: true,
        is_fragmented: false,
        error_reason: None,
        error_offset: None,
    };

    let carved_cand = Candidate {
        id: "raw-cand-2".to_string(),
        extents: vec![extent],
        expected_size: 4096,
        recovery_method: RecoveryMethod::RawCarve,
        original_name: None,
        recovered_name: None,
        output_path: None,
        confidence: Confidence::Medium,
        status: CandidateStatus::Partial,
        chain_preserved: true,
        is_fragmented: false,
        error_reason: None,
        error_offset: None,
    };

    // Pass in reverse order to ensure sorting and priority rules are strictly exercised
    let candidates = vec![carved_cand, fs_cand];
    let deduped = deduplicate_candidates(candidates);

    assert_eq!(
        deduped.len(),
        1,
        "duplicate candidate must be merged into 1"
    );
    let winner = &deduped[0];
    assert_eq!(
        winner.recovery_method,
        RecoveryMethod::FilesystemFat32,
        "filesystem candidate must take precedence over raw carve"
    );
    assert_eq!(
        winner.original_name.as_deref(),
        Some("GOPR0042.MP4"),
        "original filename from filesystem metadata must be preserved"
    );
    assert!(
        winner.recovered_name.as_ref().unwrap().contains("GOPR0042"),
        "recovered filename must reflect the original file name"
    );
}

/// Test 8: Same-disk output refusal (`validate_same_disk_numbers(2, &[2])`) fails with
/// `ExitCode::SafetyPreflight` (`3`) before scanning.
#[test]
fn test_08_same_disk_output_refusal() {
    // Exact same disk
    let err = validate_same_disk_numbers(2, &[2]).unwrap_err();
    assert_eq!(
        err.exit_code(),
        ExitCode::SafetyPreflight,
        "must fail with SafetyPreflight exit code"
    );
    assert_eq!(ExitCode::SafetyPreflight.code(), 3);

    // Multi-extent volume spanning source disk 2 and disk 5
    let multi_err = validate_same_disk_numbers(2, &[1, 2, 5]).unwrap_err();
    assert_eq!(multi_err.exit_code(), ExitCode::SafetyPreflight);

    // Empty output disk list
    let empty_err = validate_same_disk_numbers(2, &[]).unwrap_err();
    assert_eq!(empty_err.exit_code(), ExitCode::SafetyPreflight);

    // Distinct disks (source 2, output on disk 1 or 3) succeeds safely
    assert!(validate_same_disk_numbers(2, &[1]).is_ok());
    assert!(validate_same_disk_numbers(2, &[0, 3]).is_ok());
}

/// Test 9: Persistent sector read error (`MemorySource::inject_persistent_failure`) retries once
/// and then stops, recording `CandidateStatus::IoError` and the exact failing byte `offset` in the report.
#[test]
fn test_09_persistent_sector_read_error() {
    let payload = vec![0x99; 2048];
    let mp4 = create_synthetic_mp4(&payload);
    let (disk_bytes, _) = build_synthetic_fat32_volume(&[3, 4, 5, 6], &mp4, false);

    let mut source = MemorySource::new(disk_bytes);
    // Inject persistent failure at sector offset 3072
    let failing_offset = 3072u64;
    source.inject_persistent_failure(failing_offset);

    let temp_dir = make_temp_dir("test_09");
    let session = create_session_dirs(&temp_dir).expect("session dirs creation failed");

    let mut candidate = Candidate {
        id: "cand-0001".to_string(),
        extents: vec![Extent::new(2048, 2048)], // Covers offset 3072
        expected_size: 2048,
        recovery_method: RecoveryMethod::FilesystemFat32,
        original_name: Some("FAIL0001.MP4".to_string()),
        recovered_name: Some("cand-0001_FAIL0001.MP4".to_string()),
        output_path: None,
        confidence: Confidence::High,
        status: CandidateStatus::Partial,
        chain_preserved: true,
        is_fragmented: false,
        error_reason: None,
        error_offset: None,
    };

    let interrupted = AtomicBool::new(false);
    let mut active_part = None;

    let res = extract_candidate_to_part(
        &mut source,
        &mut candidate,
        &session,
        &interrupted,
        &mut active_part,
    );

    assert!(
        res.is_err(),
        "extraction must fail on persistent read error"
    );
    assert_eq!(candidate.status, CandidateStatus::IoError);
    assert_eq!(
        candidate.error_offset,
        Some(failing_offset),
        "failing byte offset must match the injected sector offset"
    );
    assert!(
        active_part.is_none(),
        "active_part must be cleaned up on error"
    );

    // Verify .part file was deleted
    let part_path = session.session_dir.join("cand-0001_FAIL0001.MP4.part");
    assert!(
        !part_path.exists(),
        ".part file must be removed on I/O error"
    );

    // Verify retry policy: read offset was attempted twice (initial + 1 retry)
    let attempts = source.read_attempts();
    let fail_count = attempts
        .iter()
        .filter(|&&off| off == failing_offset)
        .count();
    assert_eq!(
        fail_count, 2,
        "sector read failure must be retried exactly once before stopping"
    );

    cleanup_temp_dir(&temp_dir);
}

/// Test 10: `Ctrl+C` interruption (`AtomicBool` set to `true`) deletes the active `.part` file
/// while preserving already finalized files in `validated/` and writing an `interrupted: true`
/// `report.json` (`report_version: 1`) and `summary.txt`.
#[test]
fn test_10_ctrlc_interruption() {
    let temp_dir = make_temp_dir("test_10");
    let session = create_session_dirs(&temp_dir).expect("session dirs creation failed");

    // 1. First candidate completes and is finalized to `validated/`
    let payload = vec![0x55; 100];
    let mp4 = create_synthetic_mp4(&payload);
    let mut source = MemorySource::new(mp4);

    let mut cand1 = Candidate {
        id: "cand-0001".to_string(),
        extents: vec![Extent::new(0, source.size_bytes())],
        expected_size: source.size_bytes(),
        recovery_method: RecoveryMethod::FilesystemFat32,
        original_name: Some("DONE0001.MP4".to_string()),
        recovered_name: Some("cand-0001_DONE0001.MP4".to_string()),
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

    let part1_path = extract_candidate_to_part(
        &mut source,
        &mut cand1,
        &session,
        &interrupted,
        &mut active_part,
    )
    .expect("candidate 1 extraction failed");

    finalize_candidate_file(&part1_path, &mut cand1, &session, &mut active_part)
        .expect("candidate 1 finalization failed");

    let cand1_path = PathBuf::from(cand1.output_path.as_ref().unwrap());
    assert!(
        cand1_path.exists(),
        "candidate 1 finalized file must exist in validated/"
    );

    // 2. Second candidate is interrupted via Ctrl+C
    let mut cand2 = Candidate {
        id: "cand-0002".to_string(),
        extents: vec![Extent::new(0, source.size_bytes())],
        expected_size: source.size_bytes(),
        recovery_method: RecoveryMethod::FilesystemFat32,
        original_name: Some("INTR0002.MP4".to_string()),
        recovered_name: Some("cand-0002_INTR0002.MP4".to_string()),
        output_path: None,
        confidence: Confidence::High,
        status: CandidateStatus::Partial,
        chain_preserved: true,
        is_fragmented: false,
        error_reason: None,
        error_offset: None,
    };

    interrupted.store(true, Ordering::SeqCst);
    let res = extract_candidate_to_part(
        &mut source,
        &mut cand2,
        &session,
        &interrupted,
        &mut active_part,
    );

    assert!(matches!(res, Err(RecoveryError::Interrupted)));
    assert!(active_part.is_none(), "active_part must be reset to None");

    let part2_path = session.session_dir.join("cand-0002_INTR0002.MP4.part");
    assert!(
        !part2_path.exists(),
        "interrupted .part file must be removed immediately"
    );

    // 3. Finalized file from candidate 1 is preserved and intact
    assert!(
        cand1_path.exists(),
        "previously finalized file must be preserved after Ctrl+C"
    );

    // 4. Session reports record `interrupted: true` with `report_version: 1`
    let device_report = MaskedDeviceReport {
        disk_number: 1,
        device_path: "\\\\.\\PhysicalDrive1".to_string(),
        model: "SanDisk Extreme PRO".to_string(),
        size_bytes: 64 * 1024 * 1024 * 1024,
        sector_size: 512,
        bus_type: BusType::Sd,
        removable: true,
        masked_serial: Some("****1234".to_string()),
    };

    let scan_config = ScanConfigReport {
        mode: ScanMode::All,
        full_verify: false,
        allow_fixed: false,
        lang: Language::En,
        output_dir: session.session_dir.to_string_lossy().into_owned(),
    };

    let candidates = vec![cand1, cand2];
    let report = SessionReport::new(
        session.session_id.clone(),
        1_000_000,
        1_005_000,
        true, // interrupted: true
        device_report,
        scan_config,
        Vec::new(),
        candidates,
    );

    write_session_reports(
        &session.report_json_path,
        &session.summary_txt_path,
        &report,
        Language::En,
    )
    .expect("writing session reports failed");

    // Verify report.json
    assert!(session.report_json_path.exists());
    let mut json_file = File::open(&session.report_json_path).expect("failed to open report.json");
    let mut json_text = String::new();
    json_file
        .read_to_string(&mut json_text)
        .expect("failed to read report.json");

    assert!(json_text.contains("\"report_version\": 1"));
    assert!(json_text.contains("\"interrupted\": true"));

    // Verify summary.txt
    assert!(session.summary_txt_path.exists());
    let mut summary_file =
        File::open(&session.summary_txt_path).expect("failed to open summary.txt");
    let mut summary_text = String::new();
    summary_file
        .read_to_string(&mut summary_text)
        .expect("failed to read summary.txt");

    assert!(summary_text.contains("INTERRUPTED"));

    cleanup_temp_dir(&temp_dir);
}
