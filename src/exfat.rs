//! exFAT deleted entry set, allocation bitmap, and NoFatChain recovery.
//!
//! Implements Microsoft exFAT file system recovery using pinned `hadris-fat-raw` 0.3.0
//! codecs and layouts. Supports:
//! - Main and backup boot sector parsing (sector 0 fallback to sector 12)
//! - Active Allocation Bitmap discovery and bitmask checking
//! - Root and subdirectory traversal (up to depth 16 and 4096 visited directories)
//! - Deleted entry sets (`InUse` bit 0x80 cleared on File, Stream, and Name entries)
//! - Contiguous `NoFatChain` recovery with Allocation Bitmap overwrite protection
//! - Preserved exFAT FAT chain traversal (including physically fragmented files)
//! - Zeroed FAT chain fallback to safe contiguous unallocated extent (flagged as non-preserved)
//! - Cycle detection via [`ChainGuard`]

use std::collections::{HashSet, VecDeque};

use bytemuck::pod_read_unaligned;
use hadris_fat_raw::exfat::{
    parse_boot, BootSector, FileEntry, Geometry, NameEntry, StreamEntry, ATTR_DIRECTORY,
    ENTRY_BITMAP, ENTRY_END, ENTRY_FILE, ENTRY_NAME, ENTRY_SIZE, ENTRY_STREAM, FAT_BAD, FAT_END,
    FIRST_CLUSTER, IN_USE, MAX_SET, NO_FAT_CHAIN,
};
use hadris_fat_raw::ChainGuard;

use crate::error::RecoveryError;
use crate::types::{
    Candidate, CandidateStatus, Confidence, Extent, PartitionSlice, ReadSource, RecoveryMethod,
};

/// Maximum directory bytes loaded into memory per directory (16 MiB).
const MAX_DIRECTORY_BYTES: usize = 16 * 1024 * 1024;

/// Maximum Allocation Bitmap bytes loaded into memory (16 MiB).
const MAX_BITMAP_BYTES: usize = 16 * 1024 * 1024;

/// Maximum recursion depth for subdirectory traversal.
const MAX_RECURSION_DEPTH: usize = 16;

/// Maximum number of visited directory clusters to prevent infinite loops.
const MAX_VISITED_DIRECTORIES: usize = 4096;

/// Checks whether a cluster is currently marked allocated (`1`) in the exFAT Allocation Bitmap.
///
/// In the exFAT specification:
/// - Cluster 2 (`FIRST_CLUSTER`) maps to bit 0 of byte 0.
/// - For any `cluster >= FIRST_CLUSTER`, the bit index is `(cluster - FIRST_CLUSTER)`.
/// - A bit value of `1` means the cluster is allocated; `0` means it is unallocated / free.
#[must_use]
pub fn is_cluster_allocated_in_bitmap(bitmap: &[u8], cluster: u32) -> bool {
    if cluster < FIRST_CLUSTER {
        return false;
    }
    let bit_idx = (cluster - FIRST_CLUSTER) as usize;
    let byte_idx = bit_idx / 8;
    let bit_mask = 1u8 << (bit_idx % 8);
    if byte_idx < bitmap.len() {
        (bitmap[byte_idx] & bit_mask) != 0
    } else {
        false
    }
}

/// Reads a 32-bit FAT entry for `cluster` from the active FAT table.
fn read_fat_entry<R: ReadSource + ?Sized>(
    slice: &mut PartitionSlice<'_, R>,
    geo: &Geometry,
    cluster: u32,
) -> Result<u32, RecoveryError> {
    let offset = geo
        .fat_start()
        .checked_add(u64::from(cluster).checked_mul(4).ok_or_else(|| {
            RecoveryError::Parse("FAT entry offset arithmetic overflow".to_string())
        })?)
        .ok_or_else(|| RecoveryError::Parse("FAT entry offset overflow".to_string()))?;
    let mut buf = [0u8; 4];
    slice.read_exact_at(offset, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Reads the raw directory entry bytes for a directory starting at `first_cluster`.
///
/// Stops if `ENTRY_END` (`0x00`) is encountered, if max bytes is reached,
/// or if a broken/cyclic chain is detected.
fn read_directory_bytes<R: ReadSource + ?Sized>(
    slice: &mut PartitionSlice<'_, R>,
    geo: &Geometry,
    first_cluster: u32,
    no_fat_chain: bool,
    max_bytes: usize,
) -> Result<Vec<u8>, RecoveryError> {
    if !geo.is_cluster(first_cluster) {
        return Ok(Vec::new());
    }

    let cluster_size = geo.cluster_size() as usize;
    let mut dir_bytes = Vec::new();
    let mut current_cluster = first_cluster;
    let mut guard = ChainGuard::new(first_cluster);

    loop {
        if dir_bytes.len() >= max_bytes {
            break;
        }

        let Some(cluster_offset) = geo.cluster_offset(current_cluster) else {
            break;
        };

        let to_read = cluster_size.min(max_bytes - dir_bytes.len());
        let mut cluster_buf = vec![0u8; to_read];
        if slice
            .read_exact_at(cluster_offset, &mut cluster_buf)
            .is_err()
        {
            break;
        }

        let mut hit_end = false;
        for chunk in cluster_buf.as_chunks::<ENTRY_SIZE>().0 {
            if chunk[0] == ENTRY_END {
                hit_end = true;
                break;
            }
        }

        dir_bytes.extend_from_slice(&cluster_buf);

        if hit_end {
            break;
        }

        if no_fat_chain {
            let next = current_cluster.wrapping_add(1);
            if !geo.is_cluster(next) {
                break;
            }
            current_cluster = next;
        } else {
            match read_fat_entry(slice, geo, current_cluster) {
                Ok(next) => {
                    if next == FAT_END || !geo.is_cluster(next) || !guard.step(next) {
                        break;
                    }
                    current_cluster = next;
                }
                Err(_) => break,
            }
        }
    }

    Ok(dir_bytes)
}

/// Checks whether a file matches video filename extensions or begins with an ISO-BMFF box header.
fn is_video_file<R: ReadSource + ?Sized>(
    slice: &mut PartitionSlice<'_, R>,
    geo: &Geometry,
    filename: &str,
    first_cluster: u32,
) -> bool {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".mp4")
        || lower.ends_with(".mov")
        || lower.ends_with(".m4v")
        || lower.ends_with(".3gp")
    {
        return true;
    }
    has_isobmff_box_header(slice, geo, first_cluster)
}

/// Checks whether the first cluster begins with an ISO-BMFF box header (`ftyp`, `moov`, `mdat`).
fn has_isobmff_box_header<R: ReadSource + ?Sized>(
    slice: &mut PartitionSlice<'_, R>,
    geo: &Geometry,
    first_cluster: u32,
) -> bool {
    let Some(cluster_offset) = geo.cluster_offset(first_cluster) else {
        return false;
    };
    let mut header = [0u8; 16];
    if slice.read_exact_at(cluster_offset, &mut header).is_err() {
        return false;
    }
    let box_type = &header[4..8];
    box_type == b"ftyp" || box_type == b"moov" || box_type == b"mdat"
}

/// Coalesces a slice of clusters into contiguous `Extent` runs up to `data_length` bytes.
fn clusters_to_extents(
    clusters: &[u32],
    data_length: u64,
    cluster_size: u64,
    partition_offset: u64,
    geo: &Geometry,
) -> Vec<Extent> {
    if clusters.is_empty() || data_length == 0 {
        return Vec::new();
    }

    let mut runs: Vec<(u32, u64)> = Vec::new();
    for &c in clusters {
        if let Some(last) = runs.last_mut() {
            if last.0.checked_add(last.1 as u32) == Some(c) {
                last.1 += 1;
                continue;
            }
        }
        runs.push((c, 1));
    }

    let mut extents = Vec::new();
    let mut remaining = data_length;
    for (start_c, count) in runs {
        if remaining == 0 {
            break;
        }
        let Some(c_offset) = geo.cluster_offset(start_c) else {
            break;
        };
        let run_bytes = count.saturating_mul(cluster_size).min(remaining);
        if run_bytes > 0 {
            extents.push(Extent::new(partition_offset + c_offset, run_bytes));
            remaining -= run_bytes;
        }
    }
    extents
}

/// Evaluates a deleted video file entry set, allocating safe extents and computing confidence.
#[allow(clippy::too_many_arguments)]
fn process_candidate<R: ReadSource + ?Sized>(
    slice: &mut PartitionSlice<'_, R>,
    geo: &Geometry,
    bitmap: &[u8],
    partition_offset: u64,
    cand_counter: usize,
    filename: String,
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
) -> Option<Candidate> {
    let cluster_size = geo.cluster_size();
    if cluster_size == 0 || data_length == 0 {
        return None;
    }
    let expected_clusters = data_length.div_ceil(cluster_size) as u32;

    let orig_name = if filename.is_empty() {
        None
    } else {
        Some(filename.clone())
    };
    let display_name = if filename.is_empty() {
        "recovered.mp4".to_string()
    } else {
        filename
    };
    let id = format!("cand-{cand_counter:04}");
    let recovered_name = Some(format!("{id}_{display_name}"));

    if no_fat_chain || expected_clusters == 1 {
        // Case A: NoFatChain == true (or expected_clusters == 1).
        // Contiguous allocation; FAT table is not used.
        let mut unallocated_count = 0u32;
        for c_idx in 0..expected_clusters {
            let Some(c) = first_cluster.checked_add(c_idx) else {
                break;
            };
            if !geo.is_cluster(c) || is_cluster_allocated_in_bitmap(bitmap, c) {
                break;
            }
            unallocated_count += 1;
        }

        if unallocated_count == expected_clusters {
            let c_offset = geo.cluster_offset(first_cluster)?;
            let extents = vec![Extent::new(partition_offset + c_offset, data_length)];
            Some(Candidate {
                id,
                extents,
                expected_size: data_length,
                recovery_method: RecoveryMethod::FilesystemExFat,
                original_name: orig_name,
                recovered_name,
                output_path: None,
                confidence: Confidence::High,
                status: CandidateStatus::Partial,
                chain_preserved: true,
                is_fragmented: false,
                error_reason: None,
                error_offset: None,
            })
        } else if unallocated_count > 0 {
            // Truncated safe prefix.
            let c_offset = geo.cluster_offset(first_cluster)?;
            let safe_bytes = (u64::from(unallocated_count) * cluster_size).min(data_length);
            let extents = vec![Extent::new(partition_offset + c_offset, safe_bytes)];
            Some(Candidate {
                id,
                extents,
                expected_size: data_length,
                recovery_method: RecoveryMethod::FilesystemExFat,
                original_name: orig_name,
                recovered_name,
                output_path: None,
                confidence: Confidence::Low,
                status: CandidateStatus::Partial,
                chain_preserved: false,
                is_fragmented: true,
                error_reason: Some(format!(
                    "truncated: only {unallocated_count} of {expected_clusters} clusters unallocated in bitmap"
                )),
                error_offset: None,
            })
        } else {
            None
        }
    } else {
        // Case B: no_fat_chain == false && expected_clusters > 1.
        let stored = read_fat_entry(slice, geo, first_cluster).unwrap_or(0);
        if stored != 0 {
            // Subcase B1: FAT entry is non-zero (intact or partial chain).
            let mut clusters = vec![first_cluster];
            let mut guard = ChainGuard::new(first_cluster);
            let mut cur_cluster = first_cluster;
            let mut chain_broken = is_cluster_allocated_in_bitmap(bitmap, first_cluster);

            while clusters.len() < expected_clusters as usize && !chain_broken {
                let next = match read_fat_entry(slice, geo, cur_cluster) {
                    Ok(val) => val,
                    Err(_) => {
                        chain_broken = true;
                        break;
                    }
                };
                if next == FAT_END {
                    break;
                }
                if next == FAT_BAD || !geo.is_cluster(next) || !guard.step(next) {
                    chain_broken = true;
                    break;
                }
                if is_cluster_allocated_in_bitmap(bitmap, next) {
                    chain_broken = true;
                    break;
                }
                clusters.push(next);
                cur_cluster = next;
            }

            let intact = !chain_broken && clusters.len() == expected_clusters as usize;
            let extents =
                clusters_to_extents(&clusters, data_length, cluster_size, partition_offset, geo);
            if extents.is_empty() {
                return None;
            }
            let is_frag = extents.len() > 1;

            if intact {
                Some(Candidate {
                    id,
                    extents,
                    expected_size: data_length,
                    recovery_method: RecoveryMethod::FilesystemExFat,
                    original_name: orig_name,
                    recovered_name,
                    output_path: None,
                    confidence: Confidence::High,
                    status: CandidateStatus::Partial,
                    chain_preserved: true,
                    is_fragmented: is_frag,
                    error_reason: None,
                    error_offset: None,
                })
            } else {
                Some(Candidate {
                    id,
                    extents,
                    expected_size: data_length,
                    recovery_method: RecoveryMethod::FilesystemExFat,
                    original_name: orig_name,
                    recovered_name,
                    output_path: None,
                    confidence: Confidence::Low,
                    status: CandidateStatus::Partial,
                    chain_preserved: false,
                    is_fragmented: true,
                    error_reason: Some("broken, cyclic, or truncated FAT chain".to_string()),
                    error_offset: None,
                })
            }
        } else {
            // Subcase B2: FAT entry was zeroed on deletion.
            // Since NoFatChain was false, cluster mapping was lost; attempt contiguous safe fallback.
            let mut unallocated_count = 0u32;
            for c_idx in 0..expected_clusters {
                let Some(c) = first_cluster.checked_add(c_idx) else {
                    break;
                };
                if !geo.is_cluster(c) || is_cluster_allocated_in_bitmap(bitmap, c) {
                    break;
                }
                unallocated_count += 1;
            }

            if unallocated_count > 0 {
                let safe_bytes = (u64::from(unallocated_count) * cluster_size).min(data_length);
                let c_offset = geo.cluster_offset(first_cluster)?;
                let extents = vec![Extent::new(partition_offset + c_offset, safe_bytes)];
                Some(Candidate {
                    id,
                    extents,
                    expected_size: data_length,
                    recovery_method: RecoveryMethod::FilesystemExFat,
                    original_name: orig_name,
                    recovered_name,
                    output_path: None,
                    confidence: Confidence::Low,
                    status: CandidateStatus::Partial,
                    chain_preserved: false,
                    is_fragmented: true,
                    error_reason: Some(
                        "FAT chain zeroed on deletion for non-contiguous file; assumed contiguous extent"
                            .to_string(),
                    ),
                    error_offset: None,
                })
            } else {
                None
            }
        }
    }
}

/// Recovers deleted video file candidates from an exFAT partition.
///
/// Wraps `source` in a [`PartitionSlice`], parses the exFAT boot sector (with fallback to
/// sector 12 backup boot sector), loads the active Allocation Bitmap, and recursively traverses
/// directories up to depth 16 to find deleted video files.
///
/// # Errors
///
/// Returns [`RecoveryError::Parse`] if the boot sector and backup boot sector cannot be parsed,
/// or if partition boundaries are invalid. Returns [`RecoveryError::SourceIo`] on I/O failure.
pub fn recover_exfat_candidates<R: ReadSource + ?Sized>(
    source: &mut R,
    partition_offset: u64,
    partition_len: u64,
) -> Result<Vec<Candidate>, RecoveryError> {
    let mut slice = PartitionSlice::new(source, partition_offset, partition_len)?;

    // 1. Read Main Boot Sector at offset 0 (512 bytes)
    let mut boot_buf = [0u8; 512];
    let geo_res = slice
        .read_exact_at(0, &mut boot_buf)
        .map_err(|e| e.to_string())
        .and_then(|()| {
            let boot: BootSector = pod_read_unaligned(&boot_buf);
            parse_boot(&boot).map_err(|field| format!("invalid boot sector field: {field}"))
        });

    let geo = match geo_res {
        Ok(geo) => geo,
        Err(main_err) => {
            // Main Boot Sector failed; try Backup Boot Sector at sector 12
            let try_offsets = [12u64 * 512, 12u64 * u64::from(slice.sector_size())];
            let mut backup_geo = None;
            for &offset in &try_offsets {
                if offset + 512 <= slice.size_bytes()
                    && slice.read_exact_at(offset, &mut boot_buf).is_ok()
                {
                    let boot: BootSector = pod_read_unaligned(&boot_buf);
                    if let Ok(geo) = parse_boot(&boot) {
                        backup_geo = Some(geo);
                        break;
                    }
                }
            }
            backup_geo.ok_or_else(|| {
                RecoveryError::Parse(format!(
                    "failed to parse exFAT boot sector ({main_err}) and backup boot sector at sector 12"
                ))
            })?
        }
    };

    if geo.heap_start() >= partition_len {
        return Err(RecoveryError::Parse(format!(
            "exFAT cluster heap start {} exceeds partition length {partition_len}",
            geo.heap_start()
        )));
    }

    // 2. Read Root Directory and load active Allocation Bitmap
    let root_fat = read_fat_entry(&mut slice, &geo, geo.root()).unwrap_or(0);
    let root_no_fat_chain = root_fat == 0;
    let root_bytes = read_directory_bytes(
        &mut slice,
        &geo,
        geo.root(),
        root_no_fat_chain,
        MAX_DIRECTORY_BYTES,
    )?;

    // Locate active Allocation Bitmap in Root Directory
    let mut bitmap_info = None;
    for slot in root_bytes.as_chunks::<ENTRY_SIZE>().0 {
        if slot[0] == ENTRY_BITMAP {
            let entry: hadris_fat_raw::exfat::BitmapEntry = pod_read_unaligned(slot);
            if (entry.bitmap_flags & 1) == geo.active() {
                bitmap_info = Some((entry.first_cluster.get(), entry.data_length.get()));
                break;
            }
        }
    }

    let mut allocation_bitmap = Vec::new();
    if let Some((bitmap_first_cluster, bitmap_len)) = bitmap_info {
        if geo.is_cluster(bitmap_first_cluster) {
            let max_read = (bitmap_len as usize).min(MAX_BITMAP_BYTES);
            if let Some(bitmap_offset) = geo.cluster_offset(bitmap_first_cluster) {
                let mut buf = vec![0u8; max_read];
                if let Ok(n) = slice.read_at(bitmap_offset, &mut buf) {
                    buf.truncate(n);
                    allocation_bitmap = buf;
                }
            }
        }
    }

    // 3. Directory Traversal & Deleted Entry-Set Parsing
    let mut candidates = Vec::new();
    let mut cand_counter = 1usize;
    let mut visited_dirs = HashSet::new();
    let mut queue = VecDeque::new();

    visited_dirs.insert(geo.root());
    queue.push_back((geo.root(), root_no_fat_chain, 0usize, Some(root_bytes)));

    while let Some((dir_cluster, dir_no_fat_chain, depth, preloaded_bytes)) = queue.pop_front() {
        let dir_bytes = match preloaded_bytes {
            Some(b) => b,
            None => read_directory_bytes(
                &mut slice,
                &geo,
                dir_cluster,
                dir_no_fat_chain,
                MAX_DIRECTORY_BYTES,
            )?,
        };

        let slots = dir_bytes.as_chunks::<ENTRY_SIZE>().0;
        let mut i = 0;
        while i < slots.len() {
            let slot = &slots[i];
            let entry_type = slot[0];

            if entry_type == ENTRY_END {
                break;
            }

            let is_active_file = entry_type == ENTRY_FILE;
            let is_deleted_file = entry_type == (ENTRY_FILE & !IN_USE);

            if is_active_file || is_deleted_file {
                let file_entry: FileEntry = pod_read_unaligned(slot);
                let secondary_count = file_entry.secondary_count as usize;

                if (2..=18).contains(&secondary_count)
                    && secondary_count < MAX_SET
                    && i + 1 + secondary_count <= slots.len()
                {
                    let stream_slot = &slots[i + 1];
                    let stream_type = stream_slot[0];
                    let is_active_stream = stream_type == ENTRY_STREAM;
                    let is_deleted_stream = stream_type == (ENTRY_STREAM & !IN_USE);

                    let stream_valid = if is_deleted_file {
                        is_deleted_stream || is_active_stream
                    } else {
                        is_active_stream
                    };

                    if stream_valid {
                        let stream_entry: StreamEntry = pod_read_unaligned(stream_slot);
                        let is_directory = (file_entry.file_attributes.get() & ATTR_DIRECTORY) != 0;
                        let stream_first_cluster = stream_entry.first_cluster.get();
                        let stream_no_fat =
                            (stream_entry.general_secondary_flags & NO_FAT_CHAIN) != 0;

                        if is_directory {
                            if geo.is_cluster(stream_first_cluster)
                                && depth < MAX_RECURSION_DEPTH
                                && visited_dirs.len() < MAX_VISITED_DIRECTORIES
                                && visited_dirs.insert(stream_first_cluster)
                            {
                                queue.push_back((
                                    stream_first_cluster,
                                    stream_no_fat,
                                    depth + 1,
                                    None,
                                ));
                            }
                        } else if is_deleted_file {
                            let name_units_count = stream_entry.name_length as usize;
                            let mut utf16_units = Vec::with_capacity(name_units_count);
                            for k in 0..(secondary_count - 1) {
                                let name_slot = &slots[i + 2 + k];
                                let name_type = name_slot[0];
                                if name_type == ENTRY_NAME || name_type == (ENTRY_NAME & !IN_USE) {
                                    let name_entry: NameEntry = pod_read_unaligned(name_slot);
                                    for u in &name_entry.file_name {
                                        if utf16_units.len() < name_units_count {
                                            utf16_units.push(u.get());
                                        }
                                    }
                                }
                            }

                            let raw_filename: String = char::decode_utf16(utf16_units)
                                .map(|r| r.unwrap_or('\u{FFFD}'))
                                .collect();
                            let filename = raw_filename.trim().to_string();

                            let raw_data_len = stream_entry.data_length.get();
                            let valid_data_len = stream_entry.valid_data_length.get();
                            let data_length =
                                if valid_data_len > 0 && valid_data_len <= raw_data_len {
                                    valid_data_len
                                } else {
                                    raw_data_len
                                };

                            if data_length > 0
                                && geo.is_cluster(stream_first_cluster)
                                && is_video_file(&mut slice, &geo, &filename, stream_first_cluster)
                            {
                                if let Some(candidate) = process_candidate(
                                    &mut slice,
                                    &geo,
                                    &allocation_bitmap,
                                    partition_offset,
                                    cand_counter,
                                    filename,
                                    stream_first_cluster,
                                    data_length,
                                    stream_no_fat,
                                ) {
                                    candidates.push(candidate);
                                    cand_counter += 1;
                                }
                            }
                        }

                        i += 1 + secondary_count;
                        continue;
                    }
                }
            }

            i += 1;
        }
    }

    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MemorySource;
    use hadris_fat_raw::exfat::{ALLOCATION_POSSIBLE, ATTR_ARCHIVE};

    /// Helper struct for building in-memory exFAT filesystem images for unit testing.
    struct TestImageBuilder {
        data: Vec<u8>,
        fat_offset_bytes: usize,
        heap_offset_bytes: usize,
        root_offset_bytes: usize,
        bitmap_offset_bytes: usize,
    }

    impl TestImageBuilder {
        /// Creates a valid synthetic 2 MiB exFAT image (512-byte sectors, 512-byte clusters).
        fn new() -> Self {
            let total_sectors = 4096u64;
            let sector_size = 512usize;
            let mut data = vec![0u8; (total_sectors as usize) * sector_size];

            let fat_sector = 24u32;
            let fat_len_sectors = 32u32;
            let heap_sector = 64u32;
            let cluster_count = 1000u32;
            let root_cluster = 2u32;
            let bitmap_cluster = 3u32;

            // 1. Construct Main Boot Sector at sector 0
            let mut boot = [0u8; 512];
            boot[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]); // JumpBoot
            boot[3..11].copy_from_slice(b"EXFAT   "); // FileSystemName
            boot[72..80].copy_from_slice(&total_sectors.to_le_bytes()); // VolumeLength
            boot[80..84].copy_from_slice(&fat_sector.to_le_bytes()); // FatOffset
            boot[84..88].copy_from_slice(&fat_len_sectors.to_le_bytes()); // FatLength
            boot[88..92].copy_from_slice(&heap_sector.to_le_bytes()); // ClusterHeapOffset
            boot[92..96].copy_from_slice(&cluster_count.to_le_bytes()); // ClusterCount
            boot[96..100].copy_from_slice(&root_cluster.to_le_bytes()); // FirstClusterOfRootDirectory
            boot[100..104].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // VolumeSerialNumber
            boot[104..106].copy_from_slice(&0x0100u16.to_le_bytes()); // FileSystemRevision (1.0)
            boot[106..108].copy_from_slice(&0u16.to_le_bytes()); // VolumeFlags
            boot[108] = 9; // BytesPerSectorShift (2^9 = 512)
            boot[109] = 0; // SectorsPerClusterShift (2^0 = 1 sector per cluster)
            boot[110] = 1; // NumberOfFats
            boot[111] = 0x80; // DriveSelect
            boot[112] = 0xFF; // PercentInUse
            boot[510..512].copy_from_slice(&0xAA55u16.to_le_bytes()); // BootSignature

            data[0..512].copy_from_slice(&boot);

            // 2. Construct Backup Boot Sector at sector 12
            data[12 * 512..13 * 512].copy_from_slice(&boot);

            let fat_offset_bytes = (fat_sector as usize) * sector_size;
            let heap_offset_bytes = (heap_sector as usize) * sector_size;
            let root_offset_bytes = heap_offset_bytes; // cluster 2
            let bitmap_offset_bytes = heap_offset_bytes + sector_size; // cluster 3

            // 3. Initialize FAT table media header and system clusters
            data[fat_offset_bytes..fat_offset_bytes + 4]
                .copy_from_slice(&0xFFFF_FFF8u32.to_le_bytes()); // media type
            data[fat_offset_bytes + 4..fat_offset_bytes + 8]
                .copy_from_slice(&FAT_END.to_le_bytes()); // cluster 1
            data[fat_offset_bytes + 8..fat_offset_bytes + 12]
                .copy_from_slice(&FAT_END.to_le_bytes()); // cluster 2 (root dir)
            data[fat_offset_bytes + 12..fat_offset_bytes + 16]
                .copy_from_slice(&FAT_END.to_le_bytes()); // cluster 3 (bitmap)

            // 4. Root Directory Entry 0: Allocation Bitmap Entry
            let mut bitmap_entry = [0u8; 32];
            bitmap_entry[0] = ENTRY_BITMAP; // 0x81
            bitmap_entry[1] = 0; // bitmap_flags (active bitmap = 0)
            bitmap_entry[20..24].copy_from_slice(&bitmap_cluster.to_le_bytes()); // first_cluster = 3
            bitmap_entry[24..32].copy_from_slice(&128u64.to_le_bytes()); // data_length = 128 bytes
            data[root_offset_bytes..root_offset_bytes + 32].copy_from_slice(&bitmap_entry);

            // 5. Root Directory Entry 1: End of directory marker (overwritten when adding entries)
            data[root_offset_bytes + 32] = ENTRY_END;

            // 6. Allocation Bitmap: mark cluster 2 and 3 as allocated (bits 0 and 1)
            data[bitmap_offset_bytes] = 0x03;

            Self {
                data,
                fat_offset_bytes,
                heap_offset_bytes,
                root_offset_bytes,
                bitmap_offset_bytes,
            }
        }

        /// Cluster byte offset within the partition.
        fn cluster_offset(&self, cluster: u32) -> usize {
            self.heap_offset_bytes + ((cluster - FIRST_CLUSTER) as usize) * 512
        }

        /// Sets a FAT table entry for `cluster`.
        fn set_fat_entry(&mut self, cluster: u32, next: u32) {
            let offset = self.fat_offset_bytes + (cluster as usize) * 4;
            self.data[offset..offset + 4].copy_from_slice(&next.to_le_bytes());
        }

        /// Marks `cluster` as allocated (`1`) in the Allocation Bitmap.
        fn set_bitmap_allocated(&mut self, cluster: u32) {
            if cluster >= FIRST_CLUSTER {
                let bit_idx = (cluster - FIRST_CLUSTER) as usize;
                let byte_idx = self.bitmap_offset_bytes + bit_idx / 8;
                let mask = 1u8 << (bit_idx % 8);
                self.data[byte_idx] |= mask;
            }
        }

        /// Adds a deleted file entry set to the directory at `dir_offset`.
        fn add_deleted_file(
            &mut self,
            dir_offset: usize,
            slot_index: usize,
            name: &str,
            first_cluster: u32,
            data_length: u64,
            no_fat_chain: bool,
        ) {
            let base = dir_offset + slot_index * ENTRY_SIZE;

            // FileEntry (32 bytes)
            let mut file_bytes = [0u8; 32];
            file_bytes[0] = ENTRY_FILE & !IN_USE; // 0x05
            file_bytes[1] = 2; // secondary_count = 2 (Stream + Name)
            file_bytes[4..6].copy_from_slice(&ATTR_ARCHIVE.to_le_bytes());
            self.data[base..base + 32].copy_from_slice(&file_bytes);

            // StreamEntry (32 bytes)
            let mut stream_bytes = [0u8; 32];
            stream_bytes[0] = ENTRY_STREAM & !IN_USE; // 0x40
            let flags = ALLOCATION_POSSIBLE | if no_fat_chain { NO_FAT_CHAIN } else { 0 };
            stream_bytes[1] = flags;
            stream_bytes[3] = name.len() as u8;
            stream_bytes[8..16].copy_from_slice(&data_length.to_le_bytes()); // valid_data_length
            stream_bytes[20..24].copy_from_slice(&first_cluster.to_le_bytes());
            stream_bytes[24..32].copy_from_slice(&data_length.to_le_bytes()); // data_length
            self.data[base + 32..base + 64].copy_from_slice(&stream_bytes);

            // NameEntry (32 bytes)
            let mut name_bytes = [0u8; 32];
            name_bytes[0] = ENTRY_NAME & !IN_USE; // 0x41
            let mut byte_off = 2;
            for unit in name.encode_utf16() {
                if byte_off + 2 <= 32 {
                    name_bytes[byte_off..byte_off + 2].copy_from_slice(&unit.to_le_bytes());
                    byte_off += 2;
                }
            }
            self.data[base + 64..base + 96].copy_from_slice(&name_bytes);

            // Ensure next slot has ENTRY_END
            if base + 96 < self.data.len() {
                self.data[base + 96] = ENTRY_END;
            }
        }

        /// Writes payload bytes at a specific cluster.
        fn write_cluster_bytes(&mut self, cluster: u32, bytes: &[u8]) {
            let offset = self.cluster_offset(cluster);
            let len = bytes.len().min(512);
            self.data[offset..offset + len].copy_from_slice(&bytes[..len]);
        }

        /// Writes a minimal ISO-BMFF `ftyp` box header at `cluster`.
        fn write_ftyp_header(&mut self, cluster: u32) {
            let mut ftyp = [0u8; 32];
            ftyp[0..4].copy_from_slice(&32u32.to_be_bytes()); // box size
            ftyp[4..8].copy_from_slice(b"ftyp");
            ftyp[8..12].copy_from_slice(b"mp42");
            self.write_cluster_bytes(cluster, &ftyp);
        }
    }

    #[test]
    fn test_deleted_nofatchain_contiguous_mp4_recovery() {
        let mut builder = TestImageBuilder::new();
        // 2 clusters = 1024 bytes (clusters 4 and 5)
        let first_cluster = 4u32;
        let data_len = 1024u64;

        builder.write_ftyp_header(first_cluster);
        builder.write_cluster_bytes(first_cluster + 1, &[0xAA; 512]);

        builder.add_deleted_file(
            builder.root_offset_bytes,
            1, // slot 1 (slot 0 is bitmap)
            "GOPR0001.MP4",
            first_cluster,
            data_len,
            true, // NoFatChain = true
        );

        let expected_offset = builder.cluster_offset(first_cluster) as u64;
        let mut source = MemorySource::new(builder.data);
        let len = source.size_bytes();
        let candidates = recover_exfat_candidates(&mut source, 0, len).expect("recovery ok");

        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.id, "cand-0001");
        assert_eq!(cand.original_name.as_deref(), Some("GOPR0001.MP4"));
        assert_eq!(
            cand.recovered_name.as_deref(),
            Some("cand-0001_GOPR0001.MP4")
        );
        assert_eq!(cand.expected_size, data_len);
        assert_eq!(cand.confidence, Confidence::High);
        assert!(cand.chain_preserved);
        assert!(!cand.is_fragmented);
        assert_eq!(cand.extents.len(), 1);
        assert_eq!(cand.extents[0].byte_offset, expected_offset);
        assert_eq!(cand.extents[0].byte_len, data_len);
    }

    #[test]
    fn test_deleted_fragmented_mp4_with_preserved_fat_chain() {
        let mut builder = TestImageBuilder::new();
        // 3 clusters physically fragmented: clusters 4, 9, 15
        let data_len = 3 * 512u64; // 1536 bytes

        builder.set_fat_entry(4, 9);
        builder.set_fat_entry(9, 15);
        builder.set_fat_entry(15, FAT_END);

        builder.write_ftyp_header(4);
        builder.write_cluster_bytes(9, &[0xBB; 512]);
        builder.write_cluster_bytes(15, &[0xCC; 512]);

        builder.add_deleted_file(
            builder.root_offset_bytes,
            1,
            "FRAG0001.MOV",
            4,
            data_len,
            false, // NoFatChain = false (uses FAT chain)
        );

        let off4 = builder.cluster_offset(4) as u64;
        let off9 = builder.cluster_offset(9) as u64;
        let off15 = builder.cluster_offset(15) as u64;
        let mut source = MemorySource::new(builder.data);
        let len = source.size_bytes();
        let candidates = recover_exfat_candidates(&mut source, 0, len).expect("recovery ok");

        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.original_name.as_deref(), Some("FRAG0001.MOV"));
        assert_eq!(cand.confidence, Confidence::High);
        assert!(cand.chain_preserved);
        assert!(cand.is_fragmented);
        assert_eq!(cand.extents.len(), 3);
        assert_eq!(cand.extents[0].byte_offset, off4);
        assert_eq!(cand.extents[0].byte_len, 512);
        assert_eq!(cand.extents[1].byte_offset, off9);
        assert_eq!(cand.extents[1].byte_len, 512);
        assert_eq!(cand.extents[2].byte_offset, off15);
        assert_eq!(cand.extents[2].byte_len, 512);

        // Verify recovered data byte-identically across extents
        let mut recovered_bytes = Vec::new();
        for extent in &cand.extents {
            let mut buf = vec![0u8; extent.byte_len as usize];
            source
                .read_exact_at(extent.byte_offset, &mut buf)
                .expect("read extent");
            recovered_bytes.extend_from_slice(&buf);
        }
        assert_eq!(recovered_bytes.len(), 1536);
        assert_eq!(&recovered_bytes[4..8], b"ftyp");
        assert_eq!(&recovered_bytes[512..512 + 512], &[0xBB; 512]);
        assert_eq!(&recovered_bytes[1024..1024 + 512], &[0xCC; 512]);
    }

    #[test]
    fn test_deleted_fragmented_mp4_with_zeroed_fat_chain() {
        let mut builder = TestImageBuilder::new();
        // File originally had NoFatChain = 0, but FAT entry was zeroed upon deletion
        let data_len = 3 * 512u64; // 1536 bytes

        builder.write_ftyp_header(4);
        builder.set_fat_entry(4, 0); // zeroed FAT entry

        builder.add_deleted_file(
            builder.root_offset_bytes,
            1,
            "LOSTCHAIN.MP4",
            4,
            data_len,
            false, // NoFatChain = false
        );

        let mut source = MemorySource::new(builder.data);
        let len = source.size_bytes();
        let candidates = recover_exfat_candidates(&mut source, 0, len).expect("recovery ok");

        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.confidence, Confidence::Low);
        assert!(!cand.chain_preserved);
        assert!(cand.is_fragmented);
        assert!(cand.error_reason.is_some());
    }

    #[test]
    fn test_bitmap_conflict_stops_contiguous_recovery() {
        let mut builder = TestImageBuilder::new();
        // File expects 4 clusters (4, 5, 6, 7 = 2048 bytes), but cluster 6 is marked allocated
        let data_len = 4 * 512u64;

        builder.write_ftyp_header(4);
        builder.set_bitmap_allocated(6); // cluster 6 allocated by active file

        builder.add_deleted_file(
            builder.root_offset_bytes,
            1,
            "OVERWRITTEN.MP4",
            4,
            data_len,
            true, // NoFatChain = true
        );

        let mut source = MemorySource::new(builder.data);
        let len = source.size_bytes();
        let candidates = recover_exfat_candidates(&mut source, 0, len).expect("recovery ok");

        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.confidence, Confidence::Low);
        assert!(!cand.chain_preserved);
        assert!(cand.is_fragmented);
        // Safe prefix should only include clusters 4 and 5 (1024 bytes)
        assert_eq!(cand.total_extent_bytes(), 1024);
        assert!(cand.error_reason.as_ref().unwrap().contains("truncated"));
    }

    #[test]
    fn test_cyclic_fat_chain_terminates_safely() {
        let mut builder = TestImageBuilder::new();
        // FAT chain loops: 4 -> 5 -> 4
        builder.set_fat_entry(4, 5);
        builder.set_fat_entry(5, 4);

        builder.write_ftyp_header(4);

        builder.add_deleted_file(
            builder.root_offset_bytes,
            1,
            "CYCLE.MP4",
            4,
            4096, // 8 clusters expected
            false,
        );

        let mut source = MemorySource::new(builder.data);
        let len = source.size_bytes();
        let candidates = recover_exfat_candidates(&mut source, 0, len).expect("recovery ok");

        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.confidence, Confidence::Low);
        assert!(!cand.chain_preserved);
        assert!(cand.is_fragmented);
    }

    #[test]
    fn test_backup_boot_sector_fallback() {
        let mut builder = TestImageBuilder::new();
        builder.write_ftyp_header(4);
        builder.add_deleted_file(builder.root_offset_bytes, 1, "BACKUP.MP4", 4, 512, true);

        // Corrupt Main Boot Sector at sector 0
        builder.data[0..512].fill(0);

        let mut source = MemorySource::new(builder.data);
        let len = source.size_bytes();
        let candidates = recover_exfat_candidates(&mut source, 0, len).expect("recovery ok");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].original_name.as_deref(), Some("BACKUP.MP4"));
    }

    #[test]
    fn test_deleted_file_in_subdirectory_recovery() {
        let mut builder = TestImageBuilder::new();
        let dcim_cluster = 6u32;
        let file_cluster = 7u32;

        // In Root Directory: add active subdirectory entry "DCIM" pointing to cluster 6
        let root_base = builder.root_offset_bytes + ENTRY_SIZE;
        let mut file_bytes = [0u8; 32];
        file_bytes[0] = ENTRY_FILE; // active 0x85
        file_bytes[1] = 2;
        file_bytes[4..6].copy_from_slice(&ATTR_DIRECTORY.to_le_bytes());
        builder.data[root_base..root_base + 32].copy_from_slice(&file_bytes);

        let mut stream_bytes = [0u8; 32];
        stream_bytes[0] = ENTRY_STREAM; // active 0xC0
        stream_bytes[1] = ALLOCATION_POSSIBLE | NO_FAT_CHAIN;
        stream_bytes[3] = 4; // "DCIM" length
        stream_bytes[20..24].copy_from_slice(&dcim_cluster.to_le_bytes());
        stream_bytes[24..32].copy_from_slice(&512u64.to_le_bytes());
        builder.data[root_base + 32..root_base + 64].copy_from_slice(&stream_bytes);

        let mut name_bytes = [0u8; 32];
        name_bytes[0] = ENTRY_NAME;
        let mut off = 2;
        for u in "DCIM".encode_utf16() {
            name_bytes[off..off + 2].copy_from_slice(&u.to_le_bytes());
            off += 2;
        }
        builder.data[root_base + 64..root_base + 96].copy_from_slice(&name_bytes);
        builder.data[root_base + 96] = ENTRY_END;

        // Inside DCIM (cluster 6): add deleted video file "DCIM0001.MP4"
        let dcim_offset = builder.cluster_offset(dcim_cluster);
        builder.write_ftyp_header(file_cluster);
        builder.add_deleted_file(dcim_offset, 0, "DCIM0001.MP4", file_cluster, 512, true);

        let mut source = MemorySource::new(builder.data);
        let len = source.size_bytes();
        let candidates = recover_exfat_candidates(&mut source, 0, len).expect("recovery ok");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].original_name.as_deref(), Some("DCIM0001.MP4"));
    }
}
