//! FAT32 deleted directory entry and cluster chain recovery.
//!
//! Uses pinned `hadris-fat-raw = 0.3.0` read-only codec and layout primitives to parse
//! boot sectors, traverse active and deleted directory trees, reconstruct deleted
//! Long File Names (LFN) and 8.3 short names, and resolve cluster chains with both
//! preserved FAT chain tracking (including non-contiguous fragmentation) and safe
//! contiguous fallback resolution for zeroed FAT chains.

use std::collections::HashSet;

use hadris_fat_raw::{
    parse_boot, short_name, ChainGuard, FatKind, Geometry, RawDirEntry, RawLfnEntry, RootLocation,
    ATTR_DIRECTORY, ATTR_LONG_NAME, ATTR_LONG_NAME_MASK, ATTR_VOLUME_ID, BOOT_SECTOR_LEN,
    ENTRY_END, ENTRY_FREE, ENTRY_SIZE, FIRST_DATA_CLUSTER,
};

use crate::error::RecoveryError;
use crate::types::{
    Candidate, CandidateStatus, Confidence, Extent, PartitionSlice, ReadSource, RecoveryMethod,
};

/// Maximum directory recursion depth allowed to guard against deep directory nesting.
const MAX_DIR_DEPTH: u32 = 16;

/// Maximum directory clusters visited across all directories to avoid unbounded loops.
const MAX_VISITED_DIR_CLUSTERS: usize = 4096;

/// Maximum 32-byte directory slots inspected per directory to bound processing.
const MAX_DIR_SLOTS: usize = 65_536;

/// Maximum number of consecutive LFN slots buffered for a single short entry.
const MAX_LFN_ENTRIES: usize = 20;

/// Recovers deleted MP4/MOV video candidates from a FAT32 partition.
///
/// # Arguments
///
/// * `source` - Underlying block/byte source implementing [`ReadSource`].
/// * `partition_offset` - Starting byte offset of the FAT32 partition on the source disk.
/// * `partition_len` - Total length of the partition in bytes.
///
/// # Errors
///
/// Returns [`RecoveryError::Parse`] if the boot sector is invalid, corrupt, or does not
/// represent a valid FAT32 filesystem, or if a structural overflow occurs.
/// Returns [`RecoveryError::SourceIo`] if a read failure occurs on the source device.
pub fn recover_fat32_candidates<R: ReadSource + ?Sized>(
    source: &mut R,
    partition_offset: u64,
    partition_len: u64,
) -> Result<Vec<Candidate>, RecoveryError> {
    let mut slice = PartitionSlice::new(source, partition_offset, partition_len)?;

    let mut boot_buf = [0u8; BOOT_SECTOR_LEN];
    let primary_read = slice.read_exact_at(0, &mut boot_buf);
    let mut geo_res = match primary_read {
        Ok(()) => parse_boot(&boot_buf).ok(),
        Err(_) => None,
    };

    // If parsing primary boot sector at sector 0 fails, attempt backup boot sector at sector 6.
    if geo_res.is_none() && partition_len >= 7 * (BOOT_SECTOR_LEN as u64) {
        let backup_offset = 6 * (BOOT_SECTOR_LEN as u64);
        if slice.read_exact_at(backup_offset, &mut boot_buf).is_ok() {
            geo_res = parse_boot(&boot_buf).ok();
        }
    }

    let geo = geo_res.ok_or_else(|| {
        RecoveryError::Parse(
            "failed to parse valid FAT32 boot sector at sector 0 or backup sector 6".to_string(),
        )
    })?;

    if geo.kind() != FatKind::Fat32 {
        return Err(RecoveryError::Parse(format!(
            "expected FAT32 filesystem, found {:?}",
            geo.kind()
        )));
    }

    let root_cluster = match geo.root() {
        RootLocation::Cluster(cluster) => cluster,
        RootLocation::Fixed { .. } => {
            return Err(RecoveryError::Parse(
                "FAT32 root directory must be located in a cluster chain".to_string(),
            ));
        }
    };

    if geo.data_start() >= partition_len {
        return Err(RecoveryError::Parse(format!(
            "FAT32 data start ({}) exceeds partition length ({partition_len})",
            geo.data_start()
        )));
    }

    let mut candidates = Vec::new();
    let mut candidate_counter = 0u64;

    let mut dir_queue: Vec<(u32, u32)> = Vec::new();
    dir_queue.push((root_cluster, 0));

    let mut visited_dir_clusters: HashSet<u32> = HashSet::new();
    visited_dir_clusters.insert(root_cluster);

    while let Some((dir_start_cluster, depth)) = dir_queue.pop() {
        if depth > MAX_DIR_DEPTH {
            continue;
        }

        let mut cur_dir_cluster = dir_start_cluster;
        let mut dir_chain_guard = ChainGuard::new(dir_start_cluster);
        let mut dir_slots_scanned = 0usize;
        let mut pending_lfn: Vec<RawLfnEntry> = Vec::new();
        let mut stop_dir = false;

        while let Some(cluster_offset) = geo.cluster_offset(cur_dir_cluster) {
            let mut cluster_data = vec![0u8; geo.cluster_size() as usize];
            if slice
                .read_exact_at(cluster_offset, &mut cluster_data)
                .is_err()
            {
                break;
            }

            for raw in cluster_data.as_chunks::<ENTRY_SIZE>().0 {
                if dir_slots_scanned >= MAX_DIR_SLOTS {
                    stop_dir = true;
                    break;
                }
                dir_slots_scanned += 1;

                if raw[0] == ENTRY_END {
                    stop_dir = true;
                    break;
                }

                let is_lfn = (raw[11] & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME;
                if is_lfn {
                    let lfn_entry: RawLfnEntry = bytemuck::cast(*raw);
                    if pending_lfn.len() >= MAX_LFN_ENTRIES {
                        pending_lfn.remove(0);
                    }
                    pending_lfn.push(lfn_entry);
                    continue;
                }

                // Short directory entry
                let entry: RawDirEntry = bytemuck::cast(*raw);
                let is_deleted = raw[0] == ENTRY_FREE;

                // Skip volume labels
                if (entry.attributes & ATTR_VOLUME_ID) != 0 {
                    pending_lfn.clear();
                    continue;
                }

                // Skip dot entries (. and ..)
                if is_dot_entry(&entry.name, is_deleted) {
                    pending_lfn.clear();
                    continue;
                }

                let first_cluster = (((u32::from(entry.first_cluster_high.get())) << 16)
                    | u32::from(entry.first_cluster_low.get()))
                    & FatKind::Fat32.mask();
                let is_directory = (entry.attributes & ATTR_DIRECTORY) != 0;

                if is_directory {
                    if first_cluster >= FIRST_DATA_CLUSTER
                        && first_cluster <= geo.max_cluster()
                        && depth < MAX_DIR_DEPTH
                        && visited_dir_clusters.len() < MAX_VISITED_DIR_CLUSTERS
                        && visited_dir_clusters.insert(first_cluster)
                    {
                        dir_queue.push((first_cluster, depth + 1));
                    }
                    pending_lfn.clear();
                    continue;
                }

                // Regular deleted file candidate
                let file_size = u64::from(entry.size.get());
                if is_deleted
                    && file_size > 0
                    && first_cluster >= FIRST_DATA_CLUSTER
                    && first_cluster <= geo.max_cluster()
                {
                    let name = reconstruct_name(&pending_lfn, &entry);
                    if is_video_candidate(&mut slice, &geo, &name, first_cluster) {
                        candidate_counter += 1;
                        let cand_id = format!("cand-{candidate_counter:04}");
                        let candidate = resolve_candidate(
                            &mut slice,
                            partition_offset,
                            &geo,
                            cand_id,
                            name,
                            first_cluster,
                            file_size,
                        )?;
                        candidates.push(candidate);
                    }
                }

                pending_lfn.clear();
            }

            if stop_dir {
                break;
            }

            // Follow FAT cluster chain for current directory if any
            let next_dir_cluster = match read_fat_entry(&mut slice, &geo, cur_dir_cluster) {
                Ok(stored) => match FatKind::Fat32.next(stored, geo.max_cluster()) {
                    Ok(Some(nxt)) if dir_chain_guard.step(nxt) => Some(nxt),
                    _ => None,
                },
                Err(_) => None,
            };

            match next_dir_cluster {
                Some(nxt) => {
                    if !visited_dir_clusters.insert(nxt)
                        || visited_dir_clusters.len() > MAX_VISITED_DIR_CLUSTERS
                    {
                        break;
                    }
                    cur_dir_cluster = nxt;
                }
                None => break,
            }
        }
    }

    Ok(candidates)
}

/// Reads the 4-byte FAT32 allocation-table entry for `cluster`.
fn read_fat_entry<R: ReadSource + ?Sized>(
    slice: &mut R,
    geo: &Geometry,
    cluster: u32,
) -> Result<u32, RecoveryError> {
    if cluster < FIRST_DATA_CLUSTER || cluster > geo.max_cluster() {
        return Err(RecoveryError::Parse(format!(
            "cluster {cluster} is out of bounds (max: {})",
            geo.max_cluster()
        )));
    }
    let active_fat = geo.active_fat();
    let fat_offset = geo
        .fat_copy(active_fat)
        .checked_add(FatKind::Fat32.entry_offset(cluster))
        .ok_or_else(|| RecoveryError::Parse("FAT entry offset overflow".to_string()))?;
    let mut bytes = [0u8; 4];
    slice.read_exact_at(fat_offset, &mut bytes)?;
    Ok(FatKind::Fat32.decode(u64::from(cluster), &bytes))
}

/// Determines whether a filename or the initial cluster payload indicates an ISO-BMFF video.
fn is_video_candidate<R: ReadSource + ?Sized>(
    slice: &mut R,
    geo: &Geometry,
    name: &str,
    first_cluster: u32,
) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".mp4")
        || lower.ends_with(".mov")
        || lower.ends_with(".m4v")
        || lower.ends_with(".3gp")
    {
        return true;
    }

    // Inspect first cluster for recognizable ISO-BMFF container box headers.
    let Some(cluster_offset) = geo.cluster_offset(first_cluster) else {
        return false;
    };
    let mut header = [0u8; 8];
    if slice.read_exact_at(cluster_offset, &mut header).is_err() {
        return false;
    }
    let box_type = &header[4..8];
    matches!(box_type, b"ftyp" | b"moov" | b"mdat" | b"wide" | b"free")
}

/// Reconstructs the original filename from consecutive LFN slots or 8.3 short name.
fn reconstruct_name(pending_lfn: &[RawLfnEntry], entry: &RawDirEntry) -> String {
    if !pending_lfn.is_empty() {
        let target_checksum = pending_lfn.last().unwrap().checksum;
        let mut trailing_run = Vec::new();
        for lfn in pending_lfn.iter().rev() {
            if lfn.checksum == target_checksum {
                trailing_run.push(lfn);
            } else {
                break;
            }
        }

        // trailing_run holds entries from closest to short entry (piece 1) up to first in run (piece N).
        let mut utf16_units = Vec::new();
        for lfn in trailing_run {
            let (units, len) = hadris_fat_raw::lfn::unpack(&lfn.name1, &lfn.name2, &lfn.name3);
            utf16_units.extend_from_slice(&units[..len]);
        }
        let decoded = String::from_utf16_lossy(&utf16_units);
        let trimmed = decoded.trim_matches('\0').trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    // Fallback to formatted 8.3 short name
    let mut short_bytes = entry.name;
    if short_bytes[0] == ENTRY_FREE {
        short_bytes[0] = b'_';
    }
    let mut out = [0u8; short_name::DISPLAY_MAX];
    let len = short_name::display(&short_bytes, entry.nt_reserved, |b| b as char, &mut out);
    String::from_utf8_lossy(&out[..len]).to_string()
}

/// Identifies whether a directory entry represents a current or deleted dot entry (`.` or `..`).
fn is_dot_entry(name: &[u8; 11], is_deleted: bool) -> bool {
    if name[0] == b'.' {
        return true;
    }
    if is_deleted {
        if name[1..11] == *b"          " {
            return true;
        }
        if name[1] == b'.' && name[2..11] == *b"         " {
            return true;
        }
    }
    false
}

/// Coalesces a series of clusters into contiguous disk extents and clamps the total bytes
/// to `file_size`.
fn clusters_to_extents(
    partition_offset: u64,
    geo: &Geometry,
    clusters: &[u32],
    file_size: u64,
) -> Result<Vec<Extent>, RecoveryError> {
    if clusters.is_empty() {
        return Ok(Vec::new());
    }
    let cluster_size = u64::from(geo.cluster_size());
    let mut extents: Vec<Extent> = Vec::new();

    for &c in clusters {
        let rel_off = geo.cluster_offset(c).ok_or_else(|| {
            RecoveryError::Parse(format!("cluster {c} has no valid offset in geometry"))
        })?;
        let abs_off = partition_offset
            .checked_add(rel_off)
            .ok_or_else(|| RecoveryError::Parse("partition extent offset overflow".to_string()))?;

        if let Some(last) = extents.last_mut() {
            if last.byte_offset.checked_add(last.byte_len) == Some(abs_off) {
                last.byte_len = last
                    .byte_len
                    .checked_add(cluster_size)
                    .ok_or_else(|| RecoveryError::Parse("extent length overflow".to_string()))?;
                continue;
            }
        }
        extents.push(Extent::new(abs_off, cluster_size));
    }

    let mut remaining = file_size;
    let mut clamped_extents = Vec::new();
    for mut ext in extents {
        if remaining == 0 {
            break;
        }
        if ext.byte_len > remaining {
            ext.byte_len = remaining;
            clamped_extents.push(ext);
            break;
        } else {
            remaining -= ext.byte_len;
            clamped_extents.push(ext);
        }
    }

    Ok(clamped_extents)
}

/// Resolves cluster allocation for a candidate file via preserved FAT chain walk or safe contiguous fallback.
fn resolve_candidate<R: ReadSource + ?Sized>(
    slice: &mut R,
    partition_offset: u64,
    geo: &Geometry,
    cand_id: String,
    name: String,
    first_cluster: u32,
    file_size: u64,
) -> Result<Candidate, RecoveryError> {
    let cluster_size = u64::from(geo.cluster_size());
    let expected_clusters_u64 = file_size.div_ceil(cluster_size);
    let expected_clusters = u32::try_from(expected_clusters_u64).unwrap_or(u32::MAX);

    let mask = FatKind::Fat32.mask();
    let stored_first = read_fat_entry(slice, geo, first_cluster)?;
    let is_fat_preserved = (stored_first & mask) != 0;

    let (clusters, chain_preserved, is_fragmented, confidence, error_reason) = if is_fat_preserved {
        // Case 1: Preserved FAT Chain
        let mut chain_clusters = Vec::new();
        chain_clusters.push(first_cluster);
        let mut guard = ChainGuard::new(first_cluster);
        let mut curr = first_cluster;
        let mut reached_cleanly = expected_clusters <= 1;

        while chain_clusters.len() < expected_clusters as usize {
            let stored = match read_fat_entry(slice, geo, curr) {
                Ok(s) => s,
                Err(_) => break,
            };
            match FatKind::Fat32.next(stored, geo.max_cluster()) {
                Ok(Some(next_c)) => {
                    if !guard.step(next_c) {
                        // Cycle detected!
                        break;
                    }
                    chain_clusters.push(next_c);
                    curr = next_c;
                    if chain_clusters.len() == expected_clusters as usize {
                        reached_cleanly = true;
                        break;
                    }
                }
                _ => {
                    // Premature end-of-chain, bad cluster, or out-of-bounds link
                    break;
                }
            }
        }

        if reached_cleanly {
            let extents_preview =
                clusters_to_extents(partition_offset, geo, &chain_clusters, file_size)?;
            let frag = extents_preview.len() > 1;
            (chain_clusters, true, frag, Confidence::High, None)
        } else {
            (
                chain_clusters,
                false,
                true,
                Confidence::Low,
                Some("FAT cluster chain broken or prematurely truncated".to_string()),
            )
        }
    } else {
        // Case 2: Lost FAT Chain (stored & mask == 0)
        if expected_clusters <= 1 {
            (vec![first_cluster], true, false, Confidence::High, None)
        } else {
            let mut contiguous_clusters = Vec::new();
            contiguous_clusters.push(first_cluster);
            let mut stopped_early = false;

            let end_cluster = first_cluster.saturating_add(expected_clusters);
            for c in (first_cluster + 1)..end_cluster {
                if c > geo.max_cluster() {
                    stopped_early = true;
                    break;
                }
                match read_fat_entry(slice, geo, c) {
                    Ok(stored) if (stored & mask) == 0 => {
                        // Inspect cluster boundary for unexpected foreign video start (e.g. ftyp)
                        if let Some(c_off) = geo.cluster_offset(c) {
                            let mut peek = [0u8; 8];
                            if slice.read_exact_at(c_off, &mut peek).is_ok()
                                && &peek[4..8] == b"ftyp"
                            {
                                stopped_early = true;
                                break;
                            }
                        }
                        contiguous_clusters.push(c);
                    }
                    _ => {
                        stopped_early = true;
                        break;
                    }
                }
            }

            if stopped_early || contiguous_clusters.len() < expected_clusters as usize {
                (
                    contiguous_clusters,
                    false,
                    true,
                    Confidence::Low,
                    Some(
                        "zeroed FAT chain contiguous scan stopped early due to allocated or invalid cluster"
                            .to_string(),
                    ),
                )
            } else {
                (contiguous_clusters, false, false, Confidence::Medium, None)
            }
        }
    };

    let extents = clusters_to_extents(partition_offset, geo, &clusters, file_size)?;

    Ok(Candidate {
        id: cand_id,
        extents,
        expected_size: file_size,
        recovery_method: RecoveryMethod::FilesystemFat32,
        original_name: Some(name),
        recovered_name: None,
        output_path: None,
        confidence,
        status: CandidateStatus::Partial,
        chain_preserved,
        is_fragmented,
        error_reason,
        error_offset: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hadris_fat_raw::layout::{
        encode_boot_sector, plan, reserved_fat_entries, BootFields, Request, BACKUP_BOOT_SECTOR,
    };
    use hadris_fat_raw::{LongEntry, ShortEntry, ATTR_ARCHIVE};

    use crate::types::MemorySource;

    /// Helper that builds a minimal valid FAT32 volume in memory.
    fn create_synthetic_fat32_volume(total_bytes: u64) -> (Vec<u8>, Geometry) {
        let sector_size = 512u32;
        let total_sectors = total_bytes / u64::from(sector_size);
        let request = Request::new(sector_size, total_sectors).with_kind(FatKind::Fat32);
        let layout = plan(&request).expect("planning synthetic FAT32 volume");

        let mut disk = vec![0u8; total_bytes as usize];
        let fields = BootFields::new().with_volume_id(0x4242_4242);

        let boot = encode_boot_sector(&layout, &fields);
        disk[..BOOT_SECTOR_LEN].copy_from_slice(&boot);

        // Backup boot sector at sector 6
        let backup_offset = (BACKUP_BOOT_SECTOR as usize) * BOOT_SECTOR_LEN;
        disk[backup_offset..backup_offset + BOOT_SECTOR_LEN].copy_from_slice(&boot);

        // Write reserved FAT entries
        let (reserved, len) = reserved_fat_entries(FatKind::Fat32, fields.media());
        for copy in 0..layout.fat_count() {
            let fat_offset = (layout.fat_start()
                + (copy as u64) * (layout.fat_sectors() as u64) * u64::from(sector_size))
                as usize;
            disk[fat_offset..fat_offset + len].copy_from_slice(&reserved[..len]);
        }

        let geo = parse_boot(&boot).expect("parse synthetic boot sector");
        (disk, geo)
    }

    /// Sets a FAT32 entry value for `cluster` across all FAT copies.
    fn set_fat_entry(disk: &mut [u8], geo: &Geometry, cluster: u32, value: u32) {
        for copy in 0..geo.fat_count() {
            let fat_start = geo.fat_copy(copy) as usize;
            let entry_off = FatKind::Fat32.entry_offset(cluster) as usize;
            FatKind::Fat32.encode(
                u64::from(cluster),
                value,
                &mut disk[fat_start + entry_off..fat_start + entry_off + 4],
            );
        }
    }

    /// Writes an ISO-BMFF `ftyp` box header into `disk` at `offset`.
    fn write_ftyp_box(disk: &mut [u8], offset: usize) {
        let mut box_data = [0u8; 16];
        box_data[0..4].copy_from_slice(&16u32.to_be_bytes());
        box_data[4..8].copy_from_slice(b"ftyp");
        box_data[8..12].copy_from_slice(b"mp42");
        box_data[12..16].copy_from_slice(&0u32.to_be_bytes());
        disk[offset..offset + 16].copy_from_slice(&box_data);
    }

    #[test]
    fn test_deleted_contiguous_mp4_recovery_with_lfn() {
        let (mut disk, geo) = create_synthetic_fat32_volume(40 * 1024 * 1024);

        // Video file occupies cluster 3 and 4 contiguously (size = 6000 bytes).
        let cluster3_offset = geo.cluster_offset(3).unwrap() as usize;
        write_ftyp_box(&mut disk, cluster3_offset);

        // Root directory at cluster 2 (data_start)
        let root_offset = geo.data_start() as usize;

        let long_name = "Drone_Flight_4K.mp4";
        let encoded_lfn = hadris_fat_raw::lfn::Encoded::new(long_name).unwrap();

        let mut short_entry = ShortEntry::new(*b"DRONE_~1MP4", ATTR_ARCHIVE);
        short_entry.set_size(6000);
        short_entry.set_first_cluster(FatKind::Fat32, 3);
        let checksum = short_entry.lfn_checksum();

        // Write LFN entries in disk order (first on disk has LAST_ENTRY)
        let mut slot_offset = root_offset;
        for i in 0..encoded_lfn.entries() {
            let (seq, units) = encoded_lfn.entry(i);
            let long = LongEntry::new(seq, checksum, &units);
            let mut raw_lfn = long.encode();
            // Deleted LFN slots have sequence overwritten with 0xE5 by Windows
            raw_lfn[0] = ENTRY_FREE;
            disk[slot_offset..slot_offset + ENTRY_SIZE].copy_from_slice(&raw_lfn);
            slot_offset += ENTRY_SIZE;
        }

        // Write deleted short entry
        let mut raw_short = short_entry.encode();
        raw_short[0] = ENTRY_FREE;
        disk[slot_offset..slot_offset + ENTRY_SIZE].copy_from_slice(&raw_short);
        slot_offset += ENTRY_SIZE;

        // End of directory
        disk[slot_offset] = ENTRY_END;

        // Zeroed FAT chain: FAT[3] == 0, FAT[4] == 0 (unallocated)
        set_fat_entry(&mut disk, &geo, 3, 0);
        set_fat_entry(&mut disk, &geo, 4, 0);

        let mut source = MemorySource::new(disk);
        let len = source.size_bytes();
        let candidates = recover_fat32_candidates(&mut source, 0, len).expect("recovery");

        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.original_name.as_deref(), Some("Drone_Flight_4K.mp4"));
        assert_eq!(cand.expected_size, 6000);
        assert!(!cand.chain_preserved);
        assert!(!cand.is_fragmented);
        assert_eq!(cand.confidence, Confidence::Medium);
        assert_eq!(cand.extents.len(), 1);
        assert_eq!(cand.extents[0].byte_len, 6000);
        assert_eq!(cand.extents[0].byte_offset, geo.cluster_offset(3).unwrap());
        assert_eq!(cand.recovery_method, RecoveryMethod::FilesystemFat32);
    }

    #[test]
    fn test_deleted_fragmented_mp4_with_preserved_fat_chain() {
        let (mut disk, geo) = create_synthetic_fat32_volume(40 * 1024 * 1024);
        let cluster_size = geo.cluster_size() as u64;

        // Clusters: 3 -> 7 -> 12
        let file_size = cluster_size * 2 + 500;
        let cluster3_offset = geo.cluster_offset(3).unwrap() as usize;
        write_ftyp_box(&mut disk, cluster3_offset);

        // Root directory
        let root_offset = geo.data_start() as usize;
        let mut short_entry = ShortEntry::new(*b"GOPR0002MP4", ATTR_ARCHIVE);
        short_entry.set_size(file_size as u32);
        short_entry.set_first_cluster(FatKind::Fat32, 3);
        let mut raw_short = short_entry.encode();
        raw_short[0] = ENTRY_FREE;
        disk[root_offset..root_offset + ENTRY_SIZE].copy_from_slice(&raw_short);
        disk[root_offset + ENTRY_SIZE] = ENTRY_END;

        // Preserved FAT chain: 3 -> 7 -> 12 -> EOC
        set_fat_entry(&mut disk, &geo, 3, 7);
        set_fat_entry(&mut disk, &geo, 7, 12);
        set_fat_entry(&mut disk, &geo, 12, FatKind::Fat32.end_of_chain());

        let mut source = MemorySource::new(disk);
        let len = source.size_bytes();
        let candidates = recover_fat32_candidates(&mut source, 0, len).expect("recovery");

        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.original_name.as_deref(), Some("_OPR0002.MP4"));
        assert_eq!(cand.expected_size, file_size);
        assert!(cand.chain_preserved);
        assert!(cand.is_fragmented);
        assert_eq!(cand.confidence, Confidence::High);
        assert_eq!(cand.extents.len(), 3);
        assert_eq!(cand.extents[0].byte_len, cluster_size);
        assert_eq!(cand.extents[1].byte_len, cluster_size);
        assert_eq!(cand.extents[2].byte_len, 500);
        assert_eq!(cand.extents[0].byte_offset, geo.cluster_offset(3).unwrap());
        assert_eq!(cand.extents[1].byte_offset, geo.cluster_offset(7).unwrap());
        assert_eq!(cand.extents[2].byte_offset, geo.cluster_offset(12).unwrap());
        assert_eq!(cand.total_extent_bytes(), file_size);
    }

    #[test]
    fn test_zeroed_fat_chain_stopped_by_allocated_cluster() {
        let (mut disk, geo) = create_synthetic_fat32_volume(40 * 1024 * 1024);
        let cluster_size = geo.cluster_size() as u64;

        // File claims 3 clusters (size = cluster_size * 2 + 100), first_cluster = 3
        let file_size = cluster_size * 2 + 100;
        let cluster3_offset = geo.cluster_offset(3).unwrap() as usize;
        write_ftyp_box(&mut disk, cluster3_offset);

        let root_offset = geo.data_start() as usize;
        let mut short_entry = ShortEntry::new(*b"GOPR0003MP4", ATTR_ARCHIVE);
        short_entry.set_size(file_size as u32);
        short_entry.set_first_cluster(FatKind::Fat32, 3);
        let mut raw_short = short_entry.encode();
        raw_short[0] = ENTRY_FREE;
        disk[root_offset..root_offset + ENTRY_SIZE].copy_from_slice(&raw_short);
        disk[root_offset + ENTRY_SIZE] = ENTRY_END;

        // Zeroed FAT chain at cluster 3, but cluster 4 is allocated to another file!
        set_fat_entry(&mut disk, &geo, 3, 0);
        set_fat_entry(&mut disk, &geo, 4, 999); // Allocated

        let mut source = MemorySource::new(disk);
        let len = source.size_bytes();
        let candidates = recover_fat32_candidates(&mut source, 0, len).expect("recovery");

        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert_eq!(cand.original_name.as_deref(), Some("_OPR0003.MP4"));
        assert!(!cand.chain_preserved);
        assert!(cand.is_fragmented);
        assert_eq!(cand.confidence, Confidence::Low);
        assert_eq!(cand.extents.len(), 1);
        assert_eq!(cand.extents[0].byte_len, cluster_size);
        assert!(cand.error_reason.is_some());
    }

    #[test]
    fn test_cyclic_fat_chain_terminates_safely() {
        let (mut disk, geo) = create_synthetic_fat32_volume(40 * 1024 * 1024);
        let cluster_size = geo.cluster_size() as u64;

        // File requests 5 clusters, first_cluster = 4
        let file_size = cluster_size * 5;
        let cluster4_offset = geo.cluster_offset(4).unwrap() as usize;
        write_ftyp_box(&mut disk, cluster4_offset);

        let root_offset = geo.data_start() as usize;
        let mut short_entry = ShortEntry::new(*b"LOOP0001MP4", ATTR_ARCHIVE);
        short_entry.set_size(file_size as u32);
        short_entry.set_first_cluster(FatKind::Fat32, 4);
        let mut raw_short = short_entry.encode();
        raw_short[0] = ENTRY_FREE;
        disk[root_offset..root_offset + ENTRY_SIZE].copy_from_slice(&raw_short);
        disk[root_offset + ENTRY_SIZE] = ENTRY_END;

        // Loop: cluster 4 -> 5 -> 4
        set_fat_entry(&mut disk, &geo, 4, 5);
        set_fat_entry(&mut disk, &geo, 5, 4);

        let mut source = MemorySource::new(disk);
        let len = source.size_bytes();
        let candidates = recover_fat32_candidates(&mut source, 0, len).expect("recovery");

        assert_eq!(candidates.len(), 1);
        let cand = &candidates[0];
        assert!(!cand.chain_preserved);
        assert!(cand.is_fragmented);
        assert_eq!(cand.confidence, Confidence::Low);
        assert!(cand.error_reason.is_some());
    }

    #[test]
    fn test_corrupt_boot_sector_returns_controlled_parse_error() {
        let total_bytes = 40 * 1024 * 1024;
        let disk = vec![0u8; total_bytes as usize];
        let mut source = MemorySource::new(disk);
        let len = source.size_bytes();
        let res = recover_fat32_candidates(&mut source, 0, len);
        assert!(matches!(res, Err(RecoveryError::Parse(_))));
    }

    #[test]
    fn test_backup_boot_sector_fallback_when_sector0_corrupt() {
        let (mut disk, geo) = create_synthetic_fat32_volume(40 * 1024 * 1024);

        // Corrupt primary boot sector at sector 0
        disk[..BOOT_SECTOR_LEN].fill(0);

        // Backup boot sector at sector 6 remains intact
        let cluster3_offset = geo.cluster_offset(3).unwrap() as usize;
        write_ftyp_box(&mut disk, cluster3_offset);

        let root_offset = geo.data_start() as usize;
        let mut short_entry = ShortEntry::new(*b"BKUP0001MP4", ATTR_ARCHIVE);
        short_entry.set_size(1000);
        short_entry.set_first_cluster(FatKind::Fat32, 3);
        let mut raw_short = short_entry.encode();
        raw_short[0] = ENTRY_FREE;
        disk[root_offset..root_offset + ENTRY_SIZE].copy_from_slice(&raw_short);
        disk[root_offset + ENTRY_SIZE] = ENTRY_END;

        let mut source = MemorySource::new(disk);
        let len = source.size_bytes();
        let candidates = recover_fat32_candidates(&mut source, 0, len).expect("recovery");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].original_name.as_deref(), Some("_KUP0001.MP4"));
    }
}
