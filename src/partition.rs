//! MBR, GPT, and superfloppy partition parsing and filesystem detection.
//!
//! Provides read-only parsing of partition tables (GPT, MBR with EBR logical
//! partitions, and unpartitioned Superfloppy volumes) along with non-panicking
//! filesystem identification (FAT32 and exFAT) using checked arithmetic.

use std::collections::HashSet;

use crate::error::RecoveryError;
use crate::types::{FilesystemKind, PartitionInfo, PartitionScheme, ReadSource};

/// Checks a 512-byte sector to determine if it is a valid exFAT boot sector.
fn is_exfat_boot_sector(sector: &[u8; 512]) -> bool {
    if sector.len() == std::mem::size_of::<hadris_fat_raw::exfat::BootSector>() {
        let boot = bytemuck::pod_read_unaligned::<hadris_fat_raw::exfat::BootSector>(sector);
        hadris_fat_raw::exfat::parse_boot(&boot).is_ok()
    } else {
        false
    }
}

/// Checks a 512-byte sector to determine if it is a valid FAT32 boot sector.
fn is_fat32_boot_sector(sector: &[u8; 512]) -> bool {
    if let Ok(geo) = hadris_fat_raw::parse_boot(sector) {
        geo.kind() == hadris_fat_raw::FatKind::Fat32
    } else {
        false
    }
}

/// Probes a sector for known filesystems (exFAT first, then FAT32).
fn probe_boot_sector(sector: &[u8; 512]) -> FilesystemKind {
    if is_exfat_boot_sector(sector) {
        FilesystemKind::ExFat
    } else if is_fat32_boot_sector(sector) {
        FilesystemKind::Fat32
    } else {
        FilesystemKind::Unknown
    }
}

/// Detects whether a partition or disk region hosts a recognized filesystem (FAT32 or exFAT).
///
/// This function never panics. If the partition is shorter than 512 bytes or
/// reading fails, it returns [`FilesystemKind::Unknown`].
///
/// Detection checks sector 0 of the partition first. If unrecognized, it checks
/// the exFAT backup boot sector at `partition_offset + 12 * sector_size` and the
/// FAT32 backup boot sector at `partition_offset + 6 * 512` if within `partition_len`.
#[must_use]
pub fn detect_filesystem<R: ReadSource + ?Sized>(
    source: &mut R,
    partition_offset: u64,
    partition_len: u64,
) -> FilesystemKind {
    if partition_len < 512 {
        return FilesystemKind::Unknown;
    }

    let disk_size = source.size_bytes();
    let sector_size = u64::from(source.sector_size().max(512));

    // Helper to safely read 512 bytes at an absolute byte offset
    let mut read_sector = |off: u64| -> Option<[u8; 512]> {
        let end = off.checked_add(512)?;
        if end > disk_size {
            return None;
        }
        let mut buf = [0u8; 512];
        source.read_exact_at(off, &mut buf).ok().map(|()| buf)
    };

    // 1. Primary check: sector 0 of the partition
    if let Some(sector) = read_sector(partition_offset) {
        let kind = probe_boot_sector(&sector);
        if kind != FilesystemKind::Unknown {
            return kind;
        }
    }

    // 2. Backup check for exFAT at partition_offset + 12 * sector_size
    if let Some(exfat_backup_rel) = 12u64.checked_mul(sector_size) {
        if exfat_backup_rel
            .checked_add(512)
            .is_some_and(|end| end <= partition_len)
        {
            if let Some(abs_offset) = partition_offset.checked_add(exfat_backup_rel) {
                if let Some(sector) = read_sector(abs_offset) {
                    if is_exfat_boot_sector(&sector) {
                        return FilesystemKind::ExFat;
                    }
                }
            }
        }
    }

    // 3. Backup check for FAT32 at partition_offset + 6 * 512
    let fat32_backup_rel = 6u64 * 512;
    if fat32_backup_rel + 512 <= partition_len {
        if let Some(abs_offset) = partition_offset.checked_add(fat32_backup_rel) {
            if let Some(sector) = read_sector(abs_offset) {
                if is_fat32_boot_sector(&sector) {
                    return FilesystemKind::Fat32;
                }
            }
        }
    }

    FilesystemKind::Unknown
}

/// Parses partition tables on `source`, identifying Superfloppy, GPT, or MBR schemes.
///
/// # Errors
///
/// Returns [`RecoveryError::Parse`] if partition structures are corrupt, overlap,
/// exceed disk boundaries, or if disk size is smaller than 512 bytes.
/// Returns [`RecoveryError::SourceIo`] on underlying device read failures.
pub fn parse_partitions<R: ReadSource + ?Sized>(
    source: &mut R,
) -> Result<Vec<PartitionInfo>, RecoveryError> {
    let sector_size = u64::from(source.sector_size().max(512));
    let disk_size = source.size_bytes();

    if disk_size < 512 {
        return Err(RecoveryError::Parse(
            "disk smaller than 512 bytes".to_string(),
        ));
    }

    // Read sector 0
    let mut sector0 = [0u8; 512];
    source.read_exact_at(0, &mut sector0)?;

    // a) Superfloppy check:
    // Check if LBA 0 is directly a valid FAT32 or exFAT boot sector.
    let direct_fs = detect_filesystem(source, 0, disk_size);
    if direct_fs == FilesystemKind::Fat32 || direct_fs == FilesystemKind::ExFat {
        return Ok(vec![PartitionInfo {
            index: 0,
            scheme: PartitionScheme::Superfloppy,
            byte_offset: 0,
            byte_len: disk_size,
            type_id: "superfloppy".to_string(),
            name: None,
            filesystem: direct_fs,
        }]);
    }

    // b) GPT check:
    // Check if MBR has a protective partition (type 0xEE) or LBA 1 begins with "EFI PART".
    let has_protective_mbr = (0..4).any(|i| {
        let entry_offset = 446 + i * 16;
        sector0[entry_offset + 4] == 0xEE
    });

    let mut lba1_starts_with_efi_part = false;
    let lba1_offset = sector_size;
    if let Some(lba1_end) = lba1_offset.checked_add(sector_size) {
        if lba1_end <= disk_size {
            let mut sig_buf = [0u8; 8];
            if source.read_exact_at(lba1_offset, &mut sig_buf).is_ok() && &sig_buf == b"EFI PART" {
                lba1_starts_with_efi_part = true;
            }
        }
    }

    if has_protective_mbr || lba1_starts_with_efi_part {
        return parse_gpt(source, sector_size, disk_size);
    }

    // c) MBR check
    parse_mbr(source, &sector0, sector_size, disk_size)
}

/// Parses GUID Partition Table (GPT) starting at LBA 1.
fn parse_gpt<R: ReadSource + ?Sized>(
    source: &mut R,
    sector_size: u64,
    disk_size: u64,
) -> Result<Vec<PartitionInfo>, RecoveryError> {
    let lba1_offset = sector_size;
    let lba1_end = lba1_offset
        .checked_add(sector_size)
        .ok_or_else(|| RecoveryError::Parse("GPT LBA 1 offset overflow".to_string()))?;

    if lba1_end > disk_size {
        return Err(RecoveryError::Parse(
            "GPT LBA 1 extends beyond disk size".to_string(),
        ));
    }

    let sector_size_usize = usize::try_from(sector_size)
        .map_err(|_| RecoveryError::Parse("sector size exceeds usize".to_string()))?;

    let mut lba1_buf = vec![0u8; sector_size_usize];
    source.read_exact_at(lba1_offset, &mut lba1_buf)?;

    // 1. Verify signature == "EFI PART"
    if &lba1_buf[..8] != b"EFI PART" {
        return Err(RecoveryError::Parse(
            "invalid GPT header signature (expected EFI PART)".to_string(),
        ));
    }

    // 2. Verify header_size
    let header_size = u32::from_le_bytes(
        lba1_buf[12..16]
            .try_into()
            .map_err(|_| RecoveryError::Parse("invalid GPT header size bytes".to_string()))?,
    );
    if header_size < 92 || u64::from(header_size) > sector_size {
        return Err(RecoveryError::Parse(format!(
            "invalid GPT header size: {header_size} (sector size: {sector_size})"
        )));
    }

    // 3. Verify header CRC32 with bytes 16..20 zeroed
    let recorded_header_crc = u32::from_le_bytes(
        lba1_buf[16..20]
            .try_into()
            .map_err(|_| RecoveryError::Parse("invalid GPT header CRC bytes".to_string()))?,
    );
    let mut header_copy = lba1_buf[..header_size as usize].to_vec();
    header_copy[16..20].fill(0);
    let computed_header_crc = crc32fast::hash(&header_copy);
    if computed_header_crc != recorded_header_crc {
        return Err(RecoveryError::Parse(format!(
            "GPT header CRC32 mismatch: recorded 0x{recorded_header_crc:08X}, computed 0x{computed_header_crc:08X}"
        )));
    }

    // 4. Verify my_lba == 1
    let my_lba = u64::from_le_bytes(
        lba1_buf[24..32]
            .try_into()
            .map_err(|_| RecoveryError::Parse("invalid GPT my_lba bytes".to_string()))?,
    );
    if my_lba != 1 {
        return Err(RecoveryError::Parse(format!(
            "invalid GPT my_lba: {my_lba} (expected 1)"
        )));
    }

    // 5. Read header fields
    let first_usable_lba = u64::from_le_bytes(
        lba1_buf[40..48]
            .try_into()
            .map_err(|_| RecoveryError::Parse("invalid GPT first_usable_lba bytes".to_string()))?,
    );
    let last_usable_lba = u64::from_le_bytes(
        lba1_buf[48..56]
            .try_into()
            .map_err(|_| RecoveryError::Parse("invalid GPT last_usable_lba bytes".to_string()))?,
    );
    let partition_entry_lba =
        u64::from_le_bytes(lba1_buf[72..80].try_into().map_err(|_| {
            RecoveryError::Parse("invalid GPT partition_entry_lba bytes".to_string())
        })?);
    let num_partition_entries = u32::from_le_bytes(lba1_buf[80..84].try_into().map_err(|_| {
        RecoveryError::Parse("invalid GPT num_partition_entries bytes".to_string())
    })?);
    let size_of_partition_entry =
        u32::from_le_bytes(lba1_buf[84..88].try_into().map_err(|_| {
            RecoveryError::Parse("invalid GPT size_of_partition_entry bytes".to_string())
        })?);
    let partition_entry_array_crc32 = u32::from_le_bytes(
        lba1_buf[88..92]
            .try_into()
            .map_err(|_| RecoveryError::Parse("invalid GPT entry array CRC bytes".to_string()))?,
    );

    // 6. Enforce bounds
    if first_usable_lba > last_usable_lba {
        return Err(RecoveryError::Parse(format!(
            "GPT first_usable_lba ({first_usable_lba}) > last_usable_lba ({last_usable_lba})"
        )));
    }
    if num_partition_entries > 1024 {
        return Err(RecoveryError::Parse(format!(
            "GPT num_partition_entries ({num_partition_entries}) exceeds maximum (1024)"
        )));
    }
    if !(128..=4096).contains(&size_of_partition_entry) || size_of_partition_entry % 8 != 0 {
        return Err(RecoveryError::Parse(format!(
            "GPT size_of_partition_entry ({size_of_partition_entry}) invalid (must be 128..=4096 and multiple of 8)"
        )));
    }

    // 7. Compute total entry table bytes and verify array CRC32
    let total_entry_bytes = u64::from(num_partition_entries)
        .checked_mul(u64::from(size_of_partition_entry))
        .ok_or_else(|| {
            RecoveryError::Parse("GPT total partition entry table bytes overflow".to_string())
        })?;

    let entry_table_offset = partition_entry_lba
        .checked_mul(sector_size)
        .ok_or_else(|| {
            RecoveryError::Parse("GPT partition entry table offset overflow".to_string())
        })?;

    let entry_table_end = entry_table_offset
        .checked_add(total_entry_bytes)
        .ok_or_else(|| {
            RecoveryError::Parse("GPT partition entry table end overflow".to_string())
        })?;

    if entry_table_end > disk_size {
        return Err(RecoveryError::Parse(format!(
            "GPT partition entry table end ({entry_table_end}) exceeds disk size ({disk_size})"
        )));
    }

    let total_entry_bytes_usize = usize::try_from(total_entry_bytes)
        .map_err(|_| RecoveryError::Parse("GPT entry table size exceeds usize".to_string()))?;

    let mut entry_table = vec![0u8; total_entry_bytes_usize];
    source.read_exact_at(entry_table_offset, &mut entry_table)?;

    let computed_array_crc = crc32fast::hash(&entry_table);
    if computed_array_crc != partition_entry_array_crc32 {
        return Err(RecoveryError::Parse(format!(
            "GPT partition entry array CRC32 mismatch: recorded 0x{partition_entry_array_crc32:08X}, computed 0x{computed_array_crc:08X}"
        )));
    }

    // 8. Parse entries
    let entry_stride = size_of_partition_entry as usize;
    let mut partitions = Vec::new();

    for chunk in entry_table.chunks_exact(entry_stride) {
        let type_guid_bytes = &chunk[0..16];
        if type_guid_bytes.iter().all(|&b| b == 0) {
            continue; // Unused entry
        }

        let first_lba = u64::from_le_bytes(
            chunk[32..40]
                .try_into()
                .map_err(|_| RecoveryError::Parse("invalid entry first_lba bytes".to_string()))?,
        );
        let last_lba = u64::from_le_bytes(
            chunk[40..48]
                .try_into()
                .map_err(|_| RecoveryError::Parse("invalid entry last_lba bytes".to_string()))?,
        );

        if first_lba < first_usable_lba || last_lba < first_lba || last_lba > last_usable_lba {
            return Err(RecoveryError::Parse(format!(
                "GPT partition entry LBA range [{first_lba}, {last_lba}] outside usable range [{first_usable_lba}, {last_usable_lba}]"
            )));
        }

        let byte_offset = first_lba.checked_mul(sector_size).ok_or_else(|| {
            RecoveryError::Parse("GPT partition byte_offset overflow".to_string())
        })?;

        let sectors = last_lba
            .checked_sub(first_lba)
            .and_then(|s| s.checked_add(1))
            .ok_or_else(|| {
                RecoveryError::Parse("GPT partition sector count overflow".to_string())
            })?;

        let byte_len = sectors
            .checked_mul(sector_size)
            .ok_or_else(|| RecoveryError::Parse("GPT partition byte_len overflow".to_string()))?;

        let part_end = byte_offset
            .checked_add(byte_len)
            .ok_or_else(|| RecoveryError::Parse("GPT partition end offset overflow".to_string()))?;

        if part_end > disk_size {
            return Err(RecoveryError::Parse(format!(
                "GPT partition [{byte_offset}..{part_end}) exceeds disk size ({disk_size})"
            )));
        }

        // Decode UTF-16LE partition name (bytes 56..min(128, chunk.len()))
        let name_slice = &chunk[56..chunk.len().min(128)];
        let u16_chars: Vec<u16> = name_slice
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&c| c != 0)
            .collect();
        let name_str: String = char::decode_utf16(u16_chars)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect();
        let name = if name_str.trim().is_empty() {
            None
        } else {
            Some(name_str.trim().to_string())
        };

        // Format type_guid as XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        let d1 = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let d2 = u16::from_le_bytes(chunk[4..6].try_into().unwrap());
        let d3 = u16::from_le_bytes(chunk[6..8].try_into().unwrap());
        let type_id = format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            d1,
            d2,
            d3,
            chunk[8],
            chunk[9],
            chunk[10],
            chunk[11],
            chunk[12],
            chunk[13],
            chunk[14],
            chunk[15]
        );

        let filesystem = detect_filesystem(source, byte_offset, byte_len);
        let index = partitions.len() as u32;

        partitions.push(PartitionInfo {
            index,
            scheme: PartitionScheme::Gpt,
            byte_offset,
            byte_len,
            type_id,
            name,
            filesystem,
        });
    }

    // Verify no two GPT partitions overlap
    for i in 0..partitions.len() {
        for j in (i + 1)..partitions.len() {
            let p1 = &partitions[i];
            let p2 = &partitions[j];
            let end1 = p1.byte_offset + p1.byte_len;
            let end2 = p2.byte_offset + p2.byte_len;
            if p1.byte_offset < end2 && p2.byte_offset < end1 {
                return Err(RecoveryError::Parse(format!(
                    "overlapping GPT partitions detected: index {i} ([{}..{end1})) and index {j} ([{}..{end2}))",
                    p1.byte_offset, p2.byte_offset
                )));
            }
        }
    }

    Ok(partitions)
}

/// Raw representation of an MBR partition entry.
#[derive(Debug, Clone, Copy)]
struct RawMbrEntry {
    part_type: u8,
    first_lba: u32,
    byte_offset: u64,
    byte_len: u64,
}

/// Parses Master Boot Record (MBR) and Extended Boot Record (EBR) chains.
fn parse_mbr<R: ReadSource + ?Sized>(
    source: &mut R,
    sector0: &[u8; 512],
    sector_size: u64,
    disk_size: u64,
) -> Result<Vec<PartitionInfo>, RecoveryError> {
    // 1. Verify boot signature 0x55AA
    if sector0[510] != 0x55 || sector0[511] != 0xAA {
        return Err(RecoveryError::Parse(format!(
            "invalid MBR boot signature: expected 0x55AA, found 0x{:02X}{:02X}",
            sector0[510], sector0[511]
        )));
    }

    // 2. Parse the 4 16-byte partition entries at 446..510
    let mut raw_entries = Vec::new();
    for i in 0..4 {
        let off = 446 + i * 16;
        let entry = &sector0[off..off + 16];
        let part_type = entry[4];
        let first_lba = u32::from_le_bytes(entry[8..12].try_into().unwrap());
        let sector_count = u32::from_le_bytes(entry[12..16].try_into().unwrap());

        if part_type == 0 || sector_count == 0 {
            continue;
        }

        let byte_offset = u64::from(first_lba)
            .checked_mul(sector_size)
            .ok_or_else(|| {
                RecoveryError::Parse("MBR partition byte_offset overflow".to_string())
            })?;
        let byte_len = u64::from(sector_count)
            .checked_mul(sector_size)
            .ok_or_else(|| RecoveryError::Parse("MBR partition byte_len overflow".to_string()))?;
        let end_offset = byte_offset
            .checked_add(byte_len)
            .ok_or_else(|| RecoveryError::Parse("MBR partition end offset overflow".to_string()))?;

        if end_offset > disk_size {
            return Err(RecoveryError::Parse(format!(
                "MBR partition {i} extends beyond disk size: offset {byte_offset} + len {byte_len} = {end_offset} > disk size {disk_size}"
            )));
        }

        raw_entries.push(RawMbrEntry {
            part_type,
            first_lba,
            byte_offset,
            byte_len,
        });
    }

    // 3. Reject overlapping primary partitions
    for i in 0..raw_entries.len() {
        for j in (i + 1)..raw_entries.len() {
            let e1 = &raw_entries[i];
            let e2 = &raw_entries[j];
            let end1 = e1.byte_offset + e1.byte_len;
            let end2 = e2.byte_offset + e2.byte_len;
            if e1.byte_offset < end2 && e2.byte_offset < end1 {
                return Err(RecoveryError::Parse(format!(
                    "overlapping MBR primary partitions detected: offset {}..{end1} and {}..{end2}",
                    e1.byte_offset, e2.byte_offset
                )));
            }
        }
    }

    // 4. Extract primary non-extended partitions and walk EBR chains
    let mut partitions = Vec::new();
    for entry in raw_entries {
        let is_extended = matches!(entry.part_type, 0x05 | 0x0F | 0x85);
        if !is_extended {
            let filesystem = detect_filesystem(source, entry.byte_offset, entry.byte_len);
            let index = partitions.len() as u32;
            partitions.push(PartitionInfo {
                index,
                scheme: PartitionScheme::Mbr,
                byte_offset: entry.byte_offset,
                byte_len: entry.byte_len,
                type_id: format!("0x{:02X}", entry.part_type),
                name: None,
                filesystem,
            });
        } else {
            // Walk EBR chain starting at ext_base_lba
            let ext_base_lba = u64::from(entry.first_lba);
            let mut current_ebr_lba = ext_base_lba;
            let mut visited = HashSet::new();
            visited.insert(current_ebr_lba);
            let mut hops = 0;

            loop {
                if hops >= 32 {
                    return Err(RecoveryError::Parse(
                        "EBR chain exceeded maximum depth of 32 hops (possible cyclic loop)"
                            .to_string(),
                    ));
                }
                hops += 1;

                let ebr_offset = current_ebr_lba.checked_mul(sector_size).ok_or_else(|| {
                    RecoveryError::Parse("EBR sector offset overflow".to_string())
                })?;
                let ebr_end = ebr_offset
                    .checked_add(512)
                    .ok_or_else(|| RecoveryError::Parse("EBR sector end overflow".to_string()))?;
                if ebr_end > disk_size {
                    return Err(RecoveryError::Parse(format!(
                        "EBR offset {ebr_offset} extends beyond disk size {disk_size}"
                    )));
                }

                let mut ebr_sector = [0u8; 512];
                source.read_exact_at(ebr_offset, &mut ebr_sector)?;

                if ebr_sector[510] != 0x55 || ebr_sector[511] != 0xAA {
                    return Err(RecoveryError::Parse(format!(
                        "invalid EBR boot signature at LBA {current_ebr_lba} (expected 0x55AA)"
                    )));
                }

                // Entry 1: Logical partition definition
                let e1 = &ebr_sector[446..462];
                let e1_type = e1[4];
                let e1_lba_offset = u32::from_le_bytes(e1[8..12].try_into().unwrap());
                let e1_sectors = u32::from_le_bytes(e1[12..16].try_into().unwrap());

                if e1_type != 0 && e1_sectors != 0 {
                    let logical_lba = current_ebr_lba
                        .checked_add(u64::from(e1_lba_offset))
                        .ok_or_else(|| {
                            RecoveryError::Parse("logical partition LBA overflow".to_string())
                        })?;
                    let byte_offset = logical_lba.checked_mul(sector_size).ok_or_else(|| {
                        RecoveryError::Parse("logical partition byte_offset overflow".to_string())
                    })?;
                    let byte_len =
                        u64::from(e1_sectors)
                            .checked_mul(sector_size)
                            .ok_or_else(|| {
                                RecoveryError::Parse(
                                    "logical partition byte_len overflow".to_string(),
                                )
                            })?;
                    let end_offset = byte_offset.checked_add(byte_len).ok_or_else(|| {
                        RecoveryError::Parse("logical partition end offset overflow".to_string())
                    })?;

                    if end_offset > disk_size {
                        return Err(RecoveryError::Parse(format!(
                            "logical partition extends beyond disk size: offset {byte_offset} + len {byte_len} = {end_offset} > {disk_size}"
                        )));
                    }

                    let filesystem = detect_filesystem(source, byte_offset, byte_len);
                    let index = partitions.len() as u32;
                    partitions.push(PartitionInfo {
                        index,
                        scheme: PartitionScheme::Mbr,
                        byte_offset,
                        byte_len,
                        type_id: format!("0x{:02X}", e1_type),
                        name: None,
                        filesystem,
                    });
                }

                // Entry 2: Pointer to next EBR
                let e2 = &ebr_sector[462..478];
                let e2_type = e2[4];
                let e2_lba_offset = u32::from_le_bytes(e2[8..12].try_into().unwrap());
                let e2_sectors = u32::from_le_bytes(e2[12..16].try_into().unwrap());

                if e2_sectors == 0 || e2_type == 0 {
                    break; // End of EBR chain
                }

                let next_ebr_lba = ext_base_lba
                    .checked_add(u64::from(e2_lba_offset))
                    .ok_or_else(|| RecoveryError::Parse("next EBR LBA overflow".to_string()))?;

                if visited.contains(&next_ebr_lba) {
                    return Err(RecoveryError::Parse(format!(
                        "cyclic EBR chain detected: LBA {next_ebr_lba} already visited"
                    )));
                }

                visited.insert(next_ebr_lba);
                current_ebr_lba = next_ebr_lba;
            }
        }
    }

    // Reject overlapping partitions in final list
    for i in 0..partitions.len() {
        for j in (i + 1)..partitions.len() {
            let p1 = &partitions[i];
            let p2 = &partitions[j];
            let end1 = p1.byte_offset + p1.byte_len;
            let end2 = p2.byte_offset + p2.byte_len;
            if p1.byte_offset < end2 && p2.byte_offset < end1 {
                return Err(RecoveryError::Parse(format!(
                    "overlapping partitions detected: index {i} ([{}..{end1})) and index {j} ([{}..{end2}))",
                    p1.byte_offset, p2.byte_offset
                )));
            }
        }
    }

    Ok(partitions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MemorySource;

    /// Generates a valid FAT32 boot sector for testing.
    fn create_test_fat32_boot_sector(total_sectors: u32) -> [u8; 512] {
        let mut sector = [0u8; 512];
        sector[0] = 0xEB;
        sector[1] = 0x58;
        sector[2] = 0x90;
        sector[3..11].copy_from_slice(b"MSWIN4.1");
        sector[11..13].copy_from_slice(&512u16.to_le_bytes()); // 512 bytes per sector
        sector[13] = 8; // 8 sectors per cluster (4KB)
        sector[14..16].copy_from_slice(&32u16.to_le_bytes()); // 32 reserved sectors
        sector[16] = 2; // 2 FATs
        sector[17..19].copy_from_slice(&0u16.to_le_bytes()); // 0 root entries
        sector[19..21].copy_from_slice(&0u16.to_le_bytes()); // 0 16-bit total sectors
        sector[21] = 0xF8; // media descriptor
        sector[22..24].copy_from_slice(&0u16.to_le_bytes());
        sector[24..26].copy_from_slice(&32u16.to_le_bytes());
        sector[26..28].copy_from_slice(&64u16.to_le_bytes());
        sector[28..32].copy_from_slice(&0u32.to_le_bytes());
        sector[32..36].copy_from_slice(&total_sectors.to_le_bytes());

        // Extended BPB for FAT32
        sector[36..40].copy_from_slice(&2048u32.to_le_bytes()); // sectors per fat (2048 * 512 / 4 = 262,144 clusters)
        sector[40..42].copy_from_slice(&0u16.to_le_bytes());
        sector[42..44].copy_from_slice(&0u16.to_le_bytes()); // version 0.0
        sector[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster 2
        sector[48..50].copy_from_slice(&1u16.to_le_bytes()); // fsinfo sector 1
        sector[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup boot sector 6
        sector[64] = 0x80;
        sector[66] = 0x29;
        sector[67..71].copy_from_slice(&0x12345678u32.to_le_bytes());
        sector[71..82].copy_from_slice(b"NO NAME    ");
        sector[82..90].copy_from_slice(b"FAT32   ");
        sector[510] = 0x55;
        sector[511] = 0xAA;
        sector
    }

    /// Generates a valid exFAT boot sector for testing.
    fn create_test_exfat_boot_sector(volume_len_sectors: u64) -> [u8; 512] {
        let mut boot: hadris_fat_raw::exfat::BootSector = bytemuck::Zeroable::zeroed();
        boot.jump_boot = [0xEB, 0x76, 0x90];
        boot.file_system_name = *b"EXFAT   ";
        boot.partition_offset.set(0);
        boot.volume_length.set(volume_len_sectors.max(4096));
        boot.fat_offset.set(24);
        boot.fat_length.set(256);
        boot.cluster_heap_offset.set(300);
        boot.cluster_count.set(100);
        boot.first_cluster_of_root_directory.set(2);
        boot.volume_serial_number.set(0x12345678);
        boot.file_system_revision.set(0x0100);
        boot.volume_flags.set(0);
        boot.bytes_per_sector_shift = 9; // 512 bytes
        boot.sectors_per_cluster_shift = 3; // 8 sectors per cluster
        boot.number_of_fats = 1;
        boot.drive_select = 0x80;
        boot.percent_in_use = 0;
        boot.boot_signature.set(0xAA55);

        let mut sector = [0u8; 512];
        sector.copy_from_slice(bytemuck::bytes_of(&boot));
        sector
    }

    /// Generates a valid GPT disk image for testing.
    fn create_test_gpt_disk(disk_sectors: u64, partition_sectors: u64) -> Vec<u8> {
        let sector_size = 512usize;
        let total_bytes = (disk_sectors as usize) * sector_size;
        let mut data = vec![0u8; total_bytes];

        // Sector 0: Protective MBR
        data[446] = 0x00;
        data[446 + 4] = 0xEE; // protective partition
        data[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes()); // first_lba = 1
        let mbr_sectors = (disk_sectors.saturating_sub(1).min(u32::MAX as u64)) as u32;
        data[446 + 12..446 + 16].copy_from_slice(&mbr_sectors.to_le_bytes());
        data[510] = 0x55;
        data[511] = 0xAA;

        // Entries: 128 entries of 128 bytes = 16384 bytes = 32 sectors (LBA 2..34)
        let num_entries = 128u32;
        let entry_size = 128u32;
        let entry_table_bytes = (num_entries * entry_size) as usize;
        let mut entries = vec![0u8; entry_table_bytes];

        // Entry 0: Microsoft Basic Data GUID: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
        let type_guid: [u8; 16] = [
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
            0x99, 0xC7,
        ];
        entries[0..16].copy_from_slice(&type_guid);
        entries[16..32].copy_from_slice(&[0x11; 16]); // unique guid

        let first_usable_lba = 34u64;
        let last_usable_lba = disk_sectors.saturating_sub(34);
        let part_first_lba = 100u64;
        let part_last_lba = part_first_lba + partition_sectors.saturating_sub(1);

        entries[32..40].copy_from_slice(&part_first_lba.to_le_bytes());
        entries[40..48].copy_from_slice(&part_last_lba.to_le_bytes());

        // Name: "VIDEOS" in UTF-16LE
        let name_utf16: Vec<u16> = "VIDEOS".encode_utf16().collect();
        for (i, &u) in name_utf16.iter().enumerate() {
            let off = 56 + i * 2;
            entries[off..off + 2].copy_from_slice(&u.to_le_bytes());
        }

        let array_crc = crc32fast::hash(&entries);

        // Copy entries to LBA 2 (offset 1024)
        data[1024..1024 + entry_table_bytes].copy_from_slice(&entries);

        // LBA 1: GPT Header
        let mut header = [0u8; 512];
        header[0..8].copy_from_slice(b"EFI PART");
        header[8..12].copy_from_slice(&0x00010000u32.to_le_bytes()); // revision 1.0
        header[12..16].copy_from_slice(&92u32.to_le_bytes()); // header size
        header[16..20].copy_from_slice(&0u32.to_le_bytes()); // zeroed for CRC
        header[20..24].copy_from_slice(&0u32.to_le_bytes()); // reserved
        header[24..32].copy_from_slice(&1u64.to_le_bytes()); // my_lba
        header[32..40].copy_from_slice(&(disk_sectors - 1).to_le_bytes()); // alternate_lba
        header[40..48].copy_from_slice(&first_usable_lba.to_le_bytes());
        header[48..56].copy_from_slice(&last_usable_lba.to_le_bytes());
        header[56..72].copy_from_slice(&[0x22; 16]); // disk guid
        header[72..80].copy_from_slice(&2u64.to_le_bytes()); // partition_entry_lba
        header[80..84].copy_from_slice(&num_entries.to_le_bytes());
        header[84..88].copy_from_slice(&entry_size.to_le_bytes());
        header[88..92].copy_from_slice(&array_crc.to_le_bytes());

        let header_crc = crc32fast::hash(&header[..92]);
        header[16..20].copy_from_slice(&header_crc.to_le_bytes());

        // Copy header to LBA 1 (offset 512)
        data[512..1024].copy_from_slice(&header);

        data
    }

    /// Generates a valid MBR disk image with 1 primary and 2 logical partitions.
    fn create_test_mbr_disk(disk_sectors: u64) -> Vec<u8> {
        let total_bytes = (disk_sectors as usize) * 512;
        let mut data = vec![0u8; total_bytes];

        // Primary partition 1: LBA 2048..4096 (2048 sectors), type 0x07
        data[446] = 0x80;
        data[446 + 4] = 0x07;
        data[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        data[446 + 12..446 + 16].copy_from_slice(&2048u32.to_le_bytes());

        // Extended partition (Entry 2): LBA 4096..8192 (4096 sectors), type 0x0F
        data[462] = 0x00;
        data[462 + 4] = 0x0F;
        data[462 + 8..462 + 12].copy_from_slice(&4096u32.to_le_bytes());
        data[462 + 12..462 + 16].copy_from_slice(&4096u32.to_le_bytes());

        data[510] = 0x55;
        data[511] = 0xAA;

        // EBR 1 at LBA 4096 (offset 4096 * 512 = 2097152)
        let ebr1_offset = 4096 * 512;
        // Entry 1: Logical partition at LBA 4160 (rel 64), 1000 sectors, type 0x0B
        data[ebr1_offset + 446 + 4] = 0x0B;
        data[ebr1_offset + 446 + 8..ebr1_offset + 446 + 12].copy_from_slice(&64u32.to_le_bytes());
        data[ebr1_offset + 446 + 12..ebr1_offset + 446 + 16]
            .copy_from_slice(&1000u32.to_le_bytes());
        // Entry 2: Pointer to next EBR at LBA 6144 (rel 2048 from ext_base_lba 4096), 2048 sectors, type 0x05
        data[ebr1_offset + 462 + 4] = 0x05;
        data[ebr1_offset + 462 + 8..ebr1_offset + 462 + 12].copy_from_slice(&2048u32.to_le_bytes());
        data[ebr1_offset + 462 + 12..ebr1_offset + 462 + 16]
            .copy_from_slice(&2048u32.to_le_bytes());
        data[ebr1_offset + 510] = 0x55;
        data[ebr1_offset + 511] = 0xAA;

        // EBR 2 at LBA 6144 (offset 6144 * 512 = 3145728)
        let ebr2_offset = 6144 * 512;
        // Entry 1: Logical partition at LBA 6208 (rel 64), 800 sectors, type 0x07
        data[ebr2_offset + 446 + 4] = 0x07;
        data[ebr2_offset + 446 + 8..ebr2_offset + 446 + 12].copy_from_slice(&64u32.to_le_bytes());
        data[ebr2_offset + 446 + 12..ebr2_offset + 446 + 16].copy_from_slice(&800u32.to_le_bytes());
        // Entry 2: Zeros (end of chain)
        data[ebr2_offset + 510] = 0x55;
        data[ebr2_offset + 511] = 0xAA;

        data
    }

    #[test]
    fn test_truncated_disk_smaller_than_512() {
        let mut src_empty = MemorySource::new(vec![]);
        assert!(matches!(
            parse_partitions(&mut src_empty),
            Err(RecoveryError::Parse(msg)) if msg.contains("disk smaller than 512 bytes")
        ));
        assert_eq!(
            detect_filesystem(&mut src_empty, 0, 0),
            FilesystemKind::Unknown
        );

        let mut src_short = MemorySource::new(vec![0u8; 300]);
        assert!(matches!(
            parse_partitions(&mut src_short),
            Err(RecoveryError::Parse(msg)) if msg.contains("disk smaller than 512 bytes")
        ));
        assert_eq!(
            detect_filesystem(&mut src_short, 0, 300),
            FilesystemKind::Unknown
        );
    }

    #[test]
    fn test_superfloppy_fat32_detection() {
        let total_sectors = 2_000_000u32;
        let mut disk = vec![0u8; (total_sectors as usize) * 512];
        let fat32_boot = create_test_fat32_boot_sector(total_sectors);
        disk[..512].copy_from_slice(&fat32_boot);

        let mut src = MemorySource::new(disk);
        let partitions = parse_partitions(&mut src).expect("superfloppy FAT32 should parse");

        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].scheme, PartitionScheme::Superfloppy);
        assert_eq!(partitions[0].filesystem, FilesystemKind::Fat32);
        assert_eq!(partitions[0].byte_offset, 0);
        assert_eq!(partitions[0].byte_len, u64::from(total_sectors) * 512);
        assert_eq!(partitions[0].type_id, "superfloppy");
        assert_eq!(partitions[0].name, None);
    }

    #[test]
    fn test_superfloppy_exfat_detection() {
        let total_sectors = 10_000u64;
        let mut disk = vec![0u8; (total_sectors as usize) * 512];
        let exfat_boot = create_test_exfat_boot_sector(total_sectors);
        disk[..512].copy_from_slice(&exfat_boot);

        let mut src = MemorySource::new(disk);
        let partitions = parse_partitions(&mut src).expect("superfloppy exFAT should parse");

        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].scheme, PartitionScheme::Superfloppy);
        assert_eq!(partitions[0].filesystem, FilesystemKind::ExFat);
        assert_eq!(partitions[0].byte_offset, 0);
        assert_eq!(partitions[0].byte_len, total_sectors * 512);
        assert_eq!(partitions[0].type_id, "superfloppy");
        assert_eq!(partitions[0].name, None);
    }

    #[test]
    fn test_backup_boot_sector_detection_exfat_and_fat32() {
        // 1. exFAT backup at sector 12 (when sector 0 is zeroes)
        let total_sectors = 10_000u64;
        let mut exfat_disk = vec![0u8; (total_sectors as usize) * 512];
        let exfat_boot = create_test_exfat_boot_sector(total_sectors);
        exfat_disk[12 * 512..13 * 512].copy_from_slice(&exfat_boot);

        let mut src_exfat = MemorySource::new(exfat_disk);
        let fs_exfat = detect_filesystem(&mut src_exfat, 0, total_sectors * 512);
        assert_eq!(fs_exfat, FilesystemKind::ExFat);

        // 2. FAT32 backup at sector 6 (when sector 0 is zeroes)
        let fat_sectors = 2_000_000u32;
        let mut fat32_disk = vec![0u8; (fat_sectors as usize) * 512];
        let fat32_boot = create_test_fat32_boot_sector(fat_sectors);
        fat32_disk[6 * 512..7 * 512].copy_from_slice(&fat32_boot);

        let mut src_fat32 = MemorySource::new(fat32_disk);
        let fs_fat32 = detect_filesystem(&mut src_fat32, 0, u64::from(fat_sectors) * 512);
        assert_eq!(fs_fat32, FilesystemKind::Fat32);
    }

    #[test]
    fn test_valid_gpt_parsing() {
        let disk = create_test_gpt_disk(2048, 500);
        let mut src = MemorySource::new(disk);
        let partitions = parse_partitions(&mut src).expect("valid GPT should parse");

        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].scheme, PartitionScheme::Gpt);
        assert_eq!(partitions[0].index, 0);
        assert_eq!(partitions[0].byte_offset, 100 * 512);
        assert_eq!(partitions[0].byte_len, 500 * 512);
        assert_eq!(
            partitions[0].type_id,
            "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
        );
        assert_eq!(partitions[0].name.as_deref(), Some("VIDEOS"));
    }

    #[test]
    fn test_gpt_corrupted_header_crc32() {
        let mut disk = create_test_gpt_disk(2048, 500);
        disk[512 + 16] ^= 0xFF; // Invalidate header CRC

        let mut src = MemorySource::new(disk);
        let res = parse_partitions(&mut src);
        assert!(matches!(
            res,
            Err(RecoveryError::Parse(msg)) if msg.contains("GPT header CRC32 mismatch")
        ));
    }

    #[test]
    fn test_gpt_corrupted_entry_array_crc32() {
        let mut disk = create_test_gpt_disk(2048, 500);
        disk[1024 + 10] ^= 0xFF; // Invalidate entry data

        let mut src = MemorySource::new(disk);
        let res = parse_partitions(&mut src);
        assert!(matches!(
            res,
            Err(RecoveryError::Parse(msg)) if msg.contains("GPT partition entry array CRC32 mismatch")
        ));
    }

    #[test]
    fn test_gpt_oversized_num_partition_entries() {
        let mut disk = create_test_gpt_disk(2048, 500);
        disk[512 + 80..512 + 84].copy_from_slice(&2048u32.to_le_bytes()); // > 1024
        disk[512 + 16..512 + 20].copy_from_slice(&0u32.to_le_bytes());
        let new_crc = crc32fast::hash(&disk[512..512 + 92]);
        disk[512 + 16..512 + 20].copy_from_slice(&new_crc.to_le_bytes());

        let mut src = MemorySource::new(disk);
        let res = parse_partitions(&mut src);
        assert!(matches!(
            res,
            Err(RecoveryError::Parse(msg)) if msg.contains("exceeds maximum (1024)")
        ));
    }

    #[test]
    fn test_gpt_out_of_bounds_lba() {
        let mut disk = create_test_gpt_disk(2048, 500);
        // Modify last_lba of entry 0 to 5000 (exceeds disk sectors 2048)
        disk[1024 + 40..1024 + 48].copy_from_slice(&5000u64.to_le_bytes());
        let array_crc = crc32fast::hash(&disk[1024..1024 + 16384]);
        disk[512 + 88..512 + 92].copy_from_slice(&array_crc.to_le_bytes());
        disk[512 + 16..512 + 20].copy_from_slice(&0u32.to_le_bytes());
        let header_crc = crc32fast::hash(&disk[512..512 + 92]);
        disk[512 + 16..512 + 20].copy_from_slice(&header_crc.to_le_bytes());

        let mut src = MemorySource::new(disk);
        let res = parse_partitions(&mut src);
        assert!(matches!(
            res,
            Err(RecoveryError::Parse(msg)) if msg.contains("outside usable range")
        ));
    }

    #[test]
    fn test_valid_mbr_primary_and_extended_logical() {
        let disk = create_test_mbr_disk(10000);
        let mut src = MemorySource::new(disk);
        let partitions = parse_partitions(&mut src).expect("valid MBR should parse");

        assert_eq!(partitions.len(), 3);

        // Primary partition
        assert_eq!(partitions[0].scheme, PartitionScheme::Mbr);
        assert_eq!(partitions[0].index, 0);
        assert_eq!(partitions[0].byte_offset, 2048 * 512);
        assert_eq!(partitions[0].byte_len, 2048 * 512);
        assert_eq!(partitions[0].type_id, "0x07");

        // Logical partition 1
        assert_eq!(partitions[1].scheme, PartitionScheme::Mbr);
        assert_eq!(partitions[1].index, 1);
        assert_eq!(partitions[1].byte_offset, 4160 * 512);
        assert_eq!(partitions[1].byte_len, 1000 * 512);
        assert_eq!(partitions[1].type_id, "0x0B");

        // Logical partition 2
        assert_eq!(partitions[2].scheme, PartitionScheme::Mbr);
        assert_eq!(partitions[2].index, 2);
        assert_eq!(partitions[2].byte_offset, 6208 * 512);
        assert_eq!(partitions[2].byte_len, 800 * 512);
        assert_eq!(partitions[2].type_id, "0x07");
    }

    #[test]
    fn test_mbr_ebr_cyclic_loop_rejected() {
        let mut disk = create_test_mbr_disk(10000);
        let ebr2_offset = 6144 * 512;
        // Make EBR 2 point back to ext_base_lba (rel offset 0)
        disk[ebr2_offset + 462 + 4] = 0x05;
        disk[ebr2_offset + 462 + 8..ebr2_offset + 462 + 12].copy_from_slice(&0u32.to_le_bytes());
        disk[ebr2_offset + 462 + 12..ebr2_offset + 462 + 16].copy_from_slice(&100u32.to_le_bytes());

        let mut src = MemorySource::new(disk);
        let res = parse_partitions(&mut src);
        assert!(matches!(
            res,
            Err(RecoveryError::Parse(msg)) if msg.contains("cyclic EBR chain detected")
        ));
    }

    #[test]
    fn test_mbr_oversized_partition_rejected() {
        let mut disk = create_test_mbr_disk(10000);
        // Make primary partition 1 sector_count 100,000 (exceeds 10,000 sectors)
        disk[446 + 12..446 + 16].copy_from_slice(&100_000u32.to_le_bytes());

        let mut src = MemorySource::new(disk);
        let res = parse_partitions(&mut src);
        assert!(matches!(
            res,
            Err(RecoveryError::Parse(msg)) if msg.contains("extends beyond disk size")
        ));
    }

    #[test]
    fn test_mbr_overlapping_primary_partitions_rejected() {
        let mut disk = create_test_mbr_disk(10000);
        // Make extended partition start at 3000 instead of 4096 (overlaps 2048..4096)
        disk[462 + 8..462 + 12].copy_from_slice(&3000u32.to_le_bytes());

        let mut src = MemorySource::new(disk);
        let res = parse_partitions(&mut src);
        assert!(matches!(
            res,
            Err(RecoveryError::Parse(msg)) if msg.contains("overlapping MBR primary partitions detected")
        ));
    }
}
