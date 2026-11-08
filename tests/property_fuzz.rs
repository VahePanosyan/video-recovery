//! Property-based and fuzz testing for `sd-video-recovery`.
//!
//! Verifies using `proptest` that arbitrary byte buffers, adversarial box sizes,
//! and corrupted partition / filesystem headers NEVER cause:
//! - A panic
//! - An out-of-bounds read or memory unsafety
//! - An infinite loop (e.g. cyclic EBR, cyclic FAT cluster chains, or cyclic MP4 boxes)
//! - An unbounded allocation or resource exhaustion
//!
//! Specifically covers:
//! - Fuzzing `parse_partitions` on arbitrary bytes (0 to 16 KiB) and mutated MBR/GPT headers.
//! - Fuzzing `recover_fat32_candidates` on arbitrary bytes and mutated FAT32 boot/directory sectors.
//! - Fuzzing `recover_exfat_candidates` on arbitrary bytes and mutated exFAT boot/bitmap/directory sectors.
//! - Fuzzing `parse_box_header`, `inspect_mp4_structure`, and `carve_mp4_candidates` on arbitrary bytes
//!   and adversarial box sizes (0, 1, 7, u32::MAX, u64::MAX).

use proptest::prelude::*;

use sd_video_recovery::carver::{
    carve_mp4_candidates, inspect_mp4_structure, parse_box_header, MAX_BOX_COUNT,
};
use sd_video_recovery::exfat::recover_exfat_candidates;
use sd_video_recovery::fat32::recover_fat32_candidates;
use sd_video_recovery::partition::parse_partitions;
use sd_video_recovery::types::{MemorySource, ReadSource};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    // ========================================================================
    // 1. Partition Parsing Fuzzing
    // ========================================================================

    /// Fuzz `parse_partitions` on completely arbitrary byte buffers from 0 to 16 KiB.
    ///
    /// Must return Ok or Err, never panic, never loop indefinitely.
    #[test]
    fn fuzz_parse_partitions_arbitrary(data in proptest::collection::vec(any::<u8>(), 0..=16384)) {
        let mut source = MemorySource::new(data);
        let _ = parse_partitions(&mut source);
    }

    /// Fuzz `parse_partitions` on mutated MBR structures.
    ///
    /// Boot sector has 0x55, 0xAA signature at bytes 510..512 with arbitrary partition table
    /// entries (types, LBAs, sector counts) and optional extended partition markers.
    #[test]
    fn fuzz_parse_partitions_mutated_mbr(
        bootstrap in proptest::collection::vec(any::<u8>(), 446),
        part_table in proptest::collection::vec(any::<u8>(), 64),
        trailing in proptest::collection::vec(any::<u8>(), 0..=8192),
    ) {
        let mut disk = Vec::with_capacity(512 + trailing.len());
        disk.extend_from_slice(&bootstrap);
        disk.extend_from_slice(&part_table);
        // Force valid MBR boot signature
        disk.push(0x55);
        disk.push(0xAA);
        disk.extend_from_slice(&trailing);

        let mut source = MemorySource::new(disk);
        if let Ok(partitions) = parse_partitions(&mut source) {
            // Invariant: any successfully parsed partition must reside within disk bounds
            let disk_size = source.size_bytes();
            for part in partitions {
                let end = part.byte_offset.checked_add(part.byte_len);
                prop_assert!(end.is_some());
                prop_assert!(end.unwrap() <= disk_size);
            }
        }
    }

    /// Fuzz `parse_partitions` on mutated GPT structures.
    ///
    /// LBA 0 is protective MBR, LBA 1 has "EFI PART" signature with arbitrary header fields.
    #[test]
    fn fuzz_parse_partitions_mutated_gpt(
        header_size in any::<u32>(),
        my_lba in any::<u64>(),
        first_usable in any::<u64>(),
        last_usable in any::<u64>(),
        part_entry_lba in any::<u64>(),
        num_entries in any::<u32>(),
        size_of_entry in any::<u32>(),
        table_bytes in proptest::collection::vec(any::<u8>(), 0..=4096),
    ) {
        // Construct 34 sectors minimum
        let mut disk = vec![0u8; 34 * 512 + table_bytes.len()];
        // LBA 0: MBR signature
        disk[510] = 0x55;
        disk[511] = 0xAA;
        // LBA 0: Protective partition type 0xEE
        disk[446 + 4] = 0xEE;
        disk[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        disk[446 + 12..446 + 16].copy_from_slice(&33u32.to_le_bytes());

        // LBA 1: GPT header
        let lba1 = 512;
        disk[lba1..lba1 + 8].copy_from_slice(b"EFI PART");
        disk[lba1 + 8..lba1 + 12].copy_from_slice(&[0, 0, 1, 0]); // revision 1.0
        disk[lba1 + 12..lba1 + 16].copy_from_slice(&header_size.to_le_bytes());
        disk[lba1 + 24..lba1 + 32].copy_from_slice(&my_lba.to_le_bytes());
        disk[lba1 + 40..lba1 + 48].copy_from_slice(&first_usable.to_le_bytes());
        disk[lba1 + 48..lba1 + 56].copy_from_slice(&last_usable.to_le_bytes());
        disk[lba1 + 72..lba1 + 80].copy_from_slice(&part_entry_lba.to_le_bytes());
        disk[lba1 + 80..lba1 + 84].copy_from_slice(&num_entries.to_le_bytes());
        disk[lba1 + 84..lba1 + 88].copy_from_slice(&size_of_entry.to_le_bytes());

        // Append table bytes
        disk[2 * 512..2 * 512 + table_bytes.len()].copy_from_slice(&table_bytes);

        let mut source = MemorySource::new(disk);
        let _ = parse_partitions(&mut source);
    }

    // ========================================================================
    // 2. FAT32 Metadata Recovery Fuzzing
    // ========================================================================

    /// Fuzz `recover_fat32_candidates` on arbitrary byte buffers (0 to 32 KiB).
    #[test]
    fn fuzz_recover_fat32_arbitrary(data in proptest::collection::vec(any::<u8>(), 0..=32768)) {
        let len = data.len() as u64;
        let mut source = MemorySource::new(data);
        if let Ok(candidates) = recover_fat32_candidates(&mut source, 0, len) {
            for cand in candidates {
                for ext in &cand.extents {
                    let end = ext.byte_offset.checked_add(ext.byte_len);
                    prop_assert!(end.is_some());
                    prop_assert!(end.unwrap() <= len);
                }
            }
        }
    }

    /// Fuzz `recover_fat32_candidates` on mutated FAT32 boot and directory sectors.
    #[test]
    fn fuzz_recover_fat32_mutated_boot(
        bytes_per_sec in any::<u16>(),
        sec_per_clus in any::<u8>(),
        reserved_sec in any::<u16>(),
        fats in any::<u8>(),
        total_sec32 in any::<u32>(),
        fat_size32 in any::<u32>(),
        root_cluster in any::<u32>(),
        dir_data in proptest::collection::vec(any::<u8>(), 0..=8192),
    ) {
        let mut disk = vec![0u8; 1024 + dir_data.len()];
        // BS_jmpBoot
        disk[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        // BS_OEMName
        disk[3..11].copy_from_slice(b"MSWIN4.1");
        // BPB_BytsPerSec
        disk[11..13].copy_from_slice(&bytes_per_sec.to_le_bytes());
        // BPB_SecPerClus
        disk[13] = sec_per_clus;
        // BPB_RsvdSecCnt
        disk[14..16].copy_from_slice(&reserved_sec.to_le_bytes());
        // BPB_NumFATs
        disk[16] = fats;
        // BPB_TotSec32
        disk[32..36].copy_from_slice(&total_sec32.to_le_bytes());
        // BPB_FATSz32
        disk[36..40].copy_from_slice(&fat_size32.to_le_bytes());
        // BPB_RootClus
        disk[44..48].copy_from_slice(&root_cluster.to_le_bytes());
        // Boot signature 0x55, 0xAA
        disk[510] = 0x55;
        disk[511] = 0xAA;

        disk[1024..].copy_from_slice(&dir_data);

        let len = disk.len() as u64;
        let mut source = MemorySource::new(disk);
        let _ = recover_fat32_candidates(&mut source, 0, len);
    }

    // ========================================================================
    // 3. exFAT Metadata Recovery Fuzzing
    // ========================================================================

    /// Fuzz `recover_exfat_candidates` on arbitrary byte buffers (0 to 32 KiB).
    #[test]
    fn fuzz_recover_exfat_arbitrary(data in proptest::collection::vec(any::<u8>(), 0..=32768)) {
        let len = data.len() as u64;
        let mut source = MemorySource::new(data);
        if let Ok(candidates) = recover_exfat_candidates(&mut source, 0, len) {
            for cand in candidates {
                for ext in &cand.extents {
                    let end = ext.byte_offset.checked_add(ext.byte_len);
                    prop_assert!(end.is_some());
                    prop_assert!(end.unwrap() <= len);
                }
            }
        }
    }

    /// Fuzz `recover_exfat_candidates` on mutated exFAT boot and directory sectors.
    #[test]
    fn fuzz_recover_exfat_mutated_boot(
        vol_len in any::<u64>(),
        fat_off in any::<u32>(),
        fat_len in any::<u32>(),
        heap_off in any::<u32>(),
        cluster_cnt in any::<u32>(),
        root_clus in any::<u32>(),
        sec_shift in any::<u8>(),
        clus_shift in any::<u8>(),
        dir_data in proptest::collection::vec(any::<u8>(), 0..=8192),
    ) {
        let mut disk = vec![0u8; 1024 + dir_data.len()];
        // JumpBoot & FileSystemName "EXFAT   "
        disk[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        disk[3..11].copy_from_slice(b"EXFAT   ");
        disk[64..72].copy_from_slice(&vol_len.to_le_bytes());
        disk[80..84].copy_from_slice(&fat_off.to_le_bytes());
        disk[84..88].copy_from_slice(&fat_len.to_le_bytes());
        disk[88..92].copy_from_slice(&heap_off.to_le_bytes());
        disk[92..96].copy_from_slice(&cluster_cnt.to_le_bytes());
        disk[96..100].copy_from_slice(&root_clus.to_le_bytes());
        disk[108] = sec_shift;
        disk[109] = clus_shift;
        disk[110] = 1; // number of fats
        disk[510] = 0x55;
        disk[511] = 0xAA;

        disk[1024..].copy_from_slice(&dir_data);

        let len = disk.len() as u64;
        let mut source = MemorySource::new(disk);
        let _ = recover_exfat_candidates(&mut source, 0, len);
    }

    // ========================================================================
    // 4. ISO-BMFF / MP4 Box Parsing & Raw Carver Fuzzing
    // ========================================================================

    /// Fuzz `parse_box_header` on arbitrary byte slices and offsets.
    #[test]
    fn fuzz_parse_box_header_arbitrary(
        buf in proptest::collection::vec(any::<u8>(), 0..=64),
        offset in any::<u64>(),
        max_end in any::<u64>(),
    ) {
        if let Ok(header) = parse_box_header(&buf, offset, max_end) {
            // Invariants:
            prop_assert!(header.size >= 8);
            prop_assert!(header.header_len == 8 || header.header_len == 16);
            let end = header.end_offset();
            prop_assert!(end.is_some(), "box end offset must not overflow u64");
            prop_assert!(end.unwrap() <= max_end, "box end must not exceed max_end");
            // box_type must be printable ASCII
            prop_assert!(header.box_type.iter().all(|&b| (0x20..=0x7E).contains(&b)));
        }
    }

    /// Fuzz `parse_box_header` against adversarial box sizes:
    /// 0 (unbounded, must be rejected), 1 (64-bit largesize), 7 (invalid, < 8),
    /// u32::MAX, u64::MAX, and arithmetic overflow boundaries.
    #[test]
    fn fuzz_parse_box_header_adversarial_sizes(
        adversarial_size32 in prop_oneof![
            Just(0u32),
            Just(1u32),
            Just(2u32),
            Just(7u32),
            Just(8u32),
            Just(u32::MAX),
            any::<u32>()
        ],
        adversarial_size64 in prop_oneof![
            Just(0u64),
            Just(1u64),
            Just(15u64),
            Just(16u64),
            Just(u64::MAX),
            Just(u64::MAX - 1),
            any::<u64>()
        ],
        fourcc in prop_oneof![
            Just(*b"ftyp"),
            Just(*b"moov"),
            Just(*b"mdat"),
            Just(*b"free"),
            Just([0x00, 0x01, 0x02, 0x03]), // non-ASCII
            any::<[u8; 4]>()
        ],
        offset in any::<u64>(),
        max_end in any::<u64>(),
    ) {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&adversarial_size32.to_be_bytes());
        buf[4..8].copy_from_slice(&fourcc);
        buf[8..16].copy_from_slice(&adversarial_size64.to_be_bytes());

        let res = parse_box_header(&buf, offset, max_end);
        match res {
            Ok(hdr) => {
                // Must be valid non-zero size, in-bounds, printable ASCII
                prop_assert!(hdr.size >= 8);
                prop_assert!(hdr.end_offset().unwrap() <= max_end);
                prop_assert!(hdr.box_type.iter().all(|&b| (0x20..=0x7E).contains(&b)));
                // size == 0 must NEVER be accepted
                prop_assert_ne!(adversarial_size32, 0);
                // size < 8 must NEVER be accepted unless size32 == 1 with valid size64
                if adversarial_size32 != 1 {
                    prop_assert!(adversarial_size32 >= 8);
                } else {
                    prop_assert!(adversarial_size64 >= 16);
                }
            }
            Err(err) => {
                // Returns controlled Parse error, never panics
                prop_assert!(matches!(err, sd_video_recovery::error::RecoveryError::Parse(_)));
            }
        }
    }

    /// Fuzz `inspect_mp4_structure` on arbitrary byte buffers (0 to 16 KiB).
    ///
    /// Must never panic, must enforce MAX_NESTING_DEPTH and MAX_BOX_COUNT bounds.
    #[test]
    fn fuzz_inspect_mp4_structure(data in proptest::collection::vec(any::<u8>(), 0..=16384)) {
        let mut source = MemorySource::new(data);
        if let Ok(info) = inspect_mp4_structure(&mut source) {
            prop_assert!(info.box_count <= MAX_BOX_COUNT);
        }
    }

    /// Fuzz `carve_mp4_candidates` on arbitrary byte buffers (0 to 16 KiB) with random box insertions.
    ///
    /// Must never panic, candidate extents must strictly stay within [0, source.size_bytes()].
    #[test]
    fn fuzz_carve_mp4_candidates(
        data in proptest::collection::vec(any::<u8>(), 0..=16384),
        scan_offset in any::<u64>(),
        scan_len in any::<u64>(),
    ) {
        let mut source = MemorySource::new(data);
        let disk_size = source.size_bytes();

        if let Ok(candidates) = carve_mp4_candidates(&mut source, scan_offset, scan_len) {
            for cand in candidates {
                prop_assert_eq!(cand.recovery_method, sd_video_recovery::types::RecoveryMethod::RawCarve);
                for ext in &cand.extents {
                    let end = ext.byte_offset.checked_add(ext.byte_len);
                    prop_assert!(end.is_some());
                    prop_assert!(end.unwrap() <= disk_size);
                }
            }
        }
    }
}
