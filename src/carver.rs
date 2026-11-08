//! MP4/MOV ISO-BMFF box parser and raw sequential carver.
//!
//! Provides single-pass sequential raw carving and recursive box structure inspection
//! for ISO-BMFF / MP4 / QuickTime MOV containers on FAT32 and exFAT SD cards.

use crate::error::RecoveryError;
use crate::types::{Candidate, CandidateStatus, Confidence, Extent, ReadSource, RecoveryMethod};

/// Maximum allowed recursive box nesting depth (prevents stack overflow on adversarial inputs).
pub const MAX_NESTING_DEPTH: usize = 16;

/// Maximum total box count permitted per inspection or carving pass (prevents algorithmic DoS).
pub const MAX_BOX_COUNT: usize = 65_536;

/// Sanity upper bound on carved candidate file size (64 GiB).
pub const MAX_CARVED_FILE_SIZE: u64 = 64 * 1024 * 1024 * 1024;

/// Parsed ISO-BMFF box header with absolute stream offset, declared size, header length, and fourcc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxHeader {
    /// Absolute byte offset in the underlying stream where this box header begins.
    pub offset: u64,
    /// Declared total size of the box in bytes (including header and payload).
    pub size: u64,
    /// Header length in bytes (8 for standard 32-bit boxes, 16 for 64-bit `largesize` boxes).
    pub header_len: u8,
    /// 4-byte box type / fourcc (e.g. `*b"ftyp"`, `*b"moov"`, `*b"mdat"`).
    pub box_type: [u8; 4],
}

impl BoxHeader {
    /// Absolute byte offset where the box payload begins, using checked addition.
    #[must_use]
    pub const fn payload_offset(&self) -> Option<u64> {
        self.offset.checked_add(self.header_len as u64)
    }

    /// Absolute exclusive end byte offset of this box (`offset + size`), using checked addition.
    #[must_use]
    pub const fn end_offset(&self) -> Option<u64> {
        self.offset.checked_add(self.size)
    }
}

/// Structural diagnostics collected during candidate stream inspection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mp4StructureInfo {
    /// Whether an `ftyp` box was discovered at the root level.
    pub has_ftyp: bool,
    /// Whether a `moov` box was discovered.
    pub has_moov: bool,
    /// Whether an `mdat` media data box was discovered.
    pub has_mdat: bool,
    /// Whether a `moof` movie fragment box was discovered.
    pub has_moof: bool,
    /// Whether this container is fragmented ISO-BMFF (`has_moof == true`).
    pub is_fragmented_bmff: bool,
    /// Whether the container was truncated, had child boxes extending past bounds,
    /// or encountered unexpected garbage before reaching the stream boundary.
    pub is_truncated: bool,
    /// Sum of all top-level declared box bytes.
    pub total_box_bytes: u64,
    /// Total number of top-level and nested boxes visited.
    pub box_count: usize,
    /// Major brand extracted from the `ftyp` box payload, if present.
    pub major_brand: Option<[u8; 4]>,
}

impl Mp4StructureInfo {
    /// Returns `true` if this candidate has all essential top-level boxes
    /// (`ftyp`, `moov`, `mdat`) and no structural truncation was encountered.
    #[must_use]
    pub const fn is_complete_video_container(&self) -> bool {
        self.has_ftyp && self.has_moov && self.has_mdat && !self.is_truncated
    }
}

/// Returns `true` if `box_type` is a recognized container box that holds child boxes.
#[must_use]
pub fn is_container_box(box_type: &[u8; 4]) -> bool {
    matches!(
        box_type,
        b"moov"
            | b"trak"
            | b"mdia"
            | b"minf"
            | b"stbl"
            | b"moof"
            | b"traf"
            | b"mvex"
            | b"edts"
            | b"dinf"
    )
}

/// Returns `true` if `box_type` is a recognized top-level ISO-BMFF / QuickTime / camera box.
#[must_use]
pub fn is_known_top_level_box(box_type: &[u8; 4]) -> bool {
    matches!(
        box_type,
        b"ftyp"
            | b"free"
            | b"skip"
            | b"wide"
            | b"mdat"
            | b"moov"
            | b"moof"
            | b"styp"
            | b"sidx"
            | b"mfra"
            | b"uuid"
            | b"meta"
            | b"udta"
            | b"beam"
            | b"gpmf"
            | b"prft"
    )
}

/// Parses an ISO-BMFF box header from `buf` starting at stream `offset` bounded by `max_end`.
///
/// # Errors
///
/// Returns [`RecoveryError::Parse`] if `buf` is too short, `box_type` is non-ASCII,
/// size is `< 8` (or `< 16` for 64-bit largesize), size is unbounded (`0`), arithmetic
/// overflows, or the declared box range extends past `max_end`.
pub fn parse_box_header(buf: &[u8], offset: u64, max_end: u64) -> Result<BoxHeader, RecoveryError> {
    if buf.len() < 8 {
        return Err(RecoveryError::Parse(
            "buffer too short for 8-byte box header".to_string(),
        ));
    }

    let size32 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let box_type = [buf[4], buf[5], buf[6], buf[7]];

    // Validate box_type is printable ASCII (0x20..=0x7E for all 4 bytes)
    if !box_type.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return Err(RecoveryError::Parse(format!(
            "invalid non-ascii box type: {box_type:?}"
        )));
    }

    if size32 == 1 {
        // 64-bit largesize box: require buf.len() >= 16
        if buf.len() < 16 {
            return Err(RecoveryError::Parse(
                "buffer too short for 16-byte 64-bit box header".to_string(),
            ));
        }
        let size64 = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        if size64 < 16 {
            return Err(RecoveryError::Parse(format!(
                "64-bit box size {size64} < 16"
            )));
        }
        let end = offset
            .checked_add(size64)
            .ok_or_else(|| RecoveryError::Parse("64-bit box size overflow".to_string()))?;
        if end > max_end {
            return Err(RecoveryError::Parse(format!(
                "box extends past boundary: end {end} > max_end {max_end}"
            )));
        }
        Ok(BoxHeader {
            offset,
            size: size64,
            header_len: 16,
            box_type,
        })
    } else if size32 == 0 {
        Err(RecoveryError::Parse(
            "unbounded box size 0 not allowed".to_string(),
        ))
    } else if size32 < 8 {
        Err(RecoveryError::Parse(format!("box size {size32} < 8")))
    } else {
        let size = u64::from(size32);
        let end = offset
            .checked_add(size)
            .ok_or_else(|| RecoveryError::Parse("32-bit box size overflow".to_string()))?;
        if end > max_end {
            return Err(RecoveryError::Parse(format!(
                "box extends past boundary: end {end} > max_end {max_end}"
            )));
        }
        Ok(BoxHeader {
            offset,
            size,
            header_len: 8,
            box_type,
        })
    }
}

/// Recursively inspects container box children in `source`.
fn inspect_container_boxes<R: ReadSource + ?Sized>(
    source: &mut R,
    start_offset: u64,
    end_offset: u64,
    depth: usize,
    info: &mut Mp4StructureInfo,
) -> Result<(), RecoveryError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(RecoveryError::Parse(
            "max box nesting depth exceeded".to_string(),
        ));
    }

    let mut cur = start_offset;
    while cur < end_offset {
        let remaining = end_offset - cur;
        if remaining < 8 {
            info.is_truncated = true;
            break;
        }

        let mut buf = [0u8; 16];
        let to_read = (remaining.min(16)) as usize;
        let n = source.read_at(cur, &mut buf[..to_read])?;
        if n < 8 {
            info.is_truncated = true;
            break;
        }

        let header = match parse_box_header(&buf[..n], cur, end_offset) {
            Ok(h) => h,
            Err(_) => {
                info.is_truncated = true;
                break;
            }
        };

        info.box_count += 1;
        if info.box_count > MAX_BOX_COUNT {
            return Err(RecoveryError::Parse("max box count exceeded".to_string()));
        }

        if depth == 0 {
            info.total_box_bytes = info.total_box_bytes.saturating_add(header.size);
            match &header.box_type {
                b"ftyp" => {
                    info.has_ftyp = true;
                    if info.major_brand.is_none() && header.size >= 12 {
                        let mut brand = [0u8; 4];
                        if let Some(payload_off) = header.payload_offset() {
                            if source.read_exact_at(payload_off, &mut brand).is_ok()
                                && brand.iter().all(|&b| (0x20..=0x7E).contains(&b))
                            {
                                info.major_brand = Some(brand);
                            }
                        }
                    }
                }
                b"moov" => {
                    info.has_moov = true;
                }
                b"mdat" => {
                    info.has_mdat = true;
                }
                b"moof" => {
                    info.has_moof = true;
                    info.is_fragmented_bmff = true;
                }
                _ => {}
            }
        } else if header.box_type == *b"moof" {
            info.has_moof = true;
            info.is_fragmented_bmff = true;
        }

        if is_container_box(&header.box_type) {
            let payload_start = match header.payload_offset() {
                Some(p) => p,
                None => {
                    info.is_truncated = true;
                    break;
                }
            };
            let payload_end = match header.end_offset() {
                Some(e) => e,
                None => {
                    info.is_truncated = true;
                    break;
                }
            };
            inspect_container_boxes(source, payload_start, payload_end, depth + 1, info)?;
        }

        let next_cur = match header.end_offset() {
            Some(e) => e,
            None => {
                info.is_truncated = true;
                break;
            }
        };
        cur = next_cur;
    }

    if cur < end_offset {
        info.is_truncated = true;
    }

    Ok(())
}

/// Recursively inspects the ISO-BMFF box structure of a candidate source of size `source.size_bytes()`.
///
/// # Errors
///
/// Returns [`RecoveryError::Parse`] if `MAX_NESTING_DEPTH` or `MAX_BOX_COUNT` is exceeded,
/// or [`RecoveryError::SourceIo`] on read failures.
pub fn inspect_mp4_structure<R: ReadSource + ?Sized>(
    source: &mut R,
) -> Result<Mp4StructureInfo, RecoveryError> {
    let total_size = source.size_bytes();
    let mut info = Mp4StructureInfo::default();
    if total_size < 8 {
        info.is_truncated = true;
        return Ok(info);
    }

    inspect_container_boxes(source, 0, total_size, 0, &mut info)?;
    info.is_fragmented_bmff = info.has_moof;

    Ok(info)
}

/// Validates that a `moov` box contains valid, uncorrupted child boxes including `mvhd`.
pub fn validate_moov_children<R: ReadSource + ?Sized>(
    source: &mut R,
    moov_header: &BoxHeader,
) -> bool {
    let Some(payload_offset) = moov_header.payload_offset() else {
        return false;
    };
    let Some(end_offset) = moov_header.end_offset() else {
        return false;
    };

    let mut cur = payload_offset;
    let mut child_count = 0;
    let mut has_mvhd = false;

    while cur < end_offset {
        let remaining = end_offset - cur;
        if remaining < 8 {
            return false;
        }

        let mut buf = [0u8; 16];
        let to_read = (remaining.min(16)) as usize;
        let Ok(n) = source.read_at(cur, &mut buf[..to_read]) else {
            return false;
        };
        if n < 8 {
            return false;
        }

        let Ok(child) = parse_box_header(&buf[..n], cur, end_offset) else {
            return false;
        };

        if child.box_type == *b"mvhd" {
            has_mvhd = true;
        }

        child_count += 1;
        if child_count > MAX_BOX_COUNT {
            return false;
        }

        let Some(next_cur) = child.end_offset() else {
            return false;
        };
        cur = next_cur;
    }

    has_mvhd && cur == end_offset
}

/// Performs a single sequential raw carving pass over `[scan_offset, scan_offset + scan_len)`
/// to discover complete or partial MP4/MOV video containers.
///
/// # Errors
///
/// Returns [`RecoveryError::SourceIo`] if persistent sector I/O read failure occurs,
/// or [`RecoveryError::Parse`] if offset arithmetic overflows.
pub fn carve_mp4_candidates<R: ReadSource + ?Sized>(
    source: &mut R,
    scan_offset: u64,
    scan_len: u64,
) -> Result<Vec<Candidate>, RecoveryError> {
    let source_size = source.size_bytes();
    if scan_offset >= source_size || scan_len == 0 {
        return Ok(Vec::new());
    }

    let scan_end = scan_offset
        .checked_add(scan_len)
        .ok_or_else(|| RecoveryError::Parse("scan range overflow".to_string()))?
        .min(source_size);

    let finder = memchr::memmem::Finder::new(b"ftyp");
    let mut candidates = Vec::new();
    let mut candidate_index = 1usize;
    let mut outer_cursor = scan_offset;

    const CHUNK_SIZE: usize = 64 * 1024;
    const OVERLAP_SIZE: usize = 16;

    while outer_cursor < scan_end {
        let chunk_len = ((scan_end - outer_cursor).min(CHUNK_SIZE as u64)) as usize;
        let mut chunk = vec![0u8; chunk_len];
        let bytes_read = source.read_at(outer_cursor, &mut chunk)?;
        if bytes_read < 8 {
            break;
        }
        let valid_chunk = &chunk[..bytes_read];

        let mut matched_in_chunk = false;

        for match_pos in finder.find_iter(valid_chunk) {
            // b"ftyp" is at bytes 4..8 of the box.
            let Some(box_rel_pos) = match_pos.checked_sub(4) else {
                continue;
            };
            let box_start = outer_cursor + box_rel_pos as u64;
            if box_start < scan_offset || box_start >= scan_end {
                continue;
            }

            // Validate that ftyp has a valid BoxHeader (size >= 16 && size <= 4096)
            // and valid brand fourcc at offset + 8..offset + 12 (printable ASCII).
            let mut ftyp_buf = [0u8; 16];
            let avail = ((scan_end - box_start).min(16)) as usize;
            if avail < 16 {
                continue;
            }
            if source.read_at(box_start, &mut ftyp_buf)? < 16 {
                continue;
            }

            let Ok(ftyp_hdr) = parse_box_header(&ftyp_buf, box_start, scan_end) else {
                continue;
            };

            if ftyp_hdr.box_type != *b"ftyp" || ftyp_hdr.size < 16 || ftyp_hdr.size > 4096 {
                continue;
            }

            // Brand fourcc at offset + 8..offset + 12 must be printable ASCII
            if !ftyp_buf[8..12].iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                continue;
            }

            // Valid ftyp found!
            matched_in_chunk = true;
            let candidate_start = box_start;
            let mut box_cursor = match ftyp_hdr.end_offset() {
                Some(e) => e,
                None => break,
            };
            let mut box_count = 1usize;
            let mut has_moov = false;
            let mut has_mdat = false;
            let mut has_moof = false;
            let mut mdat_started = false;
            let mut last_valid_end = box_cursor;
            let mut next_ftyp_offset: Option<u64> = None;

            // Walk consecutive top-level ISO-BMFF boxes up to MAX_BOX_COUNT and scan_end
            while box_cursor < scan_end && box_count < MAX_BOX_COUNT {
                let remaining = scan_end - box_cursor;
                if remaining < 8 {
                    if (mdat_started || has_moov) && !(has_moov && has_mdat) {
                        last_valid_end = scan_end;
                        mdat_started = true;
                    }
                    break;
                }

                let mut hdr_buf = [0u8; 16];
                let to_read = (remaining.min(16)) as usize;
                let n = source.read_at(box_cursor, &mut hdr_buf[..to_read])?;
                if n < 8 {
                    if (mdat_started || has_moov) && !(has_moov && has_mdat) {
                        last_valid_end = scan_end;
                        mdat_started = true;
                    }
                    break;
                }

                // Check if another ftyp begins at box_cursor
                if &hdr_buf[4..8] == b"ftyp" {
                    if let Ok(next_hdr) = parse_box_header(&hdr_buf[..n], box_cursor, scan_end) {
                        if next_hdr.box_type == *b"ftyp"
                            && next_hdr.size >= 16
                            && next_hdr.size <= 4096
                            && n >= 12
                            && hdr_buf[8..12].iter().all(|&b| (0x20..=0x7E).contains(&b))
                        {
                            next_ftyp_offset = Some(box_cursor);
                            break;
                        }
                    }
                }

                // If classic MP4 already has moov and mdat, stop if another moov or mdat appears
                if has_moov
                    && has_mdat
                    && !has_moof
                    && (&hdr_buf[4..8] == b"moov" || &hdr_buf[4..8] == b"mdat")
                {
                    break;
                }

                let header = match parse_box_header(&hdr_buf[..n], box_cursor, scan_end) {
                    Ok(h) => h,
                    Err(_) => {
                        // Truncated box or extends past scan_end.
                        if &hdr_buf[4..8] == b"mdat" {
                            mdat_started = true;
                            last_valid_end = scan_end;
                        }
                        break;
                    }
                };

                if !is_known_top_level_box(&header.box_type) {
                    break;
                }

                if header.box_type == *b"moov" {
                    if !validate_moov_children(source, &header) {
                        break;
                    }
                    has_moov = true;
                } else if header.box_type == *b"mdat" {
                    has_mdat = true;
                    mdat_started = true;
                } else if header.box_type == *b"moof" {
                    has_moof = true;
                }

                box_count += 1;
                let Some(next_cursor) = header.end_offset() else {
                    break;
                };
                last_valid_end = next_cursor;
                box_cursor = next_cursor;

                if last_valid_end.saturating_sub(candidate_start) >= MAX_CARVED_FILE_SIZE {
                    break;
                }
            }

            // Decide candidate completion
            if has_moov && has_mdat {
                let total_size = last_valid_end - candidate_start;
                if total_size > 0 {
                    let cand = Candidate {
                        id: format!("cand-{candidate_index:04}"),
                        extents: vec![Extent::new(candidate_start, total_size)],
                        expected_size: total_size,
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
                    candidates.push(cand);
                    candidate_index += 1;
                }
                outer_cursor = (candidate_start + total_size).max(outer_cursor + 1);
                break;
            } else if mdat_started {
                let available_bytes = last_valid_end - candidate_start;
                if available_bytes > 0 {
                    let cand = Candidate {
                        id: format!("cand-{candidate_index:04}"),
                        extents: vec![Extent::new(candidate_start, available_bytes)],
                        expected_size: available_bytes,
                        recovery_method: RecoveryMethod::RawCarve,
                        original_name: None,
                        recovered_name: None,
                        output_path: None,
                        confidence: Confidence::Low,
                        status: CandidateStatus::Partial,
                        chain_preserved: false,
                        is_fragmented: true,
                        error_reason: Some(
                            "truncated video stream or incomplete moov/mdat".to_string(),
                        ),
                        error_offset: None,
                    };
                    candidates.push(cand);
                    candidate_index += 1;
                }
                if let Some(next_ftyp) = next_ftyp_offset {
                    outer_cursor = next_ftyp.max(outer_cursor + 1);
                } else {
                    outer_cursor = last_valid_end
                        .max(candidate_start + 16)
                        .max(outer_cursor + 1);
                }
                break;
            } else {
                // Not a video stream (isolated ftyp without mdat or moov)
                if let Some(next_ftyp) = next_ftyp_offset {
                    outer_cursor = next_ftyp.max(outer_cursor + 1);
                } else {
                    outer_cursor = (candidate_start + 4).max(outer_cursor + 1);
                }
                break;
            }
        }

        if !matched_in_chunk {
            if bytes_read <= OVERLAP_SIZE {
                outer_cursor += bytes_read as u64;
            } else {
                outer_cursor += (bytes_read - OVERLAP_SIZE) as u64;
            }
        }
    }

    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MemorySource;

    fn make_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = (8 + payload.len()) as u32;
        let mut out = Vec::with_capacity(size as usize);
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(box_type);
        out.extend_from_slice(payload);
        out
    }

    fn make_box64(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = (16 + payload.len()) as u64;
        let mut out = Vec::with_capacity(size as usize);
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(box_type);
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn make_ftyp(brand: &[u8; 4]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(brand);
        payload.extend_from_slice(&[0, 0, 0, 1]); // minor version
        payload.extend_from_slice(brand); // compatible brand
        make_box(b"ftyp", &payload)
    }

    fn make_moov() -> Vec<u8> {
        let mvhd = make_box(b"mvhd", &[0u8; 100]);
        let tkhd = make_box(b"tkhd", &[0u8; 42]);
        let trak = make_box(b"trak", &tkhd);
        let mut payload = Vec::new();
        payload.extend_from_slice(&mvhd);
        payload.extend_from_slice(&trak);
        make_box(b"moov", &payload)
    }

    fn make_moof() -> Vec<u8> {
        let mfhd = make_box(b"mfhd", &[0u8; 16]);
        let tfhd = make_box(b"tfhd", &[0u8; 24]);
        let traf = make_box(b"traf", &tfhd);
        let mut payload = Vec::new();
        payload.extend_from_slice(&mfhd);
        payload.extend_from_slice(&traf);
        make_box(b"moof", &payload)
    }

    #[test]
    fn test_parse_box_header_32bit() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&32u32.to_be_bytes());
        buf.extend_from_slice(b"ftyp");
        buf.extend_from_slice(&[0u8; 24]);

        let hdr = parse_box_header(&buf, 100, 200).expect("valid 32-bit box");
        assert_eq!(hdr.offset, 100);
        assert_eq!(hdr.size, 32);
        assert_eq!(hdr.header_len, 8);
        assert_eq!(&hdr.box_type, b"ftyp");
        assert_eq!(hdr.payload_offset(), Some(108));
        assert_eq!(hdr.end_offset(), Some(132));
    }

    #[test]
    fn test_parse_box_header_64bit() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(b"mdat");
        buf.extend_from_slice(&64u64.to_be_bytes());
        buf.extend_from_slice(&[0u8; 48]);

        let hdr = parse_box_header(&buf, 100, 200).expect("valid 64-bit box");
        assert_eq!(hdr.offset, 100);
        assert_eq!(hdr.size, 64);
        assert_eq!(hdr.header_len, 16);
        assert_eq!(&hdr.box_type, b"mdat");
        assert_eq!(hdr.payload_offset(), Some(116));
        assert_eq!(hdr.end_offset(), Some(164));
    }

    #[test]
    fn test_parse_box_header_rejections() {
        // Size == 0 rejected
        let buf_zero = [0, 0, 0, 0, b'f', b't', b'y', b'p'];
        assert!(parse_box_header(&buf_zero, 0, 100).is_err());

        // Size < 8 rejected
        let buf_short = [0, 0, 0, 7, b'f', b't', b'y', b'p'];
        assert!(parse_box_header(&buf_short, 0, 100).is_err());

        // 64-bit size < 16 rejected
        let mut buf64_short = Vec::new();
        buf64_short.extend_from_slice(&1u32.to_be_bytes());
        buf64_short.extend_from_slice(b"mdat");
        buf64_short.extend_from_slice(&15u64.to_be_bytes());
        assert!(parse_box_header(&buf64_short, 0, 100).is_err());

        // Non-ASCII fourcc rejected
        let buf_non_ascii = [0, 0, 0, 16, 0xFF, b't', b'y', b'p'];
        assert!(parse_box_header(&buf_non_ascii, 0, 100).is_err());

        // Buffer too short (< 8 bytes) rejected
        assert!(parse_box_header(&[0, 0, 0], 0, 100).is_err());

        // 64-bit buffer too short (< 16 bytes) rejected
        let buf64_truncated = [0, 0, 0, 1, b'm', b'd', b'a', b't', 0, 0, 0];
        assert!(parse_box_header(&buf64_truncated, 0, 100).is_err());

        // u64::MAX overflow rejected
        let mut buf_overflow = Vec::new();
        buf_overflow.extend_from_slice(&1u32.to_be_bytes());
        buf_overflow.extend_from_slice(b"mdat");
        buf_overflow.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(parse_box_header(&buf_overflow, 10, u64::MAX).is_err());

        // Out of bounds (end > max_end) rejected
        let buf_oob = [0, 0, 0, 100, b'f', b't', b'y', b'p'];
        assert!(parse_box_header(&buf_oob, 50, 100).is_err());
    }

    #[test]
    fn test_inspect_mp4_structure_classic() {
        let ftyp = make_ftyp(b"mp42");
        let moov = make_moov();
        let mdat = make_box(b"mdat", &[0xAA; 500]);
        let data = [ftyp, moov, mdat].concat();

        let mut src = MemorySource::new(data);
        let info = inspect_mp4_structure(&mut src).expect("inspect classic MP4");
        assert!(info.has_ftyp);
        assert!(info.has_moov);
        assert!(info.has_mdat);
        assert!(!info.has_moof);
        assert!(!info.is_fragmented_bmff);
        assert!(!info.is_truncated);
        assert!(info.is_complete_video_container());
        assert_eq!(info.major_brand, Some(*b"mp42"));
    }

    #[test]
    fn test_inspect_mp4_structure_faststart_and_mdat_first() {
        let ftyp = make_ftyp(b"isom");
        let moov = make_moov();
        let mdat = make_box(b"mdat", &[0xBB; 300]);

        // Faststart: moov before mdat
        let faststart_data = [ftyp.clone(), moov.clone(), mdat.clone()].concat();
        let mut src_fs = MemorySource::new(faststart_data);
        let info_fs = inspect_mp4_structure(&mut src_fs).expect("inspect faststart");
        assert!(info_fs.is_complete_video_container());

        // Classic camera recording: mdat before moov
        let mdat_first_data = [ftyp, mdat, moov].concat();
        let mut src_mf = MemorySource::new(mdat_first_data);
        let info_mf = inspect_mp4_structure(&mut src_mf).expect("inspect mdat-first");
        assert!(info_mf.is_complete_video_container());
    }

    #[test]
    fn test_inspect_mp4_structure_fragmented() {
        let ftyp = make_ftyp(b"isom");
        let moov = make_moov();
        let moof = make_moof();
        let mdat = make_box(b"mdat", &[0xCC; 200]);
        let data = [ftyp, moov, moof, mdat].concat();

        let mut src = MemorySource::new(data);
        let info = inspect_mp4_structure(&mut src).expect("inspect fragmented MP4");
        assert!(info.has_ftyp);
        assert!(info.has_moov);
        assert!(info.has_moof);
        assert!(info.has_mdat);
        assert!(info.is_fragmented_bmff);
        assert!(!info.is_truncated);
        assert!(info.is_complete_video_container());
    }

    #[test]
    fn test_inspect_mp4_structure_truncated_mdat() {
        let ftyp = make_ftyp(b"mp42");
        let moov = make_moov();
        let mut data = [ftyp, moov].concat();

        // Add declared 10,000-byte mdat, but only provide 20 bytes of payload
        data.extend_from_slice(&10_000u32.to_be_bytes());
        data.extend_from_slice(b"mdat");
        data.extend_from_slice(&[0xEE; 20]);

        let mut src = MemorySource::new(data);
        let info = inspect_mp4_structure(&mut src).expect("inspect truncated mdat");
        assert!(info.is_truncated);
        assert!(!info.is_complete_video_container());
    }

    #[test]
    fn test_inspect_mp4_structure_nesting_depth_limit() {
        let mut inner = make_box(b"dinf", &[0u8; 8]);
        for _ in 0..17 {
            inner = make_box(b"minf", &inner);
        }

        let mut src = MemorySource::new(inner);
        let res = inspect_mp4_structure(&mut src);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("max box nesting depth exceeded"));
    }

    #[test]
    fn test_inspect_mp4_structure_box_count_limit() {
        let tiny_box = make_box(b"free", &[]);
        let data = tiny_box.repeat(MAX_BOX_COUNT + 2);

        let mut src = MemorySource::new(data);
        let res = inspect_mp4_structure(&mut src);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("max box count exceeded"));
    }

    #[test]
    fn test_carve_mp4_candidates_multiple_and_64bit_and_truncated() {
        let mut disk = Vec::new();

        // 1. Initial 1024-byte zero sector padding
        disk.extend_from_slice(&[0u8; 1024]);

        // File 1: Classic MP4 (ftyp + moov + mdat)
        let file1_start = disk.len() as u64;
        let ftyp1 = make_ftyp(b"mp42");
        let moov1 = make_moov();
        let mdat1 = make_box(b"mdat", &[0x11; 400]);
        let file1_bytes = [ftyp1, moov1, mdat1].concat();
        let file1_len = file1_bytes.len() as u64;
        disk.extend_from_slice(&file1_bytes);

        // Zero padding between files
        disk.extend_from_slice(&[0u8; 512]);

        // File 2: MOV with 64-bit mdat before moov
        let file2_start = disk.len() as u64;
        let ftyp2 = make_ftyp(b"qt  ");
        let mdat2_64 = make_box64(b"mdat", &[0x22; 800]);
        let moov2 = make_moov();
        let file2_bytes = [ftyp2, mdat2_64, moov2].concat();
        let file2_len = file2_bytes.len() as u64;
        disk.extend_from_slice(&file2_bytes);

        // Zero padding between files
        disk.extend_from_slice(&[0u8; 512]);

        // File 3: Truncated MP4 (ftyp + mdat whose declared size extends past EOF)
        let file3_start = disk.len() as u64;
        let ftyp3 = make_ftyp(b"isom");
        disk.extend_from_slice(&ftyp3);
        // mdat header declaring 100,000 bytes, but only 200 bytes will be on disk
        disk.extend_from_slice(&100_000u32.to_be_bytes());
        disk.extend_from_slice(b"mdat");
        disk.extend_from_slice(&[0x33; 200]);
        let total_disk_len = disk.len() as u64;

        let mut src = MemorySource::new(disk);
        let candidates =
            carve_mp4_candidates(&mut src, 0, total_disk_len).expect("carve candidates");

        assert_eq!(candidates.len(), 3);

        // Candidate 1 checks
        assert_eq!(candidates[0].id, "cand-0001");
        assert_eq!(candidates[0].primary_offset(), Some(file1_start));
        assert_eq!(candidates[0].expected_size, file1_len);
        assert_eq!(candidates[0].recovery_method, RecoveryMethod::RawCarve);
        assert_eq!(candidates[0].confidence, Confidence::Medium);
        assert_eq!(candidates[0].status, CandidateStatus::Partial);
        assert!(candidates[0].chain_preserved);
        assert!(!candidates[0].is_fragmented);

        // Candidate 2 checks (with 64-bit mdat)
        assert_eq!(candidates[1].id, "cand-0002");
        assert_eq!(candidates[1].primary_offset(), Some(file2_start));
        assert_eq!(candidates[1].expected_size, file2_len);
        assert_eq!(candidates[1].recovery_method, RecoveryMethod::RawCarve);
        assert_eq!(candidates[1].confidence, Confidence::Medium);
        assert_eq!(candidates[1].status, CandidateStatus::Partial);
        assert!(candidates[1].chain_preserved);
        assert!(!candidates[1].is_fragmented);

        // Candidate 3 checks (truncated)
        assert_eq!(candidates[2].id, "cand-0003");
        assert_eq!(candidates[2].primary_offset(), Some(file3_start));
        assert_eq!(candidates[2].expected_size, total_disk_len - file3_start);
        assert_eq!(candidates[2].recovery_method, RecoveryMethod::RawCarve);
        assert_eq!(candidates[2].confidence, Confidence::Low);
        assert_eq!(candidates[2].status, CandidateStatus::Partial);
        assert!(!candidates[2].chain_preserved);
        assert!(candidates[2].is_fragmented);
    }
}
