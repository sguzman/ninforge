//! Read-only Nintendo 3DS CTR Importable Archive (CIA) structural inspection.
//!
//! CIA uses little-endian section sizes and 0x40-byte alignment. This parser
//! reads only the 0x2020-byte header and computes bounded file spans. The
//! content-index bitmap is descriptive; no TMD records, encrypted contents,
//! tickets, signatures or hashes are verified by this module.
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

const CIA_BASE_HEADER: usize = 0x2020;
const MAX_HEADER_SIZE: u32 = 0x10000;
const ALIGNMENT: u64 = 0x40;

fn bad(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn u32le(slice: &[u8]) -> u32 {
    u32::from_le_bytes(slice.try_into().unwrap())
}
fn u64le(slice: &[u8]) -> u64 {
    u64::from_le_bytes(slice.try_into().unwrap())
}
fn align64(value: u64) -> io::Result<u64> {
    value
        .checked_add(ALIGNMENT - 1)
        .map(|v| v & !(ALIGNMENT - 1))
        .ok_or_else(|| bad("CIA section alignment overflow"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiaSection {
    pub name: &'static str,
    pub offset_bytes: u64,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiaReport {
    pub archive_type: u16,
    pub archive_version: u16,
    pub header_size_bytes: u32,
    pub file_bytes: u64,
    pub content_index_set_bits: u32,
    pub sections: Vec<CiaSection>,
    pub file_trailing_bytes: u64,
    pub cryptographic_integrity_verified: bool,
}

/// Weak detection heuristic only: CIA has no distinct 4-byte magic.
/// Actual CIA verification requires inspecting the full header and spans.
pub fn could_be_cia(prefix: &[u8], file_bytes: u64) -> bool {
    prefix.len() >= 0x20
        && u32le(&prefix[..4]) == CIA_BASE_HEADER as u32
        && prefix[4..8] == [0; 4]
        && file_bytes >= CIA_BASE_HEADER as u64
        && u32le(&prefix[8..12]) > 0
        && u32le(&prefix[12..16]) > 0
        && u32le(&prefix[16..20]) > 0
        && u64le(&prefix[24..32]) > 0
}

/// Explicitly parse and bounds-check all CIA sections. The index bitmap is
/// counted only: matching actual contents requires a future TMD inspection.
/// No reads occur outside the first fixed 0x2020 header bytes.
pub fn inspect_cia<R: Read + Seek>(input: &mut R) -> io::Result<CiaReport> {
    let length = input.seek(SeekFrom::End(0))?;
    if length < CIA_BASE_HEADER as u64 {
        return Err(bad("CIA archive truncated before content-index header"));
    }
    input.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; CIA_BASE_HEADER];
    input.read_exact(&mut head)?;
    let size = u32le(&head[..4]);
    if size < CIA_BASE_HEADER as u32 || size > MAX_HEADER_SIZE || size % 0x20 != 0 {
        return Err(bad("CIA header size is unsupported or not 32-byte aligned"));
    }
    if u64::from(size) > length {
        return Err(bad("CIA declared header size exceeds file"));
    }
    let archive_type = u16::from_le_bytes(head[4..6].try_into().unwrap());
    let version = u16::from_le_bytes(head[6..8].try_into().unwrap());
    if archive_type != 0 || version != 0 {
        return Err(bad("CIA archive type/version unsupported"));
    }
    let cert = u64::from(u32le(&head[8..12]));
    let ticket = u64::from(u32le(&head[12..16]));
    let tmd = u64::from(u32le(&head[16..20]));
    let meta = u64::from(u32le(&head[20..24]));
    let content = u64le(&head[24..32]);
    if cert == 0 || ticket == 0 || tmd == 0 || content == 0 {
        return Err(bad(
            "CIA archive requires nonempty cert, ticket, TMD and content",
        ));
    }
    let bitmap = &head[0x20..0x2020];
    let set_bits: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
    if set_bits == 0 {
        return Err(bad("CIA content-index bitmap has no selected contents"));
    }

    let mut sections = Vec::with_capacity(5);
    let mut cursor = align64(u64::from(size))?;
    for (name, bytes) in [
        ("certificates", cert),
        ("ticket", ticket),
        ("tmd", tmd),
        ("content", content),
        ("meta", meta),
    ] {
        if bytes == 0 {
            continue;
        }
        let end = cursor
            .checked_add(bytes)
            .ok_or_else(|| bad("CIA section extent overflow"))?;
        if end > length {
            return Err(bad("CIA section extends outside supplied file"));
        }
        sections.push(CiaSection {
            name,
            offset_bytes: cursor,
            size_bytes: bytes,
        });
        cursor = align64(end)?;
    }
    // The final aligned padding may be absent for a trailing section.
    let last = sections.last().ok_or_else(|| bad("CIA has no sections"))?;
    let last_end = last.offset_bytes + last.size_bytes;
    if last_end > length {
        return Err(bad("CIA final section outside file"));
    }
    // Intermediate sections already required their next aligned starts.
    Ok(CiaReport {
        archive_type,
        archive_version: version,
        header_size_bytes: size,
        file_bytes: length,
        content_index_set_bits: set_bits,
        sections,
        file_trailing_bytes: length - last_end,
        cryptographic_integrity_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn fixture(with_meta: bool) -> Vec<u8> {
        let cert = 0x90u32;
        let ticket = 0x120u32;
        let tmd = 0xc4u32;
        let content = 0x301u64;
        let meta = if with_meta { 0x200u32 } else { 0 };
        let mut raw = vec![0u8; 0x2020];
        raw[..4].copy_from_slice(&0x2020u32.to_le_bytes());
        raw[8..12].copy_from_slice(&cert.to_le_bytes());
        raw[12..16].copy_from_slice(&ticket.to_le_bytes());
        raw[16..20].copy_from_slice(&tmd.to_le_bytes());
        raw[20..24].copy_from_slice(&meta.to_le_bytes());
        raw[24..32].copy_from_slice(&content.to_le_bytes());
        raw[0x20] = 0x80;
        raw[0x21] = 0x01;
        let mut cursor = 0x2040u64;
        for size in [cert as u64, ticket as u64, tmd as u64, content, meta as u64] {
            if size == 0 {
                continue;
            }
            let end = cursor + size;
            raw.resize(end as usize, 0);
            cursor = (end + 63) & !63;
        }
        raw
    }

    #[test]
    fn reads_five_sections_and_bitmap_without_large_reads() {
        let raw = fixture(true);
        let report = inspect_cia(&mut Cursor::new(&raw)).unwrap();
        assert_eq!(report.header_size_bytes, 0x2020);
        assert_eq!(report.sections.len(), 5);
        assert_eq!(report.content_index_set_bits, 2);
        assert_eq!(report.sections[0].offset_bytes, 0x2040);
        assert_eq!(report.sections[1].offset_bytes, 0x2100);
        assert_eq!(report.sections[2].offset_bytes, 0x2240);
        assert_eq!(report.sections[3].offset_bytes, 0x2340);
        assert!(!report.cryptographic_integrity_verified);
        assert!(could_be_cia(&raw[..0x20], raw.len() as u64));
    }

    #[test]
    fn meta_is_optional_and_final_unaligned_file_end_allowed() {
        let raw = fixture(false);
        let report = inspect_cia(&mut Cursor::new(&raw)).unwrap();
        assert_eq!(report.sections.len(), 4);
        assert_eq!(report.sections.last().unwrap().name, "content");
        assert_eq!(report.file_trailing_bytes, 0);
    }

    #[test]
    fn rejects_bad_header_and_empty_bitmap() {
        let mut raw = fixture(true);
        raw[0x20] = 0;
        raw[0x21] = 0;
        assert!(inspect_cia(&mut Cursor::new(&raw))
            .unwrap_err()
            .to_string()
            .contains("bitmap"));
        raw = fixture(false);
        raw[..4].copy_from_slice(&0x2021u32.to_le_bytes());
        assert!(inspect_cia(&mut Cursor::new(&raw)).is_err());
        raw[..4].copy_from_slice(&0x2020u32.to_le_bytes());
        raw[4] = 1;
        assert!(inspect_cia(&mut Cursor::new(&raw)).is_err());
    }

    #[test]
    fn truncated_intermediate_and_final_section_fail() {
        let raw = fixture(true);
        for cut in [0x2040usize, 0x2100, raw.len() - 1] {
            let mut shortened = raw.clone();
            shortened.truncate(cut);
            assert!(inspect_cia(&mut Cursor::new(shortened)).is_err());
        }
    }

    #[test]
    fn oversized_declared_lengths_are_rejected() {
        let mut raw = fixture(true);
        raw[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(inspect_cia(&mut Cursor::new(&raw)).is_err());
        raw = fixture(true);
        raw[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(inspect_cia(&mut Cursor::new(&raw)).is_err());
    }
}
