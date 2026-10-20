//! Opt-in 3DS CIA title-metadata (TMD) claim audit.
//!
//! Reads only the signed TMD header and content-chunk records, then compares
//! their content indices and declared sizes to the CIA header. A recognized
//! RSA/ECDSA signature *type* is not signature verification. No content bytes,
//! ticket titlekeys, hashes, certificates or encrypted data are checked.
use crate::cia;
use std::collections::HashSet;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

const MAX_TMD_RECORDS: usize = 4096;
const CHUNK_SIZE: usize = 0x30;

fn bad(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().unwrap())
}
fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().unwrap())
}
fn be64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiaTmdContent {
    pub content_id: u32,
    pub content_index: u16,
    pub content_type: u16,
    pub declared_size_bytes: u64,
    pub selected_by_cia_bitmap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiaTmdReport {
    pub title_id: u64,
    pub title_version: u16,
    pub signature_type: u32,
    pub tmd_record_count: usize,
    pub bitmap_bit_count: u32,
    pub selected_record_count: usize,
    pub bitmap_entries_without_tmd_record: u32,
    pub unselected_tmd_records: usize,
    pub selected_content_declared_bytes: u64,
    pub cia_content_region_bytes: u64,
    pub records: Vec<CiaTmdContent>,
    pub cryptographic_integrity_verified: bool,
}

fn signed_header_base(signature_type: u32) -> Option<u64> {
    match signature_type {
        0x0001_0000 | 0x0001_0003 => Some(0x240), // RSA4096
        0x0001_0001 | 0x0001_0004 => Some(0x140), // RSA2048
        0x0001_0002 | 0x0001_0005 => Some(0x80),  // ECDSA
        _ => None,
    }
}

/// Read only bounded TMD metadata and compare it with the CIA bitmap.
/// The bitmap can intentionally omit optional TMD contents. Those records
/// are reported as unselected, not errors.
pub fn inspect_cia_tmd<R: Read + Seek>(reader: &mut R) -> io::Result<CiaTmdReport> {
    let outer = cia::inspect_cia(reader)?;
    let tmd = outer
        .sections
        .iter()
        .find(|section| section.name == "tmd")
        .ok_or_else(|| bad("CIA TMD section missing"))?;
    let content = outer
        .sections
        .iter()
        .find(|section| section.name == "content")
        .ok_or_else(|| bad("CIA content section missing"))?;
    reader.seek(SeekFrom::Start(tmd.offset_bytes))?;
    let mut signature_type_raw = [0u8; 4];
    reader.read_exact(&mut signature_type_raw)?;
    let signature_type = be32(&signature_type_raw);
    let base = signed_header_base(signature_type)
        .ok_or_else(|| bad("CIA TMD signature type unsupported"))?;
    if tmd.size_bytes < base + 0x9c4 {
        return Err(bad("CIA TMD too short for signed header and info records"));
    }
    reader.seek(SeekFrom::Start(tmd.offset_bytes + base))?;
    let mut head = [0u8; 0xc4];
    reader.read_exact(&mut head)?;
    let title_id = be64(&head[0x4c..0x54]);
    let title_version = be16(&head[0x9c..0x9e]);
    let count = usize::from(be16(&head[0x9e..0xa0]));
    if count == 0 || count > MAX_TMD_RECORDS {
        return Err(bad(
            "CIA TMD record count is empty or exceeds inspection cap",
        ));
    }
    let needed = base
        .checked_add(0x9c4)
        .and_then(|v| v.checked_add(count as u64 * CHUNK_SIZE as u64))
        .ok_or_else(|| bad("CIA TMD record table size overflow"))?;
    if needed > tmd.size_bytes {
        return Err(bad("CIA TMD content chunk table truncated"));
    }
    reader.seek(SeekFrom::Start(tmd.offset_bytes + base + 0x9c4))?;
    let mut records = vec![0u8; count * CHUNK_SIZE];
    reader.read_exact(&mut records)?;

    reader.seek(SeekFrom::Start(0x20))?;
    let mut bitmap = [0u8; 0x2000];
    reader.read_exact(&mut bitmap)?;
    let bitmap_count: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
    let mut content_records = Vec::with_capacity(count);
    let mut known_indices = HashSet::new();
    let mut selected_bytes = 0u64;
    let mut selected_count = 0usize;
    for row in records.chunks_exact(CHUNK_SIZE) {
        let id = be32(&row[0..4]);
        let index = be16(&row[4..6]);
        let kind = be16(&row[6..8]);
        let size = be64(&row[8..16]);
        if size == 0 {
            return Err(bad("CIA TMD content chunk has zero declared size"));
        }
        if !known_indices.insert(index) {
            return Err(bad("CIA TMD has duplicate content indices"));
        }
        let at = usize::from(index);
        let selected = bitmap[at / 8] & (0x80 >> (at % 8)) != 0;
        if selected {
            selected_count += 1;
            selected_bytes = selected_bytes
                .checked_add(size)
                .ok_or_else(|| bad("CIA TMD selected content size overflow"))?;
        }
        content_records.push(CiaTmdContent {
            content_id: id,
            content_index: index,
            content_type: kind,
            declared_size_bytes: size,
            selected_by_cia_bitmap: selected,
        });
    }
    if selected_bytes > content.size_bytes {
        return Err(bad(
            "CIA selected TMD content exceeds archive content section",
        ));
    }
    Ok(CiaTmdReport {
        title_id,
        title_version,
        signature_type,
        tmd_record_count: count,
        bitmap_bit_count: bitmap_count,
        selected_record_count: selected_count,
        bitmap_entries_without_tmd_record: bitmap_count - selected_count as u32,
        unselected_tmd_records: count - selected_count,
        selected_content_declared_bytes: selected_bytes,
        cia_content_region_bytes: content.size_bytes,
        records: content_records,
        cryptographic_integrity_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn fixture(selected: bool) -> Vec<u8> {
        let cert = 0x80u32;
        let ticket = 0x100u32;
        let tmd = (0x140 + 0x9c4 + 0x30) as u32;
        let content = 0x400u64;
        let mut raw = vec![0u8; 0x2020];
        raw[..4].copy_from_slice(&0x2020u32.to_le_bytes());
        raw[8..12].copy_from_slice(&cert.to_le_bytes());
        raw[12..16].copy_from_slice(&ticket.to_le_bytes());
        raw[16..20].copy_from_slice(&tmd.to_le_bytes());
        raw[24..32].copy_from_slice(&content.to_le_bytes());
        raw[0x20] = if selected { 0x80 } else { 0x40 };
        let mut offset = 0x2040usize;
        for size in [
            cert as usize,
            ticket as usize,
            tmd as usize,
            content as usize,
        ] {
            raw.resize(offset + size, 0);
            offset = (offset + size + 63) & !63;
        }
        let tmd_offset = 0x2040 + cert as usize + ticket as usize;
        raw[tmd_offset..tmd_offset + 4].copy_from_slice(&0x0001_0004u32.to_be_bytes());
        let base = tmd_offset + 0x140;
        raw[base + 0x4c..base + 0x54].copy_from_slice(&0x4000000123456u64.to_be_bytes());
        raw[base + 0x9c..base + 0x9e].copy_from_slice(&8u16.to_be_bytes());
        raw[base + 0x9e..base + 0xa0].copy_from_slice(&1u16.to_be_bytes());
        let chunk = base + 0x9c4;
        raw[chunk..chunk + 4].copy_from_slice(&0xABCDu32.to_be_bytes());
        raw[chunk + 4..chunk + 6].copy_from_slice(&0u16.to_be_bytes());
        raw[chunk + 6..chunk + 8].copy_from_slice(&1u16.to_be_bytes());
        raw[chunk + 8..chunk + 16].copy_from_slice(&content.to_be_bytes());
        raw
    }

    #[test]
    fn reads_signed_metadata_claims_and_selected_content() {
        let raw = fixture(true);
        let report = inspect_cia_tmd(&mut Cursor::new(raw)).unwrap();
        assert_eq!(report.title_id, 0x4000000123456);
        assert_eq!(report.title_version, 8);
        assert_eq!(report.signature_type, 0x0001_0004);
        assert_eq!(report.selected_record_count, 1);
        assert_eq!(report.bitmap_entries_without_tmd_record, 0);
        assert_eq!(report.cia_content_region_bytes, 1024);
        assert_eq!(report.records[0].content_index, 0);
        assert_eq!(report.records[0].content_type, 1);
        assert!(!report.cryptographic_integrity_verified);
    }

    #[test]
    fn unselected_optional_record_is_not_conflated_with_inconsistent_size() {
        let raw = fixture(false);
        let report = inspect_cia_tmd(&mut Cursor::new(raw)).unwrap();
        assert_eq!(report.selected_record_count, 0);
        assert_eq!(report.unselected_tmd_records, 1);
        assert_eq!(report.bitmap_entries_without_tmd_record, 1);
    }

    #[test]
    fn oversized_selected_content_and_bad_signature_are_rejected() {
        let mut raw = fixture(true);
        let tmd = 0x2040 + 0x80 + 0x100;
        let chunk = tmd + 0x140 + 0x9c4;
        raw[chunk + 8..chunk + 16].copy_from_slice(&0x500u64.to_be_bytes());
        assert!(inspect_cia_tmd(&mut Cursor::new(raw))
            .unwrap_err()
            .to_string()
            .contains("exceeds archive"));
        let mut raw = fixture(true);
        raw[tmd..tmd + 4].fill(0);
        assert!(inspect_cia_tmd(&mut Cursor::new(raw))
            .unwrap_err()
            .to_string()
            .contains("signature type unsupported"));
    }

    #[test]
    fn incomplete_tmd_chunk_table_is_rejected() {
        let mut raw = fixture(true);
        let tmd = 0x2040 + 0x80 + 0x100;
        let count = tmd + 0x140 + 0x9e;
        raw[count..count + 2].copy_from_slice(&2u16.to_be_bytes());
        assert!(inspect_cia_tmd(&mut Cursor::new(raw))
            .unwrap_err()
            .to_string()
            .contains("table truncated"));
    }
}
