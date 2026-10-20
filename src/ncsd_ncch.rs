//! Read-only consistency check between an NCSD partition index and the
//! plaintext 0x200-byte NCCH headers at those declared partition offsets.
//! Cryptographic signatures, keys and encrypted data remain unverified.
use crate::{ncch, ncsd};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

fn bad(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NcsdNcchEntry {
    pub index: usize,
    pub ncsd_offset_bytes: u64,
    pub ncsd_partition_bytes: u64,
    pub ncch_claimed_bytes: u64,
    pub ncsd_partition_id: u64,
    pub ncch_partition_id: u64,
    /// None means no partition ID was declared by the NCSD table.
    pub partition_id_matches: Option<bool>,
    pub ncch_program_id: u64,
    pub ncch_product_code: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NcsdNcchReport {
    pub media_id: u64,
    pub checked_entries: Vec<NcsdNcchEntry>,
    pub compared_partition_ids: usize,
    pub matching_partition_ids: usize,
    pub signatures_verified: bool,
    pub encrypted_content_verified: bool,
}

/// Opt-in cross-check for CCI-like NCSD containers whose populated partitions
/// are NCCH (FS type 1). Refuse unsupported FS types rather than interpreting
/// them as NCCH. The caller's file is only opened for bounded reads.
pub fn crosscheck<R: Read + Seek>(reader: &mut R) -> io::Result<NcsdNcchReport> {
    let length = reader.seek(SeekFrom::End(0))?;
    if length < 0x200 {
        return Err(bad("NCSD file too short for header"));
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut raw = [0u8; 0x200];
    reader.read_exact(&mut raw)?;
    let ncsd = ncsd::inspect_ncsd(&raw, length)?;
    let mut checked_entries = Vec::with_capacity(ncsd.partitions.len());
    let mut compared = 0usize;
    let mut matched = 0usize;
    for part in &ncsd.partitions {
        if part.fs_type != 1 {
            return Err(bad("NCSD partition is not an NCCH filesystem type"));
        }
        if part.size_bytes < 0x200 {
            return Err(bad("NCSD partition shorter than NCCH header"));
        }
        reader.seek(SeekFrom::Start(part.offset_bytes))?;
        let mut header = [0u8; 0x200];
        reader.read_exact(&mut header)?;
        let inner = ncch::inspect_ncch(&header, part.size_bytes)?;
        if inner.declared_content_bytes > part.size_bytes {
            return Err(bad("NCCH declared size exceeds enclosing NCSD partition"));
        }
        let id_matches = if part.partition_id == 0 {
            None
        } else {
            compared += 1;
            let same = part.partition_id == inner.partition_id;
            if same {
                matched += 1;
            }
            Some(same)
        };
        checked_entries.push(NcsdNcchEntry {
            index: part.index,
            ncsd_offset_bytes: part.offset_bytes,
            ncsd_partition_bytes: part.size_bytes,
            ncch_claimed_bytes: inner.declared_content_bytes,
            ncsd_partition_id: part.partition_id,
            ncch_partition_id: inner.partition_id,
            partition_id_matches: id_matches,
            ncch_program_id: inner.program_id,
            ncch_product_code: inner.product_code,
        });
    }
    Ok(NcsdNcchReport {
        media_id: ncsd.media_id,
        checked_entries,
        compared_partition_ids: compared,
        matching_partition_ids: matched,
        signatures_verified: false,
        encrypted_content_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample() -> Vec<u8> {
        let mut raw = vec![0u8; 0x5000];
        raw[0x100..0x104].copy_from_slice(b"NCSD");
        raw[0x104..0x108].copy_from_slice(&40u32.to_le_bytes());
        raw[0x108..0x110].copy_from_slice(&0xABCDu64.to_le_bytes());
        raw[0x110] = 1; // NCCH FS
        raw[0x120..0x124].copy_from_slice(&1u32.to_le_bytes());
        raw[0x124..0x128].copy_from_slice(&24u32.to_le_bytes());
        raw[0x190..0x198].copy_from_slice(&0x1234u64.to_le_bytes());
        let p = 0x200;
        raw[p + 0x100..p + 0x104].copy_from_slice(b"NCCH");
        raw[p + 0x104..p + 0x108].copy_from_slice(&16u32.to_le_bytes());
        raw[p + 0x108..p + 0x110].copy_from_slice(&0x1234u64.to_le_bytes());
        raw[p + 0x118..p + 0x120].copy_from_slice(&0x5678u64.to_le_bytes());
        raw[p + 0x150..p + 0x158].copy_from_slice(b"CTR-DEMO");
        raw
    }

    #[test]
    fn checks_inner_ncch_bounded_header_and_matches_nonzero_ids() {
        let file = sample();
        let report = crosscheck(&mut Cursor::new(&file)).unwrap();
        assert_eq!(report.checked_entries.len(), 1);
        assert_eq!(report.compared_partition_ids, 1);
        assert_eq!(report.matching_partition_ids, 1);
        assert_eq!(report.checked_entries[0].partition_id_matches, Some(true));
        assert_eq!(report.checked_entries[0].ncsd_offset_bytes, 0x200);
        assert_eq!(report.checked_entries[0].ncch_claimed_bytes, 0x2000);
        assert_eq!(report.checked_entries[0].ncch_product_code, "CTR-DEMO");
        assert!(!report.signatures_verified);
    }

    #[test]
    fn mismatched_ids_are_reported_without_fake_authentication() {
        let mut raw = sample();
        raw[0x190..0x198].copy_from_slice(&0x9999u64.to_le_bytes());
        let report = crosscheck(&mut Cursor::new(raw)).unwrap();
        assert_eq!(report.compared_partition_ids, 1);
        assert_eq!(report.matching_partition_ids, 0);
        assert_eq!(report.checked_entries[0].partition_id_matches, Some(false));
    }

    #[test]
    fn missing_ncsd_id_does_not_manufacture_a_comparison() {
        let mut raw = sample();
        raw[0x190..0x198].fill(0);
        let result = crosscheck(&mut Cursor::new(raw)).unwrap();
        assert_eq!(result.compared_partition_ids, 0);
        assert_eq!(result.checked_entries[0].partition_id_matches, None);
    }

    #[test]
    fn rejects_wrong_inner_header_and_overlarge_claim() {
        let mut raw = sample();
        raw[0x300..0x304].fill(0);
        assert!(crosscheck(&mut Cursor::new(raw))
            .unwrap_err()
            .to_string()
            .contains("NCCH"));
        let mut raw = sample();
        raw[0x304..0x308].copy_from_slice(&30u32.to_le_bytes());
        assert!(crosscheck(&mut Cursor::new(raw))
            .unwrap_err()
            .to_string()
            .contains("exceeds enclosing"));
    }

    #[test]
    fn non_ncch_fs_type_is_rejected_explicitly() {
        let mut raw = sample();
        raw[0x110] = 3;
        assert!(crosscheck(&mut Cursor::new(raw))
            .unwrap_err()
            .to_string()
            .contains("not an NCCH"));
    }
}
