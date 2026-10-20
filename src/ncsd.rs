//! Bounded, read-only 3DS NCSD (CCI) partition-table inspection.
//!
//! NCSD contains up to eight NCCH partitions. These byte spans may be
//! encrypted and signatures are NOT verified. No keys, decrypted data,
//! proprietary signatures, or actual game images are bundled with Ninforge.
use std::io::{self, ErrorKind};

const HEADER_SIZE: usize = 0x200;
const MAX_MEDIA_UNIT_SHIFT: u8 = 8;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcsdPartition {
    pub index: usize,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub fs_type: u8,
    pub crypt_type: u8,
    pub partition_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcsdReport {
    pub media_id: u64,
    pub declared_media_bytes: u64,
    pub actual_file_bytes: u64,
    pub media_unit_bytes: u64,
    pub media_type: u8,
    pub partitions: Vec<NcsdPartition>,
    pub signature_verified: bool,
}

/// Checks only the exposed header and listed ranges. NCSD is used by more
/// than cartridge images; the cart-specific flags are reported as claims.
pub fn inspect_ncsd(header: &[u8], file_bytes: u64) -> io::Result<NcsdReport> {
    if header.len() < HEADER_SIZE || &header[0x100..0x104] != b"NCSD" {
        return Err(invalid("NCSD header truncated or magic invalid"));
    }
    let unit_shift = header[0x18e];
    if unit_shift > MAX_MEDIA_UNIT_SHIFT {
        return Err(invalid("NCSD media unit shift exceeds supported range"));
    }
    let media_unit = 0x200u64 << unit_shift;
    let declared_units = u64::from(le32(&header[0x104..0x108]));
    if declared_units == 0 {
        return Err(invalid("NCSD declared media size is zero"));
    }
    let capacity = declared_units.checked_mul(media_unit)
        .ok_or_else(|| invalid("NCSD declared size overflow"))?;
    if capacity < HEADER_SIZE as u64 || file_bytes < HEADER_SIZE as u64 {
        return Err(invalid("NCSD image smaller than required header"));
    }
    let media_id = u64::from_le_bytes(header[0x108..0x110].try_into().unwrap());
    let media_type = header[0x18d];
    let mut partitions = Vec::new();
    let mut spans = Vec::new();
    for index in 0..8 {
        let start = 0x120 + index * 8;
        let offset = u64::from(le32(&header[start..start + 4]));
        let size = u64::from(le32(&header[start + 4..start + 8]));
        if offset == 0 && size == 0 {
            continue;
        }
        if offset == 0 || size == 0 {
            return Err(invalid("NCSD partition has only one of offset and size"));
        }
        let begin = offset.checked_mul(media_unit)
            .ok_or_else(|| invalid("NCSD partition offset overflow"))?;
        let count = size.checked_mul(media_unit)
            .ok_or_else(|| invalid("NCSD partition size overflow"))?;
        let end = begin.checked_add(count)
            .ok_or_else(|| invalid("NCSD partition end overflow"))?;
        if begin < HEADER_SIZE as u64 || end > capacity || end > file_bytes {
            return Err(invalid("NCSD partition extends outside declared media or supplied file"));
        }
        spans.push((begin, end));
        let part_id = u64::from_le_bytes(
            header[0x190 + index * 8..0x198 + index * 8].try_into().unwrap()
        );
        partitions.push(NcsdPartition {
            index, offset_bytes: begin, size_bytes: count,
            fs_type: header[0x110 + index],
            crypt_type: header[0x118 + index],
            partition_id: part_id,
        });
    }
    spans.sort_by_key(|range| range.0);
    if spans.windows(2).any(|window| window[0].1 > window[1].0) {
        return Err(invalid("NCSD partition spans overlap"));
    }
    Ok(NcsdReport {
        media_id, declared_media_bytes: capacity,
        actual_file_bytes: file_bytes, media_unit_bytes: media_unit,
        media_type, partitions, signature_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic() -> Vec<u8> {
        let mut data = vec![0u8; 0x2000];
        data[0x100..0x104].copy_from_slice(b"NCSD");
        data[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
        data[0x108..0x110].copy_from_slice(&0x123456789u64.to_le_bytes());
        data[0x110] = 1;
        data[0x118] = 2;
        data[0x120..0x124].copy_from_slice(&1u32.to_le_bytes());
        data[0x124..0x128].copy_from_slice(&3u32.to_le_bytes());
        data[0x128..0x12c].copy_from_slice(&4u32.to_le_bytes());
        data[0x12c..0x130].copy_from_slice(&2u32.to_le_bytes());
        data[0x190..0x198].copy_from_slice(&0xABCDu64.to_le_bytes());
        data[0x18d] = 1; // cartridge media type claim
        data
    }

    #[test]
    fn reads_media_claims_and_nonoverlapping_partitions() {
        let data = synthetic();
        let got = inspect_ncsd(&data[..0x200], data.len() as u64).unwrap();
        assert_eq!(got.media_id, 0x123456789);
        assert_eq!(got.media_unit_bytes, 512);
        assert_eq!(got.declared_media_bytes, 8192);
        assert_eq!(got.media_type, 1);
        assert_eq!(got.partitions.len(), 2);
        assert_eq!(got.partitions[0].offset_bytes, 512);
        assert_eq!(got.partitions[0].size_bytes, 1536);
        assert_eq!(got.partitions[0].partition_id, 0xabcd);
        assert_eq!(got.partitions[1].index, 1);
        assert!(!got.signature_verified);
    }

    #[test]
    fn rejects_partition_outside_capacity_and_file() {
        let mut data = synthetic();
        data[0x120..0x124].copy_from_slice(&15u32.to_le_bytes());
        assert!(inspect_ncsd(&data[..0x200], data.len() as u64).unwrap_err()
            .to_string().contains("outside"));
        data = synthetic();
        data.truncate(0x800);
        assert!(inspect_ncsd(&data[..0x200], data.len() as u64).unwrap_err()
            .to_string().contains("outside"));
    }

    #[test]
    fn rejects_overlap_and_half_empty_entries() {
        let mut data = synthetic();
        data[0x128..0x12c].copy_from_slice(&3u32.to_le_bytes());
        assert!(inspect_ncsd(&data[..0x200], data.len() as u64).unwrap_err()
            .to_string().contains("overlap"));
        data = synthetic();
        data[0x124..0x128].fill(0);
        assert!(inspect_ncsd(&data[..0x200], data.len() as u64).unwrap_err()
            .to_string().contains("only one"));
    }

    #[test]
    fn checks_media_unit_shift_and_nonzero_declared_size() {
        let mut data = synthetic();
        data[0x18e] = 9;
        assert!(inspect_ncsd(&data[..0x200], data.len() as u64).is_err());
        data = synthetic();
        data[0x104..0x108].fill(0);
        assert!(inspect_ncsd(&data[..0x200], data.len() as u64).is_err());
        data = synthetic();
        data[0x18e] = 1;
        data[0x104..0x108].copy_from_slice(&8u32.to_le_bytes());
        // double media unit, restore original capacity; partitions scale too
        let got = inspect_ncsd(&data[..0x200], data.len() as u64).unwrap();
        assert_eq!(got.media_unit_bytes, 1024);
    }

    #[test]
    fn refuses_truncated_header_and_non_ncsd_magic() {
        let data = synthetic();
        assert!(inspect_ncsd(&data[..0x1ff], data.len() as u64).is_err());
        let mut bad = data;
        bad[0x100] = 0;
        assert!(inspect_ncsd(&bad[..0x200], bad.len() as u64).is_err());
    }
}
