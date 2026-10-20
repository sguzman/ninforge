//! Standalone 3DS NCCH/CXI/CFA unencrypted header inspection.
//! The signature, encrypted content, title keys, and superblock digests are
//! NOT verified. Parsed extents are header claims, not extractable game files.
use std::io::{self, ErrorKind};

const HEADER_BYTES: usize = 0x200;
fn bad(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn le32(buf: &[u8]) -> u32 {
    u32::from_le_bytes(buf.try_into().unwrap())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcchRegion {
    pub name: &'static str,
    pub offset_bytes: u64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcchReport {
    pub partition_id: u64,
    pub program_id: u64,
    pub product_code: String,
    pub media_unit_bytes: u64,
    pub declared_content_bytes: u64,
    pub actual_file_bytes: u64,
    pub crypto_method: u8,
    pub content_platform: u8,
    pub content_form: u8,
    pub content_type: u8,
    pub no_crypto_flag: bool,
    pub regions: Vec<NcchRegion>,
    pub cryptographic_integrity_verified: bool,
}

/// Inspect the plaintext 0x200-byte NCCH header. All offsets/sizes are
/// bounded by both the header-declared image size and the supplied file.
/// Embedded NCCH within NCSD is not implicitly correlated or extracted.
pub fn inspect_ncch(head: &[u8], file_bytes: u64) -> io::Result<NcchReport> {
    if head.len() < HEADER_BYTES || &head[0x100..0x104] != b"NCCH" {
        return Err(bad("NCCH header truncated or signature invalid"));
    }
    let shift = head[0x18e];
    if shift > 8 {
        return Err(bad("NCCH media-unit shift exceeds supported range"));
    }
    let unit = 0x200u64 << shift;
    let declared_units = u64::from(le32(&head[0x104..0x108]));
    let capacity = declared_units.checked_mul(unit)
        .ok_or_else(|| bad("NCCH declared content capacity overflow"))?;
    if capacity < HEADER_BYTES as u64 || file_bytes < HEADER_BYTES as u64 {
        return Err(bad("NCCH content smaller than header"));
    }
    let partition_id = u64::from_le_bytes(head[0x108..0x110].try_into().unwrap());
    let program_id = u64::from_le_bytes(head[0x118..0x120].try_into().unwrap());
    let code = &head[0x150..0x160];
    let code_end = code.iter().position(|byte| *byte == 0).unwrap_or(code.len());
    if !code[..code_end].iter().all(|b| b.is_ascii_graphic() && *b != b'\\') {
        return Err(bad("NCCH product code contains invalid characters"));
    }
    let product_code = std::str::from_utf8(&code[..code_end])
        .map_err(|_| bad("NCCH product code encoding invalid"))?.to_owned();
    let mut regions = Vec::new();
    let mut spans = Vec::new();
    // Optional extended header occupies 2 * the declared size at 0x200.
    let extended = u64::from(le32(&head[0x180..0x184]));
    if extended > 0 {
        let extent = extended.checked_mul(2)
            .ok_or_else(|| bad("NCCH extended header size overflow"))?;
        if extent > capacity - HEADER_BYTES as u64 || extent > file_bytes - HEADER_BYTES as u64 {
            return Err(bad("NCCH extended header extends beyond file"));
        }
        regions.push(NcchRegion {
            name: "exheader", offset_bytes: 0x200, size_bytes: extent,
        });
        spans.push((0x200, 0x200 + extent));
    }
    for (name, at) in [
        ("plain", 0x190usize),
        ("logo", 0x198),
        ("exefs", 0x1a0),
        ("romfs", 0x1b0),
    ] {
        let offset_units = u64::from(le32(&head[at..at + 4]));
        let size_units = u64::from(le32(&head[at + 4..at + 8]));
        if offset_units == 0 && size_units == 0 {
            continue;
        }
        if offset_units == 0 || size_units == 0 {
            return Err(bad("NCCH content region has incomplete offset/size pair"));
        }
        let offset = offset_units.checked_mul(unit)
            .ok_or_else(|| bad("NCCH region offset overflow"))?;
        let length = size_units.checked_mul(unit)
            .ok_or_else(|| bad("NCCH region size overflow"))?;
        let end = offset.checked_add(length)
            .ok_or_else(|| bad("NCCH region end overflow"))?;
        if offset < HEADER_BYTES as u64 || end > capacity || end > file_bytes {
            return Err(bad("NCCH region extends outside declared capacity or file"));
        }
        regions.push(NcchRegion {
            name, offset_bytes: offset, size_bytes: length,
        });
        spans.push((offset, end));
    }
    spans.sort_by_key(|span| span.0);
    if spans.windows(2).any(|ranges| ranges[0].1 > ranges[1].0) {
        return Err(bad("NCCH content-region spans overlap"));
    }
    Ok(NcchReport {
        partition_id, program_id, product_code,
        media_unit_bytes: unit, declared_content_bytes: capacity,
        actual_file_bytes: file_bytes,
        crypto_method: head[0x18b],
        content_platform: head[0x18c],
        content_form: head[0x18d] & 3,
        content_type: head[0x18d] >> 2,
        no_crypto_flag: head[0x18f] & 0x04 != 0,
        regions, cryptographic_integrity_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut data = vec![0u8; 0x3000];
        data[0x100..0x104].copy_from_slice(b"NCCH");
        data[0x104..0x108].copy_from_slice(&24u32.to_le_bytes());
        data[0x108..0x110].copy_from_slice(&0x123u64.to_le_bytes());
        data[0x118..0x120].copy_from_slice(&0x456u64.to_le_bytes());
        data[0x150..0x158].copy_from_slice(b"CTR-DEMO");
        data[0x18c] = 1;
        data[0x18d] = 1;
        data[0x1a0..0x1a4].copy_from_slice(&2u32.to_le_bytes());
        data[0x1a4..0x1a8].copy_from_slice(&4u32.to_le_bytes());
        data[0x1b0..0x1b4].copy_from_slice(&6u32.to_le_bytes());
        data[0x1b4..0x1b8].copy_from_slice(&8u32.to_le_bytes());
        data
    }

    #[test]
    fn checks_product_ids_and_region_sizes_without_content_access() {
        let data = fixture();
        let got = inspect_ncch(&data[..0x200], data.len() as u64).unwrap();
        assert_eq!(got.product_code, "CTR-DEMO");
        assert_eq!(got.partition_id, 0x123);
        assert_eq!(got.program_id, 0x456);
        assert_eq!(got.regions.len(), 2);
        assert_eq!(got.regions[0].name, "exefs");
        assert_eq!(got.regions[0].offset_bytes, 1024);
        assert_eq!(got.regions[1].name, "romfs");
        assert_eq!(got.regions[1].size_bytes, 4096);
        assert!(!got.cryptographic_integrity_verified);
    }

    #[test]
    fn rejects_overlaps_and_truncated_content_regions() {
        let mut data = fixture();
        data[0x1b0..0x1b4].copy_from_slice(&5u32.to_le_bytes());
        assert!(inspect_ncch(&data[..0x200], data.len() as u64)
            .unwrap_err().to_string().contains("overlap"));
        data = fixture();
        data[0x1b4..0x1b8].copy_from_slice(&20u32.to_le_bytes());
        assert!(inspect_ncch(&data[..0x200], data.len() as u64)
            .unwrap_err().to_string().contains("outside"));
    }

    #[test]
    fn rejects_incomplete_spans_and_exheader_overlap() {
        let mut data = fixture();
        data[0x1a0..0x1a4].fill(0);
        assert!(inspect_ncch(&data[..0x200], data.len() as u64)
            .unwrap_err().to_string().contains("incomplete"));
        data = fixture();
        data[0x180..0x184].copy_from_slice(&0x300u32.to_le_bytes());
        assert!(inspect_ncch(&data[..0x200], data.len() as u64)
            .unwrap_err().to_string().contains("overlap"));
    }

    #[test]
    fn truncated_magic_and_invalid_product_code_are_errors() {
        let data = fixture();
        assert!(inspect_ncch(&data[..0x1ff], data.len() as u64).is_err());
        let mut bad = data;
        bad[0x150] = 0x01;
        assert!(inspect_ncch(&bad[..0x200], bad.len() as u64).is_err());
    }

    #[test]
    fn unit_shift_changes_sizes_and_keeps_bounds() {
        let mut data = fixture();
        data[0x18e] = 1;
        data[0x104..0x108].copy_from_slice(&12u32.to_le_bytes());
        let got = inspect_ncch(&data[..0x200], data.len() as u64).unwrap();
        assert_eq!(got.media_unit_bytes, 1024);
        assert_eq!(got.regions[0].offset_bytes, 2048);
    }
}
