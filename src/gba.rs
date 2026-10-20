//! GBA cartridge header metadata and explicitly limited integrity checks.
//!
//! No standard GBA header field declares the complete ROM size or backup chip
//! type. The only mandatory 8-bit complement check covers bytes 0xA0..0xBC;
//! it is not a full-file checksum. The optional 156-byte logo *sum* below is
//! only a weak diagnostic and is NOT a byte-for-byte Nintendo logo comparison.
//! No proprietary logo artwork is bundled in the parser or its tests.

use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

const HEADER_BYTES: usize = 0xc0;
const LOGO_OFFSET: usize = 0x04;
const LOGO_END: usize = 0xa0;
const EXPECTED_LOGO_SUM: u16 = 0x4b1b;

fn bad(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn add(metadata: &mut Vec<(String, String)>, key: &str, value: impl ToString) {
    metadata.push((key.to_owned(), value.to_string()));
}

/// Recognize a plausible GBA header even if its complement checksum fails.
/// Detection intentionally does not claim that the logo bytes are authentic.
pub(crate) fn recognizable(header: &[u8]) -> bool {
    header.len() >= 0xbe
        && header[0xb2] == 0x96
        && header[0xac..0xb0].iter().all(u8::is_ascii_alphanumeric)
}

/// The GBA BIOS complement check, independent of file size and Nintendo logo.
pub fn complement_checksum(header: &[u8]) -> Option<u8> {
    if header.len() <= 0xbc {
        return None;
    }
    Some(header[0xa0..=0xbc].iter()
        .fold(0u8, |sum, byte| sum.wrapping_sub(*byte))
        .wrapping_sub(0x19))
}

/// Only a weak sum used by some cartridge dump tools; a matching sum does
/// not establish correct Nintendo logo artwork, a signed ROM, or provenance.
pub fn logo_weak_sum(header: &[u8]) -> Option<u16> {
    if header.len() < LOGO_END {
        return None;
    }
    Some(header[LOGO_OFFSET..LOGO_END].iter()
        .fold(0u16, |sum, byte| sum.wrapping_add(u16::from(*byte))))
}

pub(crate) fn metadata(header: &[u8]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    add(&mut result, "fixed_header_byte_valid", header[0xb2] == 0x96);
    add(&mut result, "main_unit_code", header[0xb3]);
    add(&mut result, "device_type", format!("0x{:02X}", header[0xb4]));
    add(&mut result, "device_debug_flag", header[0xb4] & 0x80 != 0);
    add(&mut result, "reserved_header_bytes_zero",
        header[0xb5..0xbc].iter().all(|value| *value == 0)
            && header[0xbe..0xc0].iter().all(|value| *value == 0));
    let calculated = complement_checksum(header).expect("full GBA header");
    add(&mut result, "header_checksum_stored",
        format!("0x{:02X}", header[0xbd]));
    add(&mut result, "header_checksum_calculated",
        format!("0x{calculated:02X}"));
    add(&mut result, "header_checksum_valid", calculated == header[0xbd]);
    let weak = logo_weak_sum(header).expect("full GBA header");
    add(&mut result, "logo_weak_sum", format!("0x{weak:04X}"));
    add(&mut result, "logo_weak_sum_matches_reference", weak == EXPECTED_LOGO_SUM);
    add(&mut result, "logo_bytes_authenticated", false);
    add(&mut result, "full_rom_checksum_available", false);
    add(&mut result, "declared_rom_size_available", false);
    add(&mut result, "save_chip_inferred", false);
    result
}

/// Explicit, read-only verification of header fields only, not the complete
/// ROM, the signature/logo bitmap, backup chip or source authenticity.
pub fn verify_gba_header<R: Read + Seek>(input: &mut R) -> io::Result<()> {
    let bytes = input.seek(SeekFrom::End(0))?;
    if bytes < HEADER_BYTES as u64 {
        return Err(bad("GBA header shorter than 0xC0 bytes"));
    }
    input.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; HEADER_BYTES];
    input.read_exact(&mut header)?;
    if !recognizable(&header) {
        return Err(bad("GBA fixed byte or cartridge game code invalid"));
    }
    if complement_checksum(&header) != Some(header[0xbd]) {
        return Err(bad("GBA header complement checksum mismatch"));
    }
    if logo_weak_sum(&header) != Some(EXPECTED_LOGO_SUM) {
        return Err(bad("GBA logo weak additive checksum mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        // Synthetic logo bytes adding to 0x4B1B; not Nintendo artwork.
        bytes[0x04..0xa0].fill(0x7b);
        bytes[0x04] = 0xa2;
        bytes[0xa0..0xa7].copy_from_slice(b"EXAMPLE");
        bytes[0xac..0xb0].copy_from_slice(b"ABCD");
        bytes[0xb0..0xb2].copy_from_slice(b"01");
        bytes[0xb2] = 0x96;
        bytes[0xbd] = complement_checksum(&bytes).unwrap();
        bytes
    }

    fn value<'a>(meta: &'a [(String, String)], name: &str) -> Option<&'a str> {
        meta.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    #[test]
    fn synthetic_header_decodes_checksums_and_no_fake_rom_capacity() {
        let bytes = sample();
        assert_eq!(logo_weak_sum(&bytes), Some(0x4b1b));
        assert!(recognizable(&bytes));
        let meta = metadata(&bytes);
        assert_eq!(value(&meta, "header_checksum_valid"), Some("true"));
        assert_eq!(value(&meta, "logo_weak_sum_matches_reference"), Some("true"));
        assert_eq!(value(&meta, "logo_bytes_authenticated"), Some("false"));
        assert_eq!(value(&meta, "declared_rom_size_available"), Some("false"));
        assert_eq!(value(&meta, "save_chip_inferred"), Some("false"));
        verify_gba_header(&mut Cursor::new(bytes)).unwrap();
    }

    #[test]
    fn changed_checksum_does_not_hide_header_but_fails_verify() {
        let mut bytes = sample();
        bytes[0xbd] ^= 1;
        assert!(recognizable(&bytes));
        assert_eq!(value(&metadata(&bytes), "header_checksum_valid"), Some("false"));
        assert!(verify_gba_header(&mut Cursor::new(bytes)).unwrap_err()
            .to_string().contains("complement checksum"));
    }

    #[test]
    fn changed_synthetic_logo_sum_fails_independently() {
        let mut bytes = sample();
        bytes[0x40] ^= 1;
        assert!(recognizable(&bytes));
        assert_eq!(value(&metadata(&bytes), "logo_weak_sum_matches_reference"), Some("false"));
        assert!(verify_gba_header(&mut Cursor::new(bytes)).unwrap_err()
            .to_string().contains("weak additive"));
    }

    #[test]
    fn reserved_bytes_and_debug_flag_are_metadata_not_authentication() {
        let mut bytes = sample();
        bytes[0xb4] = 0x80;
        bytes[0xb5] = 7;
        bytes[0xbd] = complement_checksum(&bytes).unwrap();
        let meta = metadata(&bytes);
        assert_eq!(value(&meta, "device_debug_flag"), Some("true"));
        assert_eq!(value(&meta, "reserved_header_bytes_zero"), Some("false"));
        verify_gba_header(&mut Cursor::new(bytes)).unwrap();
    }

    #[test]
    fn rejects_truncated_or_incorrect_fixed_headers() {
        let raw = sample();
        assert!(verify_gba_header(&mut Cursor::new(&raw[..0xbf])).is_err());
        let mut wrong = sample();
        wrong[0xb2] = 0;
        wrong[0xbd] = complement_checksum(&wrong).unwrap();
        assert!(!recognizable(&wrong));
        assert!(verify_gba_header(&mut Cursor::new(wrong)).is_err());
    }
}
