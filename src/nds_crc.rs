//! Nintendo DS/DSi cartridge-header CRC-16/IBM observations.
//! The logo is deliberately not embedded: tests use synthetic bytes only.
//! CRC detects accidental corruption, not authenticity or a valid signature.
use std::io::{self, ErrorKind};

/// NDS BIOS-compatible CRC-16 (initial 0xFFFF, reflected poly 0xA001).
/// Also used by DS banners. Not a cryptographic hash.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderChecks {
    pub logo_stored: u16,
    pub logo_calculated: u16,
    pub header_stored: u16,
    pub header_calculated: u16,
}

impl HeaderChecks {
    pub fn logo_valid(self) -> bool {
        self.logo_stored == self.logo_calculated
    }

    pub fn header_valid(self) -> bool {
        self.header_stored == self.header_calculated
    }

    pub fn metadata(self) -> Vec<(String, String)> {
        [
            ("nds_logo_crc_stored", format!("0x{:04X}", self.logo_stored)),
            ("nds_logo_crc_calculated", format!("0x{:04X}", self.logo_calculated)),
            ("nds_logo_crc_valid", self.logo_valid().to_string()),
            ("nds_header_crc_stored", format!("0x{:04X}", self.header_stored)),
            ("nds_header_crc_calculated", format!("0x{:04X}", self.header_calculated)),
            ("nds_header_crc_valid", self.header_valid().to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }

    /// Structural CRC integrity only; does not verify provenance/signatures.
    pub fn ensure_valid(self) -> io::Result<()> {
        if !self.logo_valid() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Nintendo DS logo CRC-16 mismatch",
            ));
        }
        if !self.header_valid() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Nintendo DS header CRC-16 mismatch",
            ));
        }
        Ok(())
    }
}

/// Logo bytes are at [0xC0, 0x15C); stored logo CRC at [0x15C, 0x15E).
/// The full NDS header CRC at 0x15E covers [0, 0x15E).
pub(crate) fn inspect_header(header: &[u8]) -> io::Result<HeaderChecks> {
    if header.len() < 0x160 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Nintendo DS header too short for CRC fields",
        ));
    }
    Ok(HeaderChecks {
        logo_stored: u16::from_le_bytes(header[0x15c..0x15e].try_into().unwrap()),
        logo_calculated: crc16(&header[0xc0..0x15c]),
        header_stored: u16::from_le_bytes(header[0x15e..0x160].try_into().unwrap()),
        header_calculated: crc16(&header[..0x15e]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fictitious logo data patched to CRC 0xCF56; no copyrighted image.
    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        bytes[12..16].copy_from_slice(b"DEMO");
        bytes[0x15a..0x15c].copy_from_slice(&[0x04, 0x68]);
        bytes[0x15c..0x15e].copy_from_slice(&0xcf56u16.to_le_bytes());
        let header_crc = crc16(&bytes[..0x15e]);
        bytes[0x15e..0x160].copy_from_slice(&header_crc.to_le_bytes());
        bytes
    }

    #[test]
    fn crc_reference_and_synthetic_logo_vector() {
        assert_eq!(crc16(b"123456789"), 0x4b37);
        assert_eq!(crc16(&fixture()[0xc0..0x15c]), 0xcf56);
    }

    #[test]
    fn both_header_checks_pass_on_synthetic_fixture() {
        let header = fixture();
        let checks = inspect_header(&header).unwrap();
        assert_eq!(checks.logo_stored, 0xcf56);
        assert!(checks.logo_valid());
        assert!(checks.header_valid());
        checks.ensure_valid().unwrap();
        assert!(checks.metadata().contains(&(
            "nds_header_crc_valid".into(), "true".into()
        )));
    }

    #[test]
    fn damaged_logo_can_be_reported_even_if_header_crc_was_recomputed() {
        let mut header = fixture();
        header[0xc0] ^= 1;
        let header_crc = crc16(&header[..0x15e]);
        header[0x15e..0x160].copy_from_slice(&header_crc.to_le_bytes());
        let checks = inspect_header(&header).unwrap();
        assert!(!checks.logo_valid());
        assert!(checks.header_valid());
        assert!(checks.ensure_valid().unwrap_err().to_string().contains("logo"));
    }

    #[test]
    fn corrupted_header_crc_does_not_invalidate_intact_logo_crc() {
        let mut header = fixture();
        header[0x20] ^= 1;
        let checks = inspect_header(&header).unwrap();
        assert!(checks.logo_valid());
        assert!(!checks.header_valid());
        assert!(checks.ensure_valid().unwrap_err().to_string().contains("header"));
    }

    #[test]
    fn offsets_are_bounded_and_truncated_data_is_rejected() {
        assert_eq!(inspect_header(&fixture()[..0x15f]).unwrap_err().kind(), ErrorKind::InvalidData);
        assert!(inspect_header(&fixture()[..0x160]).is_ok());
    }
}
