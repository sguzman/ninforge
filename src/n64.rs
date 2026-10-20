//! Read-only Nintendo 64 cartridge header inspection in all three byte orders.
//!
//! File extensions do not determine format. The ROM magic does. CRC1/CRC2
//! fields are merely *reported*, never checked without an identified CIC.
//! This parser reads only 64 bytes and cannot authenticate cartridge contents.
use std::io::{self, ErrorKind};

const HEADER_LEN: usize = 0x40;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteOrder {
    Native,
    Swap16,
    LittleEndian32,
}

impl ByteOrder {
    pub fn label(self) -> &'static str {
        match self {
            Self::Native => "big-endian (.z64)",
            Self::Swap16 => "byte-swapped 16-bit (.v64)",
            Self::LittleEndian32 => "little-endian 32-bit (.n64)",
        }
    }

    pub fn from_magic(data: &[u8]) -> Option<Self> {
        match data.get(..4)? {
            [0x80, 0x37, 0x12, 0x40] => Some(Self::Native),
            [0x37, 0x80, 0x40, 0x12] => Some(Self::Swap16),
            [0x40, 0x12, 0x37, 0x80] => Some(Self::LittleEndian32),
            _ => None,
        }
    }
}

fn normalize(header: &[u8], order: ByteOrder) -> [u8; HEADER_LEN] {
    let mut result = [0u8; HEADER_LEN];
    for (index, output) in result.iter_mut().enumerate() {
        let source = match order {
            ByteOrder::Native => index,
            ByteOrder::Swap16 => index ^ 1,
            ByteOrder::LittleEndian32 => index ^ 3,
        };
        *output = header[source];
    }
    result
}

fn be32(data: &[u8]) -> u32 {
    u32::from_be_bytes(data.try_into().unwrap())
}

fn ascii_field(bytes: &[u8]) -> (String, bool) {
    let trimmed = match bytes.iter().rposition(|&c| c != 0 && c != b' ') {
        Some(last) => &bytes[..=last],
        None => &bytes[..0],
    };
    let valid = trimmed.iter().all(|c| *c == b' ' || c.is_ascii_graphic());
    let display = trimmed.iter().map(|&c| {
        if c.is_ascii_graphic() || c == b' ' {
            char::from(c)
        } else {
            '?'
        }
    }).collect::<String>();
    (display, valid)
}

/// Describes byte-order-normalized, unauthenticated header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N64Header {
    pub byte_order: ByteOrder,
    pub clock_rate: u32,
    pub entry_point: u32,
    pub sdk_revision: u32,
    pub crc1_stored: u32,
    pub crc2_stored: u32,
    pub title: String,
    pub title_ascii_valid: bool,
    pub category: u8,
    pub game_code: String,
    pub game_code_ascii_valid: bool,
    pub country_code: u8,
    pub version: u8,
}

pub fn inspect_n64(header: &[u8]) -> io::Result<N64Header> {
    if header.len() < HEADER_LEN {
        return Err(invalid("N64 cartridge header is shorter than 64 bytes"));
    }
    let order = ByteOrder::from_magic(header)
        .ok_or_else(|| invalid("N64 cartridge byte-order magic not recognized"))?;
    let bytes = normalize(header, order);
    let (title, title_ascii_valid) = ascii_field(&bytes[0x20..0x34]);
    // A complete four-character game code consists of category, game ID,
    // and country. These are stored as untrusted header claims.
    let (game_code, game_code_ascii_valid) = ascii_field(&bytes[0x3b..0x3f]);
    Ok(N64Header {
        byte_order: order,
        clock_rate: be32(&bytes[0x04..0x08]),
        entry_point: be32(&bytes[0x08..0x0c]),
        sdk_revision: be32(&bytes[0x0c..0x10]),
        crc1_stored: be32(&bytes[0x10..0x14]),
        crc2_stored: be32(&bytes[0x14..0x18]),
        title,
        title_ascii_valid,
        category: bytes[0x3b],
        game_code,
        game_code_ascii_valid,
        country_code: bytes[0x3e],
        version: bytes[0x3f],
    })
}

impl N64Header {
    pub fn metadata(&self) -> Vec<(String, String)> {
        let mut fields = vec![
            ("byte_order".into(), self.byte_order.label().into()),
            ("title".into(), self.title.clone()),
            ("title_ascii_valid".into(), self.title_ascii_valid.to_string()),
            ("game_code".into(), self.game_code.clone()),
            ("game_code_ascii_valid".into(), self.game_code_ascii_valid.to_string()),
            ("entry_point".into(), format!("0x{:08X}", self.entry_point)),
            ("clock_rate".into(), format!("0x{:08X}", self.clock_rate)),
            ("sdk_revision".into(), format!("0x{:08X}", self.sdk_revision)),
            ("crc1_stored".into(), format!("0x{:08X}", self.crc1_stored)),
            ("crc2_stored".into(), format!("0x{:08X}", self.crc2_stored)),
            ("crc1_crc2_verified".into(), "false".into()),
            ("cic_identified".into(), "false".into()),
            ("rom_data_verified".into(), "false".into()),
            ("category_code".into(), format!("0x{:02X}", self.category)),
            ("country_code".into(), format!("0x{:02X}", self.country_code)),
            ("rom_version".into(), self.version.to_string()),
        ];
        if self.category.is_ascii_graphic() {
            fields.push(("category_character".into(), char::from(self.category).to_string()));
        }
        if self.country_code.is_ascii_graphic() {
            fields.push(("country_character".into(), char::from(self.country_code).to_string()));
        }
        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical() -> [u8; 0x40] {
        let mut bytes = [0u8; 0x40];
        bytes[..4].copy_from_slice(&[0x80, 0x37, 0x12, 0x40]);
        bytes[0x04..0x08].copy_from_slice(&0x0000000fu32.to_be_bytes());
        bytes[0x08..0x0c].copy_from_slice(&0x80000400u32.to_be_bytes());
        bytes[0x0c..0x10].copy_from_slice(&0x11223344u32.to_be_bytes());
        bytes[0x10..0x14].copy_from_slice(&0x12345678u32.to_be_bytes());
        bytes[0x14..0x18].copy_from_slice(&0x9abcdef0u32.to_be_bytes());
        bytes[0x20..0x2c].copy_from_slice(b"TEST PROGRAM");
        bytes[0x3b..0x3f].copy_from_slice(b"NABE");
        bytes[0x3f] = 3;
        bytes
    }

    fn swapped(source: &[u8; 0x40], order: ByteOrder) -> [u8; 0x40] {
        normalize(source, order)
    }

    #[test]
    fn decodes_identical_fields_in_all_three_orders() {
        let canonical = canonical();
        let expected = inspect_n64(&canonical).unwrap();
        assert_eq!(expected.title, "TEST PROGRAM");
        assert_eq!(expected.game_code, "NABE");
        assert_eq!(expected.entry_point, 0x80000400);
        assert_eq!(expected.crc2_stored, 0x9abcdef0);
        for order in [ByteOrder::Native, ByteOrder::Swap16, ByteOrder::LittleEndian32] {
            let other = inspect_n64(&swapped(&canonical, order)).unwrap();
            assert_eq!(other.byte_order, order);
            assert_eq!(other.title, expected.title);
            assert_eq!(other.entry_point, expected.entry_point);
            assert_eq!(other.crc1_stored, expected.crc1_stored);
            assert_eq!(other.game_code, expected.game_code);
            assert_eq!(other.country_code, expected.country_code);
        }
    }

    #[test]
    fn changed_raw_crc_is_reported_not_claimed_verified() {
        let mut head = canonical();
        head[0x10] ^= 0x11;
        let meta = inspect_n64(&head).unwrap().metadata();
        assert!(meta.contains(&("crc1_crc2_verified".into(), "false".into())));
        assert!(meta.contains(&("crc1_stored".into(), "0x03345678".into())));
    }

    #[test]
    fn odd_title_bytes_are_sanitized_without_changing_source() {
        let mut head = canonical();
        head[0x20] = 0x1b;
        let parsed = inspect_n64(&head).unwrap();
        assert!(parsed.title.starts_with('?'));
        assert!(!parsed.title_ascii_valid);
    }

    #[test]
    fn truncated_headers_and_unknown_magic_are_rejected() {
        let head = canonical();
        assert!(inspect_n64(&head[..0x3f]).is_err());
        let mut corrupted = head;
        corrupted[0] ^= 1;
        assert!(inspect_n64(&corrupted).is_err());
    }
}
