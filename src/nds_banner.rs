//! Read-only Nintendo DS/DSi cartridge icon/banner metadata.
//! Banner location is an NDS cartridge header field, not an arbitrary scan.
//! Sizes and CRC regions follow GBATEK and ndstool. Icon pixels are not decoded.
use crate::Entry;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

const TITLE_LANGUAGES: [&str; 8] = [
    "japanese", "english", "french", "german", "italian", "spanish", "chinese", "korean",
];
const MAX_BANNER: usize = 0x23c0;
const CRC_REGIONS: [(usize, usize, usize); 4] = [
    (2, 0x20, 0x840),
    (4, 0x20, 0x940),
    (6, 0x20, 0xa40),
    (8, 0x1240, 0x23c0),
];

fn bad(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

#[derive(Debug, Clone)]
pub(crate) struct Banner {
    pub entry: Entry,
    pub metadata: Vec<(String, String)>,
}

/// CRC-16/IBM (reflected poly 0xA001, init 0xFFFF), used for NDS
/// banner checksum regions; never mistaken for a cryptographic signature.
fn crc16(data: &[u8]) -> u16 {
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

fn version_size(version: u16) -> Option<(usize, usize, usize)> {
    match version {
        1 => Some((0x840, 6, 1)),
        2 => Some((0x940, 7, 2)),
        3 => Some((0xa40, 8, 3)),
        0x103 => Some((0x23c0, 8, 4)),
        _ => None,
    }
}

/// Inspect the banner referenced by bytes 0x68..0x6b in a recognized DS ROM.
/// Zero offset means no banner. Malformed nonzero offsets fail closed.
/// Only a maximum of 0x23c0 bytes is read regardless of ROM size.
pub(crate) fn inspect_banner<R: Read + Seek>(
    rom: &mut R,
    header: &[u8],
    rom_size: u64,
) -> io::Result<Option<Banner>> {
    if header.len() < 0x6c {
        return Err(bad("DS header too short for banner offset"));
    }
    let offset = u64::from(u32::from_le_bytes(header[0x68..0x6c].try_into().unwrap()));
    if offset == 0 {
        return Ok(None);
    }
    if offset < 0x200 || offset.checked_add(2).is_none_or(|end| end > rom_size) {
        return Err(bad("DS banner offset outside ROM or header region"));
    }
    rom.seek(SeekFrom::Start(offset))?;
    let mut version_bytes = [0u8; 2];
    rom.read_exact(&mut version_bytes)?;
    let version = u16::from_le_bytes(version_bytes);
    let (size, languages, crc_regions) =
        version_size(version).ok_or_else(|| bad("unsupported DS banner version"))?;
    if offset
        .checked_add(size as u64)
        .is_none_or(|end| end > rom_size)
    {
        return Err(bad("DS banner extends beyond ROM"));
    }
    rom.seek(SeekFrom::Start(offset))?;
    let mut bytes = [0u8; MAX_BANNER];
    rom.read_exact(&mut bytes[..size])?;
    let mut metadata = vec![
        ("banner_offset".to_string(), offset.to_string()),
        ("banner_version".to_string(), format!("0x{version:04X}")),
        ("banner_size".to_string(), size.to_string()),
    ];
    let mut all_match = true;
    for (index, &(expected_offset, start, end)) in CRC_REGIONS.iter().take(crc_regions).enumerate()
    {
        let expected = u16::from_le_bytes(
            bytes[expected_offset..expected_offset + 2]
                .try_into()
                .unwrap(),
        );
        let actual = crc16(&bytes[start..end]);
        let matches = expected == actual;
        all_match &= matches;
        metadata.push((
            format!("banner_crc{}_valid", index + 1),
            matches.to_string(),
        ));
    }
    metadata.push(("banner_crc_all_valid".into(), all_match.to_string()));

    for (i, language) in TITLE_LANGUAGES.iter().take(languages).enumerate() {
        let start = 0x240 + i * 0x100;
        let field = &bytes[start..start + 0x100];
        let units: Vec<u16> = field
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect();
        if units.is_empty() {
            continue;
        }
        let title = String::from_utf16(&units)
            .map_err(|_| bad("DS banner contains malformed UTF-16 title"))?;
        if title.chars().any(|ch| ch.is_control() && ch != '\n') {
            return Err(bad("DS banner title contains invalid control characters"));
        }
        metadata.push((format!("banner_title_{language}"), title));
    }
    Ok(Some(Banner {
        entry: Entry {
            name: "banner.bin".into(),
            offset,
            size: size as u64,
        },
        metadata,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn fixture(version: u16, title: &str) -> (Vec<u8>, Vec<u8>) {
        let (size, _, ncrcs) = version_size(version).unwrap();
        let offset = 0x300usize;
        let mut rom = vec![0u8; offset + size];
        rom[0x68..0x6c].copy_from_slice(&(offset as u32).to_le_bytes());
        rom[offset..offset + 2].copy_from_slice(&version.to_le_bytes());
        for (i, code) in title.encode_utf16().enumerate() {
            let at = offset + 0x340 + i * 2;
            rom[at..at + 2].copy_from_slice(&code.to_le_bytes());
        }
        for &(field, start, end) in CRC_REGIONS.iter().take(ncrcs) {
            let crc = crc16(&rom[offset + start..offset + end]);
            rom[offset + field..offset + field + 2].copy_from_slice(&crc.to_le_bytes());
        }
        let header = rom[..0x200].to_vec();
        (rom, header)
    }

    fn field<'a>(banner: &'a Banner, key: &str) -> Option<&'a str> {
        banner
            .metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn modbus_crc_reference_vector() {
        assert_eq!(crc16(b"123456789"), 0x4b37);
    }

    #[test]
    fn reads_v1_utf16_titles_and_verified_crc() {
        let (rom, header) = fixture(1, "Pokémon\nDemo");
        let result = inspect_banner(&mut Cursor::new(&rom), &header, rom.len() as u64)
            .unwrap()
            .unwrap();
        assert_eq!(result.entry.size, 0x840);
        assert_eq!(field(&result, "banner_version"), Some("0x0001"));
        assert_eq!(
            field(&result, "banner_title_english"),
            Some("Pokémon\nDemo")
        );
        assert_eq!(field(&result, "banner_crc_all_valid"), Some("true"));
        assert_eq!(field(&result, "banner_title_korean"), None);
    }

    #[test]
    fn v2_v3_and_dsi_sizes_and_crc_regions() {
        for (version, expected_size, crcs) in [(2, 0x940, 2), (3, 0xa40, 3), (0x103, 0x23c0, 4)] {
            let (rom, header) = fixture(version, "Extended");
            let result = inspect_banner(&mut Cursor::new(&rom), &header, rom.len() as u64)
                .unwrap()
                .unwrap();
            assert_eq!(result.entry.size, expected_size);
            assert_eq!(field(&result, "banner_crc_all_valid"), Some("true"));
            assert_eq!(
                result
                    .metadata
                    .iter()
                    .filter(|(k, _)| k.starts_with("banner_crc") && k.ends_with("_valid"))
                    .count(),
                crcs + 1
            );
        }
    }

    #[test]
    fn corrupt_banner_crc_is_reported_and_does_not_hide_titles() {
        let (mut rom, header) = fixture(1, "Example");
        rom[0x300 + 0x340] ^= 1;
        let result = inspect_banner(&mut Cursor::new(&rom), &header, rom.len() as u64)
            .unwrap()
            .unwrap();
        assert_eq!(field(&result, "banner_crc_all_valid"), Some("false"));
        assert!(field(&result, "banner_title_english").is_some());
    }

    #[test]
    fn no_banner_is_supported() {
        let rom = vec![0; 0x200];
        assert!(
            inspect_banner(&mut Cursor::new(&rom), &rom, rom.len() as u64)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_truncated_header_bad_offset_version_and_truncation() {
        let (rom, header) = fixture(1, "Title");
        assert!(inspect_banner(&mut Cursor::new(&rom), &header[..0x68], rom.len() as u64).is_err());
        let mut bad_header = header.clone();
        bad_header[0x68..0x6c].copy_from_slice(&0x100u32.to_le_bytes());
        assert!(inspect_banner(&mut Cursor::new(&rom), &bad_header, rom.len() as u64).is_err());
        let mut bad = rom.clone();
        bad[0x300..0x302].copy_from_slice(&4u16.to_le_bytes());
        assert!(inspect_banner(&mut Cursor::new(&bad), &header, bad.len() as u64).is_err());
        assert!(inspect_banner(&mut Cursor::new(&rom), &header, (rom.len() - 1) as u64).is_err());
    }

    #[test]
    fn rejects_malformed_utf16_and_disallowed_control_characters() {
        let (mut rom, header) = fixture(1, "Demo");
        rom[0x300 + 0x340..0x300 + 0x342].copy_from_slice(&0xd800u16.to_le_bytes());
        assert!(inspect_banner(&mut Cursor::new(&rom), &header, rom.len() as u64).is_err());
        let (mut rom, header) = fixture(1, "Demo");
        rom[0x300 + 0x340..0x300 + 0x342].copy_from_slice(&0x0007u16.to_le_bytes());
        assert!(inspect_banner(&mut Cursor::new(&rom), &header, rom.len() as u64).is_err());
    }
}
