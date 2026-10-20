//! Game Boy and Game Boy Color cartridge-header metadata and read-only verification.
//! The 0x150-byte header is parsed independently of integrity validation:
//! inspection can describe damaged ROMs, while explicit verification fails on
//! checksum/declared-size mismatches. No saves or ROM data are modified.

use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

const HEADER_BYTES: usize = 0x150;
const MAX_VERIFICATION_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const LOGO: [u8; 48] = [
    0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0c, 0x00, 0x0d,
    0x00, 0x08, 0x11, 0x1f, 0x88, 0x89, 0x00, 0x0e, 0xdc, 0xcc, 0x6e, 0xe6, 0xdd, 0xdd, 0xd9, 0x99,
    0xbb, 0xbb, 0x67, 0x63, 0x6e, 0x0e, 0xec, 0xcc, 0xdd, 0xdc, 0x99, 0x9f, 0xbb, 0xb9, 0x33, 0x3e,
];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn put(fields: &mut Vec<(String, String)>, name: &str, value: impl ToString) {
    fields.push((name.into(), value.to_string()));
}

pub(crate) fn has_logo(head: &[u8]) -> bool {
    head.len() >= HEADER_BYTES && head[0x104..0x134] == LOGO
}

pub(crate) fn header_checksum(head: &[u8]) -> u8 {
    head[0x134..0x14d]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_sub(*byte).wrapping_sub(1))
}

/// Declared ROM capacity, not a guarantee of actual hardware configuration.
/// Codes 0x52..0x54 are historical/unofficial and remain explicitly labeled.
pub fn rom_size(code: u8) -> Option<u64> {
    match code {
        0x00..=0x08 => Some((32 * 1024u64) << code),
        0x52 => Some(72 * 16 * 1024),
        0x53 => Some(80 * 16 * 1024),
        0x54 => Some(96 * 16 * 1024),
        _ => None,
    }
}

/// Code 0x01 was documented historically as 2 KiB, but that claim is not
/// reliably supported by cartridge evidence: preserve "unknown" instead.
pub fn ram_size(code: u8) -> Option<u64> {
    match code {
        0x00 => Some(0),
        0x02 => Some(8 * 1024),
        0x03 => Some(32 * 1024),
        0x04 => Some(128 * 1024),
        0x05 => Some(64 * 1024),
        _ => None,
    }
}

pub fn cartridge_type(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "rom_only",
        0x01 => "mbc1",
        0x02 => "mbc1_ram",
        0x03 => "mbc1_ram_battery",
        0x05 => "mbc2",
        0x06 => "mbc2_battery",
        0x08 => "rom_ram",
        0x09 => "rom_ram_battery",
        0x0b => "mmm01",
        0x0c => "mmm01_ram",
        0x0d => "mmm01_ram_battery",
        0x0f => "mbc3_timer_battery",
        0x10 => "mbc3_timer_ram_battery",
        0x11 => "mbc3",
        0x12 => "mbc3_ram",
        0x13 => "mbc3_ram_battery",
        0x19 => "mbc5",
        0x1a => "mbc5_ram",
        0x1b => "mbc5_ram_battery",
        0x1c => "mbc5_rumble",
        0x1d => "mbc5_rumble_ram",
        0x1e => "mbc5_rumble_ram_battery",
        0x20 => "mbc6",
        0x22 => "mbc7_sensor_rumble_ram_battery",
        0xfc => "pocket_camera",
        0xfd => "bandai_tama5",
        0xfe => "huc3",
        0xff => "huc1_ram_battery",
        _ => return None,
    })
}

pub(crate) fn metadata(head: &[u8], actual_bytes: u64) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let cgb = match head[0x143] {
        0x80 => "compatible",
        0xc0 => "required",
        _ => "not_declared",
    };
    put(&mut fields, "cgb_support", cgb);
    put(&mut fields, "super_game_boy_support", head[0x146] == 0x03);
    put(
        &mut fields,
        "cartridge_type",
        format!("0x{:02X}", head[0x147]),
    );
    put(
        &mut fields,
        "cartridge_type_name",
        cartridge_type(head[0x147]).unwrap_or("unknown"),
    );
    put(
        &mut fields,
        "rom_size_code",
        format!("0x{:02X}", head[0x148]),
    );
    if let Some(declared) = rom_size(head[0x148]) {
        put(&mut fields, "declared_rom_size_bytes", declared);
        put(
            &mut fields,
            "declared_rom_size_matches_file",
            declared == actual_bytes,
        );
        if (0x52..=0x54).contains(&head[0x148]) {
            put(&mut fields, "rom_size_code_basis", "historical_unofficial");
        }
    } else {
        put(&mut fields, "declared_rom_size_known", false);
    }
    put(
        &mut fields,
        "ram_size_code",
        format!("0x{:02X}", head[0x149]),
    );
    if let Some(bytes) = ram_size(head[0x149]) {
        put(&mut fields, "declared_external_ram_size_bytes", bytes);
    } else {
        put(&mut fields, "declared_external_ram_size_known", false);
    }
    put(
        &mut fields,
        "destination",
        match head[0x14a] {
            0 => "japan",
            1 => "non_japan",
            _ => "unknown",
        },
    );
    put(
        &mut fields,
        "old_licensee_code",
        format!("0x{:02X}", head[0x14b]),
    );
    if head[0x14b] == 0x33 {
        let new = &head[0x144..0x146];
        if new.iter().all(u8::is_ascii_alphanumeric) {
            put(
                &mut fields,
                "new_licensee_code",
                String::from_utf8_lossy(new).to_string(),
            );
        } else {
            put(&mut fields, "new_licensee_code", "unreadable");
        }
    }
    put(&mut fields, "cartridge_revision", head[0x14c]);
    put(
        &mut fields,
        "header_checksum_stored",
        format!("0x{:02X}", head[0x14d]),
    );
    put(
        &mut fields,
        "header_checksum_calculated",
        format!("0x{:02X}", header_checksum(head)),
    );
    put(
        &mut fields,
        "header_checksum_valid",
        head[0x14d] == header_checksum(head),
    );
    put(
        &mut fields,
        "global_checksum_stored",
        format!("0x{:04X}", u16::from_be_bytes([head[0x14e], head[0x14f]])),
    );
    put(&mut fields, "global_checksum_not_checked", true);
    // MBC2 memory is built into its controller and is not external RAM.
    if matches!(head[0x147], 0x05 | 0x06) {
        put(&mut fields, "mbc2_internal_512x4_ram", true);
    }
    fields
}

/// Full read-only GB/GBC integrity verification. The global checksum is
/// additive, not cryptographic, and may be intentionally invalid in some ROMs.
/// When requested, this strict verifier reports such a mismatch as an error.
pub fn verify_game_boy<R: Read + Seek>(reader: &mut R) -> io::Result<u64> {
    let length = reader.seek(SeekFrom::End(0))?;
    if !(32 * 1024..=MAX_VERIFICATION_BYTES).contains(&length) {
        return Err(invalid(
            "Game Boy ROM size outside supported verification bounds",
        ));
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; HEADER_BYTES];
    reader.read_exact(&mut head)?;
    if !has_logo(&head) {
        return Err(invalid("Game Boy header missing required logo"));
    }
    if head[0x14d] != header_checksum(&head) {
        return Err(invalid("Game Boy header checksum mismatch"));
    }
    let expected = rom_size(head[0x148])
        .ok_or_else(|| invalid("Game Boy ROM has unknown declared size code"))?;
    if expected != length {
        return Err(invalid(
            "Game Boy declared ROM size differs from actual file",
        ));
    }
    let stored_global = u16::from_be_bytes([head[0x14e], head[0x14f]]);
    reader.seek(SeekFrom::Start(0))?;
    let mut total = 0u16;
    let mut pos = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    while pos < length {
        let limit = ((length - pos) as usize).min(buffer.len());
        reader.read_exact(&mut buffer[..limit])?;
        for (index, byte) in buffer[..limit].iter().enumerate() {
            let absolute = pos + index as u64;
            if absolute != 0x14e && absolute != 0x14f {
                total = total.wrapping_add(u16::from(*byte));
            }
        }
        pos += limit as u64;
    }
    if total != stored_global {
        return Err(invalid("Game Boy global ROM checksum mismatch"));
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample(code: u8, mapper: u8, gbc: u8) -> Vec<u8> {
        let bytes = rom_size(code).unwrap() as usize;
        let mut image = vec![0u8; bytes];
        image[0x104..0x134].copy_from_slice(&LOGO);
        image[0x134..0x13b].copy_from_slice(b"EXAMPLE");
        image[0x143] = gbc;
        image[0x147] = mapper;
        image[0x148] = code;
        image[0x149] = 3;
        image[0x14b] = 0x33;
        image[0x144..0x146].copy_from_slice(b"01");
        image[0x14d] = header_checksum(&image);
        let checksum = image
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 0x14e && *i != 0x14f)
            .fold(0u16, |sum, (_, byte)| sum.wrapping_add(u16::from(*byte)));
        image[0x14e..0x150].copy_from_slice(&checksum.to_be_bytes());
        image
    }

    fn value<'a>(items: &'a [(String, String)], key: &str) -> Option<&'a str> {
        items
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn metadata_decodes_color_mapper_sizes_and_header_checks() {
        let bytes = sample(1, 0x13, 0x80);
        let fields = metadata(&bytes, bytes.len() as u64);
        assert_eq!(value(&fields, "cgb_support"), Some("compatible"));
        assert_eq!(
            value(&fields, "cartridge_type_name"),
            Some("mbc3_ram_battery")
        );
        assert_eq!(value(&fields, "declared_rom_size_bytes"), Some("65536"));
        assert_eq!(
            value(&fields, "declared_external_ram_size_bytes"),
            Some("32768")
        );
        assert_eq!(value(&fields, "new_licensee_code"), Some("01"));
        assert_eq!(value(&fields, "header_checksum_valid"), Some("true"));
        assert_eq!(value(&fields, "global_checksum_not_checked"), Some("true"));
        assert_eq!(
            value(&fields, "declared_rom_size_matches_file"),
            Some("true")
        );
    }

    #[test]
    fn special_rom_codes_remain_labeled_unofficial() {
        for (code, banks) in [(0x52, 72), (0x53, 80), (0x54, 96)] {
            assert_eq!(rom_size(code), Some(banks * 16384));
        }
        assert_eq!(ram_size(0x01), None);
        assert_eq!(ram_size(0x05), Some(64 * 1024));
        assert_eq!(rom_size(0x09), None);
        assert_eq!(cartridge_type(0x04), None);
        let rom = sample(0x52, 0x00, 0xc0);
        let fields = metadata(&rom, rom.len() as u64);
        assert_eq!(
            value(&fields, "rom_size_code_basis"),
            Some("historical_unofficial")
        );
        assert_eq!(value(&fields, "cgb_support"), Some("required"));
    }

    #[test]
    fn valid_full_rom_checksums_and_detects_corruption() {
        let bytes = sample(0, 0x00, 0x00);
        assert_eq!(
            verify_game_boy(&mut Cursor::new(bytes.clone())).unwrap(),
            32768
        );
        let mut modified = bytes.clone();
        modified[0x2000] ^= 1;
        let err = verify_game_boy(&mut Cursor::new(modified)).unwrap_err();
        assert!(err.to_string().contains("global"));
        let mut altered = bytes.clone();
        altered[0x14d] ^= 1;
        assert!(verify_game_boy(&mut Cursor::new(altered))
            .unwrap_err()
            .to_string()
            .contains("header checksum"));
    }

    #[test]
    fn unknown_size_and_mismatched_file_length_fail_explicit_verify() {
        let mut bytes = sample(0, 0x00, 0);
        bytes[0x148] = 0x09;
        bytes[0x14d] = header_checksum(&bytes);
        assert!(verify_game_boy(&mut Cursor::new(bytes.clone()))
            .unwrap_err()
            .to_string()
            .contains("unknown declared size"));
        bytes[0x148] = 0x00;
        bytes[0x14d] = header_checksum(&bytes);
        bytes.extend([0u8; 16]);
        assert!(verify_game_boy(&mut Cursor::new(bytes))
            .unwrap_err()
            .to_string()
            .contains("differs from actual"));
    }

    #[test]
    fn legacy_and_cgb_only_titles_have_distinct_flags() {
        let mut rom = sample(0, 0x05, 0xc0);
        rom[0x149] = 0;
        let fields = metadata(&rom, rom.len() as u64);
        assert_eq!(value(&fields, "cgb_support"), Some("required"));
        assert_eq!(value(&fields, "mbc2_internal_512x4_ram"), Some("true"));
        assert_eq!(
            value(&fields, "declared_external_ram_size_bytes"),
            Some("0")
        );
    }
}
