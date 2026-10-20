//! Explicit SNES/Super Famicom internal-header candidate inspection.
//!
//! SNES dumps have no universal leading file signature. Header positions can
//! differ by memory mapping and an optional 512-byte copier prefix. We report
//! *candidates* with independent evidence rather than automatically assigning
//! an arbitrary file to SNES or claiming cartridge/content authenticity.
//! No full-ROM checksum or dump conversion is attempted.
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

const HEADER_LEN: usize = 64;
const CANDIDATES: [(&str, u64); 3] = [
    ("lorom", 0x7fc0),
    ("hirom", 0xffc0),
    ("exhirom", 0x40ffc0),
];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnesCandidate {
    pub layout: &'static str,
    pub copier_prefix_bytes: u64,
    pub header_offset_bytes: u64,
    pub title: String,
    pub title_ascii_printable: bool,
    pub map_mode: u8,
    pub map_mode_matches_location: bool,
    pub fast_rom_claimed: bool,
    pub cartridge_type: u8,
    pub rom_size_code: u8,
    pub declared_rom_capacity_bytes: Option<u64>,
    pub declared_rom_capacity_at_least_file: Option<bool>,
    pub ram_size_code: u8,
    pub declared_ram_capacity_bytes: Option<u64>,
    pub destination_code: u8,
    pub developer_code: u8,
    pub rom_revision: u8,
    pub checksum_complement_stored: u16,
    pub checksum_stored: u16,
    pub checksum_pair_valid: bool,
    pub reset_vector: u16,
    pub reset_vector_plausible: bool,
    pub evidence_score: u8,
}

#[derive(Debug, Clone)]
pub struct SnesHeaderReport {
    pub file_bytes: u64,
    pub candidates: Vec<SnesCandidate>,
    /// Some(index) only when a unique highest-evidence candidate exists.
    pub best_candidate_index: Option<usize>,
    pub full_rom_checksum_verified: bool,
}

fn mode_matches(layout: &str, mode: u8) -> bool {
    match layout {
        "lorom" => matches!(mode, 0x20 | 0x30 | 0x22 | 0x32 | 0x23 | 0x33),
        "hirom" => matches!(mode, 0x21 | 0x31),
        "exhirom" => matches!(mode, 0x25 | 0x35),
        _ => false,
    }
}

fn declared_size(code: u8) -> Option<u64> {
    if code <= 15 { Some(1024u64 << code) } else { None }
}

fn decode_title(raw: &[u8]) -> (String, bool) {
    let trimmed = match raw.iter().rposition(|&b| b != 0 && b != b' ') {
        Some(last) => &raw[..=last],
        None => &raw[..0],
    };
    let ascii = trimmed.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
    let title = trimmed.iter().map(|&b| {
        if b.is_ascii_graphic() || b == b' ' { char::from(b) } else { '?' }
    }).collect::<String>();
    (title, ascii)
}

fn candidate(
    raw: &[u8; HEADER_LEN], layout: &'static str,
    copier_prefix: u64, offset: u64, total_file_bytes: u64
) -> Option<SnesCandidate> {
    let (title, title_ascii_printable) = decode_title(&raw[..21]);
    let map_mode = raw[0x15];
    let map_match = mode_matches(layout, map_mode);
    let complement = u16::from_le_bytes([raw[0x1c], raw[0x1d]]);
    let checksum = u16::from_le_bytes([raw[0x1e], raw[0x1f]]);
    let checksum_pair_valid = complement ^ checksum == 0xffff && checksum != 0;
    let reset_vector = u16::from_le_bytes([raw[0x3c], raw[0x3d]]);
    let reset_vector_plausible = reset_vector >= 0x8000;
    // A single valid-looking field does not make a random file SNES. A
    // location-matching map-mode and title, or a checksum complement and a
    // plausible reset vector, are required for a candidate.
    if title.is_empty() ||
        !(map_match && title_ascii_printable ||
          checksum_pair_valid && reset_vector_plausible && title_ascii_printable)
    {
        return None;
    }
    let declared_rom = declared_size(raw[0x17]);
    let rom_bytes = total_file_bytes - copier_prefix;
    let size_reasonable = declared_rom.map(|bytes| bytes >= rom_bytes);
    let mut score = 0u8;
    if map_match { score += 4; }
    if checksum_pair_valid { score += 3; }
    if title_ascii_printable { score += 2; }
    if reset_vector_plausible { score += 1; }
    if size_reasonable == Some(true) { score += 1; }

    Some(SnesCandidate {
        layout, copier_prefix_bytes: copier_prefix,
        header_offset_bytes: offset, title, title_ascii_printable,
        map_mode, map_mode_matches_location: map_match,
        fast_rom_claimed: map_mode & 0x10 != 0,
        cartridge_type: raw[0x16],
        rom_size_code: raw[0x17],
        declared_rom_capacity_bytes: declared_rom,
        declared_rom_capacity_at_least_file: size_reasonable,
        ram_size_code: raw[0x18],
        declared_ram_capacity_bytes: if raw[0x18] == 0 {
            Some(0)
        } else { declared_size(raw[0x18]) },
        destination_code: raw[0x19],
        developer_code: raw[0x1a],
        rom_revision: raw[0x1b],
        checksum_complement_stored: complement,
        checksum_stored: checksum,
        checksum_pair_valid, reset_vector, reset_vector_plausible,
        evidence_score: score,
    })
}

/// Reads at most six 64-byte candidate headers (three mappings x two copier
/// prefix assumptions). No extension-based identification or bulk ROM reads.
pub fn inspect_snes_headers<R: Read + Seek>(reader: &mut R) -> io::Result<SnesHeaderReport> {
    let length = reader.seek(SeekFrom::End(0))?;
    let mut candidates = Vec::new();
    for prefix in [0u64, 512u64] {
        for &(layout, position) in &CANDIDATES {
            let offset = prefix + position;
            if offset.checked_add(HEADER_LEN as u64).is_none_or(|end| end > length) {
                continue;
            }
            reader.seek(SeekFrom::Start(offset))?;
            let mut buffer = [0u8; HEADER_LEN];
            reader.read_exact(&mut buffer)?;
            if let Some(record) = candidate(&buffer, layout, prefix, offset, length) {
                candidates.push(record);
            }
        }
    }
    if candidates.is_empty() {
        return Err(invalid("no plausible SNES internal header candidates found"));
    }
    candidates.sort_by(|a, b| b.evidence_score.cmp(&a.evidence_score)
        .then_with(|| a.header_offset_bytes.cmp(&b.header_offset_bytes)));
    let best_candidate_index =
        if candidates.len() == 1 || candidates[0].evidence_score > candidates[1].evidence_score {
            Some(0)
        } else { None };
    Ok(SnesHeaderReport {
        file_bytes: length, candidates, best_candidate_index,
        full_rom_checksum_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn rom(layout: &str, copier: bool, good_pair: bool) -> Vec<u8> {
        let len = if layout == "exhirom" { 0x500000 } else { 0x20000 };
        let prefix = if copier { 512 } else { 0 };
        let mut data = vec![0u8; len + prefix];
        let offset = match layout {
            "lorom" => 0x7fc0,
            "hirom" => 0xffc0,
            _ => 0x40ffc0,
        } + prefix;
        data[offset..offset+12].copy_from_slice(b"EXAMPLE GAME");
        data[offset+0x15] = match layout {
            "lorom" => 0x20,
            "hirom" => 0x31,
            _ => 0x35,
        };
        data[offset+0x16] = 2;
        data[offset+0x17] = if layout == "exhirom" { 13 } else { 7 };
        data[offset+0x18] = 5;
        data[offset+0x19] = 1;
        data[offset+0x1c..offset+0x1e].copy_from_slice(
            &(if good_pair {0xedcbu16} else {0u16}).to_le_bytes()
        );
        data[offset+0x1e..offset+0x20].copy_from_slice(&0x1234u16.to_le_bytes());
        data[offset+0x3c..offset+0x3e].copy_from_slice(&0x8000u16.to_le_bytes());
        data
    }

    #[test]
    fn lorom_and_hirom_are_distinct_header_candidates() {
        for layout in ["lorom", "hirom"] {
            let data = rom(layout, false, true);
            let report = inspect_snes_headers(&mut Cursor::new(data)).unwrap();
            let best = &report.candidates[report.best_candidate_index.unwrap()];
            assert_eq!(best.layout, layout);
            assert_eq!(best.title, "EXAMPLE GAME");
            assert!(best.checksum_pair_valid);
            assert!(best.reset_vector_plausible);
            assert!(best.map_mode_matches_location);
            assert_eq!(best.declared_ram_capacity_bytes, Some(32 * 1024));
            assert!(!report.full_rom_checksum_verified);
        }
    }

    #[test]
    fn copier_prefix_is_detected_by_candidate_location_not_extension() {
        let data = rom("lorom", true, true);
        let report = inspect_snes_headers(&mut Cursor::new(data)).unwrap();
        let best = &report.candidates[report.best_candidate_index.unwrap()];
        assert_eq!(best.copier_prefix_bytes, 512);
        assert_eq!(best.header_offset_bytes, 0x81c0);
    }

    #[test]
    fn exhirom_candidate_is_supported_when_bounds_allow() {
        let data = rom("exhirom", false, true);
        let report = inspect_snes_headers(&mut Cursor::new(data)).unwrap();
        let best = &report.candidates[report.best_candidate_index.unwrap()];
        assert_eq!(best.layout, "exhirom");
        assert_eq!(best.header_offset_bytes, 0x40ffc0);
        assert_eq!(best.declared_rom_capacity_bytes, Some(8 * 1024 * 1024));
    }

    #[test]
    fn complementary_checksum_may_fail_and_still_be_reported() {
        let data = rom("lorom", false, false);
        let report = inspect_snes_headers(&mut Cursor::new(data)).unwrap();
        assert_eq!(report.candidates[0].layout, "lorom");
        assert!(!report.candidates[0].checksum_pair_valid);
        assert!(!report.full_rom_checksum_verified);
    }

    #[test]
    fn random_empty_or_truncated_files_do_not_claim_snes_identity() {
        assert!(inspect_snes_headers(&mut Cursor::new(vec![0u8; 0x20000])).is_err());
        assert!(inspect_snes_headers(&mut Cursor::new(vec![0u8; 8])).is_err());
    }
}
