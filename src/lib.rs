//! Bounded, read-only inspection of Nintendo file formats.
//!
//! Detection is based on content signatures and conservative header checks, not
//! the filename extension. No decryption keys or commercial ROMs are bundled.

pub mod cnmt;
pub mod gb;
pub mod gba;
mod hfs0;
pub mod metadata_dir;
pub mod nacp;
pub mod nca;
pub mod ncsd;
mod nds;
mod nds_banner;
mod nds_crc;
pub mod nds_save;
pub mod package;
pub mod saves;
pub mod title_inventory;
pub mod wii;

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

const HEADER_CAP: usize = 0x400;
const MAX_PFS0_ENTRIES: u32 = 100_000;
const MAX_PFS0_STRINGS: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    SwitchNsp,
    SwitchHfs0,
    SwitchNacp,
    SwitchNso,
    SwitchXci,
    SwitchNca,
    SwitchCnmt,
    Nintendo3dsCartridge,
    NintendoDs,
    Wii,
    WiiWbfs,
    GameCube,
    GameBoyAdvance,
    GameBoy,
    GameBoyColor,
    Nintendo64,
    Nes,
    Unknown,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Self::SwitchNsp => "Switch NSP/PFS0",
            Self::SwitchHfs0 => "Switch HFS0",
            Self::SwitchNacp => "Switch control.nacp",
            Self::SwitchNso => "Switch NSO executable",
            Self::SwitchXci => "Switch XCI",
            Self::SwitchNca => "Switch NCA (decrypted header)",
            Self::SwitchCnmt => "Switch CNMT metadata",
            Self::Nintendo3dsCartridge => "Nintendo 3DS NCSD",
            Self::NintendoDs => "Nintendo DS",
            Self::Wii => "Wii disc",
            Self::WiiWbfs => "Wii WBFS",
            Self::GameCube => "GameCube disc",
            Self::GameBoyAdvance => "Game Boy Advance",
            Self::GameBoy => "Game Boy",
            Self::GameBoyColor => "Game Boy Color",
            Self::Nintendo64 => "Nintendo 64",
            Self::Nes => "NES iNES",
            Self::Unknown => "Unknown",
        }
    }

    pub fn console(self) -> &'static str {
        match self {
            Self::SwitchNsp
            | Self::SwitchHfs0
            | Self::SwitchNacp
            | Self::SwitchNso
            | Self::SwitchXci
            | Self::SwitchNca
            | Self::SwitchCnmt => "switch",
            Self::Nintendo3dsCartridge => "3ds",
            Self::NintendoDs => "ds",
            Self::Wii | Self::WiiWbfs => "wii",
            Self::GameCube => "gamecube",
            Self::GameBoyAdvance => "gba",
            Self::GameBoy | Self::GameBoyColor => "gb",
            Self::Nintendo64 => "n64",
            Self::Nes => "nes",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// Absolute byte offset in the archive.
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub format: Format,
    pub bytes: u64,
    pub metadata: Vec<(String, String)>,
    pub entries: Vec<Entry>,
}

/// Returns a small metadata report without loading the full input into memory.
/// A successful report for a non-PFS0 format implies recognition, *not* a
/// cryptographic integrity check or the ability to decrypt its content.
pub fn inspect<R: Read + Seek>(input: &mut R) -> io::Result<Report> {
    let bytes = input.seek(SeekFrom::End(0))?;
    input.seek(SeekFrom::Start(0))?;
    let mut head = vec![0u8; bytes.min(HEADER_CAP as u64) as usize];
    input.read_exact(&mut head)?;
    let mut report = Report {
        format: Format::Unknown,
        bytes,
        metadata: Vec::new(),
        entries: Vec::new(),
    };

    if head.starts_with(b"WBFS") {
        report.format = Format::WiiWbfs;
        let header = wii::inspect_wbfs(input, bytes)?;
        report.add("host_sector_bytes", header.host_sector_bytes);
        report.add("wbfs_sector_bytes", header.wbfs_sector_bytes);
        report.add("declared_host_sector_count", header.declared_host_sectors);
        report.add("declared_capacity_bytes", header.declared_capacity_bytes);
        report.add("occupied_disc_slots", header.occupied_disc_slots);
        report.add("available_disc_slots", header.available_disc_slots);
        report.add("block_map_verified", false);
    } else if head.starts_with(b"PFS0") {
        report.format = Format::SwitchNsp;
        report.entries = parse_pfs0(input, bytes)?;
        report.add("entry_count", report.entries.len());
    } else if head.starts_with(b"NES\x1a") && head.len() >= 16 {
        report.format = Format::Nes;
        let nes2 = head[7] & 0x0c == 0x08;
        report.add("header", if nes2 { "NES 2.0" } else { "iNES" });
        if !nes2 {
            report.add("prg_rom_kib", u32::from(head[4]) * 16);
            report.add("chr_rom_kib", u32::from(head[5]) * 8);
            report.add(
                "mapper",
                (u16::from(head[7] & 0xf0)) | u16::from(head[6] >> 4),
            );
        }
    } else if head.starts_with(b"NSO0") && head.len() >= 0x100 {
        report.format = Format::SwitchNso;
        let id = &head[0x40..0x60];
        if id.iter().any(|byte| *byte != 0) {
            let full = id
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            let short = id[..8]
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            report.add("module_build_id", full);
            report.add("atmosphere_cheat_build_id", short);
        } else {
            report.add("build_id_available", false);
        }
    } else if head.starts_with(b"HFS0") {
        report.format = Format::SwitchHfs0;
        report.entries = hfs0::parse(input, 0, bytes, "")?;
        report.add("entry_count", report.entries.len());
    } else if is_game_boy(&head) {
        let cgb = head[0x143] == 0x80 || head[0x143] == 0xc0;
        report.format = if cgb {
            Format::GameBoyColor
        } else {
            Format::GameBoy
        };
        report.add(
            "title",
            ascii_field(&head[0x134..if cgb { 0x13f } else { 0x144 }]),
        );
        report.metadata.extend(gb::metadata(&head, bytes));
    } else if is_gba(&head) {
        report.format = Format::GameBoyAdvance;
        report.add("title", ascii_field(&head[0xa0..0xac]));
        report.add("game_code", ascii_field(&head[0xac..0xb0]));
        report.add("maker_code", ascii_field(&head[0xb0..0xb2]));
        report.add("version", head[0xbc]);
        report.metadata.extend(gba::metadata(&head));
    } else if is_nds(&head) {
        report.format = Format::NintendoDs;
        report.add("title", ascii_field(&head[0..12]));
        report.add("game_code", ascii_field(&head[12..16]));
        report.add("maker_code", ascii_field(&head[16..18]));
        report.add("unit_code", head[18]);
        report.add("rom_version", head[0x1e]);
        // CRC mismatches are observable even in damaged/header-patched ROMs.
        // The explicit "verify" CLI operation decides whether to reject them.
        report
            .metadata
            .extend(nds_crc::inspect_header(&head)?.metadata());
        report.entries = nds::sections(&head, bytes)?;
        report.add("section_count", report.entries.len());
        let files = nds::filesystem(input, &head, bytes)?;
        report.add("nitrofs_file_count", files.len());
        report.entries.extend(files);
        if let Some(banner) = nds_banner::inspect_banner(input, &head, bytes)? {
            report.metadata.extend(banner.metadata);
            report.entries.push(banner.entry);
        }
    } else if head.len() >= 4
        && (&head[0..4] == b"\x80\x37\x12\x40"
            || &head[0..4] == b"\x37\x80\x40\x12"
            || &head[0..4] == b"\x40\x12\x37\x80")
    {
        report.format = Format::Nintendo64;
        let order = match &head[0..4] {
            b"\x80\x37\x12\x40" => "big-endian (.z64)",
            b"\x37\x80\x40\x12" => "byte-swapped (.v64)",
            _ => "little-endian (.n64)",
        };
        report.add("byte_order", order);
    } else if head.len() >= 0x20 && &head[0x18..0x1c] == b"\x5d\x1c\x9e\xa3" && disc_id_ok(&head) {
        report.format = Format::Wii;
        report.add("game_id", ascii_field(&head[0..6]));
        report.add("disc_number", head[6]);
        report.add("disc_version", head[7]);
        report.add("title", ascii_field(&head[0x20..head.len().min(0x60)]));
        let disc = wii::inspect_wii_disc(input, bytes)?;
        report.add("partition_count", disc.partitions.len());
        for (group, count) in disc.group_counts.iter().enumerate() {
            report.add(&format!("partition_group_{group}_count"), count);
        }
        if let Some(region) = disc.region_code {
            report.add("region_code", region);
        }
        report.add("partition_offsets_checked", true);
        report.add("partition_contents_decrypted", false);
    } else if head.len() >= 0x20 && &head[0x1c..0x20] == b"\xc2\x33\x9f\x3d" && disc_id_ok(&head) {
        report.format = Format::GameCube;
        report.add("game_id", ascii_field(&head[0..6]));
        if head.len() >= 0x60 {
            report.add("title", ascii_field(&head[0x20..0x60]));
        }
    } else if head.len() >= 0x140 && &head[0x100..0x104] == b"HEAD" {
        report.format = Format::SwitchXci;
        let (root, entries) = hfs0::parse_xci(input, &head, bytes)?;
        report.add("root_partition_offset", root);
        report.add("entry_count", entries.len());
        report.entries = entries;
    } else if head.len() >= 0x104 && &head[0x100..0x104] == b"NCSD" {
        let ncsd = ncsd::inspect_ncsd(&head, bytes)?;
        report.format = Format::Nintendo3dsCartridge;
        report.add("media_id", format!("0x{:016X}", ncsd.media_id));
        report.add("media_unit_bytes", ncsd.media_unit_bytes);
        report.add("declared_media_size_bytes", ncsd.declared_media_bytes);
        report.add(
            "declared_media_size_matches_file",
            ncsd.declared_media_bytes == bytes,
        );
        report.add("media_type", ncsd.media_type);
        report.add("partition_count", ncsd.partitions.len());
        report.add("signature_verified", false);
        report.add("encrypted_partition_contents_verified", false);
    } else if head.len() >= 0x204
        && (&head[0x200..0x204] == b"NCA2" || &head[0x200..0x204] == b"NCA3")
    {
        return nca::inspect_decrypted_nca(input);
    }
    Ok(report)
}

impl Report {
    fn add(&mut self, key: &str, value: impl ToString) {
        self.metadata.push((key.to_string(), value.to_string()));
    }
}

/// Parsed PFS0 names are advisory; extraction always requires the caller to
/// supply an explicit destination and never treats entry names as host paths.
pub fn extract_entry<R: Read + Seek, W: Write>(
    archive: &mut R,
    entry: &Entry,
    output: &mut W,
) -> io::Result<u64> {
    archive.seek(SeekFrom::Start(entry.offset))?;
    let copied = io::copy(&mut archive.take(entry.size), output)?;
    if copied != entry.size {
        return Err(invalid("archive ended during extraction"));
    }
    Ok(copied)
}

fn parse_pfs0<R: Read + Seek>(reader: &mut R, length: u64) -> io::Result<Vec<Entry>> {
    if length < 16 {
        return Err(invalid("PFS0 header is truncated"));
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 16];
    reader.read_exact(&mut header)?;
    let count = le_u32(&header[4..8]);
    let string_size = le_u32(&header[8..12]);
    if count > MAX_PFS0_ENTRIES || string_size > MAX_PFS0_STRINGS {
        return Err(invalid(
            "PFS0 entry count or string table exceeds safety limit",
        ));
    }
    let table_bytes = u64::from(count) * 24;
    let data_start = 16u64
        .checked_add(table_bytes)
        .and_then(|n| n.checked_add(u64::from(string_size)))
        .ok_or_else(|| invalid("PFS0 table size overflow"))?;
    if data_start > length {
        return Err(invalid("PFS0 tables extend beyond input"));
    }
    let mut table = vec![0u8; table_bytes as usize];
    reader.read_exact(&mut table)?;
    let mut strings = vec![0u8; string_size as usize];
    reader.read_exact(&mut strings)?;
    let mut entries = Vec::with_capacity(count as usize);
    let mut names = HashSet::with_capacity(count as usize);
    for chunk in table.chunks_exact(24) {
        let relative = le_u64(&chunk[0..8]);
        let size = le_u64(&chunk[8..16]);
        let name_offset = le_u32(&chunk[16..20]) as usize;
        let name_bytes = strings
            .get(name_offset..)
            .and_then(|tail| tail.split(|b| *b == 0).next())
            .filter(|name| !name.is_empty() && name_offset + name.len() < strings.len())
            .ok_or_else(|| invalid("PFS0 filename missing or not NUL-terminated"))?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| invalid("PFS0 filename is not UTF-8"))?
            .to_string();
        // Like HFS0, PFS0 names are archive entry identifiers, not paths.
        // Reject directory traversal and host-path delimiters at inspection time.
        if name == "."
            || name == ".."
            || name
                .bytes()
                .any(|byte| byte == b'/' || byte == b'\\' || byte < 0x20 || byte == 0x7f)
        {
            return Err(invalid("PFS0 unsafe filename"));
        }
        if !names.insert(name.clone()) {
            return Err(invalid("PFS0 has duplicate filenames"));
        }
        let offset = data_start
            .checked_add(relative)
            .ok_or_else(|| invalid("PFS0 file offset overflow"))?;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| invalid("PFS0 entry length overflow"))?;
        if end > length {
            return Err(invalid("PFS0 entry extends beyond input"));
        }
        entries.push(Entry { name, offset, size });
    }
    // Reject overlapping nonempty spans even when both happen to be within bounds.
    let mut spans: Vec<(u64, u64)> = entries
        .iter()
        .filter(|entry| entry.size != 0)
        .map(|entry| (entry.offset, entry.offset + entry.size))
        .collect();
    spans.sort_unstable();
    if spans.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid("PFS0 file regions overlap"));
    }
    Ok(entries)
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("4-byte slice"))
}
fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("8-byte slice"))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn ascii_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}
fn disc_id_ok(head: &[u8]) -> bool {
    head[0..6].iter().all(|byte| byte.is_ascii_alphanumeric())
}
fn is_gba(head: &[u8]) -> bool {
    // Recognition and checksum validation are separate: a damaged cartridge
    // must remain inspectable instead of being silently treated as unknown.
    gba::recognizable(head)
}
fn is_nds(head: &[u8]) -> bool {
    head.len() >= 0x160
        && head[0x15c..0x15e] == [0x56, 0xcf]
        && head[12..16].iter().all(|b| b.is_ascii_alphanumeric())
}
fn is_game_boy(head: &[u8]) -> bool {
    // A damaged checksum should not hide an otherwise recognizable ROM from
    // "info"; the explicit verify operation enforces checksum correctness.
    gb::has_logo(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn report(bytes: Vec<u8>) -> io::Result<Report> {
        inspect(&mut Cursor::new(bytes))
    }

    fn synthetic_pfs0(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut bytes = b"PFS0".to_vec();
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(((name.len() + 1) as u32).to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(0u64.to_le_bytes());
        bytes.extend((payload.len() as u64).to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(name.as_bytes());
        bytes.push(0);
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn pfs0_reads_names_offsets_and_content() {
        let raw = synthetic_pfs0("example.txt", b"test data");
        let mut cursor = Cursor::new(raw.clone());
        let result = inspect(&mut cursor).unwrap();
        assert_eq!(result.format, Format::SwitchNsp);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].name, "example.txt");
        let mut output = Vec::new();
        let count = extract_entry(&mut cursor, &result.entries[0], &mut output).unwrap();
        assert_eq!(count, 9);
        assert_eq!(output, b"test data");
        assert_eq!(result.entries[0].offset + count, raw.len() as u64);
    }

    #[test]
    fn pfs0_rejects_truncated_entry() {
        let mut bytes = synthetic_pfs0("a", b"ok");
        bytes.pop();
        assert_eq!(
            report(bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn pfs0_refuses_paths_traversal_and_control_characters() {
        for name in [
            ".",
            "..",
            "../outside.nca",
            "dir/inside.nca",
            "dir\\inside.nca",
            "control\nname.nca",
            "carriage\rreturn.nca",
        ] {
            let bytes = synthetic_pfs0(name, b"safe fixture");
            assert_eq!(
                report(bytes).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "accepted dangerous PFS0 entry name: {name:?}"
            );
        }
        let valid = report(synthetic_pfs0("safe..name.nca", b"fixture")).unwrap();
        assert_eq!(valid.entries[0].name, "safe..name.nca");
    }

    #[test]
    fn pfs0_rejects_unbounded_count() {
        let mut bytes = b"PFS0".to_vec();
        bytes.extend(u32::MAX.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        assert_eq!(
            report(bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn pfs0_rejects_duplicate_names_and_overlap() {
        // Two entries share one filename and overlap their data regions.
        let mut raw = b"PFS0".to_vec();
        raw.extend(2u32.to_le_bytes());
        raw.extend(4u32.to_le_bytes());
        raw.extend(0u32.to_le_bytes());
        for (relative, size) in [(0u64, 2u64), (1, 1)] {
            raw.extend(relative.to_le_bytes());
            raw.extend(size.to_le_bytes());
            raw.extend(0u32.to_le_bytes());
            raw.extend(0u32.to_le_bytes());
        }
        raw.extend(b"a\0b\0xy");
        assert_eq!(
            report(raw.clone()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        raw[16 + 24 + 16..16 + 24 + 20].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(report(raw).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn gba_checksum_matches_independent_constant() {
        // Subtract the documented 0x19 complement, not 29 individual ones.
        let mut bytes = vec![0; 0xc0];
        bytes[0xac..0xb0].copy_from_slice(b"ABCD");
        bytes[0xb2] = 0x96;
        let complement = bytes[0xa0..0xbd]
            .iter()
            .fold(0u8, |sum, b| sum.wrapping_sub(*b))
            .wrapping_sub(0x19);
        assert_eq!(complement, 0x47);
        bytes[0xbd] = complement;
        assert_eq!(report(bytes).unwrap().format, Format::GameBoyAdvance);
    }

    #[test]
    fn nds_sections_are_reported_and_checked() {
        let mut bytes = vec![0; 0x300];
        bytes[12..16].copy_from_slice(b"ABCD");
        bytes[0x15c..0x15e].copy_from_slice(&[0x56, 0xcf]);
        bytes[0x20..0x24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x2c..0x30].copy_from_slice(&0x40u32.to_le_bytes());
        let r = report(bytes.clone()).unwrap();
        assert_eq!(r.format, Format::NintendoDs);
        assert_eq!(r.entries[0].name, "arm9.bin");
        assert_eq!(r.entries[0].size, 0x40);
        bytes.truncate(0x230);
        assert_eq!(
            report(bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn nso_reports_first_eight_bytes_as_cheat_id() {
        let mut bytes = vec![0u8; 0x100];
        bytes[0..4].copy_from_slice(b"NSO0");
        bytes[0x40..0x48].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        let result = report(bytes).unwrap();
        assert_eq!(result.format, Format::SwitchNso);
        assert!(result.metadata.contains(&(
            "atmosphere_cheat_build_id".into(),
            "123456789ABCDEF0".into()
        )));
        assert!(result
            .metadata
            .iter()
            .any(|(key, value)| key == "module_build_id" && value.len() == 64));
    }

    #[test]
    fn nso_without_build_id_does_not_invent_one() {
        let mut bytes = vec![0u8; 0x100];
        bytes[..4].copy_from_slice(b"NSO0");
        let result = report(bytes).unwrap();
        assert!(result
            .metadata
            .contains(&("build_id_available".into(), "false".into())));
        assert!(!result
            .metadata
            .iter()
            .any(|(key, _)| key == "atmosphere_cheat_build_id"));
    }

    #[test]
    fn recognizes_nes_header() {
        let mut bytes = b"NES\x1a".to_vec();
        bytes.extend([2, 1, 0, 0]);
        bytes.extend([0; 8]);
        let result = report(bytes).unwrap();
        assert_eq!(result.format, Format::Nes);
        assert!(result
            .metadata
            .contains(&("prg_rom_kib".into(), "32".into())));
    }

    #[test]
    fn recognizes_synthetic_gba_header() {
        let mut bytes = vec![0u8; 0xc0];
        bytes[0xa0..0xa4].copy_from_slice(b"DEMO");
        bytes[0xac..0xb0].copy_from_slice(b"ABCD");
        bytes[0xb2] = 0x96;
        bytes[0xbd] = bytes[0xa0..0xbd]
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_sub(*byte))
            .wrapping_sub(0x19);
        assert_eq!(report(bytes).unwrap().format, Format::GameBoyAdvance);
    }

    #[test]
    fn recognizes_synthetic_game_boy_header() {
        let mut bytes = vec![0u8; 0x150];
        bytes[0x104..0x134].copy_from_slice(&gb::LOGO);
        bytes[0x134..0x138].copy_from_slice(b"DEMO");
        bytes[0x143] = 0x80;
        bytes[0x14d] = bytes[0x134..0x14d]
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_sub(*byte).wrapping_sub(1));
        assert_eq!(report(bytes).unwrap().format, Format::GameBoyColor);
    }

    #[test]
    fn unknown_file_does_not_guess_by_extension() {
        assert_eq!(report(vec![0u8; 0x400]).unwrap().format, Format::Unknown);
    }
}
