//! Nintendo DS save-container identification. Signature-first and read-only.
//!
//! A raw save has no universal magic, so its size cannot establish the title,
//! save-chip model, emulator, or even that the bytes are a Nintendo DS save.
//! Supported structured wrappers are DeSmuME DSV, No$GBA SRAM, and Action Replay DS.
//! No decompression, guessing a cartridge association, or modification.

use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

const DSV_COOKIE: &[u8; 16] = b"|-DESMUME SAVE-|";
const NO_GBA_ID: &[u8; 31] = b"NocashGbaBackupMediaSavDataFile";
const DSV_FOOTER: u64 = 40;
const NO_GBA_HEADER: u64 = 0x50;
const ACTION_REPLAY_MAGIC: &[u8; 8] = b"ARDS0001";
const ACTION_REPLAY_HEADER: u64 = 500;
const MAX_REASONABLE_DATA: u64 = 128 * 1024 * 1024;

/// A byte-based observation, not a successful load by any emulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsSaveKind {
    DeSmuMe,
    NoGba,
    ActionReplayDs,
    RawOrUnknown,
}
impl DsSaveKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::DeSmuMe => "desmume_dsv",
            Self::NoGba => "no_gba_sram",
            Self::ActionReplayDs => "action_replay_ds",
            Self::RawOrUnknown => "raw_or_unidentified",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsSaveReport {
    pub kind: DsSaveKind,
    pub size_bytes: u64,
    /// Describes observed fields only, not verified game ownership.
    pub metadata: Vec<(String, String)>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn u32le(data: &[u8], start: usize) -> u32 {
    u32::from_le_bytes(data[start..start + 4].try_into().unwrap())
}
fn add(report: &mut DsSaveReport, key: &str, value: impl ToString) {
    report.metadata.push((key.to_owned(), value.to_string()));
}

fn common_raw_capacity(len: u64) -> bool {
    // Familiar byte lengths used by several DS backup devices, NOT evidence
    // of the hardware chip actually used by any particular game.
    [
        512,
        8 * 1024,
        32 * 1024,
        64 * 1024,
        128 * 1024,
        256 * 1024,
        512 * 1024,
        1024 * 1024,
        8 * 1024 * 1024,
    ]
    .contains(&len)
}

/// Parse a user-designated DS save candidate with bounded input reads.
/// Never decides a raw file is definitely a DS save based on its extension.
/// Structured format checks are independent of the passed filename.
pub fn inspect_ds_save<R: Read + Seek>(input: &mut R) -> io::Result<DsSaveReport> {
    let len = input.seek(SeekFrom::End(0))?;
    let mut report = DsSaveReport {
        kind: DsSaveKind::RawOrUnknown,
        size_bytes: len,
        metadata: Vec::new(),
    };
    add(&mut report, "game_association_verified", false);

    // DSV footer is the final 40 bytes, ending in its 16-byte cookie. Other
    // emulator-managed trailer bytes can precede that 40-byte footer.
    if len >= DSV_COOKIE.len() as u64 {
        input.seek(SeekFrom::End(-(DSV_COOKIE.len() as i64)))?;
        let mut cookie = [0; 16];
        input.read_exact(&mut cookie)?;
        if &cookie == DSV_COOKIE {
            if len < DSV_FOOTER {
                return Err(invalid("DeSmuME cookie without complete footer"));
            }
            input.seek(SeekFrom::End(-(DSV_FOOTER as i64)))?;
            let mut footer = [0u8; DSV_FOOTER as usize];
            input.read_exact(&mut footer)?;
            let written = u64::from(u32le(&footer, 0));
            let padded = u64::from(u32le(&footer, 4));
            let saved_type = u32le(&footer, 8);
            let address_size = u32le(&footer, 12);
            let size_parameter = u32le(&footer, 16);
            let version = u32le(&footer, 20);
            let preceding_bytes = len - DSV_FOOTER;
            if version != 0 {
                return Err(invalid("unsupported DeSmuME footer version"));
            }
            if padded == 0
                || padded > MAX_REASONABLE_DATA
                || padded > preceding_bytes
                || written > padded
            {
                return Err(invalid("DeSmuME save footer has inconsistent bounds"));
            }
            report.kind = DsSaveKind::DeSmuMe;
            add(&mut report, "data_offset", 0);
            add(&mut report, "data_size_bytes", padded);
            add(&mut report, "actually_written_size_bytes", written);
            add(
                &mut report,
                "trailer_before_footer_bytes",
                preceding_bytes - padded,
            );
            add(&mut report, "footer_size_bytes", DSV_FOOTER);
            add(&mut report, "footer_version", version);
            add(&mut report, "save_type_reserved", saved_type);
            add(&mut report, "address_size", address_size);
            add(&mut report, "save_size_parameter_reserved", size_parameter);
            add(&mut report, "format_signature_verified", true);
            return Ok(report);
        }
    }

    // A complete, recognizable 31-byte No$GBA identifier with its required
    // 0x1A terminator missing is truncated, not an unidentified raw save.
    if len == NO_GBA_ID.len() as u64 {
        input.seek(SeekFrom::Start(0))?;
        let mut prefix = [0u8; 31];
        input.read_exact(&mut prefix)?;
        if &prefix == NO_GBA_ID {
            return Err(invalid("No$GBA save header truncated"));
        }
    }
    if len >= 32 {
        input.seek(SeekFrom::Start(0))?;
        let mut id = [0u8; 32];
        input.read_exact(&mut id)?;
        if &id[..31] == NO_GBA_ID {
            if id[31] != 0x1a || len < NO_GBA_HEADER {
                return Err(invalid("No$GBA save header truncated or invalid"));
            }
            input.seek(SeekFrom::Start(0x40))?;
            let mut fields = [0u8; 16];
            input.read_exact(&mut fields)?;
            if &fields[..4] != b"SRAM" {
                return Err(invalid("No$GBA save missing SRAM section marker"));
            }
            let compressed = u32le(&fields, 4);
            if compressed > 1 {
                return Err(invalid("unsupported No$GBA compression method"));
            }
            let primary_size = u64::from(u32le(&fields, 8));
            let secondary = u64::from(u32le(&fields, 12));
            if primary_size == 0 || primary_size > MAX_REASONABLE_DATA {
                return Err(invalid("No$GBA save has unsupported data size"));
            }
            if compressed == 1 {
                if secondary == 0
                    || secondary > MAX_REASONABLE_DATA
                    || NO_GBA_HEADER
                        .checked_add(primary_size)
                        .is_none_or(|end| end > len)
                {
                    return Err(invalid("No$GBA packed data outside file bounds"));
                }
            } else if NO_GBA_HEADER
                .checked_add(primary_size)
                .is_none_or(|end| end > len)
            {
                return Err(invalid("No$GBA uncompressed data outside file bounds"));
            }
            report.kind = DsSaveKind::NoGba;
            add(
                &mut report,
                "compression",
                if compressed == 0 { "none" } else { "packed" },
            );
            add(&mut report, "stored_payload_size_bytes", primary_size);
            if compressed == 1 {
                add(&mut report, "claimed_unpacked_size_bytes", secondary);
            } else {
                add(
                    &mut report,
                    "claimed_start_address",
                    format!("0x{secondary:08X}"),
                );
            }
            add(&mut report, "payload_offset", NO_GBA_HEADER);
            add(&mut report, "payload_not_decompressed", compressed != 0);
            add(&mut report, "format_signature_verified", true);
            return Ok(report);
        }
    }

    // Original DS Action Replay exports start with ARDS0001 and use a
    // fixed 500-byte wrapper. We do not infer the game's identity from
    // uninterpreted bytes inside the wrapper or its raw save payload.
    if len >= ACTION_REPLAY_MAGIC.len() as u64 {
        input.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; 8];
        input.read_exact(&mut header)?;
        if &header == ACTION_REPLAY_MAGIC {
            if len <= ACTION_REPLAY_HEADER {
                return Err(invalid("Action Replay DS header or save payload truncated"));
            }
            let payload_size = len - ACTION_REPLAY_HEADER;
            if payload_size > MAX_REASONABLE_DATA {
                return Err(invalid("Action Replay DS save payload exceeds safety cap"));
            }
            report.kind = DsSaveKind::ActionReplayDs;
            add(&mut report, "wrapper_size_bytes", ACTION_REPLAY_HEADER);
            add(&mut report, "payload_offset", ACTION_REPLAY_HEADER);
            add(&mut report, "payload_size_bytes", payload_size);
            add(&mut report, "metadata_not_decoded", true);
            add(&mut report, "format_signature_verified", true);
            return Ok(report);
        }
    }

    add(
        &mut report,
        "common_raw_capacity_length",
        common_raw_capacity(len),
    );
    add(&mut report, "format_signature_verified", false);
    add(
        &mut report,
        "note",
        "raw save or unidentified bytes; game/chip not inferred",
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn field<'a>(report: &'a DsSaveReport, name: &str) -> Option<&'a str> {
        report
            .metadata
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn dsv(data: usize, written: usize, trailer: usize) -> Vec<u8> {
        let mut file = vec![0xA5; data + trailer];
        file.extend((written as u32).to_le_bytes());
        file.extend((data as u32).to_le_bytes());
        file.extend(0u32.to_le_bytes()); // save type reserved
        file.extend(2u32.to_le_bytes()); // bus width
        file.extend(0u32.to_le_bytes()); // save size reserved
        file.extend(0u32.to_le_bytes()); // footer v0
        file.extend(DSV_COOKIE);
        file
    }

    fn nogba(compressed: bool, payload: usize) -> Vec<u8> {
        let mut file = vec![0u8; 0x50 + payload];
        file[..31].copy_from_slice(NO_GBA_ID);
        file[31] = 0x1a;
        file[0x40..0x44].copy_from_slice(b"SRAM");
        file[0x44..0x48].copy_from_slice(&u32::from(compressed).to_le_bytes());
        file[0x48..0x4c].copy_from_slice(&(payload as u32).to_le_bytes());
        file[0x4c..0x50].copy_from_slice(&(if compressed { 16384u32 } else { 0u32 }).to_le_bytes());
        file
    }

    #[test]
    fn reads_dsv_footer_after_optional_trailer_without_assuming_game_identity() {
        let bytes = dsv(8192, 13, 8);
        let report = inspect_ds_save(&mut Cursor::new(bytes.clone())).unwrap();
        assert_eq!(report.kind, DsSaveKind::DeSmuMe);
        assert_eq!(report.size_bytes, bytes.len() as u64);
        assert_eq!(field(&report, "data_size_bytes"), Some("8192"));
        assert_eq!(field(&report, "actually_written_size_bytes"), Some("13"));
        assert_eq!(field(&report, "trailer_before_footer_bytes"), Some("8"));
        assert_eq!(field(&report, "game_association_verified"), Some("false"));
    }

    #[test]
    fn truncated_or_corrupt_dsv_footer_fails_closed() {
        let mut short = DSV_COOKIE.to_vec();
        assert!(inspect_ds_save(&mut Cursor::new(&short)).is_err());
        short = dsv(512, 513, 0);
        assert!(inspect_ds_save(&mut Cursor::new(&short)).is_err());
        let mut bad_version = dsv(512, 5, 0);
        let version = bad_version.len() - 20;
        bad_version[version..version + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(inspect_ds_save(&mut Cursor::new(bad_version)).is_err());
        let mut bad_size = dsv(512, 5, 0);
        let padded = bad_size.len() - 36;
        bad_size[padded..padded + 4].copy_from_slice(&999999u32.to_le_bytes());
        assert!(inspect_ds_save(&mut Cursor::new(bad_size)).is_err());
    }

    #[test]
    fn signature_recognizes_nogba_raw_and_packed_without_decompressing() {
        let plain = inspect_ds_save(&mut Cursor::new(nogba(false, 512))).unwrap();
        assert_eq!(plain.kind, DsSaveKind::NoGba);
        assert_eq!(field(&plain, "compression"), Some("none"));
        let packed = inspect_ds_save(&mut Cursor::new(nogba(true, 100))).unwrap();
        assert_eq!(packed.kind, DsSaveKind::NoGba);
        assert_eq!(field(&packed, "compression"), Some("packed"));
        assert_eq!(field(&packed, "claimed_unpacked_size_bytes"), Some("16384"));
        assert_eq!(field(&packed, "payload_not_decompressed"), Some("true"));
    }

    #[test]
    fn malformed_nogba_header_and_payload_are_rejected() {
        let mut bytes = nogba(false, 512);
        bytes[0x40] = 0;
        assert!(inspect_ds_save(&mut Cursor::new(&bytes)).is_err());
        bytes = nogba(true, 100);
        bytes[0x48..0x4c].copy_from_slice(&5000u32.to_le_bytes());
        assert!(inspect_ds_save(&mut Cursor::new(&bytes)).is_err());
        bytes = nogba(false, 512);
        bytes[0x44..0x48].copy_from_slice(&2u32.to_le_bytes());
        assert!(inspect_ds_save(&mut Cursor::new(bytes)).is_err());
    }

    fn ards(payload: usize) -> Vec<u8> {
        let mut file = vec![0u8; ACTION_REPLAY_HEADER as usize + payload];
        file[..8].copy_from_slice(ACTION_REPLAY_MAGIC);
        file[ACTION_REPLAY_HEADER as usize..].fill(0xA5);
        file
    }

    #[test]
    fn action_replay_ds_wrapper_identified_without_title_inference() {
        let fixture = ards(8192);
        let mut file = Cursor::new(fixture);
        let report = inspect_ds_save(&mut file).unwrap();
        assert_eq!(report.kind, DsSaveKind::ActionReplayDs);
        assert_eq!(field(&report, "wrapper_size_bytes"), Some("500"));
        assert_eq!(field(&report, "payload_offset"), Some("500"));
        assert_eq!(field(&report, "payload_size_bytes"), Some("8192"));
        assert_eq!(field(&report, "metadata_not_decoded"), Some("true"));
        assert_eq!(field(&report, "game_association_verified"), Some("false"));
    }

    #[test]
    fn action_replay_ds_truncated_wrappers_fail_closed() {
        for size in [8, 64, 499, 500] {
            let mut bytes = vec![0u8; size];
            bytes[..8].copy_from_slice(ACTION_REPLAY_MAGIC);
            assert!(inspect_ds_save(&mut Cursor::new(bytes)).is_err());
        }
        let mut false_signature = ards(512);
        false_signature[7] = b'2';
        let report = inspect_ds_save(&mut Cursor::new(false_signature)).unwrap();
        assert_eq!(report.kind, DsSaveKind::RawOrUnknown);
    }

    struct ReadCounter<'a> {
        source: Cursor<&'a [u8]>,
        read_bytes: usize,
    }

    impl Read for ReadCounter<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.source.read(buffer)?;
            self.read_bytes += count;
            Ok(count)
        }
    }

    impl Seek for ReadCounter<'_> {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.source.seek(pos)
        }
    }

    #[test]
    fn inspection_reads_only_a_small_bound_for_large_saves() {
        let cases = [
            dsv(2 * 1024 * 1024, 42, 8),
            nogba(false, 2 * 1024 * 1024),
            ards(2 * 1024 * 1024),
            vec![0xCC; 2 * 1024 * 1024],
        ];
        for case in &cases {
            let mut reader = ReadCounter {
                source: Cursor::new(case.as_slice()),
                read_bytes: 0,
            };
            let result = inspect_ds_save(&mut reader).unwrap();
            assert_eq!(result.size_bytes, case.len() as u64);
            assert!(
                reader.read_bytes <= 96,
                "save inspector read {} bytes of {}",
                reader.read_bytes,
                case.len()
            );
        }
    }

    #[test]
    fn missing_nogba_signature_terminator_is_a_truncation_error() {
        let mut cursor = Cursor::new(NO_GBA_ID.to_vec());
        let error = inspect_ds_save(&mut cursor).unwrap_err();
        assert!(error.to_string().contains("No$GBA"));
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn raw_sizes_are_hints_not_format_or_save_chip_proofs() {
        let raw = inspect_ds_save(&mut Cursor::new(vec![0x88; 8192])).unwrap();
        assert_eq!(raw.kind, DsSaveKind::RawOrUnknown);
        assert_eq!(field(&raw, "common_raw_capacity_length"), Some("true"));
        assert_eq!(field(&raw, "format_signature_verified"), Some("false"));
        let odd = inspect_ds_save(&mut Cursor::new(vec![0u8; 19])).unwrap();
        assert_eq!(odd.kind, DsSaveKind::RawOrUnknown);
        assert_eq!(field(&odd, "common_raw_capacity_length"), Some("false"));
        let empty = inspect_ds_save(&mut Cursor::new(Vec::<u8>::new())).unwrap();
        assert_eq!(empty.kind, DsSaveKind::RawOrUnknown);
    }
}
