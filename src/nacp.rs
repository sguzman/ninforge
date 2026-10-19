//! Explicit read-only inspection of decrypted Switch control.nacp metadata.
//!
//! NACP has no magic; callers must opt in rather than guessing by extension.
//! Version 21 compressed title tables are rejected, not silently misdecoded.

use crate::{Format, Report};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

const SIZE: usize = 0x4000;
const LANGUAGES: [&str; 16] = [
    "american_english",
    "british_english",
    "japanese",
    "french",
    "german",
    "latin_american_spanish",
    "spanish",
    "italian",
    "dutch",
    "canadian_french",
    "portuguese",
    "russian",
    "korean",
    "traditional_chinese",
    "simplified_chinese",
    "brazilian_portuguese",
];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn field(bytes: &[u8]) -> io::Result<String> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let text =
        std::str::from_utf8(&bytes[..end]).map_err(|_| invalid("NACP invalid UTF-8 field"))?;
    if text.chars().any(|c| c.is_control() && c != '\t') {
        return Err(invalid("NACP control characters inside text field"));
    }
    Ok(text.to_string())
}

/// Inspect a single, independently obtained, readable 0x4000-byte NACP file.
/// Does not decrypt Switch NCAs, unpack games or modify source bytes.
pub fn inspect_nacp<R: Read + Seek>(input: &mut R) -> io::Result<Report> {
    let len = input.seek(SeekFrom::End(0))?;
    if len != SIZE as u64 {
        return Err(invalid("NACP must be exactly 0x4000 bytes"));
    }
    input.seek(SeekFrom::Start(0))?;
    let mut data = [0u8; SIZE];
    input.read_exact(&mut data)?;

    if data[0x3215] != 0 {
        return Err(invalid(
            "compressed or unknown NACP title format unsupported",
        ));
    }
    let mut report = Report {
        format: Format::SwitchNacp,
        bytes: len,
        metadata: Vec::new(),
        entries: Vec::new(),
    };
    let version = field(&data[0x3060..0x3070])?;
    if !version.is_empty() {
        report.metadata.push(("display_version".into(), version));
    }
    let flags = u32::from_le_bytes(data[0x302c..0x3030].try_into().unwrap());
    report
        .metadata
        .push(("supported_language_flags".into(), format!("0x{flags:08x}")));
    for (index, language) in LANGUAGES.iter().enumerate() {
        let start = index * 0x300;
        let title = field(&data[start..start + 0x200])?;
        let publisher = field(&data[start + 0x200..start + 0x300])?;
        if !title.is_empty() {
            report.metadata.push((format!("title_{language}"), title));
        }
        if !publisher.is_empty() {
            report
                .metadata
                .push((format!("publisher_{language}"), publisher));
        }
    }
    if !report.metadata.iter().any(|(k, _)| k.starts_with("title_")) {
        return Err(invalid("NACP has no readable application titles"));
    }
    for (key, at) in [
        ("addon_content_base_id", 0x3070),
        ("save_data_owner_id", 0x3078),
    ] {
        let value = u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
        if value != 0 {
            report
                .metadata
                .push((key.into(), format!("0x{value:016x}")));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; SIZE];
        bytes[..13].copy_from_slice(b"Homebrew Demo");
        bytes[0x200..0x20d].copy_from_slice(b"Open Homebrew");
        bytes[0x3060..0x3065].copy_from_slice(b"1.2.3");
        bytes[0x302c..0x3030].copy_from_slice(&0x21u32.to_le_bytes());
        bytes[0x3078..0x3080].copy_from_slice(&0x0100_1234_5678_9000u64.to_le_bytes());
        bytes
    }
    #[test]
    fn parses_title_publisher_version_and_owner() {
        let report = inspect_nacp(&mut Cursor::new(fixture())).unwrap();
        assert_eq!(report.format, Format::SwitchNacp);
        assert!(report
            .metadata
            .contains(&("title_american_english".into(), "Homebrew Demo".into())));
        assert!(report
            .metadata
            .contains(&("publisher_american_english".into(), "Open Homebrew".into())));
        assert!(report
            .metadata
            .contains(&("display_version".into(), "1.2.3".into())));
        assert!(report
            .metadata
            .contains(&("supported_language_flags".into(), "0x00000021".into())));
    }
    #[test]
    fn refuses_truncated_compressed_and_invalid_utf8() {
        let mut data = fixture();
        data.pop();
        assert!(inspect_nacp(&mut Cursor::new(data)).is_err());
        let mut data = fixture();
        data[0x3215] = 1;
        assert!(inspect_nacp(&mut Cursor::new(data)).is_err());
        let mut data = fixture();
        data[0] = 0xff;
        assert!(inspect_nacp(&mut Cursor::new(data)).is_err());
    }
    #[test]
    fn refuses_blank_nacp() {
        assert!(inspect_nacp(&mut Cursor::new(vec![0u8; SIZE])).is_err());
    }
}
