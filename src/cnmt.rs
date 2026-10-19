//! Read plaintext packaged content metadata (.cnmt). A CNMT file contains
//! title metadata and references to NCAs, NOT any of those NCA payloads.
//! No hashes are checked, no decryption and no inferred file extraction.
use crate::{Format, Report};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

fn bad(s: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, s)
}
fn u16at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
fn u32at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}
fn meta_name(n: u8) -> &'static str {
    match n {
        1 => "system_program",
        2 => "system_data",
        3 => "system_update",
        4 => "boot_image_package",
        5 => "boot_image_package_safe",
        0x80 => "application",
        0x81 => "patch",
        0x82 => "add_on_content",
        0x83 => "delta",
        0x84 => "data_patch",
        _ => "unknown",
    }
}
fn content_name(n: u8) -> &'static str {
    match n {
        0 => "meta",
        1 => "program",
        2 => "data",
        3 => "control",
        4 => "html_document",
        5 => "legal_information",
        6 => "delta_fragment",
        _ => "unknown",
    }
}
/// A typed content reference from standalone CNMT metadata, not verified
/// against the content's hash or any particular NSP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentRecord {
    pub id: String,
    pub size: u64,
    pub content_type: &'static str,
    pub attributes: u8,
    pub id_offset: u8,
}

fn add(r: &mut Report, key: String, value: impl ToString) {
    r.metadata.push((key, value.to_string()));
}
/// Parse at most 16 MiB of an explicitly supplied plaintext CNMT file.
/// CNMT has no signature, so it should never be autodetected.
pub fn inspect_cnmt<R: Read + Seek>(r: &mut R) -> io::Result<Report> {
    inspect_cnmt_with_content(r).map(|(report, _)| report)
}

/// Parse one plaintext CNMT once and return its typed content references.
pub fn inspect_cnmt_with_content<R: Read + Seek>(
    r: &mut R,
) -> io::Result<(Report, Vec<ContentRecord>)> {
    let length = r.seek(SeekFrom::End(0))?;
    if !(0x40..=16 * 1024 * 1024).contains(&length) {
        return Err(bad("CNMT size not within supported range"));
    }
    r.seek(SeekFrom::Start(0))?;
    let mut b = vec![0; length as usize];
    r.read_exact(&mut b)?;
    let title_id = u64at(&b, 0);
    if title_id == 0 {
        return Err(bad("CNMT title ID is zero"));
    }
    let version = u32at(&b, 8);
    let kind = b[0xc];
    let ext_len = u64::from(u16at(&b, 0xe));
    let content_count = u16at(&b, 0x10);
    let related_count = u16at(&b, 0x12);
    if content_count > 4096 || related_count > 4096 {
        return Err(bad("CNMT record counts exceed safety limit"));
    }
    let records_at = 0x20u64
        .checked_add(ext_len)
        .ok_or_else(|| bad("CNMT header overflow"))?;
    let related_at = records_at
        .checked_add(u64::from(content_count) * 0x38)
        .ok_or_else(|| bad("CNMT content records overflow"))?;
    let digest_at = related_at
        .checked_add(u64::from(related_count) * 0x10)
        .ok_or_else(|| bad("CNMT related records overflow"))?;
    if digest_at.checked_add(0x20).is_none_or(|v| v > length) {
        return Err(bad("CNMT records or trailing digest are truncated"));
    }
    let ext = &b[0x20..records_at as usize];
    let mut report = Report {
        format: Format::SwitchCnmt,
        bytes: length,
        metadata: vec![],
        entries: vec![],
    };
    add(&mut report, "title_id".into(), format!("{title_id:016X}"));
    add(&mut report, "version".into(), version);
    add(&mut report, "meta_type".into(), meta_name(kind));
    add(
        &mut report,
        "meta_type_code".into(),
        format!("0x{kind:02X}"),
    );
    add(&mut report, "content_count".into(), content_count);
    add(&mut report, "related_meta_count".into(), related_count);
    add(
        &mut report,
        "required_download_system_version".into(),
        u32at(&b, 0x18),
    );
    add(&mut report, "digest_verified".into(), false);
    if matches!(kind, 0x80..=0x83) {
        if ext.len() < 8 {
            return Err(bad("CNMT application reference missing"));
        }
        let application = u64at(ext, 0);
        if application != 0 {
            let name = if kind == 0x80 {
                "patch_id"
            } else {
                "application_id"
            };
            add(&mut report, name.into(), format!("{application:016X}"));
        }
    }
    let mut references = Vec::with_capacity(usize::from(content_count));
    for i in 0..usize::from(content_count) {
        let at = records_at as usize + i * 0x38;
        let row = &b[at..at + 0x38];
        let mut size = 0u64;
        // Modern CNMT has a 5-byte size and a separate attributes byte.
        // Older 6-byte sizes above 1 TiB require a version-aware adapter.
        for (j, byte) in row[0x30..0x35].iter().enumerate() {
            size |= u64::from(*byte) << (j * 8);
        }
        let id = hex(&row[0x20..0x30]);
        if row[0x20..0x30].iter().all(|b| *b == 0) {
            return Err(bad("CNMT content reference has zero content ID"));
        }
        references.push(ContentRecord {
            id: id.clone(), size, content_type: content_name(row[0x36]),
            attributes: row[0x35], id_offset: row[0x37],
        });
        let name = format!("content_{i}");
        add(&mut report, format!("{name}_id"), id);
        add(&mut report, format!("{name}_size"), size);
        add(&mut report, format!("{name}_attributes"), row[0x35]);
        add(&mut report, format!("{name}_type"), content_name(row[0x36]));
        add(&mut report, format!("{name}_type_code"), row[0x36]);
        add(&mut report, format!("{name}_id_offset"), row[0x37]);
    }
    for i in 0..usize::from(related_count) {
        let at = related_at as usize + i * 0x10;
        let name = format!("related_{i}");
        add(
            &mut report,
            format!("{name}_title_id"),
            format!("{:016X}", u64at(&b, at)),
        );
        add(&mut report, format!("{name}_version"), u32at(&b, at + 8));
        add(&mut report, format!("{name}_type"), meta_name(b[at + 0xc]));
    }
    Ok((report, references))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn fixture() -> Vec<u8> {
        let mut b = vec![0u8; 0x20 + 0x10 + 0x38 + 0x10 + 0x20];
        b[..8].copy_from_slice(&0x0100123456789000u64.to_le_bytes());
        b[8..12].copy_from_slice(&0x10000u32.to_le_bytes());
        b[0xc] = 0x81;
        b[0xe..0x10].copy_from_slice(&0x10u16.to_le_bytes());
        b[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&1u16.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&0x0100123456788000u64.to_le_bytes());
        let at = 0x30;
        for i in 0..16 {
            b[at + 0x20 + i] = i as u8;
        }
        b[at + 0x30] = 0x34;
        b[at + 0x31] = 0x12;
        b[at + 0x36] = 1;
        b[at + 0x37] = 2;
        let related = at + 0x38;
        b[related..related + 8].copy_from_slice(&0x0100123456788000u64.to_le_bytes());
        b[related + 0xc] = 0x80;
        b
    }
    #[test]
    fn reports_content_and_patch_relation() {
        let r = inspect_cnmt(&mut Cursor::new(fixture())).unwrap();
        assert_eq!(r.format, Format::SwitchCnmt);
        assert!(r
            .metadata
            .contains(&("title_id".into(), "0100123456789000".into())));
        assert!(r
            .metadata
            .contains(&("application_id".into(), "0100123456788000".into())));
        assert!(r
            .metadata
            .contains(&("content_0_size".into(), "4660".into())));
        assert!(r
            .metadata
            .contains(&("content_0_type".into(), "program".into())));
        assert!(r
            .metadata
            .contains(&("related_0_type".into(), "application".into())));
        assert!(r.entries.is_empty());
    }
    #[test]
    fn typed_references_separate_attributes_from_five_byte_size() {
        let mut fixture = fixture();
        let record = 0x30;
        fixture[record + 0x35] = 0xa4;
        let (report, content) = inspect_cnmt_with_content(&mut Cursor::new(fixture)).unwrap();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0].size, 4660);
        assert_eq!(content[0].attributes, 0xa4);
        assert_eq!(content[0].content_type, "program");
        assert_eq!(content[0].id, "000102030405060708090A0B0C0D0E0F");
        assert!(report.metadata.contains(&("content_0_attributes".into(), "164".into())));
    }

    #[test]
    fn rejects_short_invalid_counts_and_zero_id() {
        let mut b = fixture();
        b.pop();
        assert!(inspect_cnmt(&mut Cursor::new(b)).is_err());
        let mut b = fixture();
        b[0x10..0x12].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(inspect_cnmt(&mut Cursor::new(b)).is_err());
        let mut b = fixture();
        b[..8].fill(0);
        assert!(inspect_cnmt(&mut Cursor::new(b)).is_err());
    }
    #[test]
    fn refuses_non_cnmt_data() {
        assert!(inspect_cnmt(&mut Cursor::new(vec![0x33u8; 0x200])).is_err());
    }
}
