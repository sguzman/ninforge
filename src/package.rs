//! Keyless, read-only join between a PFS0 NSP table and a supplied plaintext CNMT.
//!
//! This is an inventory cross-check, NOT title authentication, hash validation,
//! decryption, signature validation or proof that two files originate together.
//! The CNMT must be independently provided: in ordinary NSPs it lives inside
//! an encrypted metadata NCA and is not directly readable as a top-level file.

use crate::cnmt::{inspect_cnmt_with_content, ContentRecord};
use crate::{inspect, Entry, Format};
use std::collections::HashSet;
use std::io::{self, ErrorKind, Read, Seek};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchStatus {
    Present,
    Missing,
    SizeMismatch,
    CompressedUnsupported,
    Ambiguous,
}
impl MatchStatus {
    pub fn name(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::SizeMismatch => "size_mismatch",
            Self::CompressedUnsupported => "compressed_unsupported",
            Self::Ambiguous => "ambiguous",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMatch {
    pub id: String,
    pub content_type: &'static str,
    pub expected_size: u64,
    pub expected_filename: String,
    pub package_filename: Option<String>,
    pub package_size: Option<u64>,
    pub status: MatchStatus,
}

#[derive(Debug, Clone)]
pub struct PackageAudit {
    /// These title/version fields come from an independently supplied,
    /// *unverified* plaintext CNMT, not directly from the NSP.
    pub title_id: String,
    pub version: String,
    pub meta_type: String,
    pub package_entries: usize,
    pub referenced: Vec<ContentMatch>,
    pub unreferenced_nca: Vec<String>,
}
impl PackageAudit {
    pub fn count(&self, status: MatchStatus) -> usize {
        self.referenced
            .iter()
            .filter(|record| record.status == status)
            .count()
    }
    pub fn complete_by_size(&self) -> bool {
        !self.referenced.is_empty() && self.count(MatchStatus::Present) == self.referenced.len()
    }
}

/// Correlate file *names and lengths* for an NSP against a separately supplied
/// plaintext CNMT. All data remains read-only and only bounded tables are read.
pub fn audit_nsp<R: Read + Seek, C: Read + Seek>(
    nsp: &mut R,
    cnmt: &mut C,
) -> io::Result<PackageAudit> {
    let package = inspect(nsp)?;
    if package.format != Format::SwitchNsp {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "package audit currently requires NSP/PFS0",
        ));
    }
    let (metadata, references) = inspect_cnmt_with_content(cnmt)?;
    let get = |field: &str| -> io::Result<String> {
        metadata
            .metadata
            .iter()
            .find(|(key, _)| key == field)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| invalid("CNMT required metadata field missing"))
    };

    let mut matched_names = HashSet::new();
    let mut matches = Vec::with_capacity(references.len());
    for record in &references {
        let result = match_record(&package.entries, record);
        if let Some(ref filename) = result.package_filename {
            matched_names.insert(filename.to_ascii_lowercase());
        }
        matches.push(result);
    }
    // Meta NCAs need not be referenced as regular content in the CNMT and are
    // intentionally omitted from the supplementary unreferenced list.
    let mut unreferenced_nca: Vec<String> = package
        .entries
        .iter()
        .filter(|entry| {
            let name = entry.name.to_ascii_lowercase();
            name.ends_with(".nca") && !name.ends_with(".cnmt.nca") && !matched_names.contains(&name)
        })
        .map(|entry| entry.name.clone())
        .collect();
    unreferenced_nca.sort();

    Ok(PackageAudit {
        title_id: get("title_id")?,
        version: get("version")?,
        meta_type: get("meta_type")?,
        package_entries: package.entries.len(),
        referenced: matches,
        unreferenced_nca,
    })
}

fn match_record(entries: &[Entry], record: &ContentRecord) -> ContentMatch {
    let filename = format!("{}.nca", record.id.to_ascii_lowercase());
    // Content Meta NCAs conventionally use ".cnmt.nca".
    let expected = if record.content_type == "meta" {
        format!("{}.cnmt.nca", record.id.to_ascii_lowercase())
    } else {
        filename
    };
    let direct: Vec<&Entry> = entries
        .iter()
        .filter(|entry| entry.name.eq_ignore_ascii_case(&expected))
        .collect();

    let (status, actual) = if direct.len() > 1 {
        (MatchStatus::Ambiguous, None)
    } else if let [entry] = direct.as_slice() {
        let status = if entry.size == record.size {
            MatchStatus::Present
        } else {
            MatchStatus::SizeMismatch
        };
        (status, Some(*entry))
    } else {
        let compressed_name = expected
            .strip_suffix(".nca")
            .unwrap_or(&expected)
            .to_string()
            + ".ncz";
        let compressed: Vec<&Entry> = entries
            .iter()
            .filter(|entry| entry.name.eq_ignore_ascii_case(&compressed_name))
            .collect();
        match compressed.as_slice() {
            [] => (MatchStatus::Missing, None),
            [entry] => (MatchStatus::CompressedUnsupported, Some(*entry)),
            _ => (MatchStatus::Ambiguous, None),
        }
    };
    ContentMatch {
        id: record.id.clone(),
        content_type: record.content_type,
        expected_size: record.size,
        expected_filename: expected,
        package_filename: actual.map(|entry| entry.name.clone()),
        package_size: actual.map(|entry| entry.size),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const CONTENT_A: [u8; 16] = [0x11; 16];
    const CONTENT_B: [u8; 16] = [0x22; 16];

    fn cnmt(records: &[([u8; 16], u64, u8)]) -> Vec<u8> {
        let offset = 0x30usize;
        let mut data = vec![0u8; offset + records.len() * 0x38 + 0x20];
        data[0..8].copy_from_slice(&0x0100123456789000u64.to_le_bytes());
        data[8..12].copy_from_slice(&65536u32.to_le_bytes());
        data[0xc] = 0x81; // patch, with application ID in extended header
        data[0xe..0x10].copy_from_slice(&0x10u16.to_le_bytes());
        data[0x10..0x12].copy_from_slice(&(records.len() as u16).to_le_bytes());
        data[0x20..0x28].copy_from_slice(&0x0100123456788000u64.to_le_bytes());
        for (i, (id, size, kind)) in records.iter().enumerate() {
            let at = offset + i * 0x38;
            data[at + 0x20..at + 0x30].copy_from_slice(id);
            for byte in 0..5 {
                data[at + 0x30 + byte] = (size >> (8 * byte)) as u8;
            }
            data[at + 0x36] = *kind;
        }
        data
    }
    fn nsp(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let names_len: usize = entries.iter().map(|(name, _)| name.len() + 1).sum();
        let mut data = b"PFS0".to_vec();
        data.extend((entries.len() as u32).to_le_bytes());
        data.extend((names_len as u32).to_le_bytes());
        data.extend(0u32.to_le_bytes());
        let mut relative = 0u64;
        let mut name_offset = 0u32;
        for (name, content) in entries {
            data.extend(relative.to_le_bytes());
            data.extend((content.len() as u64).to_le_bytes());
            data.extend(name_offset.to_le_bytes());
            data.extend(0u32.to_le_bytes());
            relative += content.len() as u64;
            name_offset += name.len() as u32 + 1;
        }
        for (name, _) in entries {
            data.extend(name.as_bytes());
            data.push(0);
        }
        for (_, content) in entries {
            data.extend(*content);
        }
        data
    }

    #[test]
    fn correlates_content_by_exact_id_and_size_only() {
        let archive = nsp(&[
            ("11111111111111111111111111111111.nca", b"synthetic"),
            ("metadata.cnmt.nca", b"opaque"),
            ("unrelated.nca", b"x"),
        ]);
        let refs = cnmt(&[(CONTENT_A, 9, 1), (CONTENT_B, 4, 3)]);
        let result = audit_nsp(&mut Cursor::new(archive), &mut Cursor::new(refs)).unwrap();
        assert_eq!(result.title_id, "0100123456789000");
        assert_eq!(result.version, "65536");
        assert_eq!(result.package_entries, 3);
        assert_eq!(result.count(MatchStatus::Present), 1);
        assert_eq!(result.count(MatchStatus::Missing), 1);
        assert!(!result.complete_by_size());
        assert_eq!(
            result.referenced[0].package_filename.as_deref(),
            Some("11111111111111111111111111111111.nca")
        );
        assert_eq!(result.unreferenced_nca, vec!["unrelated.nca"]);
    }

    #[test]
    fn flags_mismatch_and_unsupported_compressed_nca() {
        let archive = nsp(&[
            ("11111111111111111111111111111111.nca", b"abc"),
            ("22222222222222222222222222222222.ncz", b"packed"),
        ]);
        let refs = cnmt(&[(CONTENT_A, 10, 1), (CONTENT_B, 64, 3)]);
        let result = audit_nsp(&mut Cursor::new(archive), &mut Cursor::new(refs)).unwrap();
        assert_eq!(result.count(MatchStatus::SizeMismatch), 1);
        assert_eq!(result.count(MatchStatus::CompressedUnsupported), 1);
        assert_eq!(result.referenced[0].package_size, Some(3));
        assert_eq!(result.referenced[1].package_size, Some(6));
    }

    #[test]
    fn ambiguous_case_variants_do_not_create_false_matches() {
        let archive = nsp(&[
            ("11111111111111111111111111111111.nca", b"1234"),
            ("11111111111111111111111111111111.NCA", b"1234"),
        ]);
        let refs = cnmt(&[(CONTENT_A, 4, 1)]);
        let result = audit_nsp(&mut Cursor::new(archive), &mut Cursor::new(refs)).unwrap();
        assert_eq!(result.count(MatchStatus::Ambiguous), 1);
        assert!(!result.complete_by_size());
    }

    #[test]
    fn refuses_non_nsp_and_malformed_cnmt() {
        assert_eq!(
            audit_nsp(
                &mut Cursor::new(b"not an nsp".to_vec()),
                &mut Cursor::new(cnmt(&[]))
            )
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidInput
        );
        let archive = nsp(&[]);
        assert!(audit_nsp(&mut Cursor::new(archive), &mut Cursor::new(vec![0u8; 128])).is_err());
    }

    #[test]
    fn meta_reference_uses_cnmt_nca_filename() {
        let archive = nsp(&[("11111111111111111111111111111111.cnmt.nca", b"12345")]);
        let refs = cnmt(&[(CONTENT_A, 5, 0)]);
        let result = audit_nsp(&mut Cursor::new(archive), &mut Cursor::new(refs)).unwrap();
        assert_eq!(result.count(MatchStatus::Present), 1);
        assert_eq!(
            result.referenced[0].expected_filename,
            "11111111111111111111111111111111.cnmt.nca"
        );
    }
}
