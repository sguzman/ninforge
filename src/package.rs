//! Keyless, read-only join between a PFS0 NSP table and a supplied plaintext CNMT.
//!
//! This is an inventory cross-check, NOT title authentication, hash validation,
//! decryption, signature validation or proof that two files originate together.
//! The CNMT must be independently provided: in ordinary NSPs it lives inside
//! an encrypted metadata NCA and is not directly readable as a top-level file.

use crate::cnmt::{inspect_cnmt_with_content, ContentRecord};
use crate::nacp::inspect_nacp;
use crate::{inspect, Entry, Format};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

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
/// SHA-256 comparison status relative to an untrusted, user-supplied CNMT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashStatus {
    NotChecked,
    Matched,
    Mismatched,
    Unavailable,
}
impl HashStatus {
    pub fn name(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Matched => "matched",
            Self::Mismatched => "mismatched",
            Self::Unavailable => "unavailable",
        }
    }
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
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub hash_status: HashStatus,
}

/// Metadata from a separately supplied, independently parsed file.
/// Attribution to the audited NSP is NEVER established by this structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalEvidence {
    pub kind: &'static str,
    pub provenance: &'static str,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct PackageAudit {
    /// These title/version fields come from an independently supplied,
    /// *unverified* plaintext CNMT, not directly from the NSP.
    pub title_id: String,
    pub version: String,
    pub meta_type: String,
    pub package_entries: usize,
    pub hashing_requested: bool,
    pub referenced: Vec<ContentMatch>,
    pub unreferenced_nca: Vec<String>,
    pub external_evidence: Vec<ExternalEvidence>,
}
impl PackageAudit {
    pub fn hash_count(&self, status: HashStatus) -> usize {
        self.referenced
            .iter()
            .filter(|content| content.hash_status == status)
            .count()
    }

    /// True only when --hash was requested and every referenced NCA exactly
    /// matched a SHA-256 asserted by the *supplied, unauthenticated* CNMT.
    /// Never interpret this as proof that the CNMT is legitimate.
    pub fn all_hashes_match_supplied_cnmt(&self) -> bool {
        self.hashing_requested
            && !self.referenced.is_empty()
            && self.hash_count(HashStatus::Matched) == self.referenced.len()
    }

    pub fn count(&self, status: MatchStatus) -> usize {
        self.referenced
            .iter()
            .filter(|record| record.status == status)
            .count()
    }
    pub fn complete_by_size(&self) -> bool {
        !self.referenced.is_empty() && self.count(MatchStatus::Present) == self.referenced.len()
    }

    /// Read a separately obtained NACP, preserving its identity as unverified
    /// external metadata. Display versions are NOT equivalent to CNMT versions.
    pub fn attach_nacp<R: Read + Seek>(&mut self, nacp: &mut R) -> io::Result<()> {
        if self
            .external_evidence
            .iter()
            .any(|item| item.kind == "nacp")
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "NACP already attached",
            ));
        }
        let report = inspect_nacp(nacp)?;
        self.external_evidence.push(ExternalEvidence {
            kind: "nacp",
            provenance: "user_supplied_unverified",
            fields: report.metadata,
        });
        Ok(())
    }

    /// Read an explicitly user-designated main NSO. A build ID identifies an
    /// executable, not the title; no automatic association is inferred.
    pub fn attach_main_nso<R: Read + Seek>(&mut self, nso: &mut R) -> io::Result<()> {
        if self
            .external_evidence
            .iter()
            .any(|item| item.kind == "main_nso")
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "main NSO already attached",
            ));
        }
        let report = inspect(nso)?;
        if report.format != Format::SwitchNso {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "expected readable NSO0 executable",
            ));
        }
        self.external_evidence.push(ExternalEvidence {
            kind: "main_nso",
            provenance: "user_designated_main_unverified",
            fields: report.metadata,
        });
        Ok(())
    }
}

/// Correlate file *names and lengths* for an NSP against a separately supplied
/// plaintext CNMT. All data remains read-only and only bounded tables are read.
pub fn audit_nsp<R: Read + Seek, C: Read + Seek>(
    nsp: &mut R,
    cnmt: &mut C,
) -> io::Result<PackageAudit> {
    audit_nsp_internal(nsp, cnmt, false)
}

/// Opt-in, bounded-memory, streaming SHA-256 verification of NSP NCA entry
/// bytes against digest assertions in an independently supplied plaintext CNMT.
/// This does NOT authenticate the CNMT, title identity or signatures.
pub fn audit_nsp_with_hashes<R: Read + Seek, C: Read + Seek>(
    nsp: &mut R,
    cnmt: &mut C,
) -> io::Result<PackageAudit> {
    audit_nsp_internal(nsp, cnmt, true)
}

fn audit_nsp_internal<R: Read + Seek, C: Read + Seek>(
    nsp: &mut R,
    cnmt: &mut C,
    verify_hashes: bool,
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
        let mut result = match_record(&package.entries, record);
        if let Some(ref filename) = result.package_filename {
            matched_names.insert(filename.to_ascii_lowercase());
        }
        if verify_hashes {
            if result.status == MatchStatus::Present {
                let name = result
                    .package_filename
                    .as_deref()
                    .ok_or_else(|| invalid("present entry missing path"))?;
                let entry = package
                    .entries
                    .iter()
                    .find(|entry| entry.name == name)
                    .ok_or_else(|| invalid("present entry missing from parsed NSP"))?;
                let digest = hash_entry(nsp, entry)?;
                result.actual_sha256 = Some(sha256_hex(&digest));
                result.hash_status = if digest == record.expected_sha256 {
                    HashStatus::Matched
                } else {
                    HashStatus::Mismatched
                };
            } else {
                // Missing, compressed, mismatched-size, or ambiguous files
                // cannot be verified against the CNMT's full NCA hash.
                result.hash_status = HashStatus::Unavailable;
            }
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
        hashing_requested: verify_hashes,
        referenced: matches,
        unreferenced_nca,
        external_evidence: Vec::new(),
    })
}

fn sha256_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn hash_entry<R: Read + Seek>(nsp: &mut R, entry: &Entry) -> io::Result<[u8; 32]> {
    nsp.seek(SeekFrom::Start(entry.offset))?;
    let mut reader = nsp.take(entry.size);
    let mut buffer = [0u8; 128 * 1024];
    let mut sha = Sha256::new();
    while reader.limit() != 0 {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Err(invalid("NSP entry truncated during SHA-256 verification"));
        }
        sha.update(&buffer[..count]);
    }
    Ok(sha.finalize().into())
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
        expected_sha256: sha256_hex(&record.expected_sha256),
        actual_sha256: None,
        hash_status: HashStatus::NotChecked,
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

    fn synthetic_nacp(title: &str, display_version: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x4000];
        bytes[..title.len()].copy_from_slice(title.as_bytes());
        bytes[0x3060..0x3060 + display_version.len()].copy_from_slice(display_version.as_bytes());
        bytes
    }

    fn synthetic_nso() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x100];
        bytes[..4].copy_from_slice(b"NSO0");
        bytes[0x40..0x48].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        bytes
    }

    #[test]
    fn attaches_explicit_metadata_without_claiming_title_attribution() {
        let archive = nsp(&[("11111111111111111111111111111111.nca", b"four")]);
        let refs = cnmt(&[(CONTENT_A, 4, 1)]);
        let mut audit = audit_nsp(&mut Cursor::new(archive), &mut Cursor::new(refs)).unwrap();
        audit
            .attach_nacp(&mut Cursor::new(synthetic_nacp("Sample", "1.2.3")))
            .unwrap();
        audit
            .attach_main_nso(&mut Cursor::new(synthetic_nso()))
            .unwrap();
        assert!(audit.complete_by_size());
        assert_eq!(audit.external_evidence.len(), 2);
        assert_eq!(
            audit.external_evidence[0].provenance,
            "user_supplied_unverified"
        );
        assert_eq!(
            audit.external_evidence[1].provenance,
            "user_designated_main_unverified"
        );
        assert!(audit.external_evidence[0]
            .fields
            .contains(&("title_american_english".into(), "Sample".into())));
        assert!(audit.external_evidence[0]
            .fields
            .contains(&("display_version".into(), "1.2.3".into())));
        assert!(audit.external_evidence[1].fields.contains(&(
            "atmosphere_cheat_build_id".into(),
            "123456789ABCDEF0".into()
        )));
        assert_eq!(audit.title_id, "0100123456789000");
        assert_eq!(audit.version, "65536");
    }

    #[test]
    fn rejects_non_nso_and_malformed_nacp_evidence() {
        let archive = nsp(&[]);
        let refs = cnmt(&[(CONTENT_A, 4, 1)]);
        let mut audit = audit_nsp(&mut Cursor::new(archive), &mut Cursor::new(refs)).unwrap();
        assert_eq!(
            audit
                .attach_main_nso(&mut Cursor::new(vec![0u8; 0x100]))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        assert!(audit.external_evidence.is_empty());
        assert!(audit
            .attach_nacp(&mut Cursor::new(vec![0u8; 0x4000]))
            .is_err());
        assert!(audit.external_evidence.is_empty());
        audit
            .attach_main_nso(&mut Cursor::new(synthetic_nso()))
            .unwrap();
        assert_eq!(
            audit
                .attach_main_nso(&mut Cursor::new(synthetic_nso()))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    fn cnmt_with_hash(id: [u8; 16], content: &[u8]) -> Vec<u8> {
        let mut metadata = cnmt(&[(id, content.len() as u64, 1)]);
        let hash = Sha256::digest(content);
        metadata[0x30..0x50].copy_from_slice(&hash);
        metadata
    }

    #[test]
    fn streaming_sha256_matches_exact_content_and_not_nsp_wrapper() {
        let body = b"abc";
        let archive = nsp(&[("11111111111111111111111111111111.nca", body)]);
        let metadata = cnmt_with_hash(CONTENT_A, body);
        let audit =
            audit_nsp_with_hashes(&mut Cursor::new(archive), &mut Cursor::new(metadata)).unwrap();
        assert_eq!(audit.count(MatchStatus::Present), 1);
        assert_eq!(audit.hash_count(HashStatus::Matched), 1);
        assert!(audit.all_hashes_match_supplied_cnmt());
        assert_eq!(
            audit.referenced[0].actual_sha256.as_deref(),
            Some("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
        );
    }

    #[test]
    fn hash_catches_same_length_tampering_undetected_by_size_only() {
        let archive = nsp(&[("11111111111111111111111111111111.nca", b"abd")]);
        let metadata = cnmt_with_hash(CONTENT_A, b"abc");
        let audit =
            audit_nsp_with_hashes(&mut Cursor::new(archive), &mut Cursor::new(metadata)).unwrap();
        assert!(audit.complete_by_size());
        assert_eq!(audit.hash_count(HashStatus::Mismatched), 1);
        assert!(!audit.all_hashes_match_supplied_cnmt());
        assert_ne!(
            audit.referenced[0].actual_sha256.as_deref(),
            Some(audit.referenced[0].expected_sha256.as_str())
        );
    }

    #[test]
    fn missing_and_compressed_content_cannot_be_hash_verified() {
        let archive = nsp(&[("11111111111111111111111111111111.ncz", b"packed")]);
        let metadata = cnmt_with_hash(CONTENT_A, b"abcdef");
        let audit =
            audit_nsp_with_hashes(&mut Cursor::new(archive), &mut Cursor::new(metadata)).unwrap();
        assert_eq!(audit.hash_count(HashStatus::Unavailable), 1);
        assert!(audit.referenced[0].actual_sha256.is_none());
        assert!(!audit.all_hashes_match_supplied_cnmt());
    }

    #[test]
    fn default_audit_does_not_hash_files() {
        let archive = nsp(&[("11111111111111111111111111111111.nca", b"abc")]);
        let metadata = cnmt_with_hash(CONTENT_A, b"abc");
        let audit = audit_nsp(&mut Cursor::new(archive), &mut Cursor::new(metadata)).unwrap();
        assert!(!audit.hashing_requested);
        assert_eq!(audit.hash_count(HashStatus::NotChecked), 1);
        assert!(audit.referenced[0].actual_sha256.is_none());
        assert!(!audit.all_hashes_match_supplied_cnmt());
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
