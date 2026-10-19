//! Deterministic, bounded, read-only inventory of user-supplied Switch
//! plaintext metadata bundles, grouped by claimed application identity.
//!
//! One immediate child directory = one bundle containing exactly one .cnmt,
//! plus optional control.nacp and main.nso. Nothing is decrypted, recursively
//! searched or proven to belong to the same commercial title.
//! Versions are the numeric CNMT revisions, NOT NACP display versions.

use crate::cnmt::inspect_cnmt_with_content;
use crate::metadata_dir::discover_metadata_dir;
use crate::nacp::inspect_nacp;
use crate::package::{audit_switch_package, audit_switch_package_with_hashes, audit_switch_package_with_headers, PackageAudit};
use crate::{inspect, Format};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Cursor, ErrorKind, Read};
use std::path::{Path, PathBuf};

const MAX_BUNDLES: usize = 2048;
const MAX_CNMT_BYTES: u64 = 16 * 1024 * 1024;

fn invalid(s: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, s)
}

#[derive(Debug, Clone)]
pub struct TitleRecord {
    pub bundle: String,
    /// CNMT title ID: patch/DLC have independent IDs from the base application.
    pub title_id: String,
    pub version: u32,
    pub meta_type: String,
    /// From the CNMT extension. For an application, this is its own title ID.
    /// Other types are grouped by their asserted linked application ID when present.
    pub application_group_id: String,
    pub grouping_basis: &'static str,
    /// CNMT content digest as received, NOT a signature/authenticity proof.
    pub source_sha256: String,
    pub content_count: usize,
    pub linked_application_id: Option<String>,
    pub display_title: Option<String>,
    /// Optional NACP display version, not numerically comparable to CNMT version.
    pub display_version: Option<String>,
    /// User-named main.nso build ID; no title-to-executable attribution is proven.
    pub module_build_id: Option<String>,
    pub atmosphere_cheat_build_id: Option<String>,
    /// Only checked on explicit request. Selection uses exact package.nsp or package.xci.
    pub package_filename: Option<String>,
    /// Comparison against this record's external CNMT, not authenticity proof.
    pub package_audit: Option<PackageAudit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionCollision {
    pub title_id: String,
    pub version: u32,
    pub meta_type: String,
    pub bundles: Vec<String>,
    /// Distinct plaintext CNMT byte sequences assert the same title/version/type.
    pub conflicting_content: bool,
}

#[derive(Debug, Clone)]
pub struct TitleGroup {
    /// Claimed base application title ID when linked from patch/DLC CNMT,
    /// otherwise the record's own CNMT title ID.
    pub application_id: String,
    pub records: Vec<TitleRecord>,
    /// Determined only within this supplied inventory. No remote latest claims.
    pub latest_application_version: Option<u32>,
    pub latest_patch_version: Option<u32>,
    pub version_collisions: Vec<VersionCollision>,
}

#[derive(Debug, Clone)]
pub struct TitleInventory {
    pub bundles_scanned: usize,
    pub package_audits_requested: bool,
    pub packages_audited: usize,
    pub packages_missing: usize,
    pub groups: Vec<TitleGroup>,
    pub version_collisions: usize,
}

fn field<'a>(metadata: &'a [(String, String)], key: &str) -> Option<&'a str> {
    metadata
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

/// Audit only a *deliberately named* archive within one bundle.
/// Unrelated archives are ignored rather than guessed from content or filenames.
fn discover_designated_package(directory: &Path) -> io::Result<Option<(PathBuf, String)>> {
    const MAX_ITEMS: usize = 4096;
    let mut found = None;
    for (count, entry) in fs::read_dir(directory)?.enumerate() {
        if count >= MAX_ITEMS {
            return Err(invalid("bundle directory exceeds package-discovery safety limit"));
        }
        let entry = entry?;
        let name = entry.file_name();
        let matches = name.to_str().is_some_and(|s| {
            s.eq_ignore_ascii_case("package.nsp") || s.eq_ignore_ascii_case("package.xci")
        });
        if !matches {
            continue;
        }
        if !entry.file_type()?.is_file() {
            return Err(invalid("designated package is not a regular non-symlink file"));
        }
        if found.is_some() {
            return Err(invalid("multiple designated packages in one bundle"));
        }
        let filename = name.into_string()
            .map_err(|_| invalid("designated package filename is not UTF-8"))?;
        found = Some((entry.path(), filename));
    }
    Ok(found)
}

fn read_record(
    directory: &Path,
    bundle: String,
    check_packages: bool,
    verify_hashes: bool,
    inspect_headers: bool,
) -> io::Result<TitleRecord> {
    let metadata = discover_metadata_dir(directory)?;
    let mut file = File::open(&metadata.cnmt)?;
    // An explicit upper bound even if the file grows between discovery and read.
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_CNMT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CNMT_BYTES {
        return Err(invalid("CNMT exceeds 16 MiB inventory limit"));
    }
    let source_sha256 = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    let (report, contents) = inspect_cnmt_with_content(&mut Cursor::new(&bytes))?;
    let title_id = field(&report.metadata, "title_id")
        .ok_or_else(|| invalid("CNMT title ID absent"))?
        .to_string();
    let version = field(&report.metadata, "version")
        .ok_or_else(|| invalid("CNMT version absent"))?
        .parse::<u32>()
        .map_err(|_| invalid("CNMT version invalid"))?;
    let meta_type = field(&report.metadata, "meta_type")
        .ok_or_else(|| invalid("CNMT type absent"))?
        .to_string();
    let linked_application_id = field(&report.metadata, "application_id").map(str::to_owned);
    // A base Application CNMT has patch_id, not application_id; it should
    // remain grouped by its own title ID rather than by its patch counterpart.
    let (application_group_id, grouping_basis) = if let Some(ref linked) = linked_application_id {
        (linked.clone(), "cnmt_application_reference_unverified")
    } else {
        (title_id.clone(), "cnmt_title_id_unverified")
    };

    let mut display_title = None;
    let mut display_version = None;
    if let Some(path) = metadata.nacp {
        let nacp = inspect_nacp(&mut File::open(path)?)?;
        display_title = field(&nacp.metadata, "title_american_english")
            .or_else(|| {
                nacp.metadata
                    .iter()
                    .find(|(name, _)| name.starts_with("title_"))
                    .map(|(_, value)| value.as_str())
            })
            .map(str::to_owned);
        display_version = field(&nacp.metadata, "display_version").map(str::to_owned);
    }
    let mut module_build_id = None;
    let mut atmosphere_cheat_build_id = None;
    if let Some(path) = metadata.main_nso {
        let report = inspect(&mut File::open(path)?)?;
        if report.format != Format::SwitchNso {
            return Err(invalid("main.nso does not contain a readable NSO0 header"));
        }
        module_build_id = field(&report.metadata, "module_build_id").map(str::to_owned);
        atmosphere_cheat_build_id =
            field(&report.metadata, "atmosphere_cheat_build_id").map(str::to_owned);
    }
    let (package_filename, package_audit) = if check_packages {
        if let Some((path, name)) = discover_designated_package(directory)? {
            let mut package = File::open(path)?;
            let mut cnmt = Cursor::new(&bytes);
            let audit = if inspect_headers {
                audit_switch_package_with_headers(&mut package, &mut cnmt, verify_hashes)?
            } else if verify_hashes {
                audit_switch_package_with_hashes(&mut package, &mut cnmt)?
            } else {
                audit_switch_package(&mut package, &mut cnmt)?
            };
            (Some(name), Some(audit))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };
    Ok(TitleRecord {
        bundle,
        title_id,
        version,
        meta_type,
        application_group_id,
        grouping_basis,
        source_sha256,
        content_count: contents.len(),
        linked_application_id,
        display_title,
        display_version,
        module_build_id,
        atmosphere_cheat_build_id,
        package_filename,
        package_audit,
    })
}

/// Root is a collection of immediate child directories, each holding one CNMT.
/// No inference from folder names, filename-based title IDs or other modules.
pub fn inventory_metadata_root(root: &Path) -> io::Result<TitleInventory> {
    inventory_metadata_root_with_packages(root, false, false, false)
}

/// Opt-in audit of uniquely named package.nsp/package.xci alongside each
/// plaintext metadata bundle. An absent package remains metadata-only.
/// SHA-256 and readable NCA header checks are independently opt-in.
pub fn inventory_metadata_root_with_packages(
    root: &Path,
    check_packages: bool,
    verify_hashes: bool,
    inspect_headers: bool,
) -> io::Result<TitleInventory> {
    if (verify_hashes || inspect_headers) && !check_packages {
        return Err(invalid("hash/header options require explicit package auditing"));
    }
    if !fs::symlink_metadata(root)?.file_type().is_dir() {
        return Err(invalid("inventory root must be an ordinary directory"));
    }
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    for item in fs::read_dir(root)? {
        let item = item?;
        let file_type = item.file_type()?;
        if file_type.is_symlink() {
            return Err(invalid("inventory root contains a symlink"));
        }
        if !file_type.is_dir() {
            continue;
        }
        if dirs.len() == MAX_BUNDLES {
            return Err(invalid("inventory exceeds 2048 immediate subdirectories"));
        }
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| invalid("inventory directory name is not UTF-8"))?;
        dirs.push((name, item.path()));
    }
    if dirs.is_empty() {
        return Err(invalid(
            "inventory requires at least one bundle subdirectory",
        ));
    }
    dirs.sort_by(|left, right| left.0.cmp(&right.0));
    let mut groups: BTreeMap<String, Vec<TitleRecord>> = BTreeMap::new();
    let mut packages_audited = 0;
    for (name, path) in &dirs {
        let record = read_record(path, name.clone(), check_packages, verify_hashes, inspect_headers)?;
        packages_audited += usize::from(record.package_audit.is_some());
        groups
            .entry(record.application_group_id.clone())
            .or_default()
            .push(record);
    }
    let mut versions = 0;
    let mut result = Vec::with_capacity(groups.len());
    for (application_id, mut records) in groups {
        records.sort_by(|a, b| {
            (&a.title_id, &a.meta_type, a.version, &a.bundle).cmp(&(
                &b.title_id,
                &b.meta_type,
                b.version,
                &b.bundle,
            ))
        });
        let latest_application_version = records
            .iter()
            .filter(|record| record.meta_type == "application" && record.title_id == application_id)
            .map(|record| record.version)
            .max();
        let latest_patch_version = records
            .iter()
            .filter(|record| record.meta_type == "patch")
            .map(|record| record.version)
            .max();
        let mut by_release: BTreeMap<(String, String, u32), Vec<&TitleRecord>> = BTreeMap::new();
        for record in &records {
            by_release
                .entry((
                    record.title_id.clone(),
                    record.meta_type.clone(),
                    record.version,
                ))
                .or_default()
                .push(record);
        }
        let mut version_collisions = Vec::new();
        for ((title_id, meta_type, version), duplicates) in by_release {
            if duplicates.len() < 2 {
                continue;
            }
            versions += 1;
            let original = &duplicates[0].source_sha256;
            version_collisions.push(VersionCollision {
                title_id,
                version,
                meta_type,
                bundles: duplicates.iter().map(|r| r.bundle.clone()).collect(),
                conflicting_content: duplicates.iter().any(|r| &r.source_sha256 != original),
            });
        }
        result.push(TitleGroup {
            application_id,
            records,
            latest_application_version,
            latest_patch_version,
            version_collisions,
        });
    }
    Ok(TitleInventory {
        bundles_scanned: dirs.len(),
        package_audits_requested: check_packages,
        packages_audited,
        packages_missing: if check_packages { dirs.len() - packages_audited } else { 0 },
        groups: result,
        version_collisions: versions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SERIAL: AtomicUsize = AtomicUsize::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "ninforge-title-inventory-{}-{now}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn bundle(
            &self,
            name: &str,
            title: u64,
            version: u32,
            kind: u8,
            linked: Option<u64>,
            marker: u8,
        ) {
            let dir = self.0.join(name);
            fs::create_dir(&dir).unwrap();
            let ext_len = if matches!(kind, 0x80..=0x83) {
                0x10usize
            } else {
                0
            };
            let mut cnmt = vec![0u8; 0x20 + ext_len + 0x20];
            cnmt[..8].copy_from_slice(&title.to_le_bytes());
            cnmt[8..12].copy_from_slice(&version.to_le_bytes());
            cnmt[0xc] = kind;
            cnmt[0xe..0x10].copy_from_slice(&(ext_len as u16).to_le_bytes());
            if let Some(id) = linked {
                cnmt[0x20..0x28].copy_from_slice(&id.to_le_bytes());
            }
            let last = cnmt.len() - 1;
            cnmt[last] = marker;
            fs::write(dir.join("metadata.cnmt"), cnmt).unwrap();
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    const APP: u64 = 0x0100_1234_5678_8000;
    const PATCH: u64 = 0x0100_1234_5678_8800;

    #[test]
    fn groups_application_and_multiple_patch_versions_without_conflating_versions() {
        let t = Temp::new();
        t.bundle("patch2", PATCH, 131072, 0x81, Some(APP), 2);
        t.bundle("base", APP, 0, 0x80, Some(PATCH), 0);
        t.bundle("patch1", PATCH, 65536, 0x81, Some(APP), 1);
        let result = inventory_metadata_root(&t.0).unwrap();
        assert_eq!(result.bundles_scanned, 3);
        assert_eq!(result.groups.len(), 1);
        let group = &result.groups[0];
        assert_eq!(group.application_id, format!("{APP:016X}"));
        assert_eq!(group.latest_application_version, Some(0));
        assert_eq!(group.latest_patch_version, Some(131072));
        assert_eq!(group.records[0].title_id, format!("{APP:016X}"));
        assert_eq!(group.records[2].version, 131072);
        assert!(group.version_collisions.is_empty());
    }

    #[test]
    fn competing_same_version_cnmt_digests_flag_content_conflict() {
        let t = Temp::new();
        t.bundle("a", PATCH, 65536, 0x81, Some(APP), 1);
        t.bundle("b", PATCH, 65536, 0x81, Some(APP), 2);
        let result = inventory_metadata_root(&t.0).unwrap();
        assert_eq!(result.version_collisions, 1);
        let collision = &result.groups[0].version_collisions[0];
        assert_eq!(collision.bundles, vec!["a", "b"]);
        assert!(collision.conflicting_content);
    }

    #[test]
    fn same_version_identical_bytes_remain_visible_as_duplicates() {
        let t = Temp::new();
        t.bundle("a", PATCH, 65536, 0x81, Some(APP), 1);
        t.bundle("b", PATCH, 65536, 0x81, Some(APP), 1);
        let result = inventory_metadata_root(&t.0).unwrap();
        assert_eq!(result.version_collisions, 1);
        assert!(!result.groups[0].version_collisions[0].conflicting_content);
    }

    #[test]
    fn unrelated_titles_stay_separate_and_sorted() {
        let t = Temp::new();
        t.bundle("z", 0x0100999900000000, 7, 0x80, None, 7);
        t.bundle("a", APP, 0, 0x80, None, 1);
        let result = inventory_metadata_root(&t.0).unwrap();
        assert_eq!(result.groups.len(), 2);
        assert_eq!(result.groups[0].application_id, format!("{APP:016X}"));
        assert_eq!(result.groups[1].latest_application_version, Some(7));
    }

    #[test]
    fn rejects_missing_cnmt_and_unreadable_bundle_data() {
        let t = Temp::new();
        fs::create_dir(t.0.join("empty")).unwrap();
        assert!(inventory_metadata_root(&t.0).is_err());
        fs::write(t.0.join("empty/bad.cnmt"), b"bad").unwrap();
        assert!(inventory_metadata_root(&t.0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_collection_child() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        t.bundle("base", APP, 0, 0x80, None, 1);
        symlink(t.0.join("base"), t.0.join("alias")).unwrap();
        assert!(inventory_metadata_root(&t.0).is_err());
    }
}
