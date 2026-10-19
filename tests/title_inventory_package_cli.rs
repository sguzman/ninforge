//! End-to-end checks for local title inventory linked to explicitly designated
//! NSP packages. Synthetic fixtures only; never commercial content or keys.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SERIAL: AtomicUsize = AtomicUsize::new(0);
const CONTENT_ID: [u8; 16] = [0x11; 16];
const NCA_NAME: &str = "11111111111111111111111111111111.nca";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ninforge-inventory-package-{}-{ns}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn add_bundle(&self, bundle: &str, expected: &[u8], actual: Option<&[u8]>) -> PathBuf {
        let dir = self.0.join(bundle);
        fs::create_dir(&dir).unwrap();
        let mut cnmt = vec![0u8; 0x20 + 0x10 + 0x38 + 0x20];
        cnmt[..8].copy_from_slice(&0x0100_1234_5678_8000u64.to_le_bytes());
        cnmt[8..12].copy_from_slice(&65536u32.to_le_bytes());
        cnmt[0xc] = 0x80; // application
        cnmt[0xe..0x10].copy_from_slice(&0x10u16.to_le_bytes());
        cnmt[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        cnmt[0x30..0x50].copy_from_slice(&Sha256::digest(expected));
        cnmt[0x50..0x60].copy_from_slice(&CONTENT_ID);
        for j in 0..5 {
            cnmt[0x60 + j] = (expected.len() as u64 >> (8 * j)) as u8;
        }
        cnmt[0x66] = 1; // Program
        fs::write(dir.join("metadata.cnmt"), cnmt).unwrap();
        if let Some(payload) = actual {
            fs::write(dir.join("package.nsp"), nsp(payload)).unwrap();
        }
        dir
    }
    fn run(&self, flags: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ninforge"))
            .args(["titles", "inventory"])
            .arg(&self.0)
            .args(flags)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn nsp(payload: &[u8]) -> Vec<u8> {
    let mut file = b"PFS0".to_vec();
    file.extend(1u32.to_le_bytes());
    file.extend(((NCA_NAME.len() + 1) as u32).to_le_bytes());
    file.extend(0u32.to_le_bytes());
    file.extend(0u64.to_le_bytes());
    file.extend((payload.len() as u64).to_le_bytes());
    file.extend(0u32.to_le_bytes());
    file.extend(0u32.to_le_bytes());
    file.extend(NCA_NAME.as_bytes());
    file.push(0);
    file.extend(payload);
    file
}
fn readable_nca() -> Vec<u8> {
    let mut data = vec![0u8; 0xc00];
    data[0x200..0x204].copy_from_slice(b"NCA3");
    data[0x205] = 0;
    data[0x208..0x210].copy_from_slice(&0xc00u64.to_le_bytes());
    data[0x210..0x218].copy_from_slice(&0x0100_1234_5678_8000u64.to_le_bytes());
    data
}

#[test]
fn default_inventory_never_opens_designated_game_package() {
    let f = Fixture::new();
    let bytes = readable_nca();
    f.add_bundle("demo", &bytes, Some(&bytes));
    let result = f.run(&["--json"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains(r#""package_audits_requested":false"#));
    assert!(text.contains(r#""packages_audited":0"#));
    assert!(text.contains(r#""package_audit":null"#));
    assert!(text.contains(r#""package_filename":null"#));
}

#[test]
fn explicit_package_check_matches_sha_and_header_structurally() {
    let f = Fixture::new();
    let bytes = readable_nca();
    f.add_bundle("demo", &bytes, Some(&bytes));
    let result = f.run(&["--packages", "--hash", "--headers", "--json"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains(r#""packages_audited":1"#));
    assert!(text.contains(r#""package_filename":"package.nsp""#));
    assert!(text.contains(r#""package_format":"Switch NSP/PFS0""#));
    assert!(text.contains(r#""hash_status":"matched""#));
    assert!(text.contains(r#""header_status":"consistent""#));
    assert!(text.contains(r#""hashes_match_supplied_cnmt":true"#));
    assert!(text.contains(r#""header_program_id":"0100123456788000""#));
    assert!(text.contains(r#""nacp_nso_link_verified":false"#));
    assert!(text.contains(r#""metadata_source":"external_cnmt_unverified""#));
}

#[test]
fn identical_size_modified_content_stays_unverified() {
    let f = Fixture::new();
    f.add_bundle("demo", b"abc", Some(b"abd"));
    let result = f.run(&["--packages", "--hash", "--json"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains(r#""complete_by_size":true"#));
    assert!(text.contains(r#""hash_status":"mismatched""#));
    assert!(text.contains(r#""hashes_match_supplied_cnmt":false"#));
    assert!(text.contains(r#""nacp_nso_link_verified":false"#));
}

#[test]
fn missing_package_is_metadata_only_and_bad_flags_fail() {
    let f = Fixture::new();
    f.add_bundle("demo", b"abc", None);
    let result = f.run(&["--packages", "--hash", "--json"]);
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains(r#""packages_missing":1"#));
    assert!(text.contains(r#""package_audit":null"#));
    assert!(!f.run(&["--hash", "--json"]).status.success());
    assert!(!f.run(&["--headers", "--json"]).status.success());
    assert!(!f
        .run(&["--packages", "--packages", "--json"])
        .status
        .success());
}

#[test]
fn ambiguous_designated_packages_fail_without_choosing_one() {
    let f = Fixture::new();
    let dir = f.add_bundle("demo", b"abc", Some(b"abc"));
    fs::write(dir.join("package.xci"), b"fake").unwrap();
    let result = f.run(&["--packages", "--json"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("multiple designated packages"));
    assert!(result.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn package_symlink_is_rejected_when_audit_is_requested() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let dir = f.add_bundle("demo", b"abc", None);
    let remote: &Path = &f.0.join("remote");
    fs::write(remote, b"synthetic").unwrap();
    symlink(remote, dir.join("package.nsp")).unwrap();
    let result = f.run(&["--packages", "--json"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("non-symlink"));
}


#[test]
fn evidence_json_default_is_metadata_only_with_no_cheat_link_permission() {
    let f = Fixture::new();
    f.add_bundle("demo", b"abc", Some(b"abc"));
    let result = f.run(&["--json"]);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains(r#""schema_version":1"#));
    assert!(text.contains(r#""evidence_schema_version":1"#));
    assert!(text.contains(r#""evidence":{"package":"metadata_only","headers":"not_checked","release":"unique_within_supplied_dataset","executable_association":"unavailable","cheat_target":"missing_build_id","automatic_cheat_match_allowed":false}"#));
}

#[test]
fn evidence_json_reports_hash_correspondence_but_not_verified_title_identity() {
    let f = Fixture::new();
    let nca = readable_nca();
    f.add_bundle("demo", &nca, Some(&nca));
    let output = f.run(&["--packages", "--hash", "--headers", "--json"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(r#""package":"hash_matched_to_supplied_cnmt""#));
    assert!(text.contains(r#""headers":"all_readable_headers_consistent""#));
    assert!(text.contains(r#""cheat_target":"missing_build_id""#));
    assert!(text.contains(r#""automatic_cheat_match_allowed":false"#));
    assert!(text.contains(r#""hashes_verified":false"#));
}

#[test]
fn evidence_json_distinguishes_modified_content_from_size_match() {
    let f = Fixture::new();
    f.add_bundle("demo", b"abc", Some(b"abd"));
    let output = f.run(&["--packages", "--hash", "--json"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(r#""complete_by_size":true"#));
    assert!(text.contains(r#""package":"hash_mismatched_to_supplied_cnmt""#));
    assert!(text.contains(r#""automatic_cheat_match_allowed":false"#));
}

#[test]
fn evidence_json_build_id_always_a_candidate_not_a_verified_link() {
    let f = Fixture::new();
    let dir = f.add_bundle("demo", b"abc", Some(b"abc"));
    let mut nso = vec![0u8; 0x100];
    nso[..4].copy_from_slice(b"NSO0");
    nso[0x40..0x48].copy_from_slice(&[1,2,3,4,5,6,7,8]);
    fs::write(dir.join("main.nso"), nso).unwrap();
    let output = f.run(&["--packages", "--hash", "--json"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(r#""atmosphere_cheat_build_id":"0102030405060708""#));
    assert!(text.contains(r#""cheat_target":"unverified_candidate_only""#));
    assert!(text.contains(r#""executable_association":"user_designated_main_nso_unverified""#));
    assert!(text.contains(r#""automatic_cheat_match_allowed":false"#));
}

#[test]
fn evidence_json_conflicting_same_version_cnmt_blocks_candidate_use() {
    let f = Fixture::new();
    let first = f.add_bundle("one", b"abc", None);
    f.add_bundle("two", b"def", None);
    let mut nso = vec![0u8; 0x100];
    nso[..4].copy_from_slice(b"NSO0");
    nso[0x40..0x48].copy_from_slice(&[1,2,3,4,5,6,7,8]);
    fs::write(first.join("main.nso"), nso).unwrap();
    let output = f.run(&["--json"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(r#""version_collisions":1"#));
    assert!(text.contains(r#""conflicting_content":true"#));
    assert!(text.contains(r#""release":"duplicate_conflicting_cnmt""#));
    assert!(text.contains(r#""cheat_target":"conflicting_release""#));
    assert!(text.contains(r#""automatic_cheat_match_allowed":false"#));
}
