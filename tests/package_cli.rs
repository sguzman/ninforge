//! End-to-end tests of Ninforge's public CLI using only synthetic byte fixtures.
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const ID: [u8; 16] = [0x11; 16];
const NAME: &str = "11111111111111111111111111111111.nca";

struct Fixture {
    directory: PathBuf,
    nsp: PathBuf,
    cnmt: PathBuf,
}
impl Fixture {
    fn new(stored: &[u8], expected: &[u8]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "ninforge-cli-test-{}-{timestamp}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();

        let mut package = b"PFS0".to_vec();
        package.extend(1u32.to_le_bytes());
        package.extend(((NAME.len() + 1) as u32).to_le_bytes());
        package.extend(0u32.to_le_bytes());
        package.extend(0u64.to_le_bytes());
        package.extend((stored.len() as u64).to_le_bytes());
        package.extend(0u32.to_le_bytes());
        package.extend(0u32.to_le_bytes());
        package.extend(NAME.as_bytes());
        package.push(0);
        package.extend(stored);

        let mut metadata = vec![0u8; 0x30 + 0x38 + 0x20];
        metadata[..8].copy_from_slice(&0x0100123456789000u64.to_le_bytes());
        metadata[8..12].copy_from_slice(&65536u32.to_le_bytes());
        metadata[0xc] = 0x81;
        metadata[0xe..0x10].copy_from_slice(&0x10u16.to_le_bytes());
        metadata[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        metadata[0x20..0x28].copy_from_slice(&0x0100123456788000u64.to_le_bytes());
        metadata[0x30..0x50].copy_from_slice(&Sha256::digest(expected));
        metadata[0x50..0x60].copy_from_slice(&ID);
        for i in 0..5 {
            metadata[0x60 + i] = (expected.len() as u64 >> (i * 8)) as u8;
        }
        metadata[0x66] = 1; // program

        let nsp = directory.join("synthetic.nsp");
        let cnmt = directory.join("synthetic.cnmt");
        fs::write(&nsp, package).unwrap();
        fs::write(&cnmt, metadata).unwrap();
        Self {
            directory,
            nsp,
            cnmt,
        }
    }

    fn audit_dir(&self, flags: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ninforge"))
            .arg("package")
            .arg("audit-dir")
            .arg(&self.nsp)
            .arg(&self.directory)
            .args(flags)
            .output()
            .unwrap()
    }

    fn audit(&self, flags: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ninforge"))
            .arg("package")
            .arg("audit")
            .arg(&self.nsp)
            .arg(&self.cnmt)
            .args(flags)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn cli_hash_json_verifies_multichunk_nca_payload() {
    let bytes: Vec<u8> = (0..300_000).map(|index| (index % 251) as u8).collect();
    let fixture = Fixture::new(&bytes, &bytes);
    let output = fixture.audit(&["--hash", "--json"]);
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""hashes_match_supplied_cnmt":true"#));
    assert!(json.contains(r#""hash_status":"matched""#));
    assert!(json.contains(r#""hash_matched":1"#));
    assert!(json.contains(r#""hashes_verified":false"#));
}

#[test]
fn cli_hash_detects_same_length_mutation() {
    let fixture = Fixture::new(b"abd", b"abc");
    let output = fixture.audit(&["--hash", "--json"]);
    assert!(output.status.success());
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""complete_by_size":true"#));
    assert!(json.contains(r#""hash_status":"mismatched""#));
    assert!(json.contains(r#""hashes_match_supplied_cnmt":false"#));
    assert!(json.contains(r#""hash_mismatched":1"#));
}

#[test]
fn cli_default_does_not_hash_and_duplicate_flag_is_an_error() {
    let fixture = Fixture::new(b"abc", b"abc");
    let normal = fixture.audit(&["--json"]);
    assert!(normal.status.success());
    let json = String::from_utf8(normal.stdout).unwrap();
    assert!(json.contains(r#""hashing_requested":false"#));
    assert!(json.contains(r#""hash_status":"not_checked""#));

    let invalid = fixture.audit(&["--hash", "--hash", "--json"]);
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("package option"));
}

#[test]
fn cli_auto_discovers_plaintext_cnmt_and_hashes_without_extra_paths() {
    let fixture = Fixture::new(b"abc", b"abc");
    let output = fixture.audit_dir(&["--hash", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""hash_status":"matched""#));
    assert!(json.contains(r#""hashes_match_supplied_cnmt":true"#));
    assert!(json.contains(r#""external_evidence":[]"#));
    assert!(json.contains(r#""metadata_source":"external_cnmt_unverified""#));
}

#[test]
fn cli_auto_attaches_unverified_nacp_and_designated_main_nso() {
    let fixture = Fixture::new(b"abc", b"abc");
    let mut nacp = vec![0u8; 0x4000];
    nacp[..14].copy_from_slice(b"Synthetic Demo");
    fs::write(fixture.directory.join("control.nacp"), nacp).unwrap();
    let mut nso = vec![0u8; 0x100];
    nso[..4].copy_from_slice(b"NSO0");
    nso[0x40..0x48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    fs::write(fixture.directory.join("main.nso"), nso).unwrap();
    // There can be other libraries; do not select one as the main executable.
    fs::write(fixture.directory.join("sdk.nso"), b"unrelated").unwrap();
    let output = fixture.audit_dir(&["--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""title_american_english":"Synthetic Demo""#));
    assert!(json.contains(r#""atmosphere_cheat_build_id":"0102030405060708""#));
    assert!(json.contains(r#""linked_to_package":false"#));
    assert!(json.contains(r#""provenance":"user_designated_main_unverified""#));
}

#[test]
fn cli_auto_rejects_ambiguous_plaintext_cnmt_without_guessing() {
    let fixture = Fixture::new(b"abc", b"abc");
    fs::write(fixture.directory.join("other.cnmt"), b"not a CNMT").unwrap();
    let result = fixture.audit_dir(&["--json"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("multiple CNMT"));
    assert!(result.stdout.is_empty());
}

#[test]
fn cli_auto_rejects_explicit_sidecar_flags_and_unexpected_flags() {
    let fixture = Fixture::new(b"abc", b"abc");
    assert!(!fixture
        .audit_dir(&["--nacp", "somewhere.nacp"])
        .status
        .success());
    assert!(!fixture.audit_dir(&["--bogus"]).status.success());
}

fn make_hfs0(items: &[(&str, &[u8])]) -> Vec<u8> {
    let names: usize = items.iter().map(|(name, _)| name.len() + 1).sum();
    let mut out = b"HFS0".to_vec();
    out.extend((items.len() as u32).to_le_bytes());
    out.extend((names as u32).to_le_bytes());
    out.extend(0u32.to_le_bytes());
    let mut position = 0u64;
    let mut name_position = 0u32;
    for (name, bytes) in items {
        out.extend(position.to_le_bytes());
        out.extend((bytes.len() as u64).to_le_bytes());
        out.extend(name_position.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend([0u8; 40]);
        position += bytes.len() as u64;
        name_position += name.len() as u32 + 1;
    }
    for (name, _) in items {
        out.extend(name.as_bytes());
        out.push(0);
    }
    for (_, bytes) in items {
        out.extend(*bytes);
    }
    out
}

fn make_xci(nca_payload: &[u8]) -> Vec<u8> {
    let secure = make_hfs0(&[(NAME, nca_payload)]);
    let root = make_hfs0(&[("secure", &secure)]);
    let mut xci = vec![0u8; 0x200];
    xci[0x100..0x104].copy_from_slice(b"HEAD");
    xci[0x130..0x138].copy_from_slice(&0x200u64.to_le_bytes());
    xci[0x138..0x140].copy_from_slice(&0x50u64.to_le_bytes());
    xci.extend(root);
    xci
}

#[test]
fn cli_xci_secure_content_matches_supplied_cnmt_hash() {
    let fixture = Fixture::new(b"abc", b"abc");
    let xci = fixture.directory.join("synthetic.xci");
    fs::write(&xci, make_xci(b"abc")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("package")
        .arg("audit")
        .arg(&xci)
        .arg(&fixture.cnmt)
        .args(["--hash", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""package_format":"Switch XCI""#));
    assert!(json.contains(r#""hash_status":"matched""#));
    assert!(
        json.contains(r#""package_filename":"root/secure/11111111111111111111111111111111.nca""#)
    );
}

#[test]
fn cli_xci_audit_dir_discovers_external_cnmt() {
    let fixture = Fixture::new(b"abc", b"abc");
    let xci = fixture.directory.join("synthetic.xci");
    fs::write(&xci, make_xci(b"abc")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("package")
        .arg("audit-dir")
        .arg(&xci)
        .arg(&fixture.directory)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""package_format":"Switch XCI""#));
    assert!(json.contains(r#""hash_status":"not_checked""#));
    assert!(json.contains(r#""present":1"#));
}

fn sample_readable_nca(content_type: u8) -> Vec<u8> {
    let mut nca = vec![0u8; 0xc00];
    nca[0x200..0x204].copy_from_slice(b"NCA3");
    nca[0x205] = content_type;
    nca[0x208..0x210].copy_from_slice(&0xc00u64.to_le_bytes());
    nca[0x210..0x218].copy_from_slice(&0x0100123456789000u64.to_le_bytes());
    nca
}

#[test]
fn cli_plaintext_header_consistent_and_digest_matched() {
    let nca = sample_readable_nca(0);
    let fixture = Fixture::new(&nca, &nca);
    let output = fixture.audit(&["--headers", "--hash", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""headers_requested":true"#));
    assert!(json.contains(r#""header_status":"consistent""#));
    assert!(json.contains(r#""header_program_id":"0100123456789000""#));
    assert!(json.contains(r#""header_consistent":1"#));
    assert!(json.contains(r#""hash_status":"matched""#));
}

#[test]
fn cli_plaintext_header_mismatch_is_not_a_title_verification() {
    let nca = sample_readable_nca(2);
    let fixture = Fixture::new(&nca, &nca);
    let output = fixture.audit_dir(&["--headers", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""header_status":"type_mismatch""#));
    assert!(json.contains(r#""header_type_mismatch":1"#));
    assert!(json.contains(r#""hashing_requested":false"#));
    assert!(json.contains(r#""hashes_verified":false"#));
}

#[test]
fn cli_encrypted_header_does_not_create_a_false_program_id() {
    let opaque = vec![0x99u8; 0xc00];
    let fixture = Fixture::new(&opaque, &opaque);
    let output = fixture.audit(&["--headers", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""header_status":"unavailable""#));
    assert!(json.contains(r#""header_program_id":null"#));
    assert!(json.contains(r#""header_unavailable":1"#));
}
