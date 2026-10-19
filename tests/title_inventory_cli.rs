//! Black-box CLI coverage for deterministic version-aware title inventory.
//! All files below contain only synthetic fictional Switch metadata.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SERIAL: AtomicUsize = AtomicUsize::new(0);
const APP: u64 = 0x0100_1234_5678_8000;
const PATCH: u64 = 0x0100_1234_5678_8800;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-inventory-cli-{}-{now}-{}", std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn bundle(&self, name: &str, title: u64, version: u32, kind: u8,
        related: u64, digest_marker: u8) -> PathBuf {
        let directory = self.0.join(name);
        fs::create_dir(&directory).unwrap();
        let mut cnmt = vec![0u8;0x20+0x10+0x20];
        cnmt[..8].copy_from_slice(&title.to_le_bytes());
        cnmt[8..12].copy_from_slice(&version.to_le_bytes());
        cnmt[0xc] = kind;
        cnmt[0xe..0x10].copy_from_slice(&0x10u16.to_le_bytes());
        cnmt[0x20..0x28].copy_from_slice(&related.to_le_bytes());
        cnmt[0x4f] = digest_marker;
        fs::write(directory.join("metadata.cnmt"), cnmt).unwrap();
        directory
    }
    fn run(&self, flags: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ninforge"))
            .arg("titles").arg("inventory").arg(&self.0).args(flags)
            .output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

#[test]
fn cli_json_groups_versions_and_reports_highest_locally_supplied_patch() {
    let t = Fixture::new();
    t.bundle("base", APP, 0, 0x80, PATCH, 1);
    t.bundle("patch-old", PATCH, 65536, 0x81, APP, 1);
    t.bundle("patch-new", PATCH, 131072, 0x81, APP, 2);
    let out = t.run(&["--json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let json = String::from_utf8(out.stdout).unwrap();
    assert!(json.contains(r#""schema_version":1"#));
    assert!(json.contains(r#""bundles_scanned":3"#));
    assert!(json.contains(r#""application_groups":1"#));
    assert!(json.contains(r#""latest_application_version":0"#));
    assert!(json.contains(r#""latest_patch_version":131072"#));
    assert!(json.contains(r#""source":"external_plaintext_metadata_unverified""#));
    assert!(json.contains(r#""grouping_basis":"cnmt_application_reference_unverified""#));
    assert!(json.contains(r#""nacp_nso_link_verified":false"#));
}

#[test]
fn cli_preserves_unverified_display_version_and_cheat_build_id() {
    let t = Fixture::new();
    let directory=t.bundle("base",APP,0,0x80,PATCH,1);
    let mut nacp=vec![0u8;0x4000];
    nacp[..13].copy_from_slice(b"Homebrew Demo");
    nacp[0x3060..0x3065].copy_from_slice(b"1.2.3");
    fs::write(directory.join("control.nacp"),nacp).unwrap();
    let mut nso=vec![0u8;0x100];
    nso[..4].copy_from_slice(b"NSO0");
    nso[0x40..0x48].copy_from_slice(&[1,2,3,4,5,6,7,8]);
    fs::write(directory.join("main.nso"),nso).unwrap();
    let out=t.run(&["--json"]);
    assert!(out.status.success(),"{}",String::from_utf8_lossy(&out.stderr));
    let json=String::from_utf8(out.stdout).unwrap();
    assert!(json.contains(r#""display_title":"Homebrew Demo""#));
    assert!(json.contains(r#""display_version":"1.2.3""#));
    assert!(json.contains(r#""version":0"#));
    assert!(json.contains(r#""atmosphere_cheat_build_id":"0102030405060708""#));
    assert!(json.contains(r#""nacp_nso_link_verified":false"#));
}

#[test]
fn cli_refuses_confusing_duplicate_bundles_and_invalid_arguments() {
    let t = Fixture::new();
    t.bundle("patch-a",PATCH,65536,0x81,APP,1);
    t.bundle("patch-b",PATCH,65536,0x81,APP,2);
    let out=t.run(&["--json"]);
    assert!(out.status.success());
    let json=String::from_utf8(out.stdout).unwrap();
    assert!(json.contains(r#""version_collisions":1"#));
    assert!(json.contains(r#""conflicting_content":true"#));
    assert!(json.contains(r#""bundles":["patch-a","patch-b"]"#));
    assert!(!t.run(&["--unexpected"]).status.success());
    fs::create_dir(t.0.join("empty")).unwrap();
    assert!(!t.run(&["--json"]).status.success());
}
