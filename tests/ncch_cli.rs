//! CLI regression tests for standalone 3DS NCCH header metadata.
//! Fixtures contain no actual Nintendo logos, keys, signatures or game data.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn fixture() -> Vec<u8> {
    let mut data = vec![0u8; 0x3000];
    data[0x100..0x104].copy_from_slice(b"NCCH");
    data[0x104..0x108].copy_from_slice(&24u32.to_le_bytes());
    data[0x108..0x110].copy_from_slice(&0x123u64.to_le_bytes());
    data[0x118..0x120].copy_from_slice(&0x456u64.to_le_bytes());
    data[0x150..0x158].copy_from_slice(b"CTR-DEMO");
    data[0x18c] = 1;
    data[0x18d] = 1;
    data[0x1a0..0x1a4].copy_from_slice(&2u32.to_le_bytes());
    data[0x1a4..0x1a8].copy_from_slice(&4u32.to_le_bytes());
    data[0x1b0..0x1b4].copy_from_slice(&6u32.to_le_bytes());
    data[0x1b4..0x1b8].copy_from_slice(&8u32.to_le_bytes());
    data
}
struct Fixture { dir: PathBuf, path: PathBuf }
impl Fixture {
    fn new(image: &[u8]) -> Self {
        let tick = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-ncch-test-{}-{tick}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("sample.bin");
        fs::write(&path, image).unwrap();
        Self { dir, path }
    }
    fn run(&self, command: &str, json: bool) -> Output {
        let mut cli = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cli.arg(command).arg(&self.path);
        if json { cli.arg("--json"); }
        cli.output().unwrap()
    }
    fn regions(&self, json: bool) -> Output {
        let mut cli = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cli.args(["3ds", "ncch-regions"]).arg(&self.path);
        if json { cli.arg("--json"); }
        cli.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.dir); }
}

#[test]
fn info_and_regions_list_declared_ncch_spans_without_decrypting() {
    let raw = fixture();
    let file = Fixture::new(&raw);
    let info = file.run("info", true);
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""format":"Nintendo 3DS NCCH""#));
    assert!(json.contains(r#""product_code":"CTR-DEMO""#));
    assert!(json.contains(r#""region_count":"2""#));
    assert!(json.contains(r#""cryptographic_integrity_verified":"false""#));
    let listing = file.regions(true);
    assert!(listing.status.success(), "{}", String::from_utf8_lossy(&listing.stderr));
    let json = String::from_utf8(listing.stdout).unwrap();
    assert!(json.contains(r#""format":"ncch_regions""#));
    assert!(json.contains(r#""name":"exefs","offset_bytes":1024,"size_bytes":2048"#));
    assert!(json.contains(r#""name":"romfs","offset_bytes":3072,"size_bytes":4096"#));
    assert!(json.contains(r#""cryptographic_integrity_verified":false"#));
    let checked = file.run("verify", false);
    assert!(checked.status.success());
    assert!(String::from_utf8(checked.stdout).unwrap().contains("content hashes NOT verified"));
    assert_eq!(fs::read(&file.path).unwrap(), raw);
}

#[test]
fn broken_region_bounds_fail_cleanly_while_preserving_source_bytes() {
    let mut raw = fixture();
    raw[0x1b4..0x1b8].copy_from_slice(&30u32.to_le_bytes());
    let file = Fixture::new(&raw);
    let listing = file.regions(true);
    assert!(!listing.status.success());
    assert!(listing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&listing.stderr).contains("outside"));
    assert!(!file.run("verify", false).status.success());
    assert_eq!(fs::read(&file.path).unwrap(), raw);
}

#[test]
fn reject_truncated_and_wrong_format_without_panics() {
    let raw = fixture();
    let file = Fixture::new(&raw[..0x110]);
    let info = file.run("info", true);
    assert!(!info.status.success());
    assert!(String::from_utf8_lossy(&info.stderr).contains("NCCH header truncated"));
    let bad = Fixture::new(&vec![0u8; 0x200]);
    let res = bad.regions(true);
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("requires a standalone NCCH"));
}
