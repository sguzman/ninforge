//! Black-box GBA cartridge header checking with entirely synthetic metadata.
//! The synthetic logo area only matches a weak additive sum, NOT the Nintendo
//! logo bitmap. No commercial ROM bytes or saves are bundled.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn complement(header: &[u8]) -> u8 {
    header[0xa0..0xbd]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_sub(*byte))
        .wrapping_sub(0x19)
}
fn synthetic() -> Vec<u8> {
    let mut data = vec![0u8; 2048];
    data[0x04..0xa0].fill(0x7b);
    data[0x04] = 0xa2; // weak sum 0x4B1B, no Nintendo artwork
    data[0xa0..0xa4].copy_from_slice(b"DEMO");
    data[0xac..0xb0].copy_from_slice(b"ABCD");
    data[0xb0..0xb2].copy_from_slice(b"01");
    data[0xb2] = 0x96;
    data[0xbc] = 2;
    data[0xbd] = complement(&data);
    data
}

struct Fixture {
    root: PathBuf,
    file: PathBuf,
}
impl Fixture {
    fn new(data: &[u8]) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ninforge-gba-header-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        let file = root.join("fictional.bin");
        fs::write(&file, data).unwrap();
        Self { root, file }
    }
    fn run(&self, verb: &str, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.arg(verb).arg(&self.file);
        if json {
            cmd.arg("--json");
        }
        cmd.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn gba_info_and_verify_report_limited_header_checks() {
    let original = synthetic();
    let file = Fixture::new(&original);
    let info = file.run("info", true);
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let text = String::from_utf8(info.stdout).unwrap();
    assert!(text.contains(r#""format":"Game Boy Advance""#));
    assert!(text.contains(r#""header_checksum_valid":"true""#));
    assert!(text.contains(r#""logo_weak_sum_matches_reference":"true""#));
    assert!(text.contains(r#""logo_bytes_authenticated":"false""#));
    assert!(text.contains(r#""declared_rom_size_available":"false""#));
    let checked = file.run("verify", false);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8(checked.stdout)
        .unwrap()
        .contains("header-only"));
    assert_eq!(fs::read(&file.file).unwrap(), original);
}

#[test]
fn gba_damaged_complement_remains_inspectable_but_verify_fails() {
    let mut raw = synthetic();
    raw[0xbc] ^= 1;
    let file = Fixture::new(&raw);
    let info = file.run("info", true);
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let text = String::from_utf8(info.stdout).unwrap();
    assert!(text.contains(r#""header_checksum_valid":"false""#));
    let verify = file.run("verify", false);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("complement checksum"));
}

#[test]
fn gba_logo_weak_sum_corruption_is_independent_of_header_fields() {
    let mut raw = synthetic();
    raw[0x40] ^= 1;
    let file = Fixture::new(&raw);
    let info = file.run("info", true);
    assert!(info.status.success());
    let text = String::from_utf8(info.stdout).unwrap();
    assert!(text.contains(r#""header_checksum_valid":"true""#));
    assert!(text.contains(r#""logo_weak_sum_matches_reference":"false""#));
    assert!(!file.run("verify", false).status.success());
}

#[test]
fn gba_header_verification_does_not_claim_full_rom_integrity() {
    let mut raw = synthetic();
    raw[1024] = 0xff; // outside the GBA header, intentionally unchecked
    let file = Fixture::new(&raw);
    let verify = file.run("verify", false);
    assert!(verify.status.success());
    let text = String::from_utf8(verify.stdout).unwrap();
    assert!(text.contains("no full-ROM checksum"));
    assert_eq!(fs::read(&file.file).unwrap(), raw);
}

#[test]
fn truncated_gba_file_never_causes_parser_panic() {
    let raw = synthetic();
    let file = Fixture::new(&raw[..0xbe]);
    let info = file.run("info", true);
    assert!(info.status.success());
    assert!(String::from_utf8(info.stdout)
        .unwrap()
        .contains(r#""format":"Unknown""#));
    assert!(!file.run("verify", false).status.success());
}
