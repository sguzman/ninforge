//! End-to-end DS cartridge CRC tests with entirely fabricated headers and icons.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Temp {
    path: PathBuf,
    directory: PathBuf,
}
impl Temp {
    fn new(bytes: &[u8]) -> Self {
        let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ninforge-nds-crc-{}-{ns}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("fictional.nds");
        fs::write(&path, bytes).unwrap();
        Self { path, directory }
    }
    fn run(&self, command: &str, json: bool) -> Output {
        let mut cli = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cli.arg(command).arg(&self.path);
        if json { cli.arg("--json"); }
        cli.output().unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in bytes {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xa001 } else { crc >> 1 };
        }
    }
    crc
}

fn fixture(banner: bool) -> Vec<u8> {
    let mut rom = vec![0u8; if banner { 0x300 + 0x840 } else { 0x200 }];
    rom[12..16].copy_from_slice(b"DEMO");
    // Synthetic zeros plus two padding bytes yield valid expected 0xCF56 CRC.
    // These bytes do not contain the Nintendo logo artwork.
    rom[0x15a..0x15c].copy_from_slice(&[0x04, 0x68]);
    rom[0x15c..0x15e].copy_from_slice(&0xcf56u16.to_le_bytes());
    if banner {
        rom[0x68..0x6c].copy_from_slice(&0x300u32.to_le_bytes());
        rom[0x300..0x302].copy_from_slice(&1u16.to_le_bytes());
        rom[0x300 + 0x340..0x300 + 0x342].copy_from_slice(&('A' as u16).to_le_bytes());
        let crc = crc16(&rom[0x300 + 0x20..0x300 + 0x840]);
        rom[0x302..0x304].copy_from_slice(&crc.to_le_bytes());
    }
    let header_crc = crc16(&rom[..0x15e]);
    rom[0x15e..0x160].copy_from_slice(&header_crc.to_le_bytes());
    rom
}

#[test]
fn valid_synthetic_header_reports_both_crc_values_and_verifies() {
    let data = fixture(false);
    assert_eq!(crc16(&data[0xc0..0x15c]), 0xcf56);
    let t = Temp::new(&data);
    let info = t.run("info", true);
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""nds_logo_crc_valid":"true""#));
    assert!(json.contains(r#""nds_header_crc_valid":"true""#));
    assert!(json.contains(r#""nds_logo_crc_calculated":"0xCF56""#));
    let verify = t.run("verify", false);
    assert!(verify.status.success(), "{}", String::from_utf8_lossy(&verify.stderr));
    assert!(String::from_utf8(verify.stdout).unwrap().contains("CRC-16 checks are valid"));
}

#[test]
fn edited_header_still_inspects_but_verify_fails() {
    let mut rom = fixture(false);
    rom[0x20] ^= 1;
    let t = Temp::new(&rom);
    let info = t.run("info", true);
    assert!(info.status.success());
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""nds_logo_crc_valid":"true""#));
    assert!(json.contains(r#""nds_header_crc_valid":"false""#));
    let verify = t.run("verify", false);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("header CRC-16"));
}

#[test]
fn edited_logo_is_detected_even_after_recomputing_header_crc() {
    let mut rom = fixture(false);
    rom[0xc0] ^= 1;
    let actual_header_crc = crc16(&rom[..0x15e]);
    rom[0x15e..0x160].copy_from_slice(&actual_header_crc.to_le_bytes());
    let t = Temp::new(&rom);
    let info = t.run("info", true);
    assert!(info.status.success());
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""nds_logo_crc_valid":"false""#));
    assert!(json.contains(r#""nds_header_crc_valid":"true""#));
    let verify = t.run("verify", false);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("logo CRC-16"));
}

#[test]
fn optional_banner_crc_fails_verification_without_blocking_inspection() {
    let original = fixture(true);
    let valid = Temp::new(&original);
    assert!(valid.run("verify", false).status.success());
    let mut rom = original;
    rom[0x300 + 0x340] ^= 1;
    let t = Temp::new(&rom);
    let info = t.run("info", true);
    assert!(info.status.success());
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""nds_header_crc_valid":"true""#));
    assert!(json.contains(r#""banner_crc_all_valid":"false""#));
    let verify = t.run("verify", false);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("banner CRC-16"));
}
