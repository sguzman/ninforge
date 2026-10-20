//! CLI tests of synthetic NDS banner titles, checksums and extraction.
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture { dir: PathBuf, rom: PathBuf }
impl Fixture {
    fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-nds-banner-{}-{now}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let rom = dir.join("demo.nds");
        fs::write(&rom, synthetic_rom()).unwrap();
        Self { dir, rom }
    }
    fn cmd(&self, command: &str) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_ninforge"))
            .arg(command).arg(&self.rom).output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.dir); }
}

fn crc16(data: &[u8]) -> u16 {
    let mut value = 0xffffu16;
    for &byte in data {
        value ^= u16::from(byte);
        for _ in 0..8 {
            value = if value & 1 != 0 { (value >> 1) ^ 0xa001 } else { value >> 1 };
        }
    }
    value
}
fn synthetic_rom() -> Vec<u8> {
    let mut rom = vec![0u8; 0x300 + 0x840];
    rom[12..16].copy_from_slice(b"DEMO");
    rom[0x15c..0x15e].copy_from_slice(&[0x56, 0xcf]);
    rom[0x68..0x6c].copy_from_slice(&0x300u32.to_le_bytes());
    let banner = &mut rom[0x300..];
    banner[..2].copy_from_slice(&1u16.to_le_bytes());
    for (i, code) in "Example DS".encode_utf16().enumerate() {
        banner[0x340+i*2..0x342+i*2].copy_from_slice(&code.to_le_bytes());
    }
    let checksum = crc16(&banner[0x20..0x840]);
    banner[2..4].copy_from_slice(&checksum.to_le_bytes());
    rom
}

#[test]
fn banner_title_and_crc_are_reported_and_listed() {
    let fixture = Fixture::new();
    let info = Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("info").arg(&fixture.rom).arg("--json").output().unwrap();
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""banner_title_english":"Example DS""#));
    assert!(json.contains(r#""banner_crc_all_valid":"true""#));
    let listing_json = Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("list").arg(&fixture.rom).arg("--json").output().unwrap();
    assert!(listing_json.status.success());
    assert!(String::from_utf8(listing_json.stdout).unwrap()
        .contains(r#""name":"banner.bin""#));
    let list = fixture.cmd("list");
    assert!(list.status.success());
    assert!(String::from_utf8(list.stdout).unwrap().contains("banner.bin"));
}

#[test]
fn banner_extract_is_bounded_and_no_overwrite() {
    let fixture = Fixture::new();
    let output = fixture.dir.join("banner.dat");
    let extract = || Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("extract").arg(&fixture.rom).arg("banner.bin").arg(&output)
        .output().unwrap();
    let result = extract();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let bytes = fs::read(&output).unwrap();
    assert_eq!(bytes.len(), 0x840);
    assert_eq!(&bytes[..2], &1u16.to_le_bytes());
    assert!(!extract().status.success());
    assert_eq!(fs::read(&output).unwrap(), bytes);
}

#[test]
fn corrupt_banner_reports_failed_crc_without_hiding_metadata() {
    let fixture = Fixture::new();
    let mut rom = fs::read(&fixture.rom).unwrap();
    rom[0x300 + 0x340] ^= 1;
    fs::write(&fixture.rom, rom).unwrap();
    let result = fixture.cmd("info");
    assert!(result.status.success());
    assert!(String::from_utf8(result.stdout).unwrap().contains("banner_crc_all_valid: false"));
}

#[test]
fn unknown_banner_version_rejected() {
    let fixture = Fixture::new();
    let mut rom = fs::read(&fixture.rom).unwrap();
    rom[0x300..0x302].copy_from_slice(&4u16.to_le_bytes());
    fs::write(&fixture.rom, rom).unwrap();
    let result = fixture.cmd("info");
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsupported DS banner version"));
}
