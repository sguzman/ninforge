//! End-to-end Game Boy / Game Boy Color metadata and strict checks.
//! The fixtures contain only synthetic code/data and a header recognition
//! sequence; no playable commercial ROMs, saves or keys.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const LOGO: [u8; 48] = [
    0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0c, 0x00, 0x0d,
    0x00, 0x08, 0x11, 0x1f, 0x88, 0x89, 0x00, 0x0e, 0xdc, 0xcc, 0x6e, 0xe6, 0xdd, 0xdd, 0xd9, 0x99,
    0xbb, 0xbb, 0x67, 0x63, 0x6e, 0x0e, 0xec, 0xcc, 0xdd, 0xdc, 0x99, 0x9f, 0xbb, 0xb9, 0x33, 0x3e,
];

fn header_crc(rom: &[u8]) -> u8 {
    rom[0x134..0x14d]
        .iter().fold(0u8, |acc, byte| acc.wrapping_sub(*byte).wrapping_sub(1))
}
fn fix_checksums(rom: &mut [u8]) {
    rom[0x14d] = header_crc(rom);
    let sum = rom.iter().enumerate()
        .filter(|(i, _)| *i != 0x14e && *i != 0x14f)
        .fold(0u16, |sum, (_, byte)| sum.wrapping_add(u16::from(*byte)));
    rom[0x14e..0x150].copy_from_slice(&sum.to_be_bytes());
}
fn synthetic(color: bool) -> Vec<u8> {
    let mut rom = vec![0u8; 32 * 1024];
    rom[0x104..0x134].copy_from_slice(&LOGO);
    rom[0x134..0x13a].copy_from_slice(b"SYNTH!");
    rom[0x143] = if color { 0xc0 } else { 0x00 };
    rom[0x147] = 0x03; // MBC1+RAM+BATTERY
    rom[0x148] = 0x00; // 32 KiB
    rom[0x149] = 0x02; // 8 KiB
    rom[0x14b] = 0x33;
    rom[0x144..0x146].copy_from_slice(b"01");
    fix_checksums(&mut rom);
    rom
}
struct Fixture {
    dir: PathBuf,
    rom: PathBuf,
}
impl Fixture {
    fn new(rom: &[u8]) -> Self {
        let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-gb-metadata-{}-{ns}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        // Deliberately generic filename: recognition must come from the bytes.
        let path = dir.join("fixture.bin");
        fs::write(&path, rom).unwrap();
        Self { dir, rom: path }
    }
    fn run(&self, op: &str, json: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        command.arg(op).arg(&self.rom);
        if json { command.arg("--json"); }
        command.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.dir); }
}

#[test]
fn gb_color_header_metadata_and_full_verify() {
    let rom = synthetic(true);
    let t = Fixture::new(&rom);
    let info = t.run("info", true);
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let text = String::from_utf8(info.stdout).unwrap();
    assert!(text.contains(r#""format":"Game Boy Color""#));
    assert!(text.contains(r#""cgb_support":"required""#));
    assert!(text.contains(r#""cartridge_type_name":"mbc1_ram_battery""#));
    assert!(text.contains(r#""declared_rom_size_bytes":"32768""#));
    assert!(text.contains(r#""declared_external_ram_size_bytes":"8192""#));
    assert!(text.contains(r#""header_checksum_valid":"true""#));
    assert!(text.contains(r#""declared_rom_size_matches_file":"true""#));
    let verify = t.run("verify", false);
    assert!(verify.status.success(), "{}", String::from_utf8_lossy(&verify.stderr));
    assert!(String::from_utf8(verify.stdout).unwrap().contains("global checksum match"));
}

#[test]
fn altered_header_is_still_identified_but_verify_reports_error() {
    let mut rom = synthetic(false);
    rom[0x14c] ^= 1;
    let t = Fixture::new(&rom);
    let info = t.run("info", true);
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let text = String::from_utf8(info.stdout).unwrap();
    assert!(text.contains(r#""format":"Game Boy""#));
    assert!(text.contains(r#""header_checksum_valid":"false""#));
    let verify = t.run("verify", false);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("header checksum mismatch"));
}

#[test]
fn changed_payload_is_detected_by_streamed_global_checksum() {
    let mut rom = synthetic(false);
    rom[0x2000] ^= 1;
    let t = Fixture::new(&rom);
    assert!(t.run("info", true).status.success());
    let verify = t.run("verify", false);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("global ROM checksum mismatch"));
}

#[test]
fn declared_rom_size_must_match_actual_file_for_verify() {
    let mut rom = synthetic(false);
    rom[0x148] = 1; // declares 64 KiB, actual 32 KiB
    fix_checksums(&mut rom);
    let t = Fixture::new(&rom);
    let info = t.run("info", true);
    assert!(info.status.success());
    assert!(String::from_utf8(info.stdout).unwrap()
        .contains(r#""declared_rom_size_matches_file":"false""#));
    let verify = t.run("verify", false);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("declared ROM size"));
}

#[test]
fn unknown_capacity_does_not_become_a_fake_size() {
    let mut rom = synthetic(false);
    rom[0x148] = 0xff;
    rom[0x149] = 1; // historically ambiguous RAM capacity
    fix_checksums(&mut rom);
    let t = Fixture::new(&rom);
    let info = t.run("info", true);
    assert!(info.status.success());
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""declared_rom_size_known":"false""#));
    assert!(json.contains(r#""declared_external_ram_size_known":"false""#));
    assert!(!t.run("verify", false).status.success());
}

#[test]
fn verify_fails_on_truncated_rom_without_modifying_source() {
    let rom = synthetic(false);
    let t = Fixture::new(&rom[..0x180]);
    assert!(t.run("info", true).status.success());
    let verify = t.run("verify", false);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("supported verification bounds"));
    assert_eq!(fs::read(&t.rom).unwrap(), &rom[..0x180]);
}
