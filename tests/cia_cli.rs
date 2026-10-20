//! Synthetic CIA archive CLI checks: structure only, no game contents.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn fixture(meta: bool) -> Vec<u8> {
    let mut raw = vec![0u8; 0x2020];
    raw[..4].copy_from_slice(&0x2020u32.to_le_bytes());
    raw[8..12].copy_from_slice(&0x90u32.to_le_bytes());
    raw[12..16].copy_from_slice(&0x120u32.to_le_bytes());
    raw[16..20].copy_from_slice(&0xc4u32.to_le_bytes());
    raw[20..24].copy_from_slice(&(if meta {0x200u32} else {0}).to_le_bytes());
    raw[24..32].copy_from_slice(&0x301u64.to_le_bytes());
    raw[0x20] = 0x80;
    let mut cursor = 0x2040usize;
    for amount in [0x90, 0x120, 0xc4, 0x301, if meta {0x200} else {0}] {
        if amount == 0 {continue;}
        raw.resize(cursor + amount, 0);
        cursor = (cursor + amount + 63) & !63;
    }
    raw
}
struct Fixture { dir: PathBuf, file: PathBuf }
impl Fixture {
    fn new(data: &[u8]) -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-cia-cli-{}-{stamp}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let file = dir.join("fixture.bin");
        fs::write(&file, data).unwrap();
        Self {dir, file}
    }
    fn exec(&self, name: &str, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.arg(name).arg(&self.file);
        if json {cmd.arg("--json");}
        cmd.output().unwrap()
    }
    fn sections(&self, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.args(["3ds","cia-sections"]).arg(&self.file);
        if json {cmd.arg("--json");}
        cmd.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {let _ = fs::remove_dir_all(&self.dir);}
}

#[test]
fn cia_info_and_sections_are_read_only_and_bounded() {
    let raw = fixture(true);
    let f = Fixture::new(&raw);
    let info = f.exec("info", true);
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let text = String::from_utf8(info.stdout).unwrap();
    assert!(text.contains(r#""format":"Nintendo 3DS CIA""#));
    assert!(text.contains(r#""content_index_set_bits":"1""#));
    assert!(text.contains(r#""section_count":"5""#));
    let sections = f.sections(true);
    assert!(sections.status.success(), "{}", String::from_utf8_lossy(&sections.stderr));
    let json = String::from_utf8(sections.stdout).unwrap();
    assert!(json.contains(r#""format":"cia_sections""#));
    assert!(json.contains(r#""name":"certificates","offset_bytes":8256,"size_bytes":144"#));
    assert!(json.contains(r#""name":"ticket","offset_bytes":8448,"size_bytes":288"#));
    assert!(json.contains(r#""name":"content""#));
    assert!(json.contains(r#""cryptographic_integrity_verified":false"#));
    let verify = f.exec("verify", false);
    assert!(verify.status.success(), "{}", String::from_utf8_lossy(&verify.stderr));
    assert!(String::from_utf8(verify.stdout).unwrap().contains("NOT verified"));
    assert_eq!(fs::read(&f.file).unwrap(), raw);
}

#[test]
fn cia_without_meta_is_supported() {
    let f = Fixture::new(&fixture(false));
    let out = f.sections(true);
    assert!(out.status.success());
    let json = String::from_utf8(out.stdout).unwrap();
    assert!(json.contains(r#""name":"content""#));
    assert!(!json.contains(r#""name":"meta""#));
}

#[test]
fn malformed_section_bounds_are_rejected_without_writes() {
    let mut bytes = fixture(false);
    bytes[24..32].copy_from_slice(&(u64::MAX).to_le_bytes());
    let f = Fixture::new(&bytes);
    let out = f.sections(true);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(fs::read(&f.file).unwrap(), bytes);
}

#[test]
fn unknown_binary_cannot_be_misrepresented_as_valid_cia() {
    let f = Fixture::new(&vec![0u8; 0x3000]);
    let info = f.exec("info", true);
    assert!(info.status.success());
    assert!(String::from_utf8(info.stdout).unwrap().contains(r#""format":"Unknown""#));
    assert!(!f.sections(true).status.success());
}
