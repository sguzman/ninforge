//! Synthetic CIA/TMD audit CLI checks, without game content or titlekeys.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
static SERIAL: AtomicUsize = AtomicUsize::new(0);

fn fixture(selected: bool) -> Vec<u8> {
    let cert = 0x80usize;
    let ticket = 0x100usize;
    let tmd = 0x140usize + 0x9c4 + 0x30;
    let content = 0x400usize;
    let mut raw = vec![0u8; 0x2020];
    raw[..4].copy_from_slice(&0x2020u32.to_le_bytes());
    raw[8..12].copy_from_slice(&(cert as u32).to_le_bytes());
    raw[12..16].copy_from_slice(&(ticket as u32).to_le_bytes());
    raw[16..20].copy_from_slice(&(tmd as u32).to_le_bytes());
    raw[24..32].copy_from_slice(&(content as u64).to_le_bytes());
    raw[0x20] = if selected {0x80} else {0x40};
    let mut offset = 0x2040usize;
    for length in [cert,ticket,tmd,content] {
        raw.resize(offset + length, 0);
        offset = (offset + length + 63) & !63;
    }
    let base = 0x2040 + cert + ticket;
    raw[base..base + 4].copy_from_slice(&0x0001_0004u32.to_be_bytes());
    raw[base + 0x140 + 0x4c..base + 0x140 + 0x54]
        .copy_from_slice(&0x4000000123456u64.to_be_bytes());
    raw[base + 0x140 + 0x9c..base + 0x140 + 0x9e]
        .copy_from_slice(&8u16.to_be_bytes());
    raw[base + 0x140 + 0x9e..base + 0x140 + 0xa0]
        .copy_from_slice(&1u16.to_be_bytes());
    let chunk = base + 0x140 + 0x9c4;
    raw[chunk..chunk + 4].copy_from_slice(&0xABCDu32.to_be_bytes());
    raw[chunk + 6..chunk + 8].copy_from_slice(&1u16.to_be_bytes());
    raw[chunk + 8..chunk + 16].copy_from_slice(&(content as u64).to_be_bytes());
    raw
}

struct Fixture { folder: PathBuf, path: PathBuf }
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let tick = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let folder = std::env::temp_dir().join(format!(
            "ninforge-cia-tmd-{}-{tick}-{}",
            std::process::id(), SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&folder).unwrap();
        let path = folder.join("synthetic.bin");
        fs::write(&path, bytes).unwrap();
        Self {folder,path}
    }
    fn audit(&self, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.args(["3ds","cia-audit"]).arg(&self.path);
        if json {cmd.arg("--json");}
        cmd.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {let _ = fs::remove_dir_all(&self.folder);}
}

#[test]
fn cia_tmd_audit_exposes_selected_record_and_id_without_verification_claims() {
    let raw = fixture(true);
    let f = Fixture::new(&raw);
    let output = f.audit(true);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""format":"cia_tmd_audit""#));
    assert!(json.contains(r#""title_version":8"#));
    assert!(json.contains(r#""selected_record_count":1"#));
    assert!(json.contains(r#""bitmap_entries_without_tmd_record":0"#));
    assert!(json.contains(r#""content_id":"0x0000ABCD""#));
    assert!(json.contains(r#""selected":true"#));
    assert!(json.contains(r#""cryptographic_integrity_verified":false"#));
    assert_eq!(fs::read(&f.path).unwrap(), raw);
}

#[test]
fn cia_tmd_does_not_assume_unselected_optional_content_is_present() {
    let f = Fixture::new(&fixture(false));
    let result = f.audit(true);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let json = String::from_utf8(result.stdout).unwrap();
    assert!(json.contains(r#""unselected_tmd_records":1"#));
    assert!(json.contains(r#""bitmap_entries_without_tmd_record":1"#));
    assert!(json.contains(r#""selected":false"#));
}

#[test]
fn cia_tmd_refuses_invalid_selected_size_without_touching_source() {
    let mut raw = fixture(true);
    let chunk = 0x2040 + 0x80 + 0x100 + 0x140 + 0x9c4;
    raw[chunk + 8..chunk + 16].copy_from_slice(&0x1000u64.to_be_bytes());
    let f = Fixture::new(&raw);
    let output = f.audit(true);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeds archive"));
    assert_eq!(fs::read(&f.path).unwrap(), raw);
}

#[test]
fn malformed_tmd_signature_type_fails_cleanly() {
    let mut raw = fixture(true);
    raw[0x2040 + 0x80 + 0x100..0x2040 + 0x80 + 0x104].fill(0);
    let f = Fixture::new(&raw);
    let result = f.audit(true);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("signature type unsupported"));
}
