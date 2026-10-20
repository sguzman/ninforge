//! CIA ticket/TMD consistency CLI tests, using fabricated archive metadata.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn image() -> Vec<u8> {
    let cert = 0x80usize;
    let ticket = 0x350usize;
    let tmd = 0x140usize + 0x9c4 + 0x30;
    let content = 0x400usize;
    let mut raw = vec![0u8; 0x2020];
    raw[..4].copy_from_slice(&0x2020u32.to_le_bytes());
    raw[8..12].copy_from_slice(&(cert as u32).to_le_bytes());
    raw[12..16].copy_from_slice(&(ticket as u32).to_le_bytes());
    raw[16..20].copy_from_slice(&(tmd as u32).to_le_bytes());
    raw[24..32].copy_from_slice(&(content as u64).to_le_bytes());
    raw[0x20] = 0x80;
    let mut cursor = 0x2040usize;
    for amount in [cert, ticket, tmd, content] {
        raw.resize(cursor + amount, 0);
        cursor = (cursor + amount + 63) & !63;
    }
    let tkt = 0x2040 + cert;
    let tkt_data = tkt + 0x140;
    raw[tkt..tkt + 4].copy_from_slice(&0x0001_0004u32.to_be_bytes());
    raw[tkt_data + 0x7c] = 1;
    raw[tkt_data + 0x9c..tkt_data + 0xa4].copy_from_slice(&0x4000000123456u64.to_be_bytes());
    raw[tkt_data + 0xa6..tkt_data + 0xa8].copy_from_slice(&8u16.to_be_bytes());
    let tmd_header = 0x2040 + cert + 0x380 + 0x140;
    raw[tmd_header - 0x140..tmd_header - 0x13c].copy_from_slice(&0x0001_0004u32.to_be_bytes());
    raw[tmd_header + 0x4c..tmd_header + 0x54].copy_from_slice(&0x4000000123456u64.to_be_bytes());
    raw[tmd_header + 0x9c..tmd_header + 0x9e].copy_from_slice(&8u16.to_be_bytes());
    raw[tmd_header + 0x9e..tmd_header + 0xa0].copy_from_slice(&1u16.to_be_bytes());
    let chunk = tmd_header + 0x9c4;
    raw[chunk..chunk + 4].copy_from_slice(&0xABCDu32.to_be_bytes());
    raw[chunk + 8..chunk + 16].copy_from_slice(&(content as u64).to_be_bytes());
    raw
}

struct Fixture {
    directory: PathBuf,
    file: PathBuf,
}
impl Fixture {
    fn new(data: &[u8]) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ninforge-cia-ticket-{}-{now}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let file = directory.join("fabricated.bin");
        fs::write(&file, data).unwrap();
        Self { directory, file }
    }
    fn check(&self, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.args(["3ds", "cia-ticket"]).arg(&self.file);
        if json {
            cmd.arg("--json");
        }
        cmd.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn title_ids_match_without_ticket_decryption_or_verification_claim() {
    let raw = image();
    let fixture = Fixture::new(&raw);
    let result = fixture.check(true);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json = String::from_utf8(result.stdout).unwrap();
    assert!(json.contains(r#""format":"cia_ticket_check""#));
    assert!(json.contains(r#""title_id_matches":true"#));
    assert!(json.contains(r#""title_version_matches":true"#));
    assert!(json.contains(r#""ticket_data_version":1"#));
    assert!(json.contains(r#""titlekey_decrypted":false"#));
    assert!(!json.to_ascii_lowercase().contains("titlekey_bytes"));
    assert_eq!(fs::read(&fixture.file).unwrap(), raw);
}

#[test]
fn mismatched_ticket_id_is_reported_not_hidden() {
    let mut raw = image();
    let field = 0x2040 + 0x80 + 0x140 + 0x9c;
    raw[field..field + 8].copy_from_slice(&0x4000000555555u64.to_be_bytes());
    let fixture = Fixture::new(&raw);
    let result = fixture.check(true);
    assert!(result.status.success());
    let json = String::from_utf8(result.stdout).unwrap();
    assert!(json.contains(r#""title_id_matches":false"#));
    assert!(json.contains(r#""title_version_matches":true"#));
}

#[test]
fn old_ticket_format_rejected_by_v1_only_reader() {
    let mut raw = image();
    raw[0x2040 + 0x80 + 0x140 + 0x7c] = 0;
    let fixture = Fixture::new(&raw);
    let result = fixture.check(true);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("v1"));
}
