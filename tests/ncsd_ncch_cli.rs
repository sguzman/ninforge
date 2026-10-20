//! NCSD-to-NCCH consistency tests: no game bytes or secrets.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn image() -> Vec<u8> {
    let mut data = vec![0u8; 0x5000];
    data[0x100..0x104].copy_from_slice(b"NCSD");
    data[0x104..0x108].copy_from_slice(&40u32.to_le_bytes());
    data[0x108..0x110].copy_from_slice(&0xABCDu64.to_le_bytes());
    data[0x110] = 1;
    data[0x120..0x124].copy_from_slice(&1u32.to_le_bytes());
    data[0x124..0x128].copy_from_slice(&24u32.to_le_bytes());
    data[0x190..0x198].copy_from_slice(&0x1234u64.to_le_bytes());
    data[0x300..0x304].copy_from_slice(b"NCCH");
    data[0x304..0x308].copy_from_slice(&16u32.to_le_bytes());
    data[0x308..0x310].copy_from_slice(&0x1234u64.to_le_bytes());
    data[0x318..0x320].copy_from_slice(&0x5678u64.to_le_bytes());
    data[0x350..0x358].copy_from_slice(b"CTR-DEMO");
    data
}

struct Fixture { dir: PathBuf, file: PathBuf }
impl Fixture {
    fn new(data: &[u8]) -> Self {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-crosscheck-{}-{ts}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let file = dir.join("input.bin");
        fs::write(&file, data).unwrap();
        Self {dir,file}
    }
    fn crosscheck(&self, json: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        command.args(["3ds","crosscheck"]).arg(&self.file);
        if json {command.arg("--json");}
        command.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {let _ = fs::remove_dir_all(&self.dir);}
}
#[test]
fn matching_ncch_claims_can_be_examined_without_decryption() {
    let raw = image();
    let f = Fixture::new(&raw);
    let report = f.crosscheck(true);
    assert!(report.status.success(), "{}", String::from_utf8_lossy(&report.stderr));
    let json = String::from_utf8(report.stdout).unwrap();
    assert!(json.contains(r#""format":"ncsd_ncch_crosscheck""#));
    assert!(json.contains(r#""checked_partitions":1"#));
    assert!(json.contains(r#""matching_partition_ids":1"#));
    assert!(json.contains(r#""id_matches":true"#));
    assert!(json.contains(r#""product_code":"CTR-DEMO""#));
    assert!(json.contains(r#""signatures_verified":false"#));
    assert_eq!(fs::read(&f.file).unwrap(), raw);
}

#[test]
fn mismatched_ids_are_observed_not_mistaken_for_signature_failure() {
    let mut raw = image();
    raw[0x190..0x198].copy_from_slice(&0x9999u64.to_le_bytes());
    let f = Fixture::new(&raw);
    let report = f.crosscheck(true);
    assert!(report.status.success());
    let json = String::from_utf8(report.stdout).unwrap();
    assert!(json.contains(r#""compared_partition_ids":1"#));
    assert!(json.contains(r#""matching_partition_ids":0"#));
    assert!(json.contains(r#""id_matches":false"#));
}

#[test]
fn corrupt_inner_header_is_structural_failure_without_output() {
    let mut raw = image();
    raw[0x300] = 0;
    let f = Fixture::new(&raw);
    let result = f.crosscheck(true);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("NCCH"));
}

#[test]
fn inner_claim_exceeding_outer_partition_is_rejected() {
    let mut raw = image();
    raw[0x304..0x308].copy_from_slice(&30u32.to_le_bytes());
    let f = Fixture::new(&raw);
    let result = f.crosscheck(true);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("exceeds enclosing"));
    assert_eq!(fs::read(&f.file).unwrap(), raw);
}
