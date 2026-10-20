//! Synthetic 3DS NCSD/CCI partition-index end-to-end tests.
//! No proprietary game image, RSA signature, encrypted content or key.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn synthetic() -> Vec<u8> {
    let mut raw = vec![0u8; 8192];
    raw[0x100..0x104].copy_from_slice(b"NCSD");
    raw[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
    raw[0x108..0x110].copy_from_slice(&0x12345678u64.to_le_bytes());
    raw[0x110] = 1;
    raw[0x118] = 2;
    raw[0x120..0x124].copy_from_slice(&1u32.to_le_bytes());
    raw[0x124..0x128].copy_from_slice(&3u32.to_le_bytes());
    raw[0x128..0x12c].copy_from_slice(&4u32.to_le_bytes());
    raw[0x12c..0x130].copy_from_slice(&2u32.to_le_bytes());
    raw[0x18d] = 1;
    raw
}
struct Fixture {
    directory: PathBuf,
    file: PathBuf,
}
impl Fixture {
    fn new(data: &[u8]) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ninforge-ncsd-{}-{now}-{}",
            std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        let file = directory.join("synthetic.bin");
        fs::write(&file, data).unwrap();
        Self { directory, file }
    }
    fn run(&self, command: &str, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.arg(command).arg(&self.file);
        if json { cmd.arg("--json"); }
        cmd.output().unwrap()
    }
    fn partitions(&self, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.args(["3ds", "partitions"]).arg(&self.file);
        if json { cmd.arg("--json"); }
        cmd.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.directory); }
}

#[test]
fn inspect_and_list_eight_slot_ncsd_partition_table() {
    let image = synthetic();
    let file = Fixture::new(&image);
    let info = file.run("info", true);
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""format":"Nintendo 3DS NCSD""#));
    assert!(json.contains(r#""declared_media_size_bytes":"8192""#));
    assert!(json.contains(r#""partition_count":"2""#));
    assert!(json.contains(r#""signature_verified":"false""#));
    let listing = file.partitions(true);
    assert!(listing.status.success(), "{}", String::from_utf8_lossy(&listing.stderr));
    let json = String::from_utf8(listing.stdout).unwrap();
    assert!(json.contains(r#""format":"ncsd_partitions""#));
    assert!(json.contains(r#""offset_bytes":512,"size_bytes":1536"#));
    assert!(json.contains(r#""fs_type":1,"crypt_type":2"#));
    assert!(json.contains(r#""signature_verified":false"#));
    let verification = file.run("verify", false);
    assert!(verification.status.success(), "{}", String::from_utf8_lossy(&verification.stderr));
    assert!(String::from_utf8(verification.stdout).unwrap()
        .contains("encrypted NCCH contents NOT verified"));
    assert_eq!(fs::read(&file.file).unwrap(), image);
}

#[test]
fn rejects_crossing_declared_media_or_file_bounds() {
    let mut raw = synthetic();
    raw[0x128..0x12c].copy_from_slice(&15u32.to_le_bytes());
    let f = Fixture::new(&raw);
    assert!(!f.run("info", false).status.success());
    assert!(!f.run("verify", false).status.success());
    assert!(!f.partitions(true).status.success());
    assert_eq!(fs::read(&f.file).unwrap(), raw);
}

#[test]
fn recognizes_bad_partition_overlap_instead_of_extracting_data() {
    let mut raw = synthetic();
    raw[0x128..0x12c].copy_from_slice(&2u32.to_le_bytes());
    let f = Fixture::new(&raw);
    let out = f.partitions(true);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("overlap"));
}

#[test]
fn partial_ncsd_header_is_a_clean_error() {
    let raw = synthetic();
    let f = Fixture::new(&raw[..0x150]);
    let out = f.run("info", true);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("NCSD header truncated"));
}

#[test]
fn non_ncsd_image_cannot_use_partition_command() {
    let f = Fixture::new(&vec![0u8; 1024]);
    let out = f.partitions(true);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires an NCSD"));
}
