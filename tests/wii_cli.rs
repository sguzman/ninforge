//! Synthetic Wii ISO partition-table and WBFS superblock CLI tests.
//! No commercial disc image, keys or save data are stored in this repository.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SERIAL: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    file: PathBuf,
}
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ninforge-wii-cli-{}-{now}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let file = root.join("fictional.bin");
        fs::write(&file, bytes).unwrap();
        Self { root, file }
    }
    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.args(args).arg(&self.file).output().unwrap()
    }
    fn partitions(&self, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.args(["wii", "partitions"]).arg(&self.file);
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

fn iso() -> Vec<u8> {
    let mut data = vec![0u8; 0x90000];
    data[..6].copy_from_slice(b"DEMO01");
    data[0x18..0x1c].copy_from_slice(&[0x5d, 0x1c, 0x9e, 0xa3]);
    data[0x20..0x2b].copy_from_slice(b"Fixture Wii");
    data[0x40000..0x40004].copy_from_slice(&2u32.to_be_bytes());
    data[0x40004..0x40008].copy_from_slice(&(0x40020u32 / 4).to_be_bytes());
    data[0x40020..0x40024].copy_from_slice(&(0x50000u32 / 4).to_be_bytes());
    data[0x40024..0x40028].copy_from_slice(&1u32.to_be_bytes());
    data[0x40028..0x4002c].copy_from_slice(&(0x70000u32 / 4).to_be_bytes());
    data[0x4002c..0x40030].copy_from_slice(&0u32.to_be_bytes());
    data[0x4e000..0x4e004].copy_from_slice(&1u32.to_be_bytes());
    data
}

fn wbfs() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[..4].copy_from_slice(b"WBFS");
    data[4..8].copy_from_slice(&16384u32.to_be_bytes());
    data[8] = 9;
    data[9] = 21;
    data[12] = 1;
    data
}

#[test]
fn iso_info_and_partition_index_have_correct_offsets() {
    let data = iso();
    let file = Fixture::new(&data);
    let info = Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("info")
        .arg(&file.file)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""format":"Wii disc""#));
    assert!(json.contains(r#""partition_count":"2""#));
    assert!(json.contains(r#""partition_offsets_checked":"true""#));
    assert!(json.contains(r#""partition_contents_decrypted":"false""#));
    let listing = file.partitions(true);
    assert!(
        listing.status.success(),
        "{}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let json = String::from_utf8(listing.stdout).unwrap();
    assert!(json.contains(r#""partition_count":2"#));
    assert!(json.contains(r#""offset_bytes":327680,"type":1,"type_name":"update""#));
    assert!(json.contains(r#""offset_bytes":458752,"type":0,"type_name":"data""#));
    assert!(json.contains(r#""encrypted_content_verified":false"#));
    let plain = file.partitions(false);
    assert!(plain.status.success());
    assert!(String::from_utf8(plain.stdout)
        .unwrap()
        .contains("group=0 index=1"));
    assert_eq!(fs::read(&file.file).unwrap(), data);
}

#[test]
fn iso_verify_confirms_structural_bounds_only() {
    let file = Fixture::new(&iso());
    let out = file.run(&["verify"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .contains("encrypted partition data not verified"));
}

#[test]
fn malformed_partition_addresses_refuse_info_and_verify() {
    let mut data = iso();
    data[0x40004..0x40008].copy_from_slice(&u32::MAX.to_be_bytes());
    let file = Fixture::new(&data);
    assert!(!file.run(&["info"]).status.success());
    assert!(!file.run(&["verify"]).status.success());
    let listing = file.partitions(true);
    assert!(!listing.status.success());
    assert!(String::from_utf8_lossy(&listing.stderr).contains("partition table pointer"));
    assert!(listing.stdout.is_empty());
}

#[test]
fn wbfs_superblock_recognition_keeps_blockmap_unverified() {
    let file = Fixture::new(&wbfs());
    let info = Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("info")
        .arg(&file.file)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""format":"Wii WBFS""#));
    assert!(json.contains(r#""occupied_disc_slots":"1""#));
    assert!(json.contains(r#""host_sector_bytes":"512""#));
    assert!(json.contains(r#""block_map_verified":"false""#));
    let verify = file.run(&["verify"]);
    assert!(verify.status.success());
    assert!(String::from_utf8(verify.stdout)
        .unwrap()
        .contains("disc block maps and game data not verified"));
    let listing = file.partitions(true);
    assert!(!listing.status.success());
    assert!(String::from_utf8_lossy(&listing.stderr).contains("not a WBFS container"));
}

#[test]
fn invalid_wbfs_parameters_fail_without_writes() {
    let mut data = wbfs();
    data[9] = 8;
    let file = Fixture::new(&data);
    let info = file.run(&["info"]);
    assert!(!info.status.success());
    assert!(String::from_utf8_lossy(&info.stderr).contains("WBFS"));
    assert_eq!(fs::read(&file.file).unwrap(), data);
}

fn mapped_wbfs() -> Vec<u8> {
    let mut data = vec![0u8; 4 * (1 << 21)];
    data[..4].copy_from_slice(b"WBFS");
    data[4..8].copy_from_slice(&16384u32.to_be_bytes());
    data[8] = 9;
    data[9] = 21;
    data[12] = 1;
    data[512..518].copy_from_slice(b"DEMO01");
    data[512 + 0x18..512 + 0x1c].copy_from_slice(&[0x5d, 0x1c, 0x9e, 0xa3]);
    data[512 + 0x100..512 + 0x102].copy_from_slice(&1u16.to_be_bytes());
    data
}

fn wbfs_check(file: &Fixture, json: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ninforge"));
    command.args(["wii", "wbfs-check"]).arg(&file.file);
    if json {
        command.arg("--json");
    }
    command.output().unwrap()
}

#[test]
fn deep_check_validates_synthetic_slot_and_block_map_as_read_only() {
    let raw = mapped_wbfs();
    let file = Fixture::new(&raw);
    let report = wbfs_check(&file, true);
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    let json = String::from_utf8(report.stdout).unwrap();
    assert!(json.contains(r#""format":"wbfs_map_check""#));
    assert!(json.contains(r#""disc_record_size_bytes":9728"#));
    assert!(json.contains(r#""logical_blocks_per_disc":4482"#));
    assert!(json.contains(r#""disc_id":"DEMO01""#));
    assert!(json.contains(r#""mapped_blocks":1"#));
    assert!(json.contains(r#""block_references_within_file":true"#));
    assert!(json.contains(r#""encrypted_content_verified":false"#));
    let text = wbfs_check(&file, false);
    assert!(text.status.success());
    assert!(String::from_utf8(text.stdout)
        .unwrap()
        .contains("game data and cryptographic hashes are NOT verified"));
    assert_eq!(fs::read(&file.file).unwrap(), raw);
}

#[test]
fn deep_check_rejects_invalid_maps_without_breaking_fast_info() {
    let mut raw = mapped_wbfs();
    raw[512 + 0x100..512 + 0x102].copy_from_slice(&5u16.to_be_bytes());
    let file = Fixture::new(&raw);
    let info = file.run(&["info"]);
    assert!(info.status.success()); // superblock-only remains cheap
    let check = wbfs_check(&file, true);
    assert!(!check.status.success());
    assert!(check.stdout.is_empty());
    assert!(String::from_utf8_lossy(&check.stderr).contains("volume capacity"));
}

#[test]
fn deep_check_rejects_truncated_records_and_wrong_input_format() {
    let raw = mapped_wbfs();
    let truncated = Fixture::new(&raw[..550]);
    let check = wbfs_check(&truncated, true);
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("record truncated"));
    let wii_iso = Fixture::new(&iso());
    let check = wbfs_check(&wii_iso, true);
    assert!(!check.status.success());
    assert!(String::from_utf8_lossy(&check.stderr).contains("requires a WBFS container"));
}


fn iso_with_partition_headers() -> Vec<u8> {
    let mut image = iso();
    for partition in [0x50000usize, 0x70000usize] {
        for (field, value) in [
            (0x2a4, 0x100u32),
            (0x2a8, 0x2c0 / 4),
            (0x2b8, 0x10000 / 4),
            (0x2bc, 0x8000 / 4),
        ] {
            image[partition + field..partition + field + 4]
                .copy_from_slice(&value.to_be_bytes());
        }
    }
    image
}
fn wii_partition_check(file: &Fixture, json: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ninforge"));
    command.args(["wii", "partition-check"]).arg(&file.file);
    if json { command.arg("--json"); }
    command.output().unwrap()
}

#[test]
fn partition_header_check_reports_bounded_tmd_and_data_extents() {
    let data = iso_with_partition_headers();
    let fixture = Fixture::new(&data);
    let output = wii_partition_check(&fixture, true);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""format":"wii_partition_header_check""#));
    assert!(json.contains(r#""partition_count":2"#));
    assert!(json.contains(r#""partition_offset_bytes":327680"#));
    assert!(json.contains(r#""data_offset_bytes":393216"#));
    assert!(json.contains(r#""tmd_size_bytes":256"#));
    assert!(json.contains(r#""signature_verified":false"#));
    assert!(json.contains(r#""encrypted_content_verified":false"#));
    assert!(wii_partition_check(&fixture, false).status.success());
    assert_eq!(fs::read(&fixture.file).unwrap(), data);
}

#[test]
fn damaged_partition_extent_fails_deep_check_not_fast_info() {
    let mut data = iso_with_partition_headers();
    data[0x70000 + 0x2bc..0x70000 + 0x2c0]
        .copy_from_slice(&(0x100000u32 / 4).to_be_bytes());
    let fixture = Fixture::new(&data);
    assert!(fixture.run(&["info"]).status.success());
    let checked = wii_partition_check(&fixture, true);
    assert!(!checked.status.success());
    assert!(checked.stdout.is_empty());
    assert!(String::from_utf8_lossy(&checked.stderr).contains("data extent outside ISO"));
    assert_eq!(fs::read(&fixture.file).unwrap(), data);
}
