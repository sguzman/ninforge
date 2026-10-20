//! WUX tests use synthesized sector tables and contain no game content.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    directory: PathBuf,
    image: PathBuf,
}
impl Fixture {
    fn new(content: &[u8]) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ninforge-wux-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let image = directory.join("synthetic.wux");
        fs::write(&image, content).unwrap();
        Self { directory, image }
    }
    fn command(&self, args: &[&str], json: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        command.args(args).arg(&self.image);
        if json {
            command.arg("--json");
        }
        command.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
const SECTOR: usize = 0x8000;
fn synthetic_wux(mapping: &[u32], stored: usize) -> Vec<u8> {
    let mut data = vec![0u8; (1 + stored) * SECTOR];
    data[0..4].copy_from_slice(b"WUX0");
    data[4..8].copy_from_slice(&[0x2e, 0xd0, 0x99, 0x10]);
    data[8..12].copy_from_slice(&(SECTOR as u32).to_le_bytes());
    data[16..24].copy_from_slice(&((mapping.len() * SECTOR) as u64).to_le_bytes());
    for (index, sector) in mapping.iter().enumerate() {
        let start = 32 + index * 4;
        data[start..start + 4].copy_from_slice(&sector.to_le_bytes());
    }
    data
}

#[test]
fn recognizes_wux_header_and_opt_in_map_verification() {
    let bytes = synthetic_wux(&[0, 1, 0], 2);
    let fixture = Fixture::new(&bytes);
    let info = fixture.command(&["info"], true);
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let info = String::from_utf8(info.stdout).unwrap();
    assert!(info.contains(r#""format":"Wii U WUX""#));
    assert!(info.contains(r#""logical_sector_count":"3""#));
    assert!(info.contains(r#""stored_sector_count":"2""#));
    assert!(info.contains(r#""index_table_verified":"false""#));

    let checked = fixture.command(&["wiiu", "wux-check"], true);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let report = String::from_utf8(checked.stdout).unwrap();
    assert!(report.contains(r#""index_table_verified":true"#));
    assert!(report.contains(r#""duplicate_references":1"#));
    assert!(report.contains(r#""content_hashes_verified":false"#));
    assert!(fixture.command(&["verify"], false).status.success());
    assert_eq!(fs::read(&fixture.image).unwrap(), bytes);
}

#[test]
fn rejects_truncated_wux_and_invalid_sector_geometry() {
    let mut bytes = synthetic_wux(&[0, 1, 0], 2);
    bytes.truncate(SECTOR + 1);
    assert!(!Fixture::new(&bytes)
        .command(&["info"], false)
        .status
        .success());
    let mut bytes = synthetic_wux(&[0, 1, 0], 2);
    bytes[8..12].copy_from_slice(&123u32.to_le_bytes());
    assert!(!Fixture::new(&bytes)
        .command(&["info"], false)
        .status
        .success());
    let mut bytes = synthetic_wux(&[0, 1, 0], 2);
    bytes[4] = 0;
    assert!(!Fixture::new(&bytes)
        .command(&["info"], false)
        .status
        .success());
}

#[test]
fn unmapped_stored_sector_rejected_by_deep_check_not_cheap_info() {
    let bytes = synthetic_wux(&[0, 2, 0], 2);
    let fixture = Fixture::new(&bytes);
    assert!(fixture.command(&["info"], false).status.success());
    let verify = fixture.command(&["verify"], false);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("absent stored sector"));
}
