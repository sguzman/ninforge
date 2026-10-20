//! Synthetic GameCube main DOL structural command tests.
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ninforge-gc-dol-{}-{now}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let image = directory.join("synthetic.gcm");
        fs::write(&image, content).unwrap();
        Self { directory, image }
    }
    fn run(&self, args: &[&str], json: bool) -> Output {
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
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn disc() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x1400];
    bytes[0..6].copy_from_slice(b"ABCD01");
    bytes[0x1c..0x20].copy_from_slice(&[0xc2, 0x33, 0x9f, 0x3d]);
    put(&mut bytes, 0x420, 0x480);
    put(&mut bytes, 0x424, 0x800);
    put(&mut bytes, 0x428, 12);
    put(&mut bytes, 0x42c, 12);
    bytes[0x800] = 1;
    put(&mut bytes, 0x808, 1);
    // main.dol header: text0 at 0x100, data0 at 0x140 relative to 0x480.
    put(&mut bytes, 0x480, 0x100);
    put(&mut bytes, 0x480 + 0x1c, 0x140);
    put(&mut bytes, 0x480 + 0x48, 0x80003100);
    put(&mut bytes, 0x480 + 0x48 + 7 * 4, 0x80004000);
    put(&mut bytes, 0x480 + 0x90, 0x20);
    put(&mut bytes, 0x480 + 0x90 + 7 * 4, 0x10);
    put(&mut bytes, 0x480 + 0xd8, 0x80005000);
    put(&mut bytes, 0x480 + 0xdc, 0x200);
    put(&mut bytes, 0x480 + 0xe0, 0x80003100);
    bytes
}

#[test]
fn main_dol_structural_check_reports_sections_without_changing_image() {
    let image = disc();
    let fixture = Fixture::new(&image);
    let output = fixture.run(&["gamecube", "dol-check"], true);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""format":"gamecube_main_dol""#));
    assert!(json.contains(r#""section_count":2"#));
    assert!(json.contains(r#""entrypoint_in_text":true"#));
    assert!(json.contains(r#""slot":0"#));
    assert!(json.contains(r#""kind":"data""#));
    assert!(json.contains(r#""content_hashes_verified":false"#));
    assert!(fixture.run(&["verify"], false).status.success());
    assert_eq!(fs::read(&fixture.image).unwrap(), image);
}

#[test]
fn main_dol_rejects_sections_beyond_image_and_overlapping_ranges() {
    let mut image = disc();
    put(&mut image, 0x480, 0xfffffff0);
    assert!(!Fixture::new(&image).run(&["gamecube", "dol-check"], false).status.success());
    let mut image = disc();
    put(&mut image, 0x480 + 0x1c, 0x100);
    assert!(!Fixture::new(&image).run(&["gamecube", "dol-check"], false).status.success());
    let mut image = disc();
    put(&mut image, 0x480 + 0x1c, 0x380);
    assert!(!Fixture::new(&image).run(&["gamecube", "dol-check"], false).status.success());
}

#[test]
fn no_main_dol_record_is_not_claimed_as_verified() {
    let mut image = disc();
    put(&mut image, 0x420, 0);
    assert!(Fixture::new(&image).run(&["info"], false).status.success());
    assert!(!Fixture::new(&image).run(&["gamecube", "dol-check"], false).status.success());
}
