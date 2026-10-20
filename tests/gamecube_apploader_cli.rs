//! Synthetic-only GameCube apploader layout regression tests.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    dir: PathBuf,
    image: PathBuf,
}
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-gc-apploader-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let image = dir.join("synthetic.gcm");
        fs::write(&image, bytes).unwrap();
        Self { dir, image }
    }
    fn check(&self, json: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        command.args(["gamecube", "apploader-check"]).arg(&self.image);
        if json {
            command.arg("--json");
        }
        command.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn be32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn disc() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x5000];
    bytes[0..6].copy_from_slice(b"ABCD01");
    bytes[0x1c..0x20].copy_from_slice(&[0xc2, 0x33, 0x9f, 0x3d]);
    be32(&mut bytes, 0x420, 0x3500);
    be32(&mut bytes, 0x424, 0x3800);
    be32(&mut bytes, 0x428, 12);
    be32(&mut bytes, 0x42c, 12);
    bytes[0x3800] = 1;
    be32(&mut bytes, 0x3808, 1);
    bytes[0x2440..0x244a].copy_from_slice(b"2001/01/01");
    be32(&mut bytes, 0x2450, 0x81200000);
    be32(&mut bytes, 0x2454, 0x100);
    be32(&mut bytes, 0x2458, 0x20);
    bytes
}
#[test]
fn apploader_header_and_aligned_code_bounds_are_reported() {
    let bytes = disc();
    let fixture = Fixture::new(&bytes);
    let output = fixture.check(true);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""format":"gamecube_apploader""#));
    assert!(json.contains(r#""revision":"2001/01/01""#));
    assert!(json.contains(r#""code_size_bytes":256"#));
    assert!(json.contains(r#""trailer_size_bytes":32"#));
    assert!(json.contains(r#""padded_end_bytes":9600"#));
    assert!(json.contains(r#""content_hashes_verified":false"#));
    assert_eq!(fs::read(&fixture.image).unwrap(), bytes);
}
#[test]
fn rejects_truncated_apploader_and_overlaps_with_other_disc_structures() {
    let mut bytes = disc();
    be32(&mut bytes, 0x2454, u32::MAX);
    assert!(!Fixture::new(&bytes).check(false).status.success());
    let mut bytes = disc();
    be32(&mut bytes, 0x420, 0x2500);
    assert!(!Fixture::new(&bytes).check(false).status.success());
    let mut bytes = disc();
    be32(&mut bytes, 0x424, 0x2500);
    assert!(!Fixture::new(&bytes).check(false).status.success());
}
#[test]
fn rejects_missing_apploader_code() {
    let mut bytes = disc();
    be32(&mut bytes, 0x2454, 0);
    assert!(!Fixture::new(&bytes).check(false).status.success());
}
