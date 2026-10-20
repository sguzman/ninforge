//! Synthetic-only GameCube ISO regression and safe extraction tests.
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-gc-{}-{now}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let image = dir.join("synthetic.iso");
        fs::write(&image, bytes).unwrap();
        Self { dir, image }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ninforge"))
            .args(args)
            .arg(&self.image)
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn be32(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_be_bytes());
}

fn disc() -> Vec<u8> {
    let mut data = vec![0u8; 0x1200];
    data[..6].copy_from_slice(b"ABCD01");
    data[0x1c..0x20].copy_from_slice(&[0xc2, 0x33, 0x9f, 0x3d]);
    data[0x20..0x29].copy_from_slice(b"TEST DISC");
    be32(&mut data[0x420..0x424], 0x480);
    be32(&mut data[0x424..0x428], 0x600);
    // Four FST entries: root, assets/, hello.bin, readme.txt.
    let names = b"assets\0hello.bin\0readme.txt\0";
    let fst_size = 4 * 12 + names.len();
    be32(&mut data[0x428..0x42c], fst_size as u32);
    be32(&mut data[0x42c..0x430], fst_size as u32);
    let root = 0x600;
    data[root] = 1;
    be32(&mut data[root + 8..root + 12], 4);
    data[root + 12] = 1;
    be32(&mut data[root + 20..root + 24], 3);
    // First file in assets/, named at string-table index 7.
    data[root + 24 + 3] = 7;
    be32(&mut data[root + 28..root + 32], 0x1000);
    be32(&mut data[root + 32..root + 36], 5);
    // Root file named at string-table index 17.
    data[root + 36 + 3] = 17;
    be32(&mut data[root + 40..root + 44], 0x1100);
    be32(&mut data[root + 44..root + 48], 4);
    data[root + 48..root + 48 + names.len()].copy_from_slice(names);
    data[0x1000..0x1005].copy_from_slice(b"hello");
    data[0x1100..0x1104].copy_from_slice(b"read");
    data
}

#[test]
fn gamecube_info_list_verify_and_extract_are_read_only() {
    let bytes = disc();
    let fixture = Fixture::new(&bytes);
    let info = fixture.run(&["info", "--json"]);
    // The common info syntax requires the file before --json.
    assert!(!info.status.success());
    let info = Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .args(["info"])
        .arg(&fixture.image)
        .arg("--json")
        .output()
        .unwrap();
    assert!(info.status.success(), "{}", String::from_utf8_lossy(&info.stderr));
    let info = String::from_utf8(info.stdout).unwrap();
    assert!(info.contains(r#""format":"GameCube disc""#));
    assert!(info.contains(r#""directory_count":"2""#));
    assert!(info.contains(r#""file_count":"2""#));
    let list = fixture.run(&["list"]);
    assert!(list.status.success(), "{}", String::from_utf8_lossy(&list.stderr));
    let listing = String::from_utf8(list.stdout).unwrap();
    assert!(listing.contains("assets/hello.bin"));
    assert!(listing.contains("readme.txt"));
    assert!(fixture.run(&["verify"]).status.success());

    let output = fixture.dir.join("output.bin");
    let first = Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("extract")
        .arg(&fixture.image)
        .arg("assets/hello.bin")
        .arg(&output)
        .output()
        .unwrap();
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    assert_eq!(fs::read(&output).unwrap(), b"hello");
    assert!(!Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("extract")
        .arg(&fixture.image)
        .arg("readme.txt")
        .arg(&output)
        .status()
        .unwrap()
        .success());
    assert_eq!(fs::read(&output).unwrap(), b"hello");
    assert_eq!(fs::read(&fixture.image).unwrap(), bytes);
}

#[test]
fn gamecube_rejects_truncated_and_out_of_range_tables() {
    let mut data = disc();
    data.truncate(0x610);
    assert!(!Fixture::new(&data).run(&["verify"]).status.success());
    let mut data = disc();
    be32(&mut data[0x428..0x42c], u32::MAX);
    assert!(!Fixture::new(&data).run(&["verify"]).status.success());
    let mut data = disc();
    be32(&mut data[0x608..0x60c], 100_001);
    assert!(!Fixture::new(&data).run(&["verify"]).status.success());
}

#[test]
fn gamecube_rejects_path_traversal_directory_cycles_and_invalid_extents() {
    let mut data = disc();
    data[0x630..0x636].copy_from_slice(b"../bad\0");
    // The string table begins at 0x630: first name is now a traversal path.
    assert!(!Fixture::new(&data).run(&["list"]).status.success());

    let mut data = disc();
    be32(&mut data[0x614..0x618], 1);
    // Directory subtree next index cannot point at itself.
    assert!(!Fixture::new(&data).run(&["verify"]).status.success());

    let mut data = disc();
    be32(&mut data[0x620..0x624], 0x11ff);
    assert!(!Fixture::new(&data).run(&["verify"]).status.success());

    let mut data = disc();
    be32(&mut data[0x620..0x624], 0x1100);
    assert!(!Fixture::new(&data).run(&["verify"]).status.success());
}
