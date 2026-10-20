//! End-to-end N64 cartridge header tests across all byte orders.
//! Test images contain invented metadata, not commercial ROMs or executable games.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SERIAL: AtomicUsize = AtomicUsize::new(0);

fn synthetic() -> Vec<u8> {
    let mut data = vec![0u8; 0x1000];
    data[..4].copy_from_slice(&[0x80, 0x37, 0x12, 0x40]);
    data[0x04..0x08].copy_from_slice(&0xfu32.to_be_bytes());
    data[0x08..0x0c].copy_from_slice(&0x80000400u32.to_be_bytes());
    data[0x10..0x14].copy_from_slice(&0x12345678u32.to_be_bytes());
    data[0x14..0x18].copy_from_slice(&0x9abcdef0u32.to_be_bytes());
    data[0x20..0x2c].copy_from_slice(b"TEST PROGRAM");
    data[0x3b..0x3f].copy_from_slice(b"NABE");
    data[0x3f] = 3;
    data
}

fn reordered(data: &[u8], mask: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    for (index, cell) in out.iter_mut().enumerate() {
        *cell = data[index ^ mask];
    }
    out
}

struct Fixture {
    folder: PathBuf,
    file: PathBuf,
}
impl Fixture {
    fn new(data: &[u8]) -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let folder = std::env::temp_dir().join(format!(
            "ninforge-n64-cli-{}-{stamp}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&folder).unwrap();
        // An arbitrary extension ensures byte order is determined from magic.
        let file = folder.join("cartridge.bin");
        fs::write(&file, data).unwrap();
        Self { folder, file }
    }
    fn run(&self, verb: &str, json: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        command.arg(verb).arg(&self.file);
        if json {
            command.arg("--json");
        }
        command.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.folder);
    }
}

#[test]
fn all_n64_byte_orders_produce_identical_semantic_metadata() {
    let image = synthetic();
    for (mask, order) in [
        (0, "big-endian (.z64)"),
        (1, "byte-swapped 16-bit (.v64)"),
        (3, "little-endian 32-bit (.n64)"),
    ] {
        let transformed = reordered(&image, mask);
        let file = Fixture::new(&transformed);
        let result = file.run("info", true);
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        let output = String::from_utf8(result.stdout).unwrap();
        assert!(output.contains(r#""format":"Nintendo 64""#));
        assert!(output.contains(&format!(r#""byte_order":"{order}""#)));
        assert!(output.contains(r#""title":"TEST PROGRAM""#));
        assert!(output.contains(r#""game_code":"NABE""#));
        assert!(output.contains(r#""country_character":"E""#));
        assert!(output.contains(r#""entry_point":"0x80000400""#));
        assert!(output.contains(r#""rom_version":"3""#));
        assert!(output.contains(r#""crc1_stored":"0x12345678""#));
        assert!(output.contains(r#""crc2_stored":"0x9ABCDEF0""#));
        assert!(output.contains(r#""crc1_crc2_verified":"false""#));
        assert!(output.contains(r#""rom_data_verified":"false""#));
        let check = file.run("verify", false);
        assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));
        assert!(String::from_utf8(check.stdout).unwrap().contains("NOT verified"));
        assert_eq!(fs::read(&file.file).unwrap(), transformed);
    }
}

#[test]
fn altered_crc_field_is_reported_not_marked_as_validated() {
    let mut image = synthetic();
    image[0x10] ^= 1;
    let file = Fixture::new(&image);
    let info = file.run("info", true);
    assert!(info.status.success());
    let output = String::from_utf8(info.stdout).unwrap();
    assert!(output.contains(r#""crc1_stored":"0x13345678""#));
    assert!(output.contains(r#""crc1_crc2_verified":"false""#));
}

#[test]
fn unprintable_title_is_safe_to_display_and_untrusted() {
    let mut image = synthetic();
    image[0x20] = 0x1b;
    let file = Fixture::new(&image);
    let info = file.run("info", true);
    assert!(info.status.success());
    let output = String::from_utf8(info.stdout).unwrap();
    assert!(output.contains(r#""title":"?EST PROGRAM""#));
    assert!(output.contains(r#""title_ascii_valid":"false""#));
    assert!(!output.contains('\u{1b}'));
}

#[test]
fn incomplete_header_is_an_error_not_a_valid_rom() {
    let image = synthetic();
    let file = Fixture::new(&image[..4]);
    let result = file.run("info", true);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("shorter than 64 bytes"));
    assert!(!file.run("verify", false).status.success());
}
