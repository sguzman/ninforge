//! SNES internal-header CLI regression tests, using only synthetic bytes.
//! There is no universal leading SNES magic and no automatic identification.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new(content: &[u8]) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ninforge-snes-candidate-{}-{now}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("unknown.bin");
        fs::write(&path, content).unwrap();
        Self { directory, path }
    }
    fn header(&self, json: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        command.args(["snes", "header"]).arg(&self.path);
        if json { command.arg("--json"); }
        command.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.directory); }
}

fn add_header(bytes: &mut [u8], offset: usize, mode: u8, valid_pair: bool) {
    bytes[offset..offset + 14].copy_from_slice(b"SYNTHETIC GAME");
    bytes[offset + 0x15] = mode;
    bytes[offset + 0x16] = 2;
    bytes[offset + 0x17] = 8;
    bytes[offset + 0x18] = 5;
    bytes[offset + 0x19] = 1;
    bytes[offset + 0x1c..offset + 0x1e].copy_from_slice(
        &(if valid_pair { 0xedcb_u16 } else { 0_u16 }).to_le_bytes()
    );
    bytes[offset + 0x1e..offset + 0x20].copy_from_slice(&0x1234_u16.to_le_bytes());
    bytes[offset + 0x3c..offset + 0x3e].copy_from_slice(&0x8000_u16.to_le_bytes());
}

#[test]
fn explicit_snes_header_command_recognizes_lorom_without_changing_file() {
    let mut content = vec![0u8; 0x20000];
    add_header(&mut content, 0x7fc0, 0x20, true);
    let fixture = Fixture::new(&content);
    let output = fixture.header(true);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(r#""format":"snes_header_candidates""#));
    assert!(text.contains(r#""layout":"lorom""#));
    assert!(text.contains(r#""header_offset_bytes":32704"#));
    assert!(text.contains(r#""checksum_pair_valid":true"#));
    assert!(text.contains(r#""best_candidate_index":0"#));
    assert!(text.contains(r#""full_rom_checksum_verified":false"#));
    let plain = fixture.header(false);
    assert!(plain.status.success());
    assert!(String::from_utf8(plain.stdout).unwrap().contains("cartridge authenticity NOT verified"));
    assert_eq!(fs::read(&fixture.path).unwrap(), content);

    // SNES cannot be auto-identified simply because its internal header
    // resembles a cartridge: only the explicit command interprets it.
    let info = Command::new(env!("CARGO_BIN_EXE_ninforge"))
        .arg("info").arg(&fixture.path).arg("--json").output().unwrap();
    assert!(info.status.success());
    assert!(String::from_utf8(info.stdout).unwrap().contains(r#""format":"Unknown""#));
}

#[test]
fn copier_prefix_is_reported_not_stripped_or_rewritten() {
    let mut content = vec![0u8; 0x20200];
    add_header(&mut content, 0x81c0, 0x30, true);
    let fixture = Fixture::new(&content);
    let output = fixture.header(true);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""copier_prefix_bytes":512"#));
    assert!(json.contains(r#""header_offset_bytes":33216"#));
    assert_eq!(fs::read(&fixture.path).unwrap(), content);
}

#[test]
fn equally_plausible_headers_are_reported_as_ambiguous() {
    let mut content = vec![0u8; 0x20000];
    add_header(&mut content, 0x7fc0, 0x20, true);
    add_header(&mut content, 0xffc0, 0x21, true);
    let fixture = Fixture::new(&content);
    let output = fixture.header(true);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains(r#""candidate_count":2"#));
    assert!(json.contains(r#""best_candidate_index":null"#));
    assert!(json.contains(r#""layout":"hirom""#));
}

#[test]
fn random_or_truncated_inputs_fail_without_claiming_snes() {
    for data in [vec![0u8; 0x20000], vec![0u8; 100]] {
        let fixture = Fixture::new(&data);
        let output = fixture.header(true);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("no plausible SNES"));
    }
}
