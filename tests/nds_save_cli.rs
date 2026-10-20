//! Black-box Nintendo DS save-container inspection. Synthetic fixtures only.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SERIAL: AtomicUsize = AtomicUsize::new(0);
const COOKIE: &[u8; 16] = b"|-DESMUME SAVE-|";

struct Fixture {
    dir: PathBuf,
    file: PathBuf,
}
impl Fixture {
    fn new(data: &[u8], name: &str) -> Self {
        let tick = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-nds-save-cli-{}-{tick}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let file = dir.join(name);
        fs::write(&file, data).unwrap();
        Self { dir, file }
    }
    fn run(&self, json: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cmd.args(["nds", "save", "info"]).arg(&self.file);
        if json {
            cmd.arg("--json");
        }
        cmd.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn dsv() -> Vec<u8> {
    let mut data = vec![0xab; 8192];
    data.extend(3u32.to_le_bytes());
    data.extend(8192u32.to_le_bytes());
    data.extend(0u32.to_le_bytes());
    data.extend(2u32.to_le_bytes());
    data.extend(0u32.to_le_bytes());
    data.extend(0u32.to_le_bytes());
    data.extend(COOKIE);
    data
}
fn no_gba(compressed: bool) -> Vec<u8> {
    let mut data = vec![0xFF; 0x50 + 512];
    data[..31].copy_from_slice(b"NocashGbaBackupMediaSavDataFile");
    data[31] = 0x1a;
    data[0x40..0x44].copy_from_slice(b"SRAM");
    data[0x44..0x48].copy_from_slice(&u32::from(compressed).to_le_bytes());
    data[0x48..0x4c].copy_from_slice(&512u32.to_le_bytes());
    data[0x4c..0x50].copy_from_slice(&4096u32.to_le_bytes());
    data
}

#[test]
fn dsv_footer_recognized_by_content_not_extension() {
    let file = Fixture::new(&dsv(), "unusual.dat");
    let output = file.run(true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(r#""format":"desmume_dsv""#));
    assert!(text.contains(r#""data_size_bytes":"8192""#));
    assert!(text.contains(r#""actually_written_size_bytes":"3""#));
    assert!(text.contains(r#""game_association_verified":"false""#));
}

#[test]
fn nogba_header_recognized_both_compression_modes() {
    for compressed in [false, true] {
        let file = Fixture::new(&no_gba(compressed), "backup.bin");
        let output = file.run(true);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains(r#""format":"no_gba_sram""#));
        assert!(text.contains(if compressed {
            r#""compression":"packed""#
        } else {
            r#""compression":"none""#
        }));
    }
}

#[test]
fn anonymous_raw_file_is_not_attributed_to_ds_hardware() {
    let file = Fixture::new(&vec![0x88; 8192], "fake.nds");
    let output = file.run(true);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(r#""format":"raw_or_unidentified""#));
    assert!(text.contains(r#""format_signature_verified":"false""#));
    assert!(text.contains(r#""common_raw_capacity_length":"true""#));
    let verbose = file.run(false);
    assert!(verbose.status.success());
    assert!(String::from_utf8(verbose.stdout)
        .unwrap()
        .contains("raw_or_unidentified"));
}

#[test]
fn defective_dsv_and_nogba_fail_cleanly_without_modifying_bytes() {
    let mut bad = dsv();
    let field = bad.len() - 36;
    bad[field..field + 4].copy_from_slice(&999_999u32.to_le_bytes());
    let dsv_file = Fixture::new(&bad, "broken.dsv");
    let output = dsv_file.run(true);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("DeSmuME"));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(&dsv_file.file).unwrap(), bad);

    let mut bad = no_gba(false);
    bad[0x40..0x44].copy_from_slice(b"FAIL");
    let nogba_file = Fixture::new(&bad, "broken.sav");
    let output = nogba_file.run(true);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("No$GBA"));
    assert_eq!(fs::read(&nogba_file.file).unwrap(), bad);
}


fn action_replay(payload_len: usize) -> Vec<u8> {
    let mut file = vec![0u8; 500 + payload_len];
    file[..8].copy_from_slice(b"ARDS0001");
    file[500..].fill(0x5A);
    file
}

#[test]
fn action_replay_header_identified_by_magic_without_game_guessing() {
    let bytes = action_replay(32768);
    let file = Fixture::new(&bytes, "does-not-matter.sav");
    let output = file.run(true);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(r#""format":"action_replay_ds""#));
    assert!(text.contains(r#""wrapper_size_bytes":"500""#));
    assert!(text.contains(r#""payload_offset":"500""#));
    assert!(text.contains(r#""payload_size_bytes":"32768""#));
    assert!(text.contains(r#""metadata_not_decoded":"true""#));
    assert!(text.contains(r#""game_association_verified":"false""#));
    assert_eq!(fs::read(&file.file).unwrap(), bytes);
}

#[test]
fn action_replay_truncated_file_is_rejected_without_output() {
    for size in [8, 499, 500] {
        let mut bytes = vec![0u8; size];
        bytes[..8].copy_from_slice(b"ARDS0001");
        let file = Fixture::new(&bytes, "truncated.duc");
        let result = file.run(true);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("Action Replay DS"));
        assert!(result.stdout.is_empty());
        assert_eq!(fs::read(&file.file).unwrap(), bytes);
    }
}
