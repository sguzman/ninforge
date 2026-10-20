//! Synthetic iNES/NES 2.0 metadata and structural verification tests.
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
static SERIAL: AtomicUsize = AtomicUsize::new(0);

fn nes2() -> Vec<u8> {
    let mut file = vec![0u8; 16 + 512 + 16 * 1024 + 8 * 1024];
    file[..4].copy_from_slice(b"NES\x1a");
    file[4] = 1;
    file[5] = 1;
    file[6] = 0x45; // mapper 4, vertical mirror, trainer
    file[7] = 0xa8; // NES 2.0, mapper high A0
    file[8] = 0x21; // mapper high 0x100, submapper 2
    file[10] = 0x76;
    file[11] = 0x07;
    file
}
struct Fixture {
    dir: PathBuf,
    file: PathBuf,
}
impl Fixture {
    fn new(data: &[u8]) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ninforge-nes-cli-{}-{now}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let file = dir.join("fictional.bin");
        fs::write(&file, data).unwrap();
        Self { dir, file }
    }
    fn exec(&self, command: &str, json: bool) -> Output {
        let mut cli = Command::new(env!("CARGO_BIN_EXE_ninforge"));
        cli.arg(command).arg(&self.file);
        if json {
            cli.arg("--json");
        }
        cli.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn nes2_mapper_trainer_and_ram_metadata_are_json() {
    let original = nes2();
    let f = Fixture::new(&original);
    let info = f.exec("info", true);
    assert!(
        info.status.success(),
        "{}",
        String::from_utf8_lossy(&info.stderr)
    );
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""format":"NES iNES""#));
    assert!(json.contains(r#""header":"NES 2.0""#));
    assert!(json.contains(r#""mapper":"420""#));
    assert!(json.contains(r#""submapper":"2""#));
    assert!(json.contains(r#""prg_rom_bytes":"16384""#));
    assert!(json.contains(r#""chr_rom_bytes":"8192""#));
    assert!(json.contains(r#""prg_nvram_bytes":"8192""#));
    assert!(json.contains(r#""trainer_present":"true""#));
    assert!(json.contains(r#""declared_regions_fit_file":"true""#));
    let check = f.exec("verify", false);
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(String::from_utf8(check.stdout)
        .unwrap()
        .contains("no ROM data checksum"));
    assert_eq!(fs::read(&f.file).unwrap(), original);
}

#[test]
fn nes2_truncation_is_reported_and_verify_fails() {
    let raw = nes2();
    let f = Fixture::new(&raw[..raw.len() - 1]);
    let info = f.exec("info", true);
    assert!(info.status.success());
    assert!(String::from_utf8(info.stdout)
        .unwrap()
        .contains(r#""declared_regions_fit_file":"false""#));
    assert!(!f.exec("verify", false).status.success());
}

#[test]
fn ines_with_polluted_padding_does_not_invent_high_mapper_bits() {
    let mut raw = vec![0u8; 16 + 16 * 1024];
    raw[..4].copy_from_slice(b"NES\x1a");
    raw[4] = 1;
    raw[6] = 0x30;
    raw[7] = 0xf0;
    raw[12] = b'D';
    let f = Fixture::new(&raw);
    let info = f.exec("info", true);
    assert!(info.status.success());
    let json = String::from_utf8(info.stdout).unwrap();
    assert!(json.contains(r#""mapper":"3""#));
    assert!(json.contains(r#""mapper_high_bits_ambiguous":"true""#));
}

#[test]
fn nes2_trailing_bytes_without_misc_flag_fail_verify() {
    let mut raw = nes2();
    raw.extend([0u8; 64]);
    let f = Fixture::new(&raw);
    assert!(f.exec("info", true).status.success());
    let result = f.exec("verify", false);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unexpected trailing"));
}
