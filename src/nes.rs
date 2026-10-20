//! iNES and NES 2.0 read-only cartridge-header inspection.
//!
//! A header's size and mapper claims do not authenticate a dump. Legacy
//! iNES padding is frequently polluted; when present, high mapper bits are
//! reported as ambiguous instead of trusting them as a board identity.
use std::io::{self, ErrorKind};

const MAX_NES_LENGTH: u64 = 256 * 1024 * 1024;

fn bad(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NesReport {
    pub nes2: bool,
    pub mapper: u16,
    pub mapper_high_bits_ambiguous: bool,
    pub submapper: Option<u8>,
    pub trainer_present: bool,
    pub battery_flag: bool,
    pub mirroring: &'static str,
    pub console_type: u8,
    pub prg_rom_bytes: u64,
    pub chr_rom_bytes: u64,
    pub prg_ram_bytes: Option<u64>,
    pub prg_nvram_bytes: Option<u64>,
    pub chr_ram_bytes: Option<u64>,
    pub chr_nvram_bytes: Option<u64>,
    pub timing_mode: Option<u8>,
    pub misc_rom_count: Option<u8>,
    pub trainer_offset_bytes: Option<u64>,
    pub prg_offset_bytes: u64,
    pub chr_offset_bytes: u64,
    pub minimum_file_bytes: u64,
    pub actual_file_bytes: u64,
    pub declared_regions_fit_file: bool,
}

fn size_from_nes2(low: u8, high: u8, bank_bytes: u64) -> io::Result<u64> {
    if high != 0x0f {
        return (u64::from(low) | (u64::from(high) << 8))
            .checked_mul(bank_bytes)
            .ok_or_else(|| bad("NES 2.0 declared ROM size overflow"));
    }
    let exponent = u32::from(low >> 2);
    let multiplier = u64::from((low & 0x03) * 2 + 1);
    1u64.checked_shl(exponent)
        .and_then(|v| v.checked_mul(multiplier))
        .ok_or_else(|| bad("NES 2.0 exponent ROM size overflow"))
}
fn ram_shift(shift: u8) -> Option<u64> {
    if shift == 0 { None } else { Some(64u64 << shift) }
}

/// Bounded header inspection, with no reads of PRG/CHR payload contents.
pub fn inspect_nes(head: &[u8], file_bytes: u64) -> io::Result<NesReport> {
    if head.len() < 16 || &head[..4] != b"NES\x1a" {
        return Err(bad("NES header truncated or magic invalid"));
    }
    let nes2 = head[7] & 0x0c == 0x08;
    let ambiguous = !nes2 && head[12..16].iter().any(|byte| *byte != 0);
    let mapper_low = u16::from(head[6] >> 4);
    let mapper_high = u16::from(head[7] & 0xf0);
    let mapper = if nes2 {
        mapper_low | mapper_high | (u16::from(head[8] & 0x0f) << 8)
    } else if ambiguous {
        mapper_low
    } else {
        mapper_low | mapper_high
    };
    let prg_rom = if nes2 {
        size_from_nes2(head[4], head[9] & 0x0f, 16 * 1024)?
    } else {
        u64::from(head[4]) * 16 * 1024
    };
    let chr_rom = if nes2 {
        size_from_nes2(head[5], head[9] >> 4, 8 * 1024)?
    } else {
        u64::from(head[5]) * 8 * 1024
    };
    let trainer = head[6] & 0x04 != 0;
    let prg_offset = 16u64 + if trainer { 512 } else { 0 };
    let chr_offset = prg_offset.checked_add(prg_rom)
        .ok_or_else(|| bad("NES PRG region offset overflow"))?;
    let minimum = chr_offset.checked_add(chr_rom)
        .ok_or_else(|| bad("NES CHR region end overflow"))?;
    if minimum > MAX_NES_LENGTH {
        return Err(bad("NES declared ROM regions exceed inspection safety cap"));
    }
    let mirroring = if head[6] & 0x08 != 0 {
        "four_screen"
    } else if head[6] & 0x01 != 0 {
        "vertical"
    } else {
        "horizontal"
    };
    let (prg_ram, prg_nvram, chr_ram, chr_nvram, timing, misc) = if nes2 {
        (
            ram_shift(head[10] & 0x0f),
            ram_shift(head[10] >> 4),
            ram_shift(head[11] & 0x0f),
            ram_shift(head[11] >> 4),
            Some(head[12] & 3), Some(head[14] & 3),
        )
    } else {
        // iNES byte 8 is an unreliable PRG RAM *hint*, and a zero value
        // must not be promoted to the common 8 KiB convention as proof.
        (
            if head[8] != 0 && !ambiguous {
                Some(u64::from(head[8]) * 8 * 1024)
            } else { None },
            None, None, None, None, None,
        )
    };
    Ok(NesReport {
        nes2, mapper, mapper_high_bits_ambiguous: ambiguous,
        submapper: if nes2 { Some(head[8] >> 4) } else { None },
        trainer_present: trainer,
        battery_flag: head[6] & 0x02 != 0,
        mirroring, console_type: if nes2 { head[7] & 3 } else { 0 },
        prg_rom_bytes: prg_rom, chr_rom_bytes: chr_rom,
        prg_ram_bytes: prg_ram, prg_nvram_bytes: prg_nvram,
        chr_ram_bytes: chr_ram, chr_nvram_bytes: chr_nvram,
        timing_mode: timing, misc_rom_count: misc,
        trainer_offset_bytes: if trainer { Some(16) } else { None },
        prg_offset_bytes: prg_offset, chr_offset_bytes: chr_offset,
        minimum_file_bytes: minimum, actual_file_bytes: file_bytes,
        declared_regions_fit_file: file_bytes >= minimum,
    })
}

/// Strict header-declared minimum-size check; no CRC or cryptographic checksum
/// exists for PRG/CHR data in these header formats.
pub fn verify_nes(head: &[u8], file_bytes: u64) -> io::Result<NesReport> {
    let report = inspect_nes(head, file_bytes)?;
    if !report.declared_regions_fit_file {
        return Err(bad("NES declared PRG/CHR bytes extend beyond supplied file"));
    }
    if report.nes2 && report.misc_rom_count == Some(0)
        && file_bytes != report.minimum_file_bytes
    {
        return Err(bad("NES 2.0 file has unexpected trailing bytes without misc ROM flag"));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy() -> [u8;16] {
        let mut bytes = [0u8;16];
        bytes[..4].copy_from_slice(b"NES\x1a");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes
    }
    #[test]
    fn old_ines_reports_mapper_mirroring_and_battery() {
        let mut head = legacy();
        head[6] = 0x33;
        head[7] = 0x40;
        let report = inspect_nes(&head, 16+32768+8192).unwrap();
        assert!(!report.nes2);
        assert_eq!(report.mapper, 0x43);
        assert_eq!(report.mirroring, "vertical");
        assert!(report.battery_flag);
        assert_eq!(report.prg_ram_bytes, None);
        assert!(verify_nes(&head, 16+32768+8192).is_ok());
    }
    #[test]
    fn polluted_old_ines_does_not_trust_high_mapper_nibble() {
        let mut head = legacy();
        head[6] = 0x30;
        head[7] = 0xf0;
        head[12] = b'D';
        let report = inspect_nes(&head, 16+32768+8192).unwrap();
        assert!(report.mapper_high_bits_ambiguous);
        assert_eq!(report.mapper, 3);
    }
    #[test]
    fn nes2_extended_mapper_ram_and_trainer() {
        let mut head = legacy();
        head[6] = 0x45; // mapper 4, vertical, trainer
        head[7] = 0xa8; // mapper high 0xA0 + NES2
        head[8] = 0x21; // submapper 2; mapper high 0x100
        head[9] = 0;
        head[10] = 0x76; // NV RAM 8 KiB; RAM 4 KiB
        head[11] = 0x07; // CHR RAM 8 KiB
        let file_bytes = 16+512+32768+8192;
        let result = verify_nes(&head, file_bytes).unwrap();
        assert_eq!(result.mapper, 0x1a4);
        assert_eq!(result.submapper, Some(2));
        assert_eq!(result.trainer_offset_bytes, Some(16));
        assert_eq!(result.prg_offset_bytes, 528);
        assert_eq!(result.prg_ram_bytes, Some(4096));
        assert_eq!(result.prg_nvram_bytes, Some(8192));
        assert_eq!(result.chr_ram_bytes, Some(8192));
        assert_eq!(result.chr_nvram_bytes, None);
    }
    #[test]
    fn nes2_exponent_multiplier_and_large_size_overflow() {
        let mut head = legacy();
        head[7] = 0x08;
        head[9] = 0x0f; // exponent form for PRG
        head[4] = (14 << 2) | 1; // 2^14 * 3 bytes = 49152
        head[5] = 0;
        let result = inspect_nes(&head, 16+49152).unwrap();
        assert_eq!(result.prg_rom_bytes, 49152);
        assert_eq!(result.chr_rom_bytes, 0);
        head[4] = 0xff; // 2^63 * 7, overflow
        assert!(inspect_nes(&head, 100000).is_err());
    }
    #[test]
    fn truncated_nes2_and_unexpected_trailing_data_fail() {
        let mut head = legacy();
        head[7] = 0x08;
        assert!(verify_nes(&head, 16+32768).unwrap_err()
            .to_string().contains("extend beyond"));
        assert!(verify_nes(&head, 16+32768+8192+64).unwrap_err()
            .to_string().contains("unexpected trailing"));
        head[14] = 1; // misc ROM acknowledged, length not computable
        assert!(verify_nes(&head, 16+32768+8192+64).is_ok());
    }
}
