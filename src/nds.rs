//! Nintendo DS header-defined regions. Section names are synthetic, not ROM paths.
use crate::Entry;
use std::io::{self, ErrorKind};

const FIELDS: [(&str, usize, usize); 6] = [
    ("arm9.bin", 0x20, 0x2c),
    ("arm7.bin", 0x30, 0x3c),
    ("fnt.bin", 0x40, 0x44),
    ("fat.bin", 0x48, 0x4c),
    ("arm9_overlays.bin", 0x50, 0x54),
    ("arm7_overlays.bin", 0x58, 0x5c),
];

/// Checked bounds for ROM sections; no decryption or filesystem traversal.
pub(crate) fn sections(header: &[u8], bytes: u64) -> io::Result<Vec<Entry>> {
    if header.len() < 0x60 {
        return Err(io::Error::new(ErrorKind::InvalidData, "NDS header truncated"));
    }
    let mut entries = Vec::new();
    for (name, offset_at, size_at) in FIELDS {
        let offset = u64::from(u32::from_le_bytes(header[offset_at..offset_at + 4].try_into().unwrap()));
        let size = u64::from(u32::from_le_bytes(header[size_at..size_at + 4].try_into().unwrap()));
        if offset == 0 && size == 0 { continue; }
        if offset == 0 || size == 0 || offset.checked_add(size).is_none_or(|end| end > bytes) {
            return Err(io::Error::new(ErrorKind::InvalidData, format!("NDS {name} extends outside the input")));
        }
        entries.push(Entry { name: name.to_string(), offset, size });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_sections_and_rejects_bad_spans() {
        let mut header = vec![0; 0x160];
        header[0x20..0x24].copy_from_slice(&0x200u32.to_le_bytes());
        header[0x2c..0x30].copy_from_slice(&0x40u32.to_le_bytes());
        let entries = sections(&header, 0x300).unwrap();
        assert_eq!(entries[0], Entry { name: "arm9.bin".into(), offset: 0x200, size: 0x40 });
        assert!(sections(&header, 0x23f).is_err());
        header[0x2c..0x30].copy_from_slice(&0u32.to_le_bytes());
        assert!(sections(&header, 0x300).is_err());
    }
}
