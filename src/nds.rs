//! Nintendo DS header-defined regions. Section names are synthetic, not ROM paths.
use crate::Entry;
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
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


/// Return checked NitroFS files from a DS ROM's FNT/FAT. The generated names
/// are not host paths, and are deliberately namespaced under "nitrofs/".
pub(crate) fn filesystem<R: Read + Seek>(
    input: &mut R, header: &[u8], length: u64,
) -> io::Result<Vec<Entry>> {
    fn u32_at(data: &[u8], start: usize) -> u32 {
        u32::from_le_bytes(data[start..start + 4].try_into().unwrap())
    }
    fn u16_at(data: &[u8], start: usize) -> u16 {
        u16::from_le_bytes(data[start..start + 2].try_into().unwrap())
    }
    fn load<R: Read + Seek>(input: &mut R, offset: u64, size: u64) -> io::Result<Vec<u8>> {
        input.seek(SeekFrom::Start(offset))?;
        let mut data = vec![0u8; size as usize];
        input.read_exact(&mut data)?;
        Ok(data)
    }
    fn error(message: &'static str) -> io::Error {
        io::Error::new(ErrorKind::InvalidData, message)
    }
    if header.len() < 0x50 { return Err(error("DS header too short")); }
    let fnt_offset = u64::from(u32_at(header, 0x40));
    let fnt_size = u64::from(u32_at(header, 0x44));
    let fat_offset = u64::from(u32_at(header, 0x48));
    let fat_size = u64::from(u32_at(header, 0x4c));
    if [fnt_offset, fnt_size, fat_offset, fat_size].iter().all(|n| *n == 0) {
        return Ok(Vec::new());
    }
    if fnt_offset == 0 || fat_offset == 0 || fnt_size < 8 || fnt_size > 16 * 1024 * 1024
        || fat_size == 0 || fat_size % 8 != 0 || fat_size > 8 * 1024 * 1024
        || fnt_offset.checked_add(fnt_size).is_none_or(|end| end > length)
        || fat_offset.checked_add(fat_size).is_none_or(|end| end > length)
        || fat_size / 8 > 100_000
    {
        return Err(error("invalid NitroFS FNT/FAT bounds"));
    }
    let fnt = load(input, fnt_offset, fnt_size)?;
    let fat = load(input, fat_offset, fat_size)?;
    let dir_count = usize::from(u16_at(&fnt, 6));
    if dir_count == 0 || dir_count > 4096 || dir_count * 8 > fnt.len() {
        return Err(error("invalid NitroFS directory count"));
    }
    let mut pending = vec![(0usize, "nitrofs".to_owned())];
    let mut dirs = HashSet::new();
    let mut ids = HashSet::new();
    let mut paths = HashSet::new();
    let mut entries = Vec::new();
    while let Some((dir, prefix)) = pending.pop() {
        if !dirs.insert(dir) { return Err(error("NitroFS directory cycle")); }
        let mut pos = u32_at(&fnt, dir * 8) as usize;
        let mut file_id = usize::from(u16_at(&fnt, dir * 8 + 4));
        if pos < dir_count * 8 || pos >= fnt.len() {
            return Err(error("NitroFS subtable offset outside FNT"));
        }
        loop {
            let tag = *fnt.get(pos).ok_or_else(|| error("unterminated NitroFS directory"))?;
            pos += 1;
            if tag == 0 { break; }
            let len = usize::from(tag & 0x7f);
            if len == 0 || pos.checked_add(len).is_none_or(|end| end > fnt.len()) {
                return Err(error("truncated NitroFS file or directory name"));
            }
            let name = std::str::from_utf8(&fnt[pos..pos + len])
                .map_err(|_| error("non-UTF8 NitroFS name"))?;
            pos += len;
            if name == "." || name == ".."
                || name.bytes().any(|b| b == b'/' || b == b'\\' || b < 0x20 || b == 0x7f)
            {
                return Err(error("unsafe NitroFS path component"));
            }
            let path = format!("{prefix}/{name}");
            if path.len() > 1024 || !paths.insert(path.clone()) {
                return Err(error("duplicate or overlong NitroFS path"));
            }
            if tag & 0x80 != 0 {
                if pos + 2 > fnt.len() { return Err(error("truncated NitroFS directory ID")); }
                let id = u16_at(&fnt, pos);
                pos += 2;
                if id & 0xf000 != 0xf000 { return Err(error("invalid NitroFS directory ID")); }
                let child = usize::from(id & 0x0fff);
                if child >= dir_count { return Err(error("missing NitroFS directory")); }
                if u16_at(&fnt, child * 8 + 6) != (0xf000 | dir as u16) {
                    return Err(error("incorrect NitroFS parent"));
                }
                pending.push((child, path));
            } else {
                if file_id >= fat.len() / 8 || !ids.insert(file_id) {
                    return Err(error("invalid or repeated NitroFS file ID"));
                }
                let start = u64::from(u32_at(&fat, file_id * 8));
                let end = u64::from(u32_at(&fat, file_id * 8 + 4));
                if end < start || end > length {
                    return Err(error("NitroFS file outside ROM"));
                }
                entries.push(Entry { name: path, offset: start, size: end - start });
                file_id += 1;
            }
        }
    }
    if dirs.len() != dir_count { return Err(error("orphan NitroFS directory")); }
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn nitrofs_fixture() -> Vec<u8> {
        let mut rom = vec![0u8; 0x300];
        rom[12..16].copy_from_slice(b"DEMO");
        rom[0x15c..0x15e].copy_from_slice(&[0x56, 0xcf]);
        let mut fnt = vec![0u8; 16];
        fnt[0..4].copy_from_slice(&16u32.to_le_bytes());
        fnt[6..8].copy_from_slice(&2u16.to_le_bytes());
        fnt[8..12].copy_from_slice(&29u32.to_le_bytes());
        fnt[12..14].copy_from_slice(&1u16.to_le_bytes());
        fnt[14..16].copy_from_slice(&0xf000u16.to_le_bytes());
        fnt.extend(b"\x05a.bin\x83sub\x01\xf0\0");
        assert_eq!(fnt.len(), 29);
        fnt.extend(b"\x05b.bin\0");
        rom[0x40..0x44].copy_from_slice(&0x200u32.to_le_bytes());
        rom[0x44..0x48].copy_from_slice(&(fnt.len() as u32).to_le_bytes());
        rom[0x48..0x4c].copy_from_slice(&0x240u32.to_le_bytes());
        rom[0x4c..0x50].copy_from_slice(&16u32.to_le_bytes());
        rom[0x200..0x200 + fnt.len()].copy_from_slice(&fnt);
        for (i, val) in [0x280u32, 0x282, 0x284, 0x287].iter().enumerate() {
            rom[0x240 + i * 4..0x244 + i * 4].copy_from_slice(&val.to_le_bytes());
        }
        rom[0x280..0x282].copy_from_slice(b"ab");
        rom[0x284..0x287].copy_from_slice(b"xyz");
        rom
    }

    #[test]
    fn reads_nested_nitrofs_files() {
        let rom = nitrofs_fixture();
        let mut input = Cursor::new(rom.clone());
        let result = filesystem(&mut input, &rom[..0x160], rom.len() as u64).unwrap();
        assert_eq!(result, vec![
            Entry { name: "nitrofs/a.bin".into(), offset: 0x280, size: 2 },
            Entry { name: "nitrofs/sub/b.bin".into(), offset: 0x284, size: 3 },
        ]);
        let report = crate::inspect(&mut Cursor::new(rom)).unwrap();
        assert_eq!(report.format, crate::Format::NintendoDs);
        assert_eq!(report.entries.len(), 4);
    }

    #[test]
    fn rejects_invalid_nitrofs_bounds_cycles_and_paths() {
        let mut rom = nitrofs_fixture();
        rom[0x244..0x248].copy_from_slice(&0x400u32.to_le_bytes());
        let mut input = Cursor::new(rom.clone());
        assert!(filesystem(&mut input, &rom[..0x160], rom.len() as u64).is_err());
        let mut rom = nitrofs_fixture();
        rom[0x200 + 26..0x200 + 28].copy_from_slice(&0xf000u16.to_le_bytes());
        let mut input = Cursor::new(rom.clone());
        assert!(filesystem(&mut input, &rom[..0x160], rom.len() as u64).is_err());
        let mut rom = nitrofs_fixture();
        rom[0x200 + 17] = b'/';
        let mut input = Cursor::new(rom.clone());
        assert!(filesystem(&mut input, &rom[..0x160], rom.len() as u64).is_err());
    }

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
