//! Read-only GameCube GCM/ISO filesystem-table inspection.
//! All offsets are absolute disc-image byte positions (unlike Wii partitions).
//! Only FST structure and file byte ranges are checked; no content authentication.

use crate::Entry;
use std::collections::HashSet;
use std::io::{self, Read, Seek, SeekFrom};

const HEADER_BYTES: usize = 0x440;
const MAX_FST_BYTES: u32 = 16 * 1024 * 1024;
const MAX_FST_ENTRIES: usize = 100_000;
const MAX_PATH_BYTES: usize = 2048;

#[derive(Debug, Clone)]
pub struct GameCubeDisc {
    pub dol_offset_bytes: u32,
    pub fst_offset_bytes: u32,
    pub fst_size_bytes: u32,
    pub fst_max_size_bytes: u32,
    pub directory_count: usize,
    pub entries: Vec<Entry>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("four-byte field"))
}

/// Parse the bounded FST, resolve nested paths, and reject malformed entries.
/// A successful result is structural evidence only, not game authenticity.
pub fn inspect_gamecube<R: Read + Seek>(
    reader: &mut R,
    file_bytes: u64,
) -> io::Result<GameCubeDisc> {
    if file_bytes < HEADER_BYTES as u64 {
        return Err(invalid("GameCube disc header is truncated"));
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; HEADER_BYTES];
    reader.read_exact(&mut header)?;
    if header[0x1c..0x20] != [0xc2, 0x33, 0x9f, 0x3d] {
        return Err(invalid("GameCube disc magic is missing"));
    }
    let dol_offset = be32(&header[0x420..0x424]);
    let fst_offset = be32(&header[0x424..0x428]);
    let fst_size = be32(&header[0x428..0x42c]);
    let fst_max_size = be32(&header[0x42c..0x430]);
    if !(12..=MAX_FST_BYTES).contains(&fst_size) {
        return Err(invalid(
            "GameCube FST size is invalid or exceeds safety limit",
        ));
    }
    if fst_max_size != 0 && fst_max_size < fst_size {
        return Err(invalid("GameCube FST exceeds the advertised maximum size"));
    }
    let fst_start = u64::from(fst_offset);
    let fst_end = fst_start
        .checked_add(u64::from(fst_size))
        .ok_or_else(|| invalid("GameCube FST range overflow"))?;
    if fst_start < HEADER_BYTES as u64 || fst_end > file_bytes {
        return Err(invalid("GameCube FST extends outside the disc image"));
    }
    if dol_offset != 0
        && (u64::from(dol_offset) < HEADER_BYTES as u64 || u64::from(dol_offset) >= file_bytes)
    {
        return Err(invalid(
            "GameCube main DOL offset is outside the disc image",
        ));
    }

    reader.seek(SeekFrom::Start(fst_start))?;
    let mut fst = vec![0u8; fst_size as usize];
    reader.read_exact(&mut fst)?;
    if fst[0] != 1 || fst[1..8] != [0; 7] {
        return Err(invalid("GameCube FST root is not a canonical directory"));
    }
    let entry_count = be32(&fst[8..12]) as usize;
    if entry_count == 0 || entry_count > MAX_FST_ENTRIES {
        return Err(invalid("GameCube FST entry count exceeds safety limit"));
    }
    let table_bytes = entry_count
        .checked_mul(12)
        .ok_or_else(|| invalid("GameCube FST table size overflow"))?;
    if table_bytes > fst.len() {
        return Err(invalid("GameCube FST entries extend beyond the table"));
    }

    let strings = &fst[table_bytes..];
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut ranges = Vec::new();
    // (directory entry index, index immediately following subtree, full path)
    let mut stack = vec![(0usize, entry_count, String::new())];
    let mut directories = 1usize;

    for index in 1..entry_count {
        while stack.last().is_some_and(|item| index >= item.1) {
            stack.pop();
        }
        let (parent_index, parent_end, parent_path) = stack
            .last()
            .ok_or_else(|| invalid("GameCube FST entry is outside its parent directory"))?;
        let start = index * 12;
        let item = &fst[start..start + 12];
        if item[0] > 1 {
            return Err(invalid("GameCube FST entry has an unsupported type"));
        }
        let name_offset = ((item[1] as usize) << 16) | ((item[2] as usize) << 8) | item[3] as usize;
        let tail = strings
            .get(name_offset..)
            .ok_or_else(|| invalid("GameCube FST filename offset is invalid"))?;
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid("GameCube FST filename is unterminated"))?;
        let name_bytes = &tail[..end];
        if name_bytes.is_empty()
            || name_bytes == b"."
            || name_bytes == b".."
            || name_bytes
                .iter()
                .any(|byte| *byte == b'/' || *byte == b'\\' || *byte < 0x20 || *byte == 0x7f)
        {
            return Err(invalid("GameCube FST contains an unsafe filename"));
        }
        // A later encoding-aware adapter can support original Shift-JIS names.
        // Never invent or silently replace names that cannot be represented.
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| invalid("GameCube FST filename is not UTF-8"))?;
        let path = if parent_path.is_empty() {
            name.to_owned()
        } else {
            format!("{parent_path}/{name}")
        };
        if path.len() > MAX_PATH_BYTES || !seen.insert(path.clone()) {
            return Err(invalid(
                "GameCube FST contains a duplicate or overlong path",
            ));
        }

        let field = be32(&item[4..8]);
        let last = be32(&item[8..12]);
        if item[0] == 1 {
            if field as usize != *parent_index
                || (last as usize) <= index
                || (last as usize) > *parent_end
            {
                return Err(invalid(
                    "GameCube FST directory parent or subtree is invalid",
                ));
            }
            directories += 1;
            stack.push((index, last as usize, path));
        } else {
            let offset = u64::from(field);
            let size = u64::from(last);
            let end = offset
                .checked_add(size)
                .ok_or_else(|| invalid("GameCube FST file extent overflow"))?;
            if end > file_bytes || (size != 0 && offset < HEADER_BYTES as u64) {
                return Err(invalid(
                    "GameCube FST file extends outside usable image bounds",
                ));
            }
            if size != 0 && offset < fst_end && end > fst_start {
                return Err(invalid("GameCube FST file overlaps the filesystem table"));
            }
            if size != 0 {
                ranges.push((offset, end));
            }
            entries.push(Entry {
                name: path,
                offset,
                size,
            });
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|window| window[0].1 > window[1].0) {
        return Err(invalid("GameCube FST file byte ranges overlap"));
    }
    Ok(GameCubeDisc {
        dol_offset_bytes: dol_offset,
        fst_offset_bytes: fst_offset,
        fst_size_bytes: fst_size,
        fst_max_size_bytes: fst_max_size,
        directory_count: directories,
        entries,
    })
}

/// A loadable section from the GameCube main DOL executable.
#[derive(Debug, Clone)]
pub struct DolSection {
    pub kind: &'static str,
    pub slot: usize,
    pub disc_offset_bytes: u64,
    pub size_bytes: u32,
    pub load_address: u32,
}

#[derive(Debug, Clone)]
pub struct MainDolReport {
    pub dol_offset_bytes: u32,
    pub entry_point: u32,
    pub bss_address: u32,
    pub bss_size_bytes: u32,
    pub entrypoint_in_text: bool,
    pub sections: Vec<DolSection>,
}

/// Validate the DOL's 18 optional section spans without reading code bytes.
/// Memory load addresses and entrypoint placement are reported, not trusted.
/// This does not authenticate executables or parse the PowerPC instructions.
pub fn inspect_main_dol<R: Read + Seek>(
    reader: &mut R,
    file_bytes: u64,
    disc: &GameCubeDisc,
) -> io::Result<MainDolReport> {
    let dol_start = u64::from(disc.dol_offset_bytes);
    if dol_start == 0 {
        return Err(invalid("GameCube disc has no main DOL offset"));
    }
    let header_end = dol_start
        .checked_add(0x100)
        .ok_or_else(|| invalid("GameCube DOL header offset overflow"))?;
    if header_end > file_bytes {
        return Err(invalid("GameCube main DOL header is truncated"));
    }
    let fst_start = u64::from(disc.fst_offset_bytes);
    let fst_end = fst_start + u64::from(disc.fst_size_bytes);
    if dol_start < fst_end && header_end > fst_start {
        return Err(invalid("GameCube DOL header overlaps the FST"));
    }
    reader.seek(SeekFrom::Start(dol_start))?;
    let mut header = [0u8; 0x100];
    reader.read_exact(&mut header)?;

    let mut sections = Vec::new();
    let mut ranges = Vec::new();
    for index in 0..18usize {
        let relative = u64::from(be32(&header[index * 4..index * 4 + 4]));
        let address = be32(&header[0x48 + index * 4..0x4c + index * 4]);
        let size = be32(&header[0x90 + index * 4..0x94 + index * 4]);
        if size == 0 && relative == 0 {
            continue;
        }
        if size == 0 || relative < 0x100 {
            return Err(invalid("GameCube DOL has an inconsistent section record"));
        }
        let start = dol_start
            .checked_add(relative)
            .ok_or_else(|| invalid("GameCube DOL section offset overflow"))?;
        let end = start
            .checked_add(u64::from(size))
            .ok_or_else(|| invalid("GameCube DOL section end overflow"))?;
        if end > file_bytes {
            return Err(invalid("GameCube DOL section extends beyond the image"));
        }
        if start < fst_end && end > fst_start {
            return Err(invalid("GameCube DOL section overlaps the FST"));
        }
        ranges.push((start, end));
        sections.push(DolSection {
            kind: if index < 7 { "text" } else { "data" },
            slot: if index < 7 { index } else { index - 7 },
            disc_offset_bytes: start,
            size_bytes: size,
            load_address: address,
        });
    }
    if sections.is_empty() {
        return Err(invalid("GameCube DOL has no loadable sections"));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid("GameCube DOL section byte ranges overlap"));
    }
    let entry_point = be32(&header[0xe0..0xe4]);
    let entrypoint_in_text = sections.iter().any(|section| {
        section.kind == "text"
            && u64::from(section.load_address) <= u64::from(entry_point)
            && u64::from(entry_point)
                < u64::from(section.load_address) + u64::from(section.size_bytes)
    });
    Ok(MainDolReport {
        dol_offset_bytes: disc.dol_offset_bytes,
        entry_point,
        bss_address: be32(&header[0xd8..0xdc]),
        bss_size_bytes: be32(&header[0xdc..0xe0]),
        entrypoint_in_text,
        sections,
    })
}
