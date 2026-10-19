//! Bounded, read-only HFS0 and XCI partition indexing. Hashes are not verified.
use crate::Entry;
use std::collections::HashSet;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

fn bad(s: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, s)
}
fn u32le(x: &[u8]) -> u32 {
    u32::from_le_bytes(x.try_into().unwrap())
}
fn u64le(x: &[u8]) -> u64 {
    u64::from_le_bytes(x.try_into().unwrap())
}

/// Read a HFS0 directory at an absolute offset, bounded to an absolute end.
/// Return absolute byte offsets suitable for extracting individual entries.
pub(crate) fn parse<R: Read + Seek>(
    r: &mut R,
    base: u64,
    limit: u64,
    prefix: &str,
) -> io::Result<Vec<Entry>> {
    let header_end = base
        .checked_add(16)
        .ok_or_else(|| bad("HFS0 header overflow"))?;
    if header_end > limit {
        return Err(bad("HFS0 header truncated"));
    }
    r.seek(SeekFrom::Start(base))?;
    let mut header = [0u8; 16];
    r.read_exact(&mut header)?;
    if &header[0..4] != b"HFS0" {
        return Err(bad("HFS0 magic mismatch"));
    }
    let count = u32le(&header[4..8]);
    let names_size = u32le(&header[8..12]);
    if count > 100_000 || names_size > 16 * 1024 * 1024 {
        return Err(bad("HFS0 table exceeds safety cap"));
    }
    let table_size = u64::from(count) * 64;
    let data_start = header_end
        .checked_add(table_size)
        .and_then(|n| n.checked_add(u64::from(names_size)))
        .ok_or_else(|| bad("HFS0 data offset overflow"))?;
    if data_start > limit {
        return Err(bad("HFS0 table extends past partition"));
    }
    let mut table = vec![0u8; table_size as usize];
    r.read_exact(&mut table)?;
    let mut strings = vec![0u8; names_size as usize];
    r.read_exact(&mut strings)?;
    let mut seen = HashSet::new();
    let mut entries = Vec::with_capacity(count as usize);
    for row in table.chunks_exact(64) {
        let relative = u64le(&row[..8]);
        let size = u64le(&row[8..16]);
        let name_offset = u32le(&row[16..20]) as usize;
        let hashed_size = u64::from(u32le(&row[20..24]));
        if hashed_size > size {
            return Err(bad("HFS0 hashed region exceeds file"));
        }
        let suffix = strings
            .get(name_offset..)
            .ok_or_else(|| bad("HFS0 invalid name offset"))?;
        let end = suffix
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| bad("HFS0 filename not terminated"))?;
        let name =
            std::str::from_utf8(&suffix[..end]).map_err(|_| bad("HFS0 invalid UTF8 filename"))?;
        if name.is_empty()
            || name == "."
            || name == ".."
            || name
                .bytes()
                .any(|b| b == b'/' || b == b'\\' || b < 0x20 || b == 0x7f)
        {
            return Err(bad("HFS0 unsafe filename"));
        }
        if !seen.insert(name.to_owned()) {
            return Err(bad("HFS0 duplicate name"));
        }
        let offset = data_start
            .checked_add(relative)
            .ok_or_else(|| bad("HFS0 offset overflow"))?;
        if offset.checked_add(size).is_none_or(|n| n > limit) {
            return Err(bad("HFS0 entry extends beyond partition"));
        }
        let name = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        entries.push(Entry { name, offset, size });
    }
    let mut spans: Vec<(u64, u64)> = entries
        .iter()
        .filter(|e| e.size > 0)
        .map(|e| (e.offset, e.offset + e.size))
        .collect();
    spans.sort_unstable();
    if spans.windows(2).any(|two| two[0].1 > two[1].0) {
        return Err(bad("HFS0 file data overlap"));
    }
    Ok(entries)
}

/// List the root HFS0 plus one nested partition level, without decryption.
pub(crate) fn parse_xci<R: Read + Seek>(
    r: &mut R,
    head: &[u8],
    length: u64,
) -> io::Result<(u64, Vec<Entry>)> {
    if head.len() < 0x140 {
        return Err(bad("XCI card header truncated"));
    }
    let base = u64le(&head[0x130..0x138]);
    let declared_header = u64le(&head[0x138..0x140]);
    if declared_header < 16 || base.checked_add(declared_header).is_none_or(|n| n > length) {
        return Err(bad("XCI root header bounds invalid"));
    }
    let roots = parse(r, base, length, "root")?;
    let mut entries = roots.clone();
    for root in roots {
        if root.size < 16 {
            continue;
        }
        r.seek(SeekFrom::Start(root.offset))?;
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic == b"HFS0" {
            let limit = root
                .offset
                .checked_add(root.size)
                .ok_or_else(|| bad("XCI partition overflow"))?;
            let children = parse(r, root.offset, limit, &root.name)?;
            if entries
                .len()
                .checked_add(children.len())
                .is_none_or(|n| n > 150_000)
            {
                return Err(bad("XCI listing exceeds safety cap"));
            }
            entries.extend(children);
        }
    }
    Ok((base, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn fixture(name: &str, bytes: &[u8]) -> Vec<u8> {
        let mut out = b"HFS0".to_vec();
        out.extend(1u32.to_le_bytes());
        out.extend(((name.len() + 1) as u32).to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(0u64.to_le_bytes());
        out.extend((bytes.len() as u64).to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend([0u8; 40]);
        out.extend(name.as_bytes());
        out.push(0);
        out.extend(bytes);
        out
    }
    #[test]
    fn reads_and_extracts_entry() {
        let buf = fixture("secure", b"abc");
        let mut cur = Cursor::new(buf.clone());
        let list = parse(&mut cur, 0, buf.len() as u64, "").unwrap();
        assert_eq!(list[0].name, "secure");
        let mut data = Vec::new();
        crate::extract_entry(&mut cur, &list[0], &mut data).unwrap();
        assert_eq!(data, b"abc");
    }
    #[test]
    fn rejects_path_and_hash_and_truncation() {
        let bad_path = fixture("../evil", b"abc");
        assert!(parse(
            &mut Cursor::new(bad_path.clone()),
            0,
            bad_path.len() as u64,
            ""
        )
        .is_err());
        let mut buf = fixture("safe", b"abc");
        buf[0x24..0x28].copy_from_slice(&4u32.to_le_bytes());
        assert!(parse(&mut Cursor::new(buf.clone()), 0, buf.len() as u64, "").is_err());
        buf[0x24..0x28].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse(&mut Cursor::new(buf.clone()), 0, (buf.len() - 1) as u64, "").is_err());
    }
    #[test]
    fn reads_nested_xci_root() {
        let inner = fixture("demo.nca", b"synthetic");
        let outer = fixture("secure", &inner);
        let mut xci = vec![0u8; 0x200];
        xci[0x100..0x104].copy_from_slice(b"HEAD");
        xci[0x130..0x138].copy_from_slice(&0x200u64.to_le_bytes());
        xci[0x138..0x140].copy_from_slice(&0x50u64.to_le_bytes());
        xci.extend(outer);
        let mut reader = Cursor::new(xci.clone());
        let (offset, files) = parse_xci(&mut reader, &xci[..0x200], xci.len() as u64).unwrap();
        assert_eq!(offset, 0x200);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "root/secure");
        assert_eq!(files[1].name, "root/secure/demo.nca");
        assert_eq!(files[1].size, 9);
        assert_eq!(
            crate::inspect(&mut Cursor::new(xci)).unwrap().entries.len(),
            2
        );
    }
}
