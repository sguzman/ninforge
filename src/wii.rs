//! Bounded read-only Wii disc partition-table and WBFS header inspection.
//!
//! Wii disc table offsets are 32-bit big-endian values in four-byte words.
//! WBFS magic is a container/superblock only: its contents are NOT Wii ISO
//! bytes at the same offsets, and its block map is not yet decoded.
//! Neither parser decrypts content or authenticates partitions.

use std::collections::HashSet;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

const TABLE_BASE: u64 = 0x40000;
const GROUP_COUNT: usize = 4;
const MAX_PARTITIONS: usize = 4096;
const MAX_GROUP_PARTITIONS: u32 = 2048;
const MIN_PARTITION_OFFSET: u64 = TABLE_BASE + 0x20;

fn bad(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn be32(data: &[u8]) -> u32 {
    u32::from_be_bytes(data.try_into().unwrap())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiiPartition {
    pub group: usize,
    pub index: u32,
    pub offset_bytes: u64,
    pub partition_type: u32,
}
impl WiiPartition {
    pub fn kind(&self) -> &'static str {
        match self.partition_type {
            0 => "data",
            1 => "update",
            2 => "channel_installer",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WiiDiscReport {
    pub partitions: Vec<WiiPartition>,
    pub group_counts: [u32; GROUP_COUNT],
    pub group_table_offsets: [Option<u64>; GROUP_COUNT],
    pub region_code: Option<u32>,
}

fn read_at<R: Read + Seek>(input: &mut R, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
    input.seek(SeekFrom::Start(offset))?;
    input.read_exact(bytes)
}

/// Inspect a raw Wii disc image, without opening its encrypted partitions.
/// Partition entries are *addresses*, not file slices: their lengths are not
/// established by this table, so they must not be exposed as extractable files.
pub fn inspect_wii_disc<R: Read + Seek>(
    input: &mut R,
    file_bytes: u64,
) -> io::Result<WiiDiscReport> {
    if file_bytes < TABLE_BASE + 32 {
        return Err(bad("Wii disc missing 0x40000 partition-group table"));
    }
    let mut groups = [0u8; 32];
    read_at(input, TABLE_BASE, &mut groups)?;
    let mut counts = [0u32; GROUP_COUNT];
    let mut offsets = [None; GROUP_COUNT];
    let mut total = 0usize;
    for group in 0..GROUP_COUNT {
        let field = &groups[group * 8..group * 8 + 8];
        let count = be32(&field[..4]);
        let pointer = u64::from(be32(&field[4..8])) * 4;
        counts[group] = count;
        if count == 0 {
            // Empty groups can retain a stale address; no reads are made.
            continue;
        }
        if count > MAX_GROUP_PARTITIONS {
            return Err(bad("Wii partition group exceeds safety cap"));
        }
        total = total.checked_add(count as usize)
            .filter(|value| *value <= MAX_PARTITIONS)
            .ok_or_else(|| bad("Wii partition count exceeds safety cap"))?;
        let table_bytes = u64::from(count) * 8;
        if pointer < MIN_PARTITION_OFFSET
            || pointer % 4 != 0
            || pointer.checked_add(table_bytes).is_none_or(|end| end > file_bytes)
        {
            return Err(bad("Wii partition table pointer outside disc"));
        }
        offsets[group] = Some(pointer);
    }

    let mut partitions = Vec::with_capacity(total);
    let mut seen_offsets = HashSet::new();
    for group in 0..GROUP_COUNT {
        let Some(base) = offsets[group] else { continue; };
        let count = counts[group] as usize;
        let mut table = vec![0u8; count * 8];
        read_at(input, base, &mut table)?;
        for (index, row) in table.chunks_exact(8).enumerate() {
            let position = u64::from(be32(&row[..4])) * 4;
            let partition_type = be32(&row[4..8]);
            // A partition contains a 0x2c0-byte ticket/metadata header.
            // Do not parse encrypted data, infer its length, or create entries.
            if position < MIN_PARTITION_OFFSET
                || position.checked_add(0x2c0).is_none_or(|end| end > file_bytes)
            {
                return Err(bad("Wii partition header outside disc"));
            }
            if !seen_offsets.insert(position) {
                return Err(bad("Wii partition table has duplicate offsets"));
            }
            partitions.push(WiiPartition {
                group,
                index: index as u32,
                offset_bytes: position,
                partition_type,
            });
        }
    }
    let region_code = if file_bytes >= 0x4e004 {
        let mut region = [0u8; 4];
        read_at(input, 0x4e000, &mut region)?;
        Some(be32(&region))
    } else {
        None
    };
    Ok(WiiDiscReport {
        partitions, group_counts: counts,
        group_table_offsets: offsets, region_code,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WbfsHeader {
    pub host_sector_bytes: u64,
    pub wbfs_sector_bytes: u64,
    pub declared_host_sectors: u32,
    pub declared_capacity_bytes: u64,
    pub occupied_disc_slots: usize,
    pub available_disc_slots: usize,
    pub file_bytes: u64,
}

/// Parse a WBFS superblock and its first-sector disc-slot array.
/// A standalone/sparse WBFS image may be smaller than the logical volume.
/// Slot presence does not validate the disc block map or embedded game data.
pub fn inspect_wbfs<R: Read + Seek>(
    input: &mut R,
    file_bytes: u64,
) -> io::Result<WbfsHeader> {
    if file_bytes < 12 {
        return Err(bad("WBFS superblock truncated"));
    }
    let mut preface = [0u8; 12];
    read_at(input, 0, &mut preface)?;
    if &preface[..4] != b"WBFS" {
        return Err(bad("WBFS magic mismatch"));
    }
    let sectors = be32(&preface[4..8]);
    let host_shift = preface[8];
    let wbfs_shift = preface[9];
    if sectors == 0 || !(9..=16).contains(&host_shift)
        || !(15..=25).contains(&wbfs_shift) || wbfs_shift < host_shift
    {
        return Err(bad("WBFS sector parameters unsupported or invalid"));
    }
    let host = 1u64 << host_shift;
    let wbfs = 1u64 << wbfs_shift;
    if file_bytes < host {
        return Err(bad("WBFS file shorter than first host sector"));
    }
    let declared = u64::from(sectors)
        .checked_mul(host)
        .ok_or_else(|| bad("WBFS declared capacity overflow"))?;
    if declared < host || declared < wbfs {
        return Err(bad("WBFS declared volume smaller than its allocation unit"));
    }
    let mut first_sector = vec![0u8; host as usize];
    read_at(input, 0, &mut first_sector)?;
    let slots = &first_sector[12..];
    let occupied = slots.iter().filter(|value| **value != 0).count();
    Ok(WbfsHeader {
        host_sector_bytes: host,
        wbfs_sector_bytes: wbfs,
        declared_host_sectors: sectors,
        declared_capacity_bytes: declared,
        occupied_disc_slots: occupied,
        available_disc_slots: slots.len(),
        file_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn disc(groups: &[(usize, Vec<(u32, u32)>)]) -> Vec<u8> {
        let mut raw = vec![0u8; 0x80000];
        raw[0x18..0x1c].copy_from_slice(&[0x5d, 0x1c, 0x9e, 0xa3]);
        raw[..6].copy_from_slice(b"DEMO01");
        raw[0x20..0x2a].copy_from_slice(b"Fixture Wii");
        raw[0x4e000..0x4e004].copy_from_slice(&1u32.to_be_bytes());
        let mut cursor = 0x40020usize;
        for (group, entries) in groups {
            raw[0x40000 + group * 8..0x40004 + group * 8]
                .copy_from_slice(&(entries.len() as u32).to_be_bytes());
            raw[0x40004 + group * 8..0x40008 + group * 8]
                .copy_from_slice(&((cursor as u32) / 4).to_be_bytes());
            for (offset, kind) in entries {
                raw[cursor..cursor + 4].copy_from_slice(&(offset / 4).to_be_bytes());
                raw[cursor + 4..cursor + 8].copy_from_slice(&kind.to_be_bytes());
                cursor += 8;
            }
        }
        raw
    }

    #[test]
    fn reads_all_four_partition_groups_and_unknown_types() {
        let raw = disc(&[
            (0, vec![(0x50000, 1), (0x60000, 0)]),
            (2, vec![(0x70000, 0x4142_4344)]),
        ]);
        let mut input = Cursor::new(&raw);
        let report = inspect_wii_disc(&mut input, raw.len() as u64).unwrap();
        assert_eq!(report.partitions.len(), 3);
        assert_eq!(report.group_counts, [2, 0, 1, 0]);
        assert_eq!(report.partitions[0].kind(), "update");
        assert_eq!(report.partitions[1].kind(), "data");
        assert_eq!(report.partitions[2].kind(), "unknown");
        assert_eq!(report.partitions[2].group, 2);
        assert_eq!(report.region_code, Some(1));
    }

    #[test]
    fn rejects_truncated_table_bad_address_and_duplicates() {
        let mut raw = disc(&[(0, vec![(0x50000, 0)])]);
        raw[0x40004..0x40008].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(inspect_wii_disc(&mut Cursor::new(&raw), raw.len() as u64).is_err());
        raw = disc(&[(0, vec![(0x50000, 0)])]);
        raw[0x40020..0x40024].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(inspect_wii_disc(&mut Cursor::new(&raw), raw.len() as u64).is_err());
        raw = disc(&[(0, vec![(0x50000, 0), (0x50000, 1)])]);
        assert!(inspect_wii_disc(&mut Cursor::new(&raw), raw.len() as u64).is_err());
        raw = disc(&[(0, vec![(0x50000, 0)])]);
        raw.truncate(0x40010);
        assert!(inspect_wii_disc(&mut Cursor::new(&raw), raw.len() as u64).is_err());
    }

    #[test]
    fn refuses_excessive_partition_counts() {
        let mut raw = disc(&[]);
        raw[0x40000..0x40004].copy_from_slice(&4096u32.to_be_bytes());
        assert!(inspect_wii_disc(&mut Cursor::new(&raw), raw.len() as u64).is_err());
    }

    fn wbfs(sector_shift: u8, sectors: u32) -> Vec<u8> {
        let mut raw = vec![0u8; 1usize << sector_shift];
        raw[..4].copy_from_slice(b"WBFS");
        raw[4..8].copy_from_slice(&sectors.to_be_bytes());
        raw[8] = sector_shift;
        raw[9] = 21;
        raw[12] = 1;
        raw
    }

    #[test]
    fn wbfs_reads_first_sector_slots_and_capacity() {
        let raw = wbfs(9, 16384);
        let mut reader = Cursor::new(&raw);
        let report = inspect_wbfs(&mut reader, raw.len() as u64).unwrap();
        assert_eq!(report.host_sector_bytes, 512);
        assert_eq!(report.wbfs_sector_bytes, 2 * 1024 * 1024);
        assert_eq!(report.occupied_disc_slots, 1);
        assert_eq!(report.available_disc_slots, 500);
        assert_eq!(report.declared_capacity_bytes, 8 * 1024 * 1024);
        assert_eq!(report.file_bytes, 512);
    }

    #[test]
    fn wbfs_rejects_bad_shift_short_sector_and_zero_capacity() {
        let mut raw = wbfs(9, 16384);
        raw[8] = 8;
        assert!(inspect_wbfs(&mut Cursor::new(&raw), raw.len() as u64).is_err());
        raw = wbfs(9, 16384);
        raw[9] = 8;
        assert!(inspect_wbfs(&mut Cursor::new(&raw), raw.len() as u64).is_err());
        raw = wbfs(9, 16384);
        raw[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(inspect_wbfs(&mut Cursor::new(&raw), raw.len() as u64).is_err());
        raw = wbfs(9, 16384);
        raw.truncate(128);
        assert!(inspect_wbfs(&mut Cursor::new(&raw), raw.len() as u64).is_err());
    }
}
