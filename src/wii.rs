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
        total = total
            .checked_add(count as usize)
            .filter(|value| *value <= MAX_PARTITIONS)
            .ok_or_else(|| bad("Wii partition count exceeds safety cap"))?;
        let table_bytes = u64::from(count) * 8;
        if pointer < MIN_PARTITION_OFFSET
            || pointer % 4 != 0
            || pointer
                .checked_add(table_bytes)
                .is_none_or(|end| end > file_bytes)
        {
            return Err(bad("Wii partition table pointer outside disc"));
        }
        offsets[group] = Some(pointer);
    }

    let mut partitions = Vec::with_capacity(total);
    let mut seen_offsets = HashSet::new();
    for group in 0..GROUP_COUNT {
        let Some(base) = offsets[group] else {
            continue;
        };
        let count = counts[group] as usize;
        let mut table = vec![0u8; count * 8];
        read_at(input, base, &mut table)?;
        for (index, row) in table.chunks_exact(8).enumerate() {
            let position = u64::from(be32(&row[..4])) * 4;
            let partition_type = be32(&row[4..8]);
            // A partition contains a 0x2c0-byte ticket/metadata header.
            // Do not parse encrypted data, infer its length, or create entries.
            if position < MIN_PARTITION_OFFSET
                || position
                    .checked_add(0x2c0)
                    .is_none_or(|end| end > file_bytes)
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
        partitions,
        group_counts: counts,
        group_table_offsets: offsets,
        region_code,
    })
}

/// Structural spans declared by a Wii ISO partition's unencrypted header.
/// All offsets below are absolute byte positions within the supplied ISO.
/// These are unauthenticated claims, never evidence of a valid ticket or TMD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiiPartitionHeader {
    pub group: usize,
    pub index: u32,
    pub partition_offset_bytes: u64,
    pub partition_type: u32,
    pub tmd_offset_bytes: u64,
    pub tmd_size_bytes: u64,
    pub cert_offset_bytes: Option<u64>,
    pub cert_size_bytes: u64,
    pub h3_offset_bytes: Option<u64>,
    pub data_offset_bytes: u64,
    pub data_size_bytes: u64,
}

fn word_offset(raw: &[u8]) -> u64 {
    u64::from(be32(raw)) * 4
}

fn checked_partition_span(
    base: u64,
    relative: u64,
    size: u64,
    file_bytes: u64,
    data_start: u64,
) -> io::Result<(u64, u64)> {
    if relative < 0x2c0 || size == 0 {
        return Err(bad(
            "Wii partition metadata span is empty or overlaps its header",
        ));
    }
    let start = base
        .checked_add(relative)
        .ok_or_else(|| bad("Wii partition metadata address overflow"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| bad("Wii partition metadata span overflow"))?;
    if end > data_start || end > file_bytes {
        return Err(bad(
            "Wii partition metadata span outside header area or ISO",
        ));
    }
    Ok((start, end))
}

/// Opt-in header check: read only 28 bytes of *unencrypted* offset/length
/// fields for each partition already identified by the four Wii disc tables.
/// TMD, certificate and H3 bytes are not parsed, trusted, or authenticated.
pub fn inspect_wii_partition_headers<R: Read + Seek>(
    input: &mut R,
    file_bytes: u64,
) -> io::Result<Vec<WiiPartitionHeader>> {
    let disc = inspect_wii_disc(input, file_bytes)?;
    let mut verified = Vec::with_capacity(disc.partitions.len());
    for part in &disc.partitions {
        let metadata_start = part
            .offset_bytes
            .checked_add(0x2a4)
            .ok_or_else(|| bad("Wii partition field offset overflow"))?;
        let metadata_end = metadata_start
            .checked_add(0x1c)
            .ok_or_else(|| bad("Wii partition field end overflow"))?;
        if metadata_end > file_bytes {
            return Err(bad("Wii partition header fields outside ISO"));
        }
        let mut bytes = [0u8; 0x1c];
        read_at(input, metadata_start, &mut bytes)?;
        let tmd_size = u64::from(be32(&bytes[0..4]));
        let tmd_relative = word_offset(&bytes[4..8]);
        let cert_size = u64::from(be32(&bytes[8..12]));
        let cert_relative = word_offset(&bytes[12..16]);
        let h3_relative = word_offset(&bytes[16..20]);
        let data_relative = word_offset(&bytes[20..24]);
        let data_size = word_offset(&bytes[24..28]);
        if data_relative < 0x2c0 || data_size == 0 {
            return Err(bad("Wii partition has invalid data offset or empty data"));
        }
        let data_start = part
            .offset_bytes
            .checked_add(data_relative)
            .ok_or_else(|| bad("Wii partition data offset overflow"))?;
        let data_end = data_start
            .checked_add(data_size)
            .ok_or_else(|| bad("Wii partition data length overflow"))?;
        if data_end > file_bytes {
            return Err(bad("Wii partition data extent outside ISO"));
        }
        let tmd = checked_partition_span(
            part.offset_bytes,
            tmd_relative,
            tmd_size,
            file_bytes,
            data_start,
        )?;
        let cert = if cert_size == 0 && cert_relative == 0 {
            None
        } else {
            Some(checked_partition_span(
                part.offset_bytes,
                cert_relative,
                cert_size,
                file_bytes,
                data_start,
            )?)
        };
        let h3 = if h3_relative == 0 {
            None
        } else {
            Some(checked_partition_span(
                part.offset_bytes,
                h3_relative,
                0x18000,
                file_bytes,
                data_start,
            )?)
        };
        let mut ranges = vec![tmd];
        if let Some(span) = cert {
            ranges.push(span);
        }
        if let Some(span) = h3 {
            ranges.push(span);
        }
        ranges.sort_by_key(|span| span.0);
        if ranges.windows(2).any(|window| window[0].1 > window[1].0) {
            return Err(bad("Wii partition metadata spans overlap"));
        }
        verified.push(WiiPartitionHeader {
            group: part.group,
            index: part.index,
            partition_offset_bytes: part.offset_bytes,
            partition_type: part.partition_type,
            tmd_offset_bytes: tmd.0,
            tmd_size_bytes: tmd_size,
            cert_offset_bytes: cert.map(|span| span.0),
            cert_size_bytes: cert_size,
            h3_offset_bytes: h3.map(|span| span.0),
            data_offset_bytes: data_start,
            data_size_bytes: data_size,
        });
    }
    Ok(verified)
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
pub fn inspect_wbfs<R: Read + Seek>(input: &mut R, file_bytes: u64) -> io::Result<WbfsHeader> {
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
    if sectors == 0
        || !(9..=16).contains(&host_shift)
        || !(15..=25).contains(&wbfs_shift)
        || wbfs_shift < host_shift
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

/// Original libwbfs uses a dual-layer Wii disc ceiling of 286864 Wii
/// sectors (0x8000 bytes each) for the per-disc logical block table.
const MAX_WII_SECTORS_PER_DISC: u64 = 143_432 * 2;
const MAX_CHECKED_WBFS_SLOTS: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WbfsDiscMap {
    pub slot: usize,
    pub disc_id: String,
    pub info_offset_bytes: u64,
    pub mapped_blocks: usize,
    pub logical_blocks: usize,
    pub last_physical_block: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WbfsMapReport {
    pub host_sector_bytes: u64,
    pub wbfs_sector_bytes: u64,
    pub declared_capacity_bytes: u64,
    pub disc_record_size_bytes: u64,
    pub logical_blocks_per_disc: usize,
    pub physical_block_count: u64,
    pub checked_slots: usize,
    pub mapped_blocks_total: usize,
    pub discs: Vec<WbfsDiscMap>,
    /// All mapped physical blocks were inside the supplied file.
    /// Neither SHA-1 data hashes nor disc filesystem contents were examined.
    pub block_references_within_file: bool,
}

/// Strict, opt-in WBFS structural verification of occupied slot metadata and
/// their big-endian wlba maps. This reads at most the 64 KiB host header plus
/// 2048 bounded disc records; it never reads mapped game-data blocks.
///
/// WBFS slot N metadata is at host_sector + N * disc_info_sz; the
/// wlba table begins at offset 0x100 within each disc record. Its length is
/// based on the fixed maximum dual-layer Wii disc size, NOT this game's size.
/// Nonzero wlba values refer to one-based physical WBFS sector indices.
pub fn validate_wbfs_maps<R: Read + Seek>(
    input: &mut R,
    file_bytes: u64,
) -> io::Result<WbfsMapReport> {
    let header = inspect_wbfs(input, file_bytes)?;
    let host = header.host_sector_bytes;
    let wbfs = header.wbfs_sector_bytes;
    let physical_blocks = header.declared_capacity_bytes / wbfs;
    if physical_blocks < 2 || physical_blocks > u16::MAX as u64 {
        return Err(bad(
            "WBFS physical block count cannot be represented by wlba indices",
        ));
    }

    let shift = wbfs.trailing_zeros() - 15;
    let logical_blocks = (MAX_WII_SECTORS_PER_DISC >> shift) as usize;
    if logical_blocks == 0 {
        return Err(bad("WBFS disc block table has no addressable entries"));
    }
    let raw_info_size = 0x100u64 + logical_blocks as u64 * 2;
    let disc_record_size = raw_info_size
        .checked_add(host - 1)
        .ok_or_else(|| bad("WBFS disc record alignment overflow"))?
        / host
        * host;

    // The original layout keeps a free-block bitmap at the end of WBFS
    // sector zero. Disc metadata may not overlap this reserved area.
    let bitmap_bytes = physical_blocks / 8;
    let bitmap_start = (wbfs - bitmap_bytes) / host * host;
    if bitmap_start <= host || disc_record_size > bitmap_start - host {
        return Err(bad("WBFS metadata leaves no space for disc records"));
    }
    let possible_records = (bitmap_start - host) / disc_record_size;
    let valid_slots = possible_records.min((host - 12) as u64) as usize;

    let mut first_sector = vec![0u8; host as usize];
    read_at(input, 0, &mut first_sector)?;
    let slot_bytes = &first_sector[12..];
    if slot_bytes[valid_slots..].iter().any(|b| *b != 0) {
        return Err(bad("WBFS occupied slot exceeds disc metadata capacity"));
    }
    let occupied: Vec<usize> = slot_bytes[..valid_slots]
        .iter()
        .enumerate()
        .filter_map(|(index, flag)| match *flag {
            0 => None,
            _ => Some(index),
        })
        .collect();
    if occupied.len() > MAX_CHECKED_WBFS_SLOTS {
        return Err(bad("WBFS occupied disc slots exceed validation safety cap"));
    }
    if occupied.iter().any(|&slot| slot_bytes[slot] != 1) {
        return Err(bad("WBFS disc slot has invalid occupancy flag"));
    }

    let mut discs = Vec::with_capacity(occupied.len());
    let mut assigned = HashSet::new();
    let mut mapped_blocks_total = 0usize;
    for &slot in &occupied {
        let start = host + slot as u64 * disc_record_size;
        let end = start + disc_record_size;
        if end > bitmap_start || end > file_bytes {
            return Err(bad(
                "WBFS occupied disc record truncated or overlaps bitmap",
            ));
        }
        let mut record = vec![0u8; raw_info_size as usize];
        read_at(input, start, &mut record)?;
        if record[0x18..0x1c] != [0x5d, 0x1c, 0x9e, 0xa3] {
            return Err(bad("WBFS occupied disc record is missing Wii disc magic"));
        }
        if !record[..6].iter().all(u8::is_ascii_alphanumeric) {
            return Err(bad("WBFS occupied disc record has invalid disc identifier"));
        }
        let disc_id = std::str::from_utf8(&record[..6])
            .map_err(|_| bad("WBFS occupied disc identifier not UTF-8"))?
            .to_owned();
        let mut mapped = 0usize;
        let mut last = None;
        for block in record[0x100..].chunks_exact(2) {
            let address = u16::from_be_bytes([block[0], block[1]]);
            if address == 0 {
                continue;
            }
            let physical = u64::from(address);
            if physical >= physical_blocks {
                return Err(bad("WBFS block index exceeds declared volume capacity"));
            }
            let block_end = (physical + 1) * wbfs;
            if block_end > file_bytes {
                return Err(bad("WBFS mapped block extends beyond supplied file"));
            }
            if !assigned.insert(address) {
                return Err(bad("WBFS duplicate physical block mapping"));
            }
            mapped += 1;
            mapped_blocks_total += 1;
            last = Some(last.map_or(address, |prev: u16| prev.max(address)));
        }
        discs.push(WbfsDiscMap {
            slot,
            disc_id,
            info_offset_bytes: start,
            mapped_blocks: mapped,
            logical_blocks,
            last_physical_block: last,
        });
    }
    Ok(WbfsMapReport {
        host_sector_bytes: host,
        wbfs_sector_bytes: wbfs,
        declared_capacity_bytes: header.declared_capacity_bytes,
        disc_record_size_bytes: disc_record_size,
        logical_blocks_per_disc: logical_blocks,
        physical_block_count: physical_blocks,
        checked_slots: occupied.len(),
        mapped_blocks_total,
        discs,
        block_references_within_file: true,
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
        raw[0x20..0x2b].copy_from_slice(b"Fixture Wii");
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

    fn partition_header_fixture() -> Vec<u8> {
        let mut raw = disc(&[(0, vec![(0x50000, 0)])]);
        let p = 0x50000usize;
        // Layout fields follow the 0x2a4 ticket. Offsets and data size use
        // 32-bit big-endian words, TMD and cert lengths use plain bytes.
        for (field, value) in [
            (0x2a4, 0x100u32),    // TMD bytes
            (0x2a8, 0x2c0 / 4),   // TMD offset in words
            (0x2ac, 0x80),        // certificate bytes
            (0x2b0, 0x3c0 / 4),   // certificate relative offset
            (0x2b4, 0x4000 / 4),  // H3 relative offset
            (0x2b8, 0x20000 / 4), // encrypted data relative offset
            (0x2bc, 0x8000 / 4),  // encrypted data length
        ] {
            raw[p + field..p + field + 4].copy_from_slice(&value.to_be_bytes());
        }
        raw
    }

    #[test]
    fn wii_partition_header_reads_unencrypted_spans() {
        let raw = partition_header_fixture();
        let result =
            inspect_wii_partition_headers(&mut Cursor::new(&raw), raw.len() as u64).unwrap();
        assert_eq!(result.len(), 1);
        let item = &result[0];
        assert_eq!(item.group, 0);
        assert_eq!(item.partition_type, 0);
        assert_eq!(item.tmd_offset_bytes, 0x502c0);
        assert_eq!(item.tmd_size_bytes, 0x100);
        assert_eq!(item.cert_offset_bytes, Some(0x503c0));
        assert_eq!(item.h3_offset_bytes, Some(0x54000));
        assert_eq!(item.data_offset_bytes, 0x70000);
        assert_eq!(item.data_size_bytes, 0x8000);
    }

    #[test]
    fn wii_partition_header_rejects_invalid_metadata() {
        let mut raw = partition_header_fixture();
        let p = 0x50000usize;
        raw[p + 0x2a8..p + 0x2ac].copy_from_slice(&0x80u32.to_be_bytes());
        assert!(
            inspect_wii_partition_headers(&mut Cursor::new(&raw), raw.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("overlaps its header")
        );
        raw = partition_header_fixture();
        raw[p + 0x2b8..p + 0x2bc].copy_from_slice(&(0x30000u32 / 4).to_be_bytes());
        assert!(
            inspect_wii_partition_headers(&mut Cursor::new(&raw), raw.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("data extent outside ISO")
        );
        raw = partition_header_fixture();
        raw[p + 0x2bc..p + 0x2c0].copy_from_slice(&0u32.to_be_bytes());
        assert!(
            inspect_wii_partition_headers(&mut Cursor::new(&raw), raw.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("empty data")
        );
        raw = partition_header_fixture();
        raw[p + 0x2b4..p + 0x2b8].copy_from_slice(&(0x10000u32 / 4).to_be_bytes());
        assert!(
            inspect_wii_partition_headers(&mut Cursor::new(&raw), raw.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("outside header area")
        );
        raw = partition_header_fixture();
        raw[p + 0x2b0..p + 0x2b4].copy_from_slice(&(0x320u32 / 4).to_be_bytes());
        assert!(
            inspect_wii_partition_headers(&mut Cursor::new(&raw), raw.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );
    }

    #[test]
    fn wii_partition_header_supports_optional_cert_and_h3_absence() {
        let mut raw = partition_header_fixture();
        let p = 0x50000usize;
        for field in [0x2ac, 0x2b0, 0x2b4] {
            raw[p + field..p + field + 4].fill(0);
        }
        let result =
            inspect_wii_partition_headers(&mut Cursor::new(&raw), raw.len() as u64).unwrap();
        assert_eq!(result[0].cert_offset_bytes, None);
        assert_eq!(result[0].h3_offset_bytes, None);
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

    /// Use a 2 MiB WBFS allocation unit, four physical units, two metadata
    /// records and *synthetic* Wii disc-header copies (no encrypted contents).
    fn wbfs_mapped() -> Vec<u8> {
        let wbfs_bytes = 1usize << 21;
        let mut data = vec![0u8; wbfs_bytes * 4];
        data[..4].copy_from_slice(b"WBFS");
        data[4..8].copy_from_slice(&16384u32.to_be_bytes());
        data[8] = 9; // 512-byte host sector
        data[9] = 21; // 2 MiB WBFS sector
        data[12] = 1; // first disc
        data[13] = 1; // second disc
        let first = 512;
        let second = 512 + 9728;
        for (slot, offset, block) in [(0, first, 1u16), (1, second, 2u16)] {
            data[offset..offset + 6].copy_from_slice(if slot == 0 { b"DEMO01" } else { b"DEMO02" });
            data[offset + 0x18..offset + 0x1c].copy_from_slice(&[0x5d, 0x1c, 0x9e, 0xa3]);
            data[offset + 0x100..offset + 0x102].copy_from_slice(&block.to_be_bytes());
        }
        data
    }

    #[test]
    fn deep_wbfs_maps_check_two_real_record_positions() {
        let image = wbfs_mapped();
        let report = validate_wbfs_maps(&mut Cursor::new(&image), image.len() as u64).unwrap();
        assert_eq!(report.physical_block_count, 4);
        assert_eq!(report.disc_record_size_bytes, 9728);
        assert_eq!(report.logical_blocks_per_disc, 4482);
        assert_eq!(report.checked_slots, 2);
        assert_eq!(report.mapped_blocks_total, 2);
        assert_eq!(report.discs[0].disc_id, "DEMO01");
        assert_eq!(report.discs[1].disc_id, "DEMO02");
        assert_eq!(report.discs[0].info_offset_bytes, 512);
        assert_eq!(report.discs[1].info_offset_bytes, 10240);
        assert!(report.block_references_within_file);
    }

    #[test]
    fn deep_wbfs_refuses_truncated_or_invalid_slot_records() {
        let image = wbfs_mapped();
        let mut truncated = image.clone();
        truncated.truncate(10240 + 100);
        // Clear the first physical mapping so the *record truncation* is
        // reached before checking any allocated game-data blocks.
        truncated[512 + 0x100..512 + 0x102].copy_from_slice(&0u16.to_be_bytes());
        assert!(
            validate_wbfs_maps(&mut Cursor::new(&truncated), truncated.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("disc record truncated")
        );
        let mut corrupted = image.clone();
        corrupted[512 + 0x18] ^= 1;
        assert!(
            validate_wbfs_maps(&mut Cursor::new(&corrupted), corrupted.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("disc magic")
        );
        corrupted = image.clone();
        corrupted[13] = 2; // original WBFS slot occupancy is 0 or 1
        assert!(
            validate_wbfs_maps(&mut Cursor::new(&corrupted), corrupted.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("occupancy")
        );
        corrupted = image;
        corrupted[0x0c + 400] = 1; // beyond disc metadata capacity
        assert!(
            validate_wbfs_maps(&mut Cursor::new(&corrupted), corrupted.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("metadata capacity")
        );
    }

    #[test]
    fn deep_wbfs_rejects_out_of_bounds_and_reused_block_indices() {
        let image = wbfs_mapped();
        let mut invalid = image.clone();
        invalid[512 + 0x100..512 + 0x102].copy_from_slice(&4u16.to_be_bytes());
        assert!(
            validate_wbfs_maps(&mut Cursor::new(&invalid), invalid.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("volume capacity")
        );
        invalid = image.clone();
        invalid[512 + 0x102..512 + 0x104].copy_from_slice(&1u16.to_be_bytes());
        assert!(
            validate_wbfs_maps(&mut Cursor::new(&invalid), invalid.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("duplicate physical")
        );
        invalid = image.clone();
        invalid[10240 + 0x100..10240 + 0x102].copy_from_slice(&1u16.to_be_bytes());
        assert!(
            validate_wbfs_maps(&mut Cursor::new(&invalid), invalid.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("duplicate physical")
        );
        invalid = image;
        invalid.truncate(2 * (1 << 21) + 1024);
        assert!(
            validate_wbfs_maps(&mut Cursor::new(&invalid), invalid.len() as u64)
                .unwrap_err()
                .to_string()
                .contains("beyond supplied file")
        );
    }

    #[test]
    fn deep_wbfs_zero_disc_header_can_be_checked_without_disc_reads() {
        let mut raw = wbfs(9, 16384);
        raw[12] = 0;
        let report = validate_wbfs_maps(&mut Cursor::new(&raw), raw.len() as u64).unwrap();
        assert_eq!(report.checked_slots, 0);
        assert_eq!(report.mapped_blocks_total, 0);
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
