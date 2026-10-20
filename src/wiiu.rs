//! Read-only Wii U WUX sector-deduplication container inspection.
//! WUX sectors contain opaque WUD bytes. No partition parsing, decryption,
//! authenticity check, or reconstruction is attempted.

use std::io::{self, Read, Seek, SeekFrom};

const WUX_HEADER_BYTES: u64 = 32;
const MIN_SECTOR_BYTES: u32 = 0x100;
const MAX_SECTOR_BYTES: u32 = 16 * 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_LOGICAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const WUX_SECOND_MAGIC: [u8; 4] = [0x2e, 0xd0, 0x99, 0x10];

#[derive(Debug, Clone)]
pub struct WuxInfo {
    pub logical_size_bytes: u64,
    pub sector_size_bytes: u32,
    pub flags: u32,
    pub logical_sector_count: u64,
    pub stored_sector_count: u64,
    pub index_table_offset: u64,
    pub sector_array_offset: u64,
}

#[derive(Debug, Clone)]
pub struct WuxIndexReport {
    pub logical_sector_count: u64,
    pub stored_sector_count: u64,
    pub referenced_stored_sectors: u64,
    pub duplicate_references: u64,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("four-byte field"))
}
fn le64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("eight-byte field"))
}
fn align_up(number: u64, factor: u64) -> io::Result<u64> {
    number
        .checked_add(factor - 1)
        .map(|value| value / factor * factor)
        .ok_or_else(|| invalid("WUX sector-array offset overflow"))
}

/// Validate the header, index table extent, and physical sector-array extent.
/// Sector mapping values are NOT read here; opt in with validate_wux_index.
pub fn inspect_wux<R: Read + Seek>(reader: &mut R, bytes: u64) -> io::Result<WuxInfo> {
    if bytes < WUX_HEADER_BYTES {
        return Err(invalid("WUX header is truncated"));
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; WUX_HEADER_BYTES as usize];
    reader.read_exact(&mut header)?;
    if &header[..4] != b"WUX0" || header[4..8] != WUX_SECOND_MAGIC {
        return Err(invalid(
            "WUX header magic does not match the supported format",
        ));
    }
    let sector_size = le32(&header[8..12]);
    if !(MIN_SECTOR_BYTES..=MAX_SECTOR_BYTES).contains(&sector_size)
        || !sector_size.is_power_of_two()
    {
        return Err(invalid(
            "WUX sector size is unsupported or exceeds the safety cap",
        ));
    }
    let logical_size = le64(&header[16..24]);
    if logical_size == 0 || logical_size > MAX_LOGICAL_BYTES {
        return Err(invalid(
            "WUX uncompressed size is unsupported or exceeds safety cap",
        ));
    }
    let factor = u64::from(sector_size);
    let logical_sectors = logical_size
        .checked_add(factor - 1)
        .ok_or_else(|| invalid("WUX logical sector count overflow"))?
        / factor;
    let index_bytes = logical_sectors
        .checked_mul(4)
        .ok_or_else(|| invalid("WUX index table length overflow"))?;
    if index_bytes > MAX_INDEX_BYTES {
        return Err(invalid("WUX index table exceeds memory and safety limits"));
    }
    let index_end = WUX_HEADER_BYTES
        .checked_add(index_bytes)
        .ok_or_else(|| invalid("WUX index table offset overflow"))?;
    if index_end > bytes {
        return Err(invalid("WUX index table extends beyond input"));
    }
    let data_start = align_up(index_end, factor)?;
    if data_start > bytes || (bytes - data_start) % factor != 0 {
        return Err(invalid(
            "WUX stored sector array is truncated or misaligned",
        ));
    }
    let stored_sector_count = (bytes - data_start) / factor;
    if stored_sector_count == 0 || stored_sector_count > logical_sectors {
        return Err(invalid("WUX stored sector count is inconsistent"));
    }

    Ok(WuxInfo {
        logical_size_bytes: logical_size,
        sector_size_bytes: sector_size,
        flags: le32(&header[24..28]),
        logical_sector_count: logical_sectors,
        stored_sector_count,
        index_table_offset: WUX_HEADER_BYTES,
        sector_array_offset: data_start,
    })
}

/// Stream and validate all little-endian WUX sector indices without reading
/// stored WUD sectors. Duplicate indices are valid deduplication references.
pub fn validate_wux_index<R: Read + Seek>(
    reader: &mut R,
    info: &WuxInfo,
) -> io::Result<WuxIndexReport> {
    reader.seek(SeekFrom::Start(info.index_table_offset))?;
    let mut seen = vec![false; info.stored_sector_count as usize];
    let mut remaining = info.logical_sector_count;
    let mut referenced = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    while remaining != 0 {
        let batch = remaining.min((buffer.len() / 4) as u64) as usize;
        let chunk = &mut buffer[..batch * 4];
        reader.read_exact(chunk)?;
        for item in chunk.chunks_exact(4) {
            let mapped = le32(item) as u64;
            if mapped >= info.stored_sector_count {
                return Err(invalid(
                    "WUX logical sector references an absent stored sector",
                ));
            }
            if !seen[mapped as usize] {
                seen[mapped as usize] = true;
                referenced += 1;
            }
        }
        remaining -= batch as u64;
    }
    Ok(WuxIndexReport {
        logical_sector_count: info.logical_sector_count,
        stored_sector_count: info.stored_sector_count,
        referenced_stored_sectors: referenced,
        duplicate_references: info.logical_sector_count - referenced,
    })
}
