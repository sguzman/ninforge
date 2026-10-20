//! CIA ticket/TMD consistency observations. The encrypted titlekey and all
//! ticket cryptographic material are deliberately ignored. A matching title
//! ID or version says nothing about certificate chains or authentic signatures.
use crate::{cia, cia_tmd};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};

fn bad(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}
fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().unwrap())
}
fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().unwrap())
}
fn be64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiaTicketReport {
    pub signature_type: u32,
    pub ticket_data_version: u8,
    pub ticket_title_id: u64,
    pub tmd_title_id: u64,
    pub title_id_matches: bool,
    pub ticket_title_version: u16,
    pub tmd_title_version: u16,
    pub title_version_matches: bool,
    pub ticket_signature_verified: bool,
    pub tmd_signature_verified: bool,
    pub titlekey_decrypted: bool,
}

/// Read only the first 4 bytes and minimal declared ticket-data fields.
/// Calls the existing bounded CIA/TMD inspector for the other side. No ticket
/// private material, raw titlekey, or hash/signature data is exposed.
pub fn inspect_cia_ticket<R: Read + Seek>(reader: &mut R) -> io::Result<CiaTicketReport> {
    let outer = cia::inspect_cia(reader)?;
    let metadata = cia_tmd::inspect_cia_tmd(reader)?;
    let ticket = outer
        .sections
        .iter()
        .find(|section| section.name == "ticket")
        .ok_or_else(|| bad("CIA ticket section missing"))?;
    reader.seek(SeekFrom::Start(ticket.offset_bytes))?;
    let mut sig = [0u8; 4];
    reader.read_exact(&mut sig)?;
    let signature_type = be32(&sig);
    let base = cia_tmd::signed_header_base(signature_type)
        .ok_or_else(|| bad("CIA ticket signature type unsupported"))?;
    if ticket.size_bytes < base + 0x210 {
        return Err(bad("CIA ticket section truncated before full ticket data"));
    }
    let mut head = [0u8; 0xb0];
    reader.seek(SeekFrom::Start(ticket.offset_bytes + base))?;
    reader.read_exact(&mut head)?;
    let version = head[0x7c];
    if version != 1 {
        return Err(bad("CIA ticket is not a supported 3DS v1 ticket"));
    }
    let title_id = be64(&head[0x9c..0xa4]);
    let title_version = be16(&head[0xa6..0xa8]);
    Ok(CiaTicketReport {
        signature_type,
        ticket_data_version: version,
        ticket_title_id: title_id,
        tmd_title_id: metadata.title_id,
        title_id_matches: title_id == metadata.title_id,
        ticket_title_version: title_version,
        tmd_title_version: metadata.title_version,
        title_version_matches: title_version == metadata.title_version,
        ticket_signature_verified: false,
        tmd_signature_verified: false,
        titlekey_decrypted: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn fixture() -> Vec<u8> {
        let cert = 0x80usize;
        let ticket = 0x350usize;
        let tmd = 0x140usize + 0x9c4 + 0x30;
        let content = 0x400usize;
        let mut raw = vec![0u8; 0x2020];
        raw[..4].copy_from_slice(&0x2020u32.to_le_bytes());
        raw[8..12].copy_from_slice(&(cert as u32).to_le_bytes());
        raw[12..16].copy_from_slice(&(ticket as u32).to_le_bytes());
        raw[16..20].copy_from_slice(&(tmd as u32).to_le_bytes());
        raw[24..32].copy_from_slice(&(content as u64).to_le_bytes());
        raw[0x20] = 0x80;
        let mut cursor = 0x2040usize;
        for len in [cert, ticket, tmd, content] {
            raw.resize(cursor + len, 0);
            cursor = (cursor + len + 63) & !63;
        }
        let ticket_at = 0x2040 + cert;
        raw[ticket_at..ticket_at + 4].copy_from_slice(&0x0001_0004u32.to_be_bytes());
        let ticket_data = ticket_at + 0x140;
        raw[ticket_data + 0x7c] = 1;
        raw[ticket_data + 0x9c..ticket_data + 0xa4]
            .copy_from_slice(&0x4000000123456u64.to_be_bytes());
        raw[ticket_data + 0xa6..ticket_data + 0xa8].copy_from_slice(&8u16.to_be_bytes());
        let tmd_at = 0x2040 + cert + ((ticket + 63) & !63);
        raw[tmd_at..tmd_at + 4].copy_from_slice(&0x0001_0004u32.to_be_bytes());
        let tmd_data = tmd_at + 0x140;
        raw[tmd_data + 0x4c..tmd_data + 0x54].copy_from_slice(&0x4000000123456u64.to_be_bytes());
        raw[tmd_data + 0x9c..tmd_data + 0x9e].copy_from_slice(&8u16.to_be_bytes());
        raw[tmd_data + 0x9e..tmd_data + 0xa0].copy_from_slice(&1u16.to_be_bytes());
        let chunk = tmd_data + 0x9c4;
        raw[chunk..chunk + 4].copy_from_slice(&0x1234u32.to_be_bytes());
        raw[chunk + 8..chunk + 16].copy_from_slice(&(content as u64).to_be_bytes());
        raw
    }

    #[test]
    fn reports_matching_ticket_and_tmd_title_id_without_signature_claim() {
        let raw = fixture();
        let report = inspect_cia_ticket(&mut Cursor::new(raw)).unwrap();
        assert!(report.title_id_matches);
        assert!(report.title_version_matches);
        assert_eq!(report.ticket_data_version, 1);
        assert_eq!(report.ticket_title_id, 0x4000000123456);
        assert!(!report.titlekey_decrypted);
        assert!(!report.ticket_signature_verified);
        assert!(!report.tmd_signature_verified);
    }

    #[test]
    fn mismatched_title_id_and_version_remain_observable() {
        let mut raw = fixture();
        let data = 0x2040 + 0x80 + 0x140;
        raw[data + 0x9c..data + 0xa4].copy_from_slice(&0x4000000ABCDEFu64.to_be_bytes());
        raw[data + 0xa6..data + 0xa8].copy_from_slice(&9u16.to_be_bytes());
        let got = inspect_cia_ticket(&mut Cursor::new(raw)).unwrap();
        assert!(!got.title_id_matches);
        assert!(!got.title_version_matches);
    }

    #[test]
    fn rejects_ticket_version_zero_and_unknown_signature_type() {
        let mut raw = fixture();
        raw[0x2040 + 0x80 + 0x140 + 0x7c] = 0;
        assert!(inspect_cia_ticket(&mut Cursor::new(raw))
            .unwrap_err()
            .to_string()
            .contains("v1"));
        let mut raw = fixture();
        raw[0x2040 + 0x80..0x2040 + 0x84].fill(0);
        assert!(inspect_cia_ticket(&mut Cursor::new(raw))
            .unwrap_err()
            .to_string()
            .contains("signature type unsupported"));
    }

    #[test]
    fn detects_ticket_structural_truncation() {
        let mut raw = fixture();
        raw[12..16].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(inspect_cia_ticket(&mut Cursor::new(raw)).is_err());
    }
}
