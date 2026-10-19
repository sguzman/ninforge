//! Parse a separately obtained, plaintext/decrypted NCA2 or NCA3 header.
//! Raw retail headers are AES-XTS encrypted and cannot be read here.
use crate::{Format, Report};
use std::io::{self, Read, Seek, SeekFrom, ErrorKind};

fn bad(s: &'static str) -> io::Error { io::Error::new(ErrorKind::InvalidData, s) }
fn u32at(b: &[u8], i: usize) -> u32 { u32::from_le_bytes(b[i..i+4].try_into().unwrap()) }
fn u64at(b: &[u8], i: usize) -> u64 { u64::from_le_bytes(b[i..i+8].try_into().unwrap()) }
fn kind(n: u8) -> Option<&'static str> {
    match n { 0=>Some("program"), 1=>Some("meta"), 2=>Some("control"),
      3=>Some("manual"), 4=>Some("data"), 5=>Some("public_data"), _=>None }
}
pub fn inspect_decrypted_nca<R: Read + Seek>(r: &mut R) -> io::Result<Report> {
    let physical = r.seek(SeekFrom::End(0))?;
    if physical < 0x400 { return Err(bad("NCA header shorter than 0x400")); }
    r.seek(SeekFrom::Start(0))?;
    let mut b = [0u8;0x400];
    r.read_exact(&mut b)?;
    if &b[0x200..0x204] != b"NCA2" && &b[0x200..0x204] != b"NCA3" {
        return Err(bad("NCA header not decrypted; encrypted NCAs need keys"));
    }
    if b[0x204] > 1 { return Err(bad("NCA distribution invalid")); }
    let content_type = kind(b[0x205]).ok_or_else(|| bad("NCA content type invalid"))?;
    let declared = u64at(&b,0x208);
    if declared < 0x400 || (physical != 0x400 && declared != physical) {
        return Err(bad("NCA size inconsistent with supplied file"));
    }
    let mut m = Vec::new();
    m.push(("header_state".to_string(), "decrypted".to_string()));
    m.push(("header_only".to_string(), (physical==0x400).to_string()));
    m.push(("content_type".to_string(), content_type.to_string()));
    m.push(("distribution".to_string(), if b[0x204]==0 {"download"} else {"gamecard"}.into()));
    m.push(("nca_version".to_string(), String::from_utf8_lossy(&b[0x200..0x204]).to_string()));
    m.push(("declared_size".to_string(), declared.to_string()));
    m.push(("program_id".to_string(), format!("{:016X}", u64at(&b,0x210))));
    m.push(("content_index".to_string(), u32at(&b,0x218).to_string()));
    m.push(("key_generation_old".to_string(), b[0x206].to_string()));
    m.push(("key_generation".to_string(), b[0x220].to_string()));
    m.push(("key_area_index".to_string(), b[0x207].to_string()));
    if b[0x230..0x240].iter().any(|x| *x!=0) {
        m.push(("rights_id".into(), b[0x230..0x240].iter().map(|x|format!("{x:02X}")).collect()));
    }
    let mut spans = Vec::new();
    for index in 0..4 {
        let start = u64::from(u32at(&b,0x240+index*16)) * 0x200;
        let end = u64::from(u32at(&b,0x244+index*16)) * 0x200;
        if start == 0 && end == 0 {continue;}
        if start < 0xc00 || end <= start || end > declared {
            return Err(bad("NCA filesystem section bounds invalid"));
        }
        spans.push((start,end));
        m.push((format!("section_{index}_offset"),start.to_string()));
        m.push((format!("section_{index}_size"),(end-start).to_string()));
    }
    spans.sort_unstable();
    if spans.windows(2).any(|w|w[0].1>w[1].0) {
        return Err(bad("NCA filesystem sections overlap"));
    }
    m.push(("section_count".into(),spans.len().to_string()));
    Ok(Report{format:Format::SwitchNca,bytes:physical,metadata:m,entries:vec![]})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn fixture() -> Vec<u8> {
        let mut b=vec![0;0x400];
        b[0x200..0x204].copy_from_slice(b"NCA3");
        b[0x205]=1;
        b[0x208..0x210].copy_from_slice(&0x2000u64.to_le_bytes());
        b[0x210..0x218].copy_from_slice(&0x0100AABBCCDDEE00u64.to_le_bytes());
        b[0x240..0x244].copy_from_slice(&6u32.to_le_bytes());
        b[0x244..0x248].copy_from_slice(&16u32.to_le_bytes());
        b
    }
    #[test]
    fn reads_title_type_and_sections() {
        let r=inspect_decrypted_nca(&mut Cursor::new(fixture())).unwrap();
        assert_eq!(r.format,Format::SwitchNca);
        assert!(r.metadata.contains(&("program_id".into(),"0100AABBCCDDEE00".into())));
        assert!(r.metadata.contains(&("section_0_size".into(),"5120".into())));
        assert!(r.metadata.contains(&("content_type".into(),"meta".into())));
    }
    #[test]
    fn refuses_encrypted_and_truncated_input() {
        assert!(inspect_decrypted_nca(&mut Cursor::new(vec![0;0x400])).is_err());
        assert!(inspect_decrypted_nca(&mut Cursor::new(vec![0;0x200])).is_err());
    }
    #[test]
    fn rejects_invalid_ranges_and_size() {
        let mut x=fixture();
        x[0x244..0x248].copy_from_slice(&0xffffu32.to_le_bytes());
        assert!(inspect_decrypted_nca(&mut Cursor::new(x)).is_err());
        let mut x=fixture();
        x.extend([0u8;0x10]);
        assert!(inspect_decrypted_nca(&mut Cursor::new(x)).is_err());
        let mut x=fixture();
        x[0x248..0x24c].copy_from_slice(&7u32.to_le_bytes());
        x[0x24c..0x250].copy_from_slice(&10u32.to_le_bytes());
        assert!(inspect_decrypted_nca(&mut Cursor::new(x)).is_err());
    }
}
