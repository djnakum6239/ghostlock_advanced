use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 4] = b"CrAU";
const HEADER_SIZE: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadHeader {
    pub major_version: u64,
    pub manifest_size: u64,
    pub metadata_signature_size: u32,
    pub manifest_offset: u64,
    pub metadata_signature_offset: u64,
}

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data.get(offset..offset + 4).ok_or_else(|| anyhow::anyhow!("payload header is truncated"))?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
}

fn read_u64_be(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data.get(offset..offset + 8).ok_or_else(|| anyhow::anyhow!("payload header is truncated"))?;
    Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
}

/// Parses only the authenticated payload container header; it does not apply or execute updates.
pub fn parse_payload_header(data: &[u8]) -> Result<PayloadHeader> {
    if data.len() < HEADER_SIZE || &data[..4] != MAGIC {
        bail!("invalid payload.bin header");
    }

    let major_version = read_u64_be(data, 4)?;
    if major_version == 0 {
        bail!("unsupported payload version");
    }

    let manifest_size = read_u64_be(data, 12)?;
    let metadata_signature_size = read_u32_be(data, 20)?;
    let manifest_offset = HEADER_SIZE as u64;
    let metadata_signature_offset = manifest_offset
        .checked_add(manifest_size)
        .ok_or_else(|| anyhow::anyhow!("payload manifest offset overflow"))?;
    let end = metadata_signature_offset
        .checked_add(metadata_signature_size as u64)
        .ok_or_else(|| anyhow::anyhow!("payload metadata signature offset overflow"))?;

    if end > data.len() as u64 {
        bail!("payload header references data beyond input");
    }

    Ok(PayloadHeader {
        major_version,
        manifest_size,
        metadata_signature_size,
        manifest_offset,
        metadata_signature_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_payload_header() {
        let mut data = Vec::from(*MAGIC);
        data.extend_from_slice(&2u64.to_be_bytes());
        data.extend_from_slice(&3u64.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(b"abcde");
        let header = parse_payload_header(&data).unwrap();
        assert_eq!(header.major_version, 2);
        assert_eq!(header.manifest_size, 3);
        assert_eq!(header.metadata_signature_size, 2);
        assert_eq!(header.metadata_signature_offset, 27);
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse_payload_header(b"CrAU").is_err());
    }

    #[test]
    fn rejects_out_of_bounds_manifest() {
        let mut data = Vec::from(*MAGIC);
        data.extend_from_slice(&2u64.to_be_bytes());
        data.extend_from_slice(&100u64.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        assert!(parse_payload_header(&data).is_err());
    }
}
