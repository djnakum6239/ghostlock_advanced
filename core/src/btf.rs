use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

const BTF_MAGIC: u16 = 0xeb9f;
const HEADER_SIZE: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtfHeader {
    pub version: u8,
    pub flags: u8,
    pub header_length: u32,
    pub type_offset: u32,
    pub type_length: u32,
    pub string_offset: u32,
    pub string_length: u32,
}

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow::anyhow!("BTF header is truncated"))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("BTF header is truncated"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// Parses and bounds-checks a BTF header without interpreting type records.
pub fn parse_btf_header(data: &[u8]) -> Result<BtfHeader> {
    if data.len() < HEADER_SIZE || read_u16_le(data, 0)? != BTF_MAGIC {
        bail!("invalid BTF header");
    }

    let header = BtfHeader {
        version: data[2],
        flags: data[3],
        header_length: read_u32_le(data, 4)?,
        type_offset: read_u32_le(data, 8)?,
        type_length: read_u32_le(data, 12)?,
        string_offset: read_u32_le(data, 16)?,
        string_length: read_u32_le(data, 20)?,
    };

    if header.version != 1 || header.header_length < HEADER_SIZE as u32 {
        bail!("unsupported BTF header version or length");
    }
    let header_end = header.header_length as usize;
    if header_end > data.len() {
        bail!("BTF header extends beyond input");
    }
    let check_region = |offset: u32, length: u32| -> Result<()> {
        let start = header_end
            .checked_add(offset as usize)
            .ok_or_else(|| anyhow::anyhow!("BTF region overflow"))?;
        let end = start
            .checked_add(length as usize)
            .ok_or_else(|| anyhow::anyhow!("BTF region overflow"))?;
        if end > data.len() {
            bail!("BTF region extends beyond input");
        }
        Ok(())
    };
    check_region(header.type_offset, header.type_length)?;
    check_region(header.string_offset, header.string_length)?;
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_btf_header() {
        let mut data = vec![0u8; 32];
        data[0..2].copy_from_slice(&BTF_MAGIC.to_le_bytes());
        data[2] = 1;
        data[4..8].copy_from_slice(&24u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        data[12..16].copy_from_slice(&4u32.to_le_bytes());
        data[16..20].copy_from_slice(&4u32.to_le_bytes());
        data[20..24].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(parse_btf_header(&data).unwrap().version, 1);
    }

    #[test]
    fn rejects_invalid_btf_version() {
        let mut data = vec![0u8; 24];
        data[0..2].copy_from_slice(&BTF_MAGIC.to_le_bytes());
        data[2] = 2;
        data[4..8].copy_from_slice(&24u32.to_le_bytes());
        assert!(parse_btf_header(&data).is_err());
    }
}
