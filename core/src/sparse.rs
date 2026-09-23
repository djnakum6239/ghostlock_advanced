use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

const SPARSE_MAGIC: u32 = 0xed26ff3a;
const HEADER_SIZE: usize = 28;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseHeader {
    pub major_version: u16,
    pub minor_version: u16,
    pub file_header_size: u16,
    pub chunk_header_size: u16,
    pub block_size: u32,
    pub total_blocks: u32,
    pub total_chunks: u32,
    pub image_checksum: u32,
}

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow::anyhow!("sparse header is truncated"))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("sparse header is truncated"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

pub fn parse_sparse_header(data: &[u8]) -> Result<SparseHeader> {
    if data.len() < HEADER_SIZE || read_u32_le(data, 0)? != SPARSE_MAGIC {
        bail!("invalid Android sparse image header");
    }
    let header = SparseHeader {
        major_version: read_u16_le(data, 4)?,
        minor_version: read_u16_le(data, 6)?,
        file_header_size: read_u16_le(data, 8)?,
        chunk_header_size: read_u16_le(data, 10)?,
        block_size: read_u32_le(data, 12)?,
        total_blocks: read_u32_le(data, 16)?,
        total_chunks: read_u32_le(data, 20)?,
        image_checksum: read_u32_le(data, 24)?,
    };
    if header.major_version != 1
        || header.file_header_size < HEADER_SIZE as u16
        || header.chunk_header_size < 12
        || header.block_size == 0
        || header.block_size % 4 != 0
    {
        bail!("unsupported or invalid sparse image header");
    }
    if header.file_header_size as usize > data.len() {
        bail!("sparse file header extends beyond input");
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sparse_header() {
        let mut data = vec![0u8; HEADER_SIZE];
        data[0..4].copy_from_slice(&SPARSE_MAGIC.to_le_bytes());
        data[4..6].copy_from_slice(&1u16.to_le_bytes());
        data[8..10].copy_from_slice(&28u16.to_le_bytes());
        data[10..12].copy_from_slice(&12u16.to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[16..20].copy_from_slice(&2u32.to_le_bytes());
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(parse_sparse_header(&data).unwrap().block_size, 4096);
    }

    #[test]
    fn rejects_bad_sparse_magic() {
        assert!(parse_sparse_header(&[0u8; HEADER_SIZE]).is_err());
    }
}
