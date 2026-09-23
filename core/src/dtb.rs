use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

const FDT_MAGIC: u32 = 0xd00dfeed;
const HEADER_SIZE: usize = 40;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtbHeader {
    pub total_size: u32,
    pub structure_offset: u32,
    pub strings_offset: u32,
    pub memory_reservation_offset: u32,
    pub version: u32,
    pub last_compatible_version: u32,
    pub boot_cpuid_phys: u32,
    pub strings_size: u32,
    pub structure_size: u32,
}

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data.get(offset..offset + 4).ok_or_else(|| anyhow::anyhow!("DTB header is truncated"))?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
}

/// Parses and bounds-checks a flattened device tree header without modifying the DTB.
pub fn parse_dtb_header(data: &[u8]) -> Result<DtbHeader> {
    if data.len() < HEADER_SIZE || read_u32_be(data, 0)? != FDT_MAGIC {
        bail!("invalid DTB header");
    }

    let header = DtbHeader {
        total_size: read_u32_be(data, 4)?,
        structure_offset: read_u32_be(data, 8)?,
        strings_offset: read_u32_be(data, 12)?,
        memory_reservation_offset: read_u32_be(data, 16)?,
        version: read_u32_be(data, 20)?,
        last_compatible_version: read_u32_be(data, 24)?,
        boot_cpuid_phys: read_u32_be(data, 28)?,
        strings_size: read_u32_be(data, 32)?,
        structure_size: read_u32_be(data, 36)?,
    };

    if header.total_size < HEADER_SIZE as u32 || header.total_size > data.len() as u32 {
        bail!("DTB total size is outside input");
    }
    if header.version < header.last_compatible_version {
        bail!("invalid DTB version ordering");
    }

    let total = header.total_size as usize;
    let check_region = |offset: u32, size: u32| -> Result<()> {
        let start = offset as usize;
        let end = start.checked_add(size as usize).ok_or_else(|| anyhow::anyhow!("DTB region overflow"))?;
        if start < HEADER_SIZE || end > total {
            bail!("DTB region is outside image");
        }
        Ok(())
    };

    check_region(header.structure_offset, header.structure_size)?;
    check_region(header.strings_offset, header.strings_size)?;
    if header.memory_reservation_offset as usize >= total {
        bail!("DTB memory reservation table is outside image");
    }

    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dtb_header() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&64u32.to_be_bytes());
        data[8..12].copy_from_slice(&40u32.to_be_bytes());
        data[12..16].copy_from_slice(&48u32.to_be_bytes());
        data[16..20].copy_from_slice(&40u32.to_be_bytes());
        data[20..24].copy_from_slice(&17u32.to_be_bytes());
        data[24..28].copy_from_slice(&16u32.to_be_bytes());
        data[32..36].copy_from_slice(&8u32.to_be_bytes());
        data[36..40].copy_from_slice(&8u32.to_be_bytes());
        assert_eq!(parse_dtb_header(&data).unwrap().version, 17);
    }

    #[test]
    fn rejects_invalid_dtb_bounds() {
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&40u32.to_be_bytes());
        data[20..24].copy_from_slice(&17u32.to_be_bytes());
        data[24..28].copy_from_slice(&16u32.to_be_bytes());
        data[8..12].copy_from_slice(&40u32.to_be_bytes());
        data[36..40].copy_from_slice(&8u32.to_be_bytes());
        assert!(parse_dtb_header(&data).is_err());
    }
}
