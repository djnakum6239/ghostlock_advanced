use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

const FDT_MAGIC: u32 = 0xd00dfeed;
const HEADER_SIZE: usize = 40;
const MEMORY_RESERVATION_ENTRY_SIZE: usize = 16;

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
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("DTB header is truncated"))?;
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
    let check_region = |offset: u32, size: u32| -> Result<(usize, usize)> {
        let start = offset as usize;
        let end = start
            .checked_add(size as usize)
            .ok_or_else(|| anyhow::anyhow!("DTB region overflow"))?;
        if start < HEADER_SIZE || end > total {
            bail!("DTB region is outside image");
        }
        Ok((start, end))
    };

    let (structure_start, structure_end) =
        check_region(header.structure_offset, header.structure_size)?;
    let (strings_start, strings_end) = check_region(header.strings_offset, header.strings_size)?;

    if structure_start < strings_end && strings_start < structure_end {
        bail!("DTB structure and strings regions overlap");
    }

    let reservation_start = header.memory_reservation_offset as usize;
    let reservation_end = reservation_start
        .checked_add(MEMORY_RESERVATION_ENTRY_SIZE)
        .ok_or_else(|| anyhow::anyhow!("DTB memory reservation table overflow"))?;
    if reservation_start < HEADER_SIZE || reservation_end > total {
        bail!("DTB memory reservation table is truncated");
    }

    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_dtb() -> Vec<u8> {
        let mut data = vec![0u8; 80];
        data[0..4].copy_from_slice(&FDT_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&80u32.to_be_bytes());
        data[8..12].copy_from_slice(&40u32.to_be_bytes());
        data[12..16].copy_from_slice(&48u32.to_be_bytes());
        data[16..20].copy_from_slice(&64u32.to_be_bytes());
        data[20..24].copy_from_slice(&17u32.to_be_bytes());
        data[24..28].copy_from_slice(&16u32.to_be_bytes());
        data[32..36].copy_from_slice(&8u32.to_be_bytes());
        data[36..40].copy_from_slice(&8u32.to_be_bytes());
        data
    }

    #[test]
    fn parses_dtb_header() {
        assert_eq!(parse_dtb_header(&valid_dtb()).unwrap().version, 17);
    }

    #[test]
    fn rejects_invalid_dtb_bounds() {
        let mut data = valid_dtb();
        data[4..8].copy_from_slice(&40u32.to_be_bytes());
        assert!(parse_dtb_header(&data).is_err());
    }

    #[test]
    fn rejects_truncated_memory_reservation_table() {
        let mut data = valid_dtb();
        data[16..20].copy_from_slice(&72u32.to_be_bytes());
        assert!(parse_dtb_header(&data).is_err());
    }

    #[test]
    fn rejects_overlapping_structure_and_strings() {
        let mut data = valid_dtb();
        data[12..16].copy_from_slice(&44u32.to_be_bytes());
        assert!(parse_dtb_header(&data).is_err());
    }
}
