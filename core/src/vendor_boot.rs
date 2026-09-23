use anyhow::{bail, Result};
use crate::model::{ImageKind, VendorBootImage};

const MAGIC: &[u8; 8] = b"VNDRBOOT";
const V3_HEADER_MIN: usize = 2112;
const V4_HEADER_MIN: usize = 2128;

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
    let bytes = data.get(offset..end).ok_or_else(|| anyhow::anyhow!("truncated vendor boot header"))?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
    let bytes = data.get(offset..end).ok_or_else(|| anyhow::anyhow!("truncated vendor boot header"))?;
    Ok(u64::from_le_bytes(bytes.try_into()?))
}

fn align_up(value: usize, alignment: usize) -> Result<usize> {
    if alignment == 0 || !alignment.is_power_of_two() { bail!("invalid vendor boot page size"); }
    value.checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .ok_or_else(|| anyhow::anyhow!("vendor boot alignment overflow"))
}

fn range(data: &[u8], offset: usize, size: usize, label: &str) -> Result<Vec<u8>> {
    let end = offset.checked_add(size).ok_or_else(|| anyhow::anyhow!("{label} range overflow"))?;
    if end > data.len() { bail!("{label} extends past vendor boot image"); }
    Ok(data[offset..end].to_vec())
}

pub fn parse_vendor_boot_image(data: &[u8]) -> Result<VendorBootImage> {
    if data.len() < V3_HEADER_MIN || &data[..8] != MAGIC {
        bail!("not a supported vendor_boot image");
    }
    let header_version = read_u32(data, 8)?;
    if header_version != 3 && header_version != 4 { bail!("unsupported vendor_boot header version: {header_version}"); }
    let page_size = read_u32(data, 12)?;
    if page_size == 0 || !page_size.is_power_of_two() { bail!("invalid vendor_boot page size"); }

    let kernel_load_addr = read_u32(data, 16)? as u64;
    let ramdisk_load_addr = read_u32(data, 20)? as u64;
    let vendor_ramdisk_size = read_u32(data, 24)? as usize;
    let header_size = read_u32(data, 2096)? as usize;
    let dtb_size = read_u32(data, 2100)? as usize;
    let dtb_load_addr = read_u64(data, 2104)?;

    let minimum_header = if header_version == 4 { V4_HEADER_MIN } else { V3_HEADER_MIN };
    if header_size < minimum_header || header_size > data.len() { bail!("invalid vendor_boot header size"); }
    let header_end = align_up(header_size, page_size as usize)?;
    let ramdisk_end = header_end.checked_add(vendor_ramdisk_size)
        .ok_or_else(|| anyhow::anyhow!("vendor ramdisk offset overflow"))?;
    let dtb_offset = align_up(ramdisk_end, page_size as usize)?;
    let vendor_ramdisk = range(data, header_end, vendor_ramdisk_size, "vendor ramdisk")?;
    let dtb = range(data, dtb_offset, dtb_size, "DTB")?;

    let (table_offset, table_size, bootconfig_offset, bootconfig_size) = if header_version == 4 {
        let table_size = read_u32(data, 2112)? as usize;
        let entries = read_u32(data, 2116)? as usize;
        let entry_size = read_u32(data, 2120)? as usize;
        let config_size = read_u32(data, 2124)? as usize;
        if entry_size == 0 && entries != 0 { bail!("invalid vendor ramdisk table entry size"); }
        let expected = entries.checked_mul(entry_size).ok_or_else(|| anyhow::anyhow!("vendor ramdisk table overflow"))?;
        if expected > table_size { bail!("vendor ramdisk table is smaller than its entries"); }
        let table_offset = align_up(dtb_offset.checked_add(dtb_size).ok_or_else(|| anyhow::anyhow!("DTB offset overflow"))?, page_size as usize)?;
        let config_offset = align_up(table_offset.checked_add(table_size).ok_or_else(|| anyhow::anyhow!("table offset overflow"))?, page_size as usize)?;
        (Some(table_offset as u64), Some(table_size as u64), Some(config_offset as u64), Some(config_size as u64))
    } else { (None, None, None, None) };

    Ok(VendorBootImage {
        kind: ImageKind::VendorBoot,
        header_version, page_size, kernel_load_addr, ramdisk_load_addr,
        vendor_ramdisk_offset: header_end as u64, vendor_ramdisk_size: vendor_ramdisk_size as u64,
        dtb_offset: dtb_offset as u64, dtb_size: dtb_size as u64, dtb_load_addr,
        vendor_ramdisk_table_offset: table_offset, vendor_ramdisk_table_size: table_size,
        bootconfig_offset, bootconfig_size, vendor_ramdisk, dtb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(version: u32) -> Vec<u8> {
        let page = 4096usize;
        let header = if version == 4 { V4_HEADER_MIN } else { V3_HEADER_MIN };
        let ramdisk = 8usize;
        let ramdisk_off = align_up(header, page).unwrap();
        let dtb_off = align_up(ramdisk_off + ramdisk, page).unwrap();
        let extra = if version == 4 { page * 2 } else { 0 };
        let mut data = vec![0u8; dtb_off + 8 + extra];
        data[..8].copy_from_slice(MAGIC);
        data[8..12].copy_from_slice(&version.to_le_bytes());
        data[12..16].copy_from_slice(&(page as u32).to_le_bytes());
        data[16..20].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        data[20..24].copy_from_slice(&0x8100_0000u32.to_le_bytes());
        data[24..28].copy_from_slice(&(ramdisk as u32).to_le_bytes());
        data[2096..2100].copy_from_slice(&(header as u32).to_le_bytes());
        data[2100..2104].copy_from_slice(&8u32.to_le_bytes());
        data[2104..2112].copy_from_slice(&0x8200_0000u64.to_le_bytes());
        if version == 4 {
            data[2112..2116].copy_from_slice(&0u32.to_le_bytes());
            data[2116..2120].copy_from_slice(&0u32.to_le_bytes());
            data[2120..2124].copy_from_slice(&0u32.to_le_bytes());
            data[2124..2128].copy_from_slice(&0u32.to_le_bytes());
        }
        data[ramdisk_off..ramdisk_off + ramdisk].fill(0xAA);
        data[dtb_off..dtb_off + 8].fill(0xD0);
        data
    }

    #[test]
    fn parses_v3_sections() {
        let parsed = parse_vendor_boot_image(&image(3)).unwrap();
        assert_eq!(parsed.page_size, 4096);
        assert_eq!(parsed.vendor_ramdisk.len(), 8);
        assert_eq!(parsed.dtb.len(), 8);
        assert!(parsed.vendor_ramdisk_table_offset.is_none());
    }

    #[test]
    fn parses_v4_sections() {
        let parsed = parse_vendor_boot_image(&image(4)).unwrap();
        assert_eq!(parsed.header_version, 4);
        assert!(parsed.vendor_ramdisk_table_offset.is_some());
        assert_eq!(parsed.bootconfig_size, Some(0));
    }

    #[test]
    fn rejects_bad_magic() { assert!(parse_vendor_boot_image(b"bad").is_err()); }
}
