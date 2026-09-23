use anyhow::{bail, Result};
use crate::model::{ImageKind, InitBootImage};

const MAGIC: &[u8; 8] = b"ANDROID!";
const PAGE_SIZE: usize = 4096;
const HEADER_SIZE_V4: u32 = 1584;
const BOOT_SIGNATURE_SIZE_OFFSET: usize = 1580;

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
    let bytes = data.get(offset..end).ok_or_else(|| anyhow::anyhow!("truncated init_boot header"))?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}

pub fn parse_init_boot_image(data: &[u8]) -> Result<InitBootImage> {
    if data.len() < PAGE_SIZE || &data[..8] != MAGIC {
        bail!("not an init_boot image");
    }

    let kernel_size = read_u32(data, 8)?;
    let ramdisk_size = read_u32(data, 12)?;
    let header_size = read_u32(data, 20)?;
    let header_version = read_u32(data, 40)?;

    if header_version != 4 {
        bail!("init_boot requires Android boot header version 4");
    }
    if kernel_size != 0 {
        bail!("init_boot kernel size must be zero");
    }
    if header_size != HEADER_SIZE_V4 {
        bail!("unexpected init_boot header size: {header_size}");
    }

    let boot_signature_size = read_u32(data, BOOT_SIGNATURE_SIZE_OFFSET)?;
    let ramdisk_offset = PAGE_SIZE;
    let ramdisk_end = ramdisk_offset
        .checked_add(ramdisk_size as usize)
        .ok_or_else(|| anyhow::anyhow!("init_boot ramdisk range overflow"))?;

    if ramdisk_end > data.len() {
        bail!("init_boot ramdisk extends past image");
    }

    Ok(InitBootImage {
        kind: ImageKind::InitBoot,
        header_version,
        page_size: PAGE_SIZE as u32,
        header_size,
        kernel_size,
        ramdisk_offset: ramdisk_offset as u64,
        ramdisk_size,
        boot_signature_size,
        ramdisk: data[ramdisk_offset..ramdisk_end].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(kernel_size: u32, ramdisk_size: usize) -> Vec<u8> {
        let mut data = vec![0u8; PAGE_SIZE + ramdisk_size];
        data[..8].copy_from_slice(MAGIC);
        data[8..12].copy_from_slice(&kernel_size.to_le_bytes());
        data[12..16].copy_from_slice(&(ramdisk_size as u32).to_le_bytes());
        data[20..24].copy_from_slice(&HEADER_SIZE_V4.to_le_bytes());
        data[40..44].copy_from_slice(&4u32.to_le_bytes());
        data[BOOT_SIGNATURE_SIZE_OFFSET..BOOT_SIGNATURE_SIZE_OFFSET + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        data[PAGE_SIZE..].fill(0xA5);
        data
    }

    #[test]
    fn parses_init_boot_ramdisk() {
        let parsed = parse_init_boot_image(&image(0, 32)).unwrap();
        assert_eq!(parsed.kind, ImageKind::InitBoot);
        assert_eq!(parsed.header_version, 4);
        assert_eq!(parsed.page_size, 4096);
        assert_eq!(parsed.ramdisk_offset, 4096);
        assert_eq!(parsed.ramdisk_size, 32);
        assert_eq!(parsed.ramdisk.len(), 32);
    }

    #[test]
    fn rejects_nonzero_kernel() {
        assert!(parse_init_boot_image(&image(1, 8)).is_err());
    }

    #[test]
    fn rejects_wrong_header_version() {
        let mut data = image(0, 8);
        data[40..44].copy_from_slice(&3u32.to_le_bytes());
        assert!(parse_init_boot_image(&data).is_err());
    }

    #[test]
    fn rejects_truncated_ramdisk() {
        let mut data = image(0, 16);
        data.truncate(data.len() - 1);
        assert!(parse_init_boot_image(&data).is_err());
    }
}
