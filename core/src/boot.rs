use anyhow::{bail, Result};
use crate::model::{ImageKind, KernelImage};

const MAGIC: &[u8; 8] = b"ANDROID!";
const MODERN_PAGE_SIZE: u32 = 4096;

pub fn parse_boot_image(data: &[u8]) -> Result<KernelImage> {
    if data.len() < 44 { bail!("image is too small"); }
    if &data[..8] != MAGIC { bail!("not an Android boot image"); }

    let kernel_size = u32::from_le_bytes(data[8..12].try_into()?) as usize;
    if kernel_size == 0 { bail!("boot image kernel size is zero"); }
    let header_version = u32::from_le_bytes(data[40..44].try_into()?);

    let (page_size, kernel_load_addr, kernel_offset) = match header_version {
        0..=2 => {
            let load_addr = u32::from_le_bytes(data[12..16].try_into()?) as u64;
            let page_size = u32::from_le_bytes(data[36..40].try_into()?);
            if page_size == 0 || !page_size.is_power_of_two() { bail!("invalid legacy boot page size"); }
            (page_size, Some(load_addr), page_size as usize)
        }
        3 | 4 => (MODERN_PAGE_SIZE, None, MODERN_PAGE_SIZE as usize),
        _ => bail!("unsupported Android boot header version: {header_version}"),
    };

    let end = kernel_offset.checked_add(kernel_size)
        .ok_or_else(|| anyhow::anyhow!("kernel range overflow"))?;
    if end > data.len() { bail!("kernel extends past image"); }

    let kind = match header_version {
        0 => ImageKind::BootV0,
        1 => ImageKind::BootV1,
        2 => ImageKind::BootV2,
        3 => ImageKind::BootV3,
        4 => ImageKind::BootV4,
        _ => unreachable!(),
    };

    Ok(KernelImage {
        kind,
        header_version: Some(header_version),
        page_size: Some(page_size),
        kernel_load_addr,
        kernel_offset: Some(kernel_offset as u64),
        kernel_size: Some(kernel_size as u64),
        kernel: data[kernel_offset..end].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(version: u32, page_size: u32, kernel_size: usize) -> Vec<u8> {
        let offset = if version <= 2 { page_size as usize } else { MODERN_PAGE_SIZE as usize };
        let mut data = vec![0u8; offset + kernel_size];
        data[..8].copy_from_slice(MAGIC);
        data[8..12].copy_from_slice(&(kernel_size as u32).to_le_bytes());
        if version <= 2 {
            data[12..16].copy_from_slice(&0x8000_8000u32.to_le_bytes());
            data[36..40].copy_from_slice(&page_size.to_le_bytes());
        }
        data[40..44].copy_from_slice(&version.to_le_bytes());
        for (i, byte) in data[offset..].iter_mut().enumerate() { *byte = (i as u8).wrapping_add(1); }
        data
    }

    #[test]
    fn rejects_non_boot_data() { assert!(parse_boot_image(b"not an image").is_err()); }

    #[test]
    fn parses_legacy_header_and_separates_load_address_from_file_offset() {
        let parsed = parse_boot_image(&image(2, 4096, 16)).unwrap();
        assert_eq!(parsed.kind, ImageKind::BootV2);
        assert_eq!(parsed.page_size, Some(4096));
        assert_eq!(parsed.kernel_load_addr, Some(0x8000_8000));
        assert_eq!(parsed.kernel_offset, Some(4096));
        assert_eq!(parsed.kernel.len(), 16);
    }

    #[test]
    fn parses_modern_header_without_legacy_load_address() {
        let parsed = parse_boot_image(&image(4, 0, 12)).unwrap();
        assert_eq!(parsed.kind, ImageKind::BootV4);
        assert_eq!(parsed.page_size, Some(4096));
        assert_eq!(parsed.kernel_load_addr, None);
        assert_eq!(parsed.kernel_offset, Some(4096));
        assert_eq!(parsed.kernel.len(), 12);
    }

    #[test]
    fn rejects_unsupported_header_version() { assert!(parse_boot_image(&image(5, 4096, 1)).is_err()); }

    #[test]
    fn rejects_truncated_kernel() {
        let mut data = image(2, 4096, 8); data.truncate(data.len() - 1);
        assert!(parse_boot_image(&data).is_err());
    }
}
