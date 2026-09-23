use anyhow::{bail, Result};
use crate::model::{ImageKind, KernelImage};

const MAGIC: &[u8; 8] = b"ANDROID!";

pub fn parse_boot_image(data: &[u8]) -> Result<KernelImage> {
    if data.len() < 44 {
        bail!("image is too small");
    }
    if &data[..8] != MAGIC {
        bail!("not an Android boot image");
    }

    let kernel_size = u32::from_le_bytes(data[8..12].try_into()?) as u64;
    let kernel_addr = u32::from_le_bytes(data[12..16].try_into()?) as u64;
    let ramdisk_size = u32::from_le_bytes(data[16..20].try_into()?) as u64;
    let page_size = u32::from_le_bytes(data[36..40].try_into()?) as u32;
    let header_version = if data.len() >= 164 {
        u32::from_le_bytes(data[40..44].try_into()?)
    } else {
        0
    };

    if page_size == 0 || !page_size.is_power_of_two() {
        bail!("invalid boot page size");
    }

    let kernel_offset = page_size as usize;
    let end = kernel_offset.checked_add(kernel_size as usize)
        .ok_or_else(|| anyhow::anyhow!("kernel range overflow"))?;

    if end > data.len() {
        bail!("kernel extends past image");
    }

    let kind = match header_version {
        0 => ImageKind::BootV0,
        1 => ImageKind::BootV1,
        2 => ImageKind::BootV2,
        3 => ImageKind::BootV3,
        _ => ImageKind::BootV4,
    };

    Ok(KernelImage {
        kind,
        header_version: Some(header_version),
        page_size: Some(page_size),
        kernel_offset: Some(kernel_addr),
        kernel_size: Some(kernel_size),
        kernel: data[kernel_offset..end].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_boot_data() {
        assert!(parse_boot_image(b"not an image").is_err());
    }
}
