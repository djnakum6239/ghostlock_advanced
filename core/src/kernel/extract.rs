use anyhow::{bail, Result};
use crate::{boot::parse_boot_image, init_boot::parse_init_boot_image, model::{ExtractedKernel, ImageKind}, vendor_boot::parse_vendor_boot_image};

pub fn extract_kernel(data: &[u8]) -> Result<ExtractedKernel> {
    if data.len() < 8 { bail!("image is too small"); }
    match &data[..8] {
        b"ANDROID!" => {
            if let Ok(image) = parse_boot_image(data) {
                return Ok(ExtractedKernel { source: image.kind, data: image.kernel, source_offset: image.kernel_offset });
            }
            let init = parse_init_boot_image(data)?;
            if !init.ramdisk.is_empty() { bail!("init_boot contains no kernel payload"); }
            Ok(ExtractedKernel { source: ImageKind::InitBoot, data: Vec::new(), source_offset: None })
        }
        b"VNDRBOOT" => {
            let image = parse_vendor_boot_image(data)?;
            bail!("vendor_boot does not contain the Android kernel payload; use boot.img")
        }
        _ => Ok(ExtractedKernel { source: ImageKind::RawKernel, data: data.to_vec(), source_offset: Some(0) }),
    }
}
