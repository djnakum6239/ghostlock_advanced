use anyhow::{bail, Result};
use crate::{boot::parse_boot_image, init_boot::parse_init_boot_image, model::{CompressionKind, ExtractedKernel, ImageKind}, vendor_boot::parse_vendor_boot_image};

fn detect_compression(data: &[u8]) -> CompressionKind {
    if data.starts_with(&[0x1f, 0x8b]) { CompressionKind::Gzip }
    else if data.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) { CompressionKind::Xz }
    else if data.starts_with(&[0x04, 0x22, 0x4d, 0x18]) { CompressionKind::Lz4 }
    else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) { CompressionKind::Zstd }
    else if data.starts_with(&[0x89, 0x4c, 0x5a, 0x4f]) { CompressionKind::Lzop }
    else if data.len() >= 6 && data[..6] == [0x8d, 0x00, 0x00, 0x00, 0x00, 0x00] { CompressionKind::Brotli }
    else if data.starts_with(b"\xD6\xC3\x2F\x00") { CompressionKind::Unknown }
    else { CompressionKind::None }
}

pub fn extract_kernel(data: &[u8]) -> Result<ExtractedKernel> {
    if data.len() < 8 { bail!("image is too small"); }
    match &data[..8] {
        b"ANDROID!" => {
            if let Ok(image) = parse_boot_image(data) {
                return Ok(ExtractedKernel { source: image.kind, data: image.kernel, source_offset: image.kernel_offset, compression: detect_compression(&image.kernel) });
            }
            let init = parse_init_boot_image(data)?;
            if !init.ramdisk.is_empty() { bail!("init_boot contains no kernel payload"); }
            Ok(ExtractedKernel { source: ImageKind::InitBoot, data: Vec::new(), source_offset: None, compression: CompressionKind::None })
        }
        b"VNDRBOOT" => {
            let image = parse_vendor_boot_image(data)?;
            bail!("vendor_boot does not contain the Android kernel payload; use boot.img")
        }
        _ => Ok(ExtractedKernel { source: ImageKind::RawKernel, data: data.to_vec(), source_offset: Some(0), compression: detect_compression(data) }),
    }
}
