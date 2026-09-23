use anyhow::{bail, Result};
use crate::{boot::parse_boot_image, init_boot::parse_init_boot_image, model::{CompressionKind, ExtractedKernel, ImageKind}, vendor_boot::parse_vendor_boot_image};

fn detect_compression(data: &[u8]) -> CompressionKind {
    if data.starts_with(&[0x1f, 0x8b]) { CompressionKind::Gzip }
    else if data.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) { CompressionKind::Xz }
    else if data.starts_with(&[0x04, 0x22, 0x4d, 0x18]) { CompressionKind::Lz4 }
    else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) { CompressionKind::Zstd }
    else { CompressionKind::None }
}

pub fn extract_kernel(data: &[u8]) -> Result<ExtractedKernel> {
    if data.len() < 8 {
        return Ok(ExtractedKernel {
            source: ImageKind::RawKernel,
            data: data.to_vec(),
            source_offset: Some(0),
            compression: detect_compression(data),
        });
    }
    match &data[..8] {
        b"ANDROID!" => {
            if let Ok(image) = parse_boot_image(data) {
                let compression = detect_compression(&image.kernel);
                return Ok(ExtractedKernel {
                    source: image.kind,
                    data: image.kernel,
                    source_offset: image.kernel_offset,
                    compression,
                });
            }
            let _init = parse_init_boot_image(data)?;
            bail!("init_boot contains no kernel payload; use boot.img")
        }
        b"VNDRBOOT" => {
            let _image = parse_vendor_boot_image(data)?;
            bail!("vendor_boot does not contain the Android kernel payload; use boot.img")
        }
        _ => Ok(ExtractedKernel { source: ImageKind::RawKernel, data: data.to_vec(), source_offset: Some(0), compression: detect_compression(data) }),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_kernel_compression_signatures() {
        assert_eq!(detect_compression(&[0x1f, 0x8b]), CompressionKind::Gzip);
        assert_eq!(detect_compression(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), CompressionKind::Xz);
        assert_eq!(detect_compression(&[0x04, 0x22, 0x4d, 0x18]), CompressionKind::Lz4);
        assert_eq!(detect_compression(&[0x28, 0xb5, 0x2f, 0xfd]), CompressionKind::Zstd);
        assert_eq!(detect_compression(b"ELF"), CompressionKind::None);
    }

    #[test]
    fn rejects_init_boot_as_kernel_source() {
        let mut image = vec![0u8; 8192];
        image[..8].copy_from_slice(b"ANDROID!");
        image[8..12].copy_from_slice(&0u32.to_le_bytes());
        image[12..16].copy_from_slice(&1u32.to_le_bytes());
        image[20..24].copy_from_slice(&1584u32.to_le_bytes());
        image[40..44].copy_from_slice(&4u32.to_le_bytes());
        image[4096] = 0x41;
        let err = extract_kernel(&image).unwrap_err().to_string();
        assert!(err.contains("init_boot contains no kernel payload"));
    }
}
