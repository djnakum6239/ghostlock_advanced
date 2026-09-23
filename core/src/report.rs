use anyhow::Result;

use crate::{
    android_images::detect_image_kind,
    kernel::extract_kernel,
    metadata::detect_metadata,
    model::{
        AnalysisReport, ImageKind, ImageSummary, KernelSummary, SymbolSummary, ValidationSummary,
    },
};

fn compression_name(kind: &crate::model::CompressionKind) -> Option<String> {
    match kind {
        crate::model::CompressionKind::None => None,
        crate::model::CompressionKind::Gzip => Some("gzip".into()),
        crate::model::CompressionKind::Xz => Some("xz".into()),
        crate::model::CompressionKind::Lz4 => Some("lz4".into()),
        crate::model::CompressionKind::Lzop => Some("lzop".into()),
        crate::model::CompressionKind::Zstd => Some("zstd".into()),
        crate::model::CompressionKind::Brotli => Some("brotli".into()),
        crate::model::CompressionKind::Unknown => Some("unknown".into()),
    }
}

/// Produces a safe, read-only analysis summary for an Android image or raw kernel.
pub fn analyze_image(data: &[u8]) -> Result<AnalysisReport> {
    let extracted = extract_kernel(data)?;
    let metadata = detect_metadata(&extracted.data);

    let image = match detect_image_kind(data) {
        Ok(crate::android_images::DetectedImageKind::Boot) => {
            let parsed = crate::boot::parse_boot_image(data)?;
            ImageSummary {
                kind: Some(parsed.kind),
                header_version: parsed.header_version,
                page_size: parsed.page_size,
            }
        }
        Ok(crate::android_images::DetectedImageKind::VendorBoot) => {
            let parsed = crate::vendor_boot::parse_vendor_boot_image(data)?;
            ImageSummary {
                kind: Some(parsed.kind),
                header_version: Some(parsed.header_version),
                page_size: Some(parsed.page_size),
            }
        }
        Ok(crate::android_images::DetectedImageKind::InitBoot) => {
            let parsed = crate::init_boot::parse_init_boot_image(data)?;
            ImageSummary {
                kind: Some(parsed.kind),
                header_version: Some(parsed.header_version),
                page_size: Some(parsed.page_size),
            }
        }
        Err(_) => ImageSummary {
            kind: Some(ImageKind::RawKernel),
            ..ImageSummary::default()
        },
    };

    Ok(AnalysisReport {
        image,
        kernel: KernelSummary {
            release: metadata.release,
            architecture: metadata.architecture,
            compression: compression_name(&extracted.compression),
        },
        symbols: SymbolSummary::default(),
        validation: ValidationSummary::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzes_raw_kernel_metadata() {
        let kernel = b"Linux version 5.4.254-qgki-gd8141a929274 #1";
        let report = analyze_image(kernel).unwrap();
        assert_eq!(report.image.kind, Some(ImageKind::RawKernel));
        assert_eq!(
            report.kernel.release.as_deref(),
            Some("5.4.254-qgki-gd8141a929274")
        );
        assert_eq!(report.kernel.compression, None);
    }

    #[test]
    fn reports_kernel_compression() {
        let mut kernel = b"Linux version 5.4.254-test ".to_vec();
        kernel.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00]);
        let report = analyze_image(&kernel).unwrap();
        assert_eq!(report.kernel.compression.as_deref(), Some("gzip"));
    }
}
