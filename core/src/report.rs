use anyhow::Result;

use crate::{
    android_images::detect_image_kind,
    kallsyms::scan_candidates,
    ota_zip::read_ota_entry,
    kernel::{decompress_kernel, extract_kernel},
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
    let detected = detect_image_kind(data);
    let extracted = match detected {
        Ok(crate::android_images::DetectedImageKind::Boot) | Err(_) => Some(extract_kernel(data)?),
        Ok(crate::android_images::DetectedImageKind::VendorBoot)
        | Ok(crate::android_images::DetectedImageKind::InitBoot) => None,
    };
    let (metadata, symbols, validation) = match &extracted {
        Some(kernel) => {
            let analysis_data = decompress_kernel(&kernel.data, &kernel.compression)?;
            let metadata = detect_metadata(&analysis_data);
            let candidate = scan_candidates(&analysis_data).into_iter().next();
            let validation = candidate
                .as_ref()
                .map(|_| ValidationSummary {
                    address_range_valid: true,
                    symbol_names_valid: false,
                    tables_consistent: true,
                })
                .unwrap_or_default();
            let symbols = candidate
                .map(|candidate| SymbolSummary {
                    source: Some("embedded-kallsyms".into()),
                    count: Some(candidate.num_syms),
                    confidence: candidate.confidence,
                })
                .unwrap_or_default();
            (metadata, symbols, validation)
        }
        None => (crate::metadata::KernelMetadata::default(), SymbolSummary::default(), ValidationSummary::default()),
    };

    let image = match detected {
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
            compression: extracted.as_ref().and_then(|kernel| compression_name(&kernel.compression)),
        },
        symbols,
        validation,
    })
}

/// Analyzes an image stored as a named entry in an OTA ZIP package.
pub fn analyze_ota_entry(data: &[u8], entry_name: &str) -> Result<AnalysisReport> {
    let image = read_ota_entry(data, entry_name)?;
    analyze_image(&image)
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
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"kernel").unwrap();
        let kernel = encoder.finish().unwrap();
        let report = analyze_image(&kernel).unwrap();
        assert_eq!(report.kernel.compression.as_deref(), Some("gzip"));
    }

    #[test]
    fn reports_embedded_kallsyms_candidate() {
        let mut kernel = vec![0u8; 42 + 256 * 2];
        kernel[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        kernel[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        kernel[16..20].copy_from_slice(&2u32.to_le_bytes());
        kernel[20..24].copy_from_slice(&[1, 2, 3, 0]);
        kernel[24..42].copy_from_slice(b"A\0B\0C\0D\0E\0F\0G\0H\0I\0");
        for index in 0..256usize {
            let value = (index.min(8) * 2) as u16;
            let offset = 42 + index * 2;
            kernel[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        let report = analyze_image(&kernel).unwrap();
        assert_eq!(report.symbols.source.as_deref(), Some("embedded-kallsyms"));
        assert_eq!(report.symbols.count, Some(2));
    }

    #[test]
    fn analyzes_init_boot_without_kernel_payload() {
        let mut image = vec![0u8; 4096 + 4];
        image[..8].copy_from_slice(b"ANDROID!");
        image[8..12].copy_from_slice(&0u32.to_le_bytes());
        image[12..16].copy_from_slice(&4u32.to_le_bytes());
        image[20..24].copy_from_slice(&1584u32.to_le_bytes());
        image[40..44].copy_from_slice(&4u32.to_le_bytes());
        image[1580..1584].copy_from_slice(&0u32.to_le_bytes());
        image[4096..4100].copy_from_slice(b"test");
        let report = analyze_image(&image).unwrap();
        assert_eq!(report.image.kind, Some(ImageKind::InitBoot));
        assert_eq!(report.kernel.release, None);
    }

    #[test]
    fn reports_metadata_from_compressed_kernel() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"Linux version 5.4.254-qgki-gd8141a929274 #1").unwrap();
        let compressed = encoder.finish().unwrap();
        let report = analyze_image(&compressed).unwrap();
        assert_eq!(report.kernel.compression.as_deref(), Some("gzip"));
        assert_eq!(report.kernel.release.as_deref(), Some("5.4.254-qgki-gd8141a929274"));
    }

    #[test]
    fn reports_raw_kernel_architecture() {
        let mut kernel = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        kernel.resize(20, 0);
        kernel[18] = 0xb7;
        kernel[19] = 0x00;
        kernel.extend_from_slice(b" Linux version 5.4.254-test ");
        let report = analyze_image(&kernel).unwrap();
        assert_eq!(report.kernel.architecture.as_deref(), Some("aarch64"));
    }
}
