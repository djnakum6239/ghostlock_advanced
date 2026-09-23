use std::io::Cursor;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OtaZipSummary {
    pub entries: usize,
    pub has_payload: bool,
    pub has_boot: bool,
    pub has_vendor_boot: bool,
    pub has_init_boot: bool,
    pub has_xbl_config: bool,
    pub metadata_entries: usize,
}

/// Inspects an OTA ZIP without executing update scripts or modifying its contents.
pub fn inspect_ota_zip(data: &[u8]) -> Result<OtaZipSummary> {
    if data.len() < 4 {
        bail!("ZIP data is too small");
    }

    let mut archive = ZipArchive::new(Cursor::new(data))?;
    let mut summary = OtaZipSummary {
        entries: archive.len(),
        ..OtaZipSummary::default()
    };

    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name().replace('\\', "/");
        summary.has_payload |= name == "payload.bin";
        summary.has_boot |= name == "boot.img" || name.ends_with("/boot.img");
        summary.has_vendor_boot |= name == "vendor_boot.img" || name.ends_with("/vendor_boot.img");
        summary.has_init_boot |= name == "init_boot.img" || name.ends_with("/init_boot.img");
        summary.has_xbl_config |= name == "xbl_config.img" || name.ends_with("/xbl_config.img");
        if name == "META-INF/com/android/metadata" || name.ends_with("/META-INF/com/android/metadata") {
            summary.metadata_entries += 1;
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};

    #[test]
    fn inspects_known_ota_entries() {
        let mut bytes = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut bytes);
            let options = SimpleFileOptions::default();
            for name in [
                "payload.bin",
                "boot.img",
                "vendor_boot.img",
                "init_boot.img",
                "xbl_config.img",
                "META-INF/com/android/metadata",
            ] {
                writer.start_file(name, options).unwrap();
                writer.write_all(b"test").unwrap();
            }
            writer.finish().unwrap();
        }

        let summary = inspect_ota_zip(bytes.get_ref()).unwrap();
        assert_eq!(summary.entries, 6);
        assert!(summary.has_payload);
        assert!(summary.has_boot);
        assert!(summary.has_vendor_boot);
        assert!(summary.has_init_boot);
        assert!(summary.has_xbl_config);
        assert_eq!(summary.metadata_entries, 1);
    }

    #[test]
    fn rejects_truncated_zip() {
        assert!(inspect_ota_zip(b"PK").is_err());
    }
}
