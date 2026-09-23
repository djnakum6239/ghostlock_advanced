use crate::model::ImageKind;
use crate::{
    boot::parse_boot_image, init_boot::parse_init_boot_image, vendor_boot::parse_vendor_boot_image,
};
use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedImageKind {
    Boot,
    VendorBoot,
    InitBoot,
}

pub fn detect_image_kind(data: &[u8]) -> Result<DetectedImageKind> {
    if data.len() < 8 {
        bail!("image is too small");
    }
    if &data[..8] == b"VNDRBOOT" {
        return Ok(DetectedImageKind::VendorBoot);
    }
    if &data[..8] != b"ANDROID!" {
        bail!("unknown Android image magic");
    }
    if parse_init_boot_image(data).is_ok() {
        return Ok(DetectedImageKind::InitBoot);
    }
    if parse_boot_image(data).is_ok() {
        return Ok(DetectedImageKind::Boot);
    }
    bail!("ANDROID! image did not validate as boot or init_boot")
}

pub fn detect_image_kind_strict(data: &[u8]) -> Result<ImageKind> {
    match detect_image_kind(data)? {
        DetectedImageKind::Boot => Ok(parse_boot_image(data)?.kind),
        DetectedImageKind::VendorBoot => Ok(parse_vendor_boot_image(data)?.kind),
        DetectedImageKind::InitBoot => Ok(parse_init_boot_image(data)?.kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_magic() {
        assert!(detect_image_kind(b"XXXXXXXX").is_err());
    }
}
