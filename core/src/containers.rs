use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerKind {
    OtaZip,
    PayloadBin,
}

pub fn detect_container_kind(data: &[u8]) -> Result<ContainerKind> {
    if data.starts_with(b"CrAU") {
        return Ok(ContainerKind::PayloadBin);
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") || data.starts_with(b"PK\x07\x08") {
        return Ok(ContainerKind::OtaZip);
    }
    bail!("unknown container format")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_payload_container() {
        assert_eq!(detect_container_kind(b"CrAU").unwrap(), ContainerKind::PayloadBin);
    }

    #[test]
    fn detects_zip_variants() {
        assert_eq!(detect_container_kind(b"PK\x03\x04").unwrap(), ContainerKind::OtaZip);
        assert_eq!(detect_container_kind(b"PK\x05\x06").unwrap(), ContainerKind::OtaZip);
        assert_eq!(detect_container_kind(b"PK\x07\x08").unwrap(), ContainerKind::OtaZip);
    }
}
