use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::{
    btf::{parse_btf_header, BtfHeader},
    containers::{detect_container_kind, ContainerKind},
    dtb::{parse_dtb_header, DtbHeader},
    elf::{parse_elf_header, ElfHeader},
    model::AnalysisReport,
    ota_zip::{inspect_ota_zip, OtaZipSummary},
    payload::{parse_payload_header, PayloadHeader},
    report::analyze_image,
    sparse::{parse_sparse_header, SparseHeader},
    xbl_config::{inspect_xbl_config, XblConfigSummary},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "result")]
pub enum AnalysisResult {
    Image(AnalysisReport),
    OtaZip(OtaZipSummary),
    Payload(PayloadHeader),
    Elf(ElfHeader),
    Dtb(DtbHeader),
    Btf(BtfHeader),
    Sparse(SparseHeader),
    XblConfig(XblConfigSummary),
}

pub fn analyze_input(data: &[u8]) -> Result<AnalysisResult> {
    if let Ok(container) = detect_container_kind(data) {
        return match container {
            ContainerKind::OtaZip => Ok(AnalysisResult::OtaZip(inspect_ota_zip(data)?)),
            ContainerKind::PayloadBin => Ok(AnalysisResult::Payload(parse_payload_header(data)?)),
        };
    }
    if data.starts_with(b"\x7fELF") {
        return Ok(AnalysisResult::Elf(parse_elf_header(data)?));
    }
    if data.len() >= 4 && data[..4] == [0xd0, 0x0d, 0xfe, 0xed] {
        return Ok(AnalysisResult::Dtb(parse_dtb_header(data)?));
    }
    if data.len() >= 2 && data[..2] == [0x9f, 0xeb] {
        return Ok(AnalysisResult::Btf(parse_btf_header(data)?));
    }
    if data.len() >= 4 && data[..4] == [0x3a, 0xff, 0x26, 0xed] {
        return Ok(AnalysisResult::Sparse(parse_sparse_header(data)?));
    }
    if data.starts_with(b"xbl_config")
        || data
            .windows(b"xbl_config".len())
            .any(|window| window == b"xbl_config")
    {
        return Ok(AnalysisResult::XblConfig(inspect_xbl_config(data)?));
    }
    if data.is_empty() {
        bail!("input is empty");
    }
    Ok(AnalysisResult::Image(analyze_image(data)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatches_payload() {
        let mut data = b"CrAU".to_vec();
        data.extend_from_slice(&2u64.to_be_bytes());
        data.extend_from_slice(&0u64.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            analyze_input(&data).unwrap(),
            AnalysisResult::Payload(_)
        ));
    }

    #[test]
    fn dispatches_xbl_metadata_marker() {
        let data = b"xbl_config\0platform=sm7325\0";
        assert!(matches!(
            analyze_input(data).unwrap(),
            AnalysisResult::XblConfig(_)
        ));
    }

    #[test]
    fn rejects_empty_input() {
        assert!(analyze_input(&[]).is_err());
    }
}
