use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImageKind {
    BootV0,
    BootV1,
    BootV2,
    BootV3,
    BootV4,
    VendorBoot,
    InitBoot,
    PayloadBin,
    OtaZip,
    RawKernel,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelImage {
    pub kind: ImageKind,
    pub header_version: Option<u32>,
    pub page_size: Option<u32>,
    pub kernel_offset: Option<u64>,
    pub kernel_size: Option<u64>,
    pub kernel: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub image: ImageSummary,
    pub kernel: KernelSummary,
    pub symbols: SymbolSummary,
    pub validation: ValidationSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImageSummary {
    pub kind: Option<ImageKind>,
    pub header_version: Option<u32>,
    pub page_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KernelSummary {
    pub release: Option<String>,
    pub architecture: Option<String>,
    pub compression: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SymbolSummary {
    pub source: Option<String>,
    pub count: Option<usize>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationSummary {
    pub address_range_valid: bool,
    pub symbol_names_valid: bool,
    pub tables_consistent: bool,
}
