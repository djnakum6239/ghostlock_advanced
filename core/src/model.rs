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
    pub kernel_load_addr: Option<u64>,
    pub kernel_offset: Option<u64>,
    pub kernel_size: Option<u64>,
    pub kernel: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorBootImage {
    pub kind: ImageKind,
    pub header_version: u32,
    pub page_size: u32,
    pub kernel_load_addr: u64,
    pub ramdisk_load_addr: u64,
    pub vendor_ramdisk_offset: u64,
    pub vendor_ramdisk_size: u64,
    pub dtb_offset: u64,
    pub dtb_size: u64,
    pub dtb_load_addr: u64,
    pub vendor_ramdisk_table_offset: Option<u64>,
    pub vendor_ramdisk_table_size: Option<u64>,
    pub bootconfig_offset: Option<u64>,
    pub bootconfig_size: Option<u64>,
    pub vendor_ramdisk: Vec<u8>,
    pub dtb: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitBootImage {
    pub kind: ImageKind,
    pub header_version: u32,
    pub page_size: u32,
    pub header_size: u32,
    pub kernel_size: u32,
    pub ramdisk_offset: u64,
    pub ramdisk_size: u32,
    pub boot_signature_size: u32,
    pub ramdisk: Vec<u8>,
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
    pub build_id: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedKernel {
    pub source: ImageKind,
    pub data: Vec<u8>,
    pub source_offset: Option<u64>,
    pub compression: CompressionKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompressionKind {
    None,
    Gzip,
    Xz,
    Lz4,
    Lzop,
    Zstd,
    Brotli,
    Unknown,
}
