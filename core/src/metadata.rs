use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KernelMetadata {
    pub release: Option<String>,
    pub build_id: Option<String>,
    pub compiler: Option<String>,
    pub architecture: Option<String>,
    pub compression: Option<String>,
    pub btf_present: bool,
}

pub fn detect_architecture(kernel: &[u8]) -> Option<&'static str> {
    if kernel.len() >= 4 && kernel[..4] == [0x7f, b'E', b'L', b'F'] {
        Some("elf")
    } else if kernel.len() >= 4 && kernel[..4] == [0xd0, 0x0b, 0xb0, 0x0d] {
        Some("arm64-image-or-container")
    } else {
        None
    }
}
