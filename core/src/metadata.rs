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
    if kernel.len() >= 20 && kernel[..4] == [0x7f, b'E', b'L', b'F'] {
        let class = kernel[4];
        let data = kernel[5];
        if class == 2 && data == 1 && kernel[18..20] == [0xb7, 0x00] {
            return Some("aarch64");
        }
        if class == 1 && data == 1 && kernel[18..20] == [0x28, 0x00] {
            return Some("arm");
        }
        return Some("elf");
    }
    if kernel.len() >= 4 && kernel[..4] == [0xd0, 0x0b, 0xb0, 0x0d] {
        return Some("arm64-image-or-container");
    }
    None
}

/// Extracts the Linux release from an embedded version banner.
pub fn detect_release(kernel: &[u8]) -> Option<String> {
    const PREFIX: &[u8] = b"Linux version ";
    let start = kernel.windows(PREFIX.len()).position(|window| window == PREFIX)? + PREFIX.len();
    let rest = &kernel[start..];
    let end = rest.iter().position(|&byte| byte == b' ' || byte == b'\0' || byte == b'\n')?;
    if end == 0 {
        return None;
    }
    let release = std::str::from_utf8(&rest[..end]).ok()?;
    if release.bytes().all(|byte| byte.is_ascii_graphic()) {
        Some(release.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{detect_architecture, detect_release};

    #[test]
    fn detects_elf_machine_architecture() {
        let mut elf = vec![0u8; 20];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18..20].copy_from_slice(&0xb7u16.to_le_bytes());
        assert_eq!(detect_architecture(&elf), Some("aarch64"));
        elf[18..20].copy_from_slice(&0x28u16.to_le_bytes());
        elf[4] = 1;
        assert_eq!(detect_architecture(&elf), Some("arm"));
    }

    #[test]
    fn rejects_unknown_or_truncated_elf() {
        assert_eq!(detect_architecture(&[0x7f, b'E', b'L', b'F']), None);
        let mut elf = vec![0u8; 20];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        assert_eq!(detect_architecture(&elf), Some("elf"));
    }

    #[test]
    fn detects_linux_release_banner() {
        let kernel = b"prefix Linux version 5.4.254-qgki-gd8141a929274 #1 SMP PREEMPT";
        assert_eq!(detect_release(kernel).as_deref(), Some("5.4.254-qgki-gd8141a929274"));
    }

    #[test]
    fn rejects_malformed_linux_release_banner() {
        assert_eq!(detect_release(b"Linux version "), None);
        assert_eq!(detect_release(b"Linux version \xff"), None);
    }
}
