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
    let version_core = release.split_once('-').map_or(release, |(core, _)| core);
    let components: Vec<&str> = version_core.split('.').collect();
    if components.len() < 2
        || components
            .iter()
            .any(|component| component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    if !release
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b".-+_~".contains(&byte))
    {
        return None;
    }
    Some(release.to_owned())
}

/// Extracts a compiler identifier from a Linux kernel's embedded build strings.
pub fn detect_compiler(kernel: &[u8]) -> Option<String> {
    const PREFIXES: [&[u8]; 2] = [b"gcc version ", b"clang version "];

    for prefix in PREFIXES {
        let start = match kernel.windows(prefix.len()).position(|window| window == prefix) {
            Some(position) => position + prefix.len(),
            None => continue,
        };
        let rest = &kernel[start..];
        let end = rest
            .iter()
            .position(|&byte| byte == b' ' || byte == b'\0' || byte == b'\n')
            .unwrap_or(rest.len());
        if end == 0 {
            continue;
        }
        let compiler = std::str::from_utf8(&rest[..end]).ok()?;
        if compiler.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Some(compiler.to_owned());
        }
    }

    None
}


/// Extracts a GNU build ID from PT_NOTE segments in a little-endian ELF image.
pub fn detect_build_id(kernel: &[u8]) -> Option<String> {
    if kernel.len() < 20 || &kernel[..4] != b"\x7fELF" || kernel[5] != 1 {
        return None;
    }

    let class = kernel[4];
    let (phoff, phentsize, phnum) = match class {
        1 => (
            read_u32_le(kernel, 28)? as u64,
            read_u16_le(kernel, 42)? as u64,
            read_u16_le(kernel, 44)? as u64,
        ),
        2 => (
            read_u64_le(kernel, 32)?,
            read_u16_le(kernel, 54)? as u64,
            read_u16_le(kernel, 56)? as u64,
        ),
        _ => return None,
    };
    let phdr_size = if class == 1 { 32usize } else { 56usize };
    if phentsize < phdr_size as u64 {
        return None;
    }

    for index in 0..phnum {
        let entry = phoff.checked_add(index.checked_mul(phentsize)?)?;
        let entry_end = entry.checked_add(phdr_size as u64)?;
        if entry_end > kernel.len() as u64 {
            return None;
        }
        let entry = entry as usize;
        if read_u32_le(kernel, entry)? != 4 {
            continue;
        }

        let (note_offset, note_size) = if class == 1 {
            (
                read_u32_le(kernel, entry + 4)? as u64,
                read_u32_le(kernel, entry + 16)? as u64,
            )
        } else {
            (
                read_u64_le(kernel, entry + 8)?,
                read_u64_le(kernel, entry + 32)?,
            )
        };
        let note_end = note_offset.checked_add(note_size)?;
        if note_end > kernel.len() as u64 {
            return None;
        }

        let mut cursor = note_offset as usize;
        let end = note_end as usize;
        while cursor.checked_add(12)? <= end {
            let namesz = read_u32_le(kernel, cursor)? as usize;
            let descsz = read_u32_le(kernel, cursor + 4)? as usize;
            let note_type = read_u32_le(kernel, cursor + 8)?;
            cursor += 12;

            let name_padded = align4(namesz)?;
            let desc_padded = align4(descsz)?;
            let name_end = cursor.checked_add(name_padded)?;
            let desc_start = name_end;
            let desc_end = desc_start.checked_add(desc_padded)?;
            if desc_end > end {
                return None;
            }

            if note_type == 3
                && namesz >= 3
                && kernel.get(cursor..cursor + 3) == Some(b"GNU")
                && descsz > 0
            {
                let desc = kernel.get(desc_start..desc_start + descsz)?;
                return Some(desc.iter().map(|byte| format!("{byte:02x}")).collect());
            }

            cursor = desc_end;
        }
    }

    None
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(offset..offset + 8)?.try_into().ok()?))
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

pub fn detect_metadata(kernel: &[u8]) -> KernelMetadata {
    KernelMetadata {
        release: detect_release(kernel),
        build_id: detect_build_id(kernel),
        compiler: detect_compiler(kernel),
        architecture: detect_architecture(kernel).map(str::to_owned),
        ..KernelMetadata::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{detect_architecture, detect_build_id, detect_compiler, detect_release};

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
        assert_eq!(detect_release(b"Linux version android-kernel"), None);
        assert_eq!(detect_release(b"Linux version 5..4.254"), None);
        assert_eq!(detect_release(b"Linux version 5"), None);
        assert_eq!(detect_release(b"Linux version 5.4.254-rc1"), Some("5.4.254-rc1".to_owned()));
    }

    #[test]
    fn detects_gnu_build_id_from_elf_note() {
        let mut elf = vec![0u8; 256];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());

        elf[64..68].copy_from_slice(&4u32.to_le_bytes());
        elf[72..80].copy_from_slice(&128u64.to_le_bytes());
        elf[96..104].copy_from_slice(&36u64.to_le_bytes());

        elf[128..132].copy_from_slice(&4u32.to_le_bytes());
        elf[132..136].copy_from_slice(&20u32.to_le_bytes());
        elf[136..140].copy_from_slice(&3u32.to_le_bytes());
        elf[140..144].copy_from_slice(b"GNU\0");
        elf[144..164].copy_from_slice(&[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0x11, 0x22, 0x33, 0x44,
        ]);

        assert_eq!(
            detect_build_id(&elf).as_deref(),
            Some("0123456789abcdef1032547698badcfe11223344")
        );
    }

    #[test]
    fn rejects_invalid_gnu_build_id_note() {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        assert_eq!(detect_build_id(&elf), None);
    }

    #[test]
    fn detects_gcc_and_clang_versions() {
        assert_eq!(detect_compiler(b"built with gcc version 12.3.0 (GCC)"), Some("12.3.0".to_owned()));
        assert_eq!(detect_compiler(b"built with clang version 18.1.8"), Some("18.1.8".to_owned()));
    }

    #[test]
    fn rejects_missing_compiler_version() {
        assert_eq!(detect_compiler(b"compiler information unavailable"), None);
        assert_eq!(detect_compiler(b"gcc version "), None);
    }

    #[test]
    fn combines_detected_kernel_metadata() {
        let kernel = b"Linux version 5.4.254-qgki-gd8141a929274 #1 gcc version 12.3.0";
        let metadata = super::detect_metadata(kernel);
        assert_eq!(metadata.release.as_deref(), Some("5.4.254-qgki-gd8141a929274"));
        assert_eq!(metadata.build_id, None);
        assert_eq!(metadata.compiler.as_deref(), Some("12.3.0"));
        assert_eq!(metadata.architecture, None);
        assert!(!metadata.btf_present);
    }


}
