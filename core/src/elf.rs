use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfHeader {
    pub class: u8,
    pub endian: u8,
    pub machine: u16,
    pub entry: u64,
    pub program_header_offset: u64,
    pub section_header_offset: u64,
    pub program_header_size: u16,
    pub program_header_count: u16,
    pub section_header_size: u16,
    pub section_header_count: u16,
    pub section_name_index: u16,
}

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow::anyhow!("ELF header is truncated"))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow::anyhow!("ELF header is truncated"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| anyhow::anyhow!("ELF header is truncated"))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn check_table(offset: u64, entry_size: u16, count: u16, len: usize) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    if entry_size == 0 {
        bail!("ELF table has zero entry size");
    }
    let end = offset
        .checked_add(u64::from(entry_size) * u64::from(count))
        .ok_or_else(|| anyhow::anyhow!("ELF table offset overflow"))?;
    if end > len as u64 {
        bail!("ELF table extends beyond input");
    }
    Ok(())
}

/// Parses an ELF32/ELF64 little-endian header and validates table bounds.
pub fn parse_elf_header(data: &[u8]) -> Result<ElfHeader> {
    if data.len() < 20 || &data[..4] != b"\x7fELF" {
        bail!("invalid ELF header");
    }
    let class = data[4];
    let endian = data[5];
    if endian != 1 || (class != 1 && class != 2) {
        bail!("unsupported ELF class or endianness");
    }
    if data[6] != 1 {
        bail!("unsupported ELF identification version");
    }

    let machine = read_u16_le(data, 18)?;
    let (entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx) = if class == 2 {
        if data.len() < 64 {
            bail!("ELF64 header is truncated");
        }
        if read_u16_le(data, 52)? != 64 {
            bail!("ELF64 header size is invalid");
        }
        if read_u32_le(data, 16)? != 1 {
            bail!("unsupported ELF version");
        }
        (
            read_u64_le(data, 24)?,
            read_u64_le(data, 32)?,
            read_u64_le(data, 40)?,
            read_u16_le(data, 54)?,
            read_u16_le(data, 56)?,
            read_u16_le(data, 58)?,
            read_u16_le(data, 60)?,
            read_u16_le(data, 62)?,
        )
    } else {
        if data.len() < 52 {
            bail!("ELF32 header is truncated");
        }
        if read_u16_le(data, 40)? != 52 {
            bail!("ELF32 header size is invalid");
        }
        if read_u32_le(data, 16)? != 1 {
            bail!("unsupported ELF version");
        }
        (
            u64::from(read_u32_le(data, 24)?),
            u64::from(read_u32_le(data, 28)?),
            u64::from(read_u32_le(data, 32)?),
            read_u16_le(data, 42)?,
            read_u16_le(data, 44)?,
            read_u16_le(data, 46)?,
            read_u16_le(data, 48)?,
            read_u16_le(data, 50)?,
        )
    };

    check_table(phoff, phentsize, phnum, data.len())?;
    check_table(shoff, shentsize, shnum, data.len())?;
    if shnum != 0 && shstrndx >= shnum {
        bail!("ELF section-name index is outside section table");
    }

    Ok(ElfHeader {
        class,
        endian,
        machine,
        entry,
        program_header_offset: phoff,
        section_header_offset: shoff,
        program_header_size: phentsize,
        program_header_count: phnum,
        section_header_size: shentsize,
        section_header_count: shnum,
        section_name_index: shstrndx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_elf64_header() {
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[18..20].copy_from_slice(&183u16.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&1u16.to_le_bytes());
        data[58..60].copy_from_slice(&64u16.to_le_bytes());
        data[60..62].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(parse_elf_header(&data).unwrap().machine, 183);
    }

    #[test]
    fn rejects_bad_elf_magic() {
        assert!(parse_elf_header(&[0u8; 64]).is_err());
    }

    #[test]
    fn rejects_invalid_elf_header_size() {
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(b"\\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        data[52..54].copy_from_slice(&63u16.to_le_bytes());
        assert!(parse_elf_header(&data).is_err());
    }
}
