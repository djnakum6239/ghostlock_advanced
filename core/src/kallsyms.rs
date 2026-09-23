use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AddressMode {
    Absolute,
    Relative,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KallsymsCandidate {
    pub address_table: Range<usize>,
    pub names_table: Range<usize>,
    pub markers_table: Option<Range<usize>>,
    pub token_table: Range<usize>,
    pub token_index: Range<usize>,
    pub num_syms: usize,
    pub address_mode: AddressMode,
    pub confidence: f32,
}

/// Candidate scanner entry point. The implementation deliberately separates
/// discovery from validation so old kernels do not depend on one fixed layout.
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(offset..offset + 8)?.try_into().ok()?))
}

fn looks_like_token_index(data: &[u8], offset: usize) -> bool {
    let mut previous = 0u16;
    let mut distinct = 0usize;
    for index in 0..256 {
        let Some(value) = read_u16_le(data, offset + index * 2) else { return false; };
        if index > 0 && value < previous {
            return false;
        }
        if index > 0 && value != previous {
            distinct += 1;
        }
        previous = value;
    }
    previous != 0 && distinct >= 8
}

fn valid_token_table(data: &[u8], start: usize, end: usize) -> bool {
    if start >= end || end > data.len() || end - start > 0xffff {
        return false;
    }
    for index in 0..256usize {
        let Some(token_offset) = read_u16_le(data, end + index * 2) else {
            return false;
        };
        let token_offset = token_offset as usize;
        if token_offset >= end - start {
            return false;
        }
        let token_start = start + token_offset;
        let Some(token_end) = data[token_start..end].iter().position(|&byte| byte == 0) else {
            return false;
        };
        let token = &data[token_start..token_start + token_end];
        if token.is_empty() || token.len() > 255 || token.iter().any(|byte| !byte.is_ascii_graphic() && *byte != b' ') {
            return false;
        }
    }
    true
}

fn monotonic_addresses(data: &[u8], start: usize, count: usize, width: usize) -> bool {
    if count < 2 {
        return false;
    }
    let mut previous = match width {
        4 => match read_u32_le(data, start) {
            Some(value) => u64::from(value),
            None => return false,
        },
        8 => match read_u64_le(data, start) {
            Some(value) => value,
            None => return false,
        },
        _ => return false,
    };
    for index in 1..count {
        let offset = match index.checked_mul(width).and_then(|value| start.checked_add(value)) {
            Some(value) => value,
            None => return false,
        };
        let current = match width {
            4 => match read_u32_le(data, offset) {
                Some(value) => u64::from(value),
                None => return false,
            },
            8 => match read_u64_le(data, offset) {
                Some(value) => value,
                None => return false,
            },
            _ => return false,
        };
        if current < previous {
            return false;
        }
        previous = current;
    }
    true
}

/// Decodes one compressed kallsyms name using its token table and token index.
pub fn decode_symbol_name(
    names: &[u8],
    token_table: &[u8],
    token_index: &[u8],
    offset: usize,
) -> Option<String> {
    let length = *names.get(offset)? as usize;
    let compressed = names.get(offset + 1..offset + 1 + length)?;
    if token_index.len() < 512 {
        return None;
    }

    let mut expanded = Vec::new();
    for &token in compressed {
        let index = token as usize * 2;
        let token_offset = u16::from_le_bytes(token_index.get(index..index + 2)?.try_into().ok()?) as usize;
        let token_bytes = token_table.get(token_offset..)?.split(|&byte| byte == 0).next()?;
        expanded.extend_from_slice(token_bytes);
    }

    if expanded.is_empty() {
        return None;
    }
    if expanded.len() > 1 {
        expanded.remove(0);
    }
    String::from_utf8(expanded).ok()
}

/// Scans for structurally plausible embedded kallsyms tables.
///
/// This is deliberately conservative: it only reports candidates when the
/// token-index table and address table have mutually consistent bounds.
pub fn scan_candidates(kernel: &[u8]) -> Vec<KallsymsCandidate> {
    const TOKEN_INDEX_BYTES: usize = 256 * 2;
    const MAX_SYMBOLS: usize = 1_000_000;
    const SEARCH_WINDOW: usize = 32 * 1024 * 1024;
    const MAX_CANDIDATES: usize = 32;

    let mut candidates = Vec::new();
    if kernel.len() < TOKEN_INDEX_BYTES {
        return candidates;
    }

    let mut token_index_offset = 0usize;
    while token_index_offset + TOKEN_INDEX_BYTES <= kernel.len()
        && candidates.len() < MAX_CANDIDATES
    {
        if !looks_like_token_index(kernel, token_index_offset) {
            token_index_offset += 2;
            continue;
        }

        let search_start = token_index_offset.saturating_sub(SEARCH_WINDOW);
        let mut token_table_start = token_index_offset.saturating_sub(1);
        while token_table_start >= search_start {
            if valid_token_table(kernel, token_table_start, token_index_offset) {
                break;
            }
            if token_table_start == 0 {
                break;
            }
            token_table_start -= 1;
        }
        if !valid_token_table(kernel, token_table_start, token_index_offset) {
            token_index_offset += 2;
            continue;
        }

        let search_start = token_table_start.saturating_sub(SEARCH_WINDOW);
        let mut num_syms_offset = token_table_start.saturating_sub(4);
        while num_syms_offset >= search_start && candidates.len() < MAX_CANDIDATES {
            let Some(num_syms) = read_u32_le(kernel, num_syms_offset).map(|v| v as usize) else {
                if num_syms_offset < 4 { break; }
                num_syms_offset -= 4;
                continue;
            };
            if !(2..=MAX_SYMBOLS).contains(&num_syms) {
                if num_syms_offset < 4 { break; }
                num_syms_offset -= 4;
                continue;
            }

            for (width, address_mode) in [(8usize, AddressMode::Absolute), (4usize, AddressMode::Relative)] {
                let Some(address_bytes) = num_syms.checked_mul(width) else { continue; };
                let Some(address_start) = num_syms_offset.checked_sub(address_bytes) else { continue; };
                if address_start < search_start || num_syms_offset > token_table_start {
                    continue;
                }
                if !monotonic_addresses(kernel, address_start, num_syms, width) {
                    continue;
                }

                let names_start = num_syms_offset + 4;
                if names_start >= token_table_start {
                    continue;
                }

                let candidate = KallsymsCandidate {
                    address_table: address_start..num_syms_offset,
                    names_table: names_start..token_table_start,
                    markers_table: None,
                    token_table: token_table_start..token_index_offset,
                    token_index: token_index_offset..token_index_offset + TOKEN_INDEX_BYTES,
                    num_syms,
                    address_mode: address_mode.clone(),
                    confidence: 0.75,
                };
                if validate_candidate(&candidate, kernel.len()) {
                    candidates.push(candidate);
                }
            }

            if num_syms_offset < 4 {
                break;
            }
            num_syms_offset -= 4;
        }

        token_index_offset += 2;
    }

    candidates
}

pub fn validate_candidate(candidate: &KallsymsCandidate, kernel_len: usize) -> bool {
    fn valid_range(range: &Range<usize>, len: usize) -> bool {
        range.start < range.end && range.end <= len
    }

    if !valid_range(&candidate.address_table, kernel_len)
        || !valid_range(&candidate.names_table, kernel_len)
        || !valid_range(&candidate.token_table, kernel_len)
        || !valid_range(&candidate.token_index, kernel_len)
        || candidate.num_syms == 0
        || !(0.0..=1.0).contains(&candidate.confidence)
    {
        return false;
    }

    if let Some(markers) = &candidate.markers_table {
        if !valid_range(markers, kernel_len) {
            return false;
        }
    }

    let address_width = match candidate.address_mode {
        AddressMode::Absolute => 8,
        AddressMode::Relative => 4,
    };

    let Some(expected_address_bytes) = candidate.num_syms.checked_mul(address_width) else {
        return false;
    };

    candidate.address_table.len() == expected_address_bytes
        && candidate.names_table.start >= candidate.address_table.end
        && candidate.token_index.start >= candidate.token_table.end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> KallsymsCandidate {
        KallsymsCandidate {
            address_table: 0..16,
            names_table: 16..32,
            markers_table: None,
            token_table: 32..64,
            token_index: 64..576,
            num_syms: 2,
            address_mode: AddressMode::Absolute,
            confidence: 0.75,
        }
    }

    #[test]
    fn decodes_compressed_symbol_name() {
        let names = [3u8, 0, 1, 2];
        let token_table = b"T\0init\0_task\0";
        let mut token_index = vec![0u8; 512];
        token_index[0..2].copy_from_slice(&0u16.to_le_bytes());
        token_index[2..4].copy_from_slice(&2u16.to_le_bytes());
        token_index[4..6].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(
            decode_symbol_name(&names, token_table, &token_index, 0).as_deref(),
            Some("init_task")
        );
    }

    #[test]
    fn scans_synthetic_kallsyms_layout() {
        let mut kernel = vec![0u8; 42 + 256 * 2];
        kernel[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        kernel[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        kernel[16..20].copy_from_slice(&2u32.to_le_bytes());
        kernel[20..24].copy_from_slice(&[1, 2, 3, 0]);
        kernel[24..42].copy_from_slice(b"A\0B\0C\0D\0E\0F\0G\0H\0I\0");
        for index in 0..256usize {
            let value = (index.min(15) * 2) as u16;
            let offset = 40 + index * 2;
            kernel[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        assert!(looks_like_token_index(&kernel, 42));
        assert!(valid_token_table(&kernel, 24, 42));
        let candidates = scan_candidates(&kernel);
        assert!(candidates.iter().any(|candidate| {
            candidate.num_syms == 2
                && candidate.address_table == (0..16)
                && candidate.token_table == (24..42)
        }));
    }

    #[test]
    fn validates_well_formed_candidate() {
        assert!(validate_candidate(&candidate(), 1024));
    }

    #[test]
    fn rejects_wrong_address_table_size() {
        let mut value = candidate();
        value.address_table = 0..8;
        assert!(!validate_candidate(&value, 1024));
    }

    #[test]
    fn rejects_confidence_outside_range() {
        let mut value = candidate();
        value.confidence = 1.1;
        assert!(!validate_candidate(&value, 1024));
    }
}
