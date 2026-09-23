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
pub fn scan_candidates(kernel: &[u8]) -> Vec<KallsymsCandidate> {
    let _ = kernel;
    Vec::new()
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
