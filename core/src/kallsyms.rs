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
    candidate.address_table.start <= candidate.address_table.end
        && candidate.names_table.start <= candidate.names_table.end
        && candidate.token_table.start <= candidate.token_table.end
        && candidate.token_index.start <= candidate.token_index.end
        && candidate.address_table.end <= kernel_len
        && candidate.names_table.end <= kernel_len
        && candidate.token_table.end <= kernel_len
        && candidate.token_index.end <= kernel_len
        && candidate.num_syms > 0
}
