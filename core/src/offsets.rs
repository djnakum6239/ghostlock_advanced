use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffsetDocument {
    pub schema_version: u32,
    pub kernel: KernelIdentity,
    pub source: String,
    pub values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelIdentity {
    pub release: Option<String>,
    pub build_id: Option<String>,
}

pub fn parse_offsets_json(input: &str) -> Result<OffsetDocument> {
    let doc: OffsetDocument = serde_json::from_str(input)?;
    if doc.schema_version != 1 {
        bail!("unsupported offsets.json schema version");
    }
    if doc.source.trim().is_empty() {
        bail!("offset document source is empty");
    }
    Ok(doc)
}

pub fn matches_kernel(doc: &OffsetDocument, release: Option<&str>, build_id: Option<&str>) -> bool {
    let release_ok = doc
        .kernel
        .release
        .as_deref()
        .map_or(true, |v| Some(v) == release);
    let build_ok = doc
        .kernel
        .build_id
        .as_deref()
        .map_or(true, |v| Some(v) == build_id);
    release_ok && build_ok
}
