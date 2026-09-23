use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XblConfigSummary {
    pub size: usize,
    pub printable_strings: usize,
    pub has_null_padding: bool,
}

/// Read-only inspection of Qualcomm XBL config data.
///
/// The parser intentionally treats the blob as opaque firmware metadata rather
/// than interpreting or executing configuration values.
pub fn inspect_xbl_config(data: &[u8]) -> Result<XblConfigSummary> {
    if data.is_empty() {
        bail!("xbl_config is empty");
    }

    let mut printable_strings = 0usize;
    let mut in_string = false;
    let mut has_null_padding = false;

    for &byte in data {
        if byte == 0 {
            if in_string {
                printable_strings += 1;
                in_string = false;
            }
            has_null_padding = true;
        } else if byte.is_ascii_graphic() || byte == b' ' {
            in_string = true;
        } else {
            in_string = false;
        }
    }

    if in_string {
        printable_strings += 1;
    }

    Ok(XblConfigSummary {
        size: data.len(),
        printable_strings,
        has_null_padding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_xbl_config_as_opaque_metadata() {
        let summary = inspect_xbl_config(b"key=value\0platform=sm7325\0").unwrap();
        assert_eq!(summary.size, 26);
        assert_eq!(summary.printable_strings, 2);
        assert!(summary.has_null_padding);
    }

    #[test]
    fn rejects_empty_xbl_config() {
        assert!(inspect_xbl_config(&[]).is_err());
    }
}
