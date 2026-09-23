use std::{env, fs};

use uka_core::{boot::parse_boot_image, offsets::parse_offsets_json};

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("analyze-boot") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing image path"))?;
            let data = fs::read(path)?;
            let image = parse_boot_image(&data)?;
            println!("{}", serde_json::to_string_pretty(&image)?);
        }
        Some("validate-offsets") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing JSON path"))?;
            let text = fs::read_to_string(path)?;
            let doc = parse_offsets_json(&text)?;
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  uka-cli analyze-boot <boot.img>");
            eprintln!("  uka-cli validate-offsets <offsets.json>");
        }
    }
    Ok(())
}
