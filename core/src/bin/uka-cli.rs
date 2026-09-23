use std::{env, fs};

use uka_core::{boot::parse_boot_image, metadata::detect_metadata, offsets::parse_offsets_json};

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("analyze-boot") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing image path"))?;
            let data = fs::read(path)?;
            let image = parse_boot_image(&data)?;
            println!("{}", serde_json::to_string_pretty(&image)?);
        }
        Some("analyze-kernel") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing kernel path"))?;
            let data = fs::read(path)?;
            println!("{}", serde_json::to_string_pretty(&detect_metadata(&data))?);
        }
        Some("analyze") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing image path"))?;
            let data = fs::read(path)?;
            println!("{}", serde_json::to_string_pretty(&uka_core::report::analyze_image(&data)?)?);
        }
        Some("analyze-ota") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing OTA ZIP path"))?;
            let data = fs::read(path)?;
            println!("{}", serde_json::to_string_pretty(&uka_core::ota_zip::inspect_ota_zip(&data)?)?);
        }
        Some("analyze-ota-entry") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing OTA ZIP path"))?;
            let entry = args.next().ok_or_else(|| anyhow::anyhow!("missing OTA entry name"))?;
            let data = fs::read(path)?;
            println!("{}", serde_json::to_string_pretty(&uka_core::report::analyze_ota_entry(&data, &entry)?)?);
        }
        Some("analyze-payload") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing payload.bin path"))?;
            let data = fs::read(path)?;
            println!("{}", serde_json::to_string_pretty(&uka_core::payload::parse_payload_header(&data)?)?);
        }
        Some("analyze-dtb") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing DTB path"))?;
            let data = fs::read(path)?;
            println!("{}", serde_json::to_string_pretty(&uka_core::dtb::parse_dtb_header(&data)?)?);
        }
        Some("analyze-elf") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing ELF path"))?;
            let data = fs::read(path)?;
            println!("{}", serde_json::to_string_pretty(&uka_core::elf::parse_elf_header(&data)?)?);
        }
        Some("analyze-btf") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing BTF path"))?;
            let data = fs::read(path)?;
            println!("{}", serde_json::to_string_pretty(&uka_core::btf::parse_btf_header(&data)?)?);
        }
        Some("analyze-sparse") => {
            let path = args.next().ok_or_else(|| anyhow::anyhow!("missing sparse image path"))?;
            let data = fs::read(path)?;
            println!("{}", serde_json::to_string_pretty(&uka_core::sparse::parse_sparse_header(&data)?)?);
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
            eprintln!("  uka-cli analyze-kernel <kernel>");
            eprintln!("  uka-cli analyze <image-or-kernel>");
            eprintln!("  uka-cli analyze-ota <ota.zip>");
            eprintln!("  uka-cli analyze-ota-entry <ota.zip> <entry>");
            eprintln!("  uka-cli analyze-payload <payload.bin>");
            eprintln!("  uka-cli analyze-dtb <dtb>");
            eprintln!("  uka-cli analyze-elf <elf>");
            eprintln!("  uka-cli analyze-btf <btf>");
            eprintln!("  uka-cli analyze-sparse <sparse.img>");
            eprintln!("  uka-cli validate-offsets <offsets.json>");
        }
    }
    Ok(())
}
