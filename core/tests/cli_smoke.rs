use std::{fs, process::Command};

use zip::{write::SimpleFileOptions, ZipWriter};

fn write_fixture(name: &str, data: &[u8]) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("uka-cli-smoke-{}-{name}", std::process::id()));
    fs::write(&path, data).unwrap();
    path
}

fn run(command: &str, args: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_uka-cli"))
        .arg(command)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn boot_image() -> Vec<u8> {
    let page = 4096usize;
    let kernel = b"Linux";
    let mut data = vec![0u8; page + kernel.len()];
    data[..8].copy_from_slice(b"ANDROID!");
    data[8..12].copy_from_slice(&(kernel.len() as u32).to_le_bytes());
    data[12..16].copy_from_slice(&0x8000_8000u32.to_le_bytes());
    data[36..40].copy_from_slice(&(page as u32).to_le_bytes());
    data[40..44].copy_from_slice(&2u32.to_le_bytes());
    data[page..].copy_from_slice(kernel);
    data
}

fn payload() -> Vec<u8> {
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(b"CrAU");
    data.extend_from_slice(&2u64.to_be_bytes());
    data.extend_from_slice(&0u64.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data
}

fn dtb() -> Vec<u8> {
    let mut data = vec![0u8; 80];
    data[0..4].copy_from_slice(&0xd00d_feed_u32.to_be_bytes());
    data[4..8].copy_from_slice(&80u32.to_be_bytes());
    data[8..12].copy_from_slice(&40u32.to_be_bytes());
    data[12..16].copy_from_slice(&48u32.to_be_bytes());
    data[16..20].copy_from_slice(&64u32.to_be_bytes());
    data[20..24].copy_from_slice(&17u32.to_be_bytes());
    data[24..28].copy_from_slice(&16u32.to_be_bytes());
    data[32..36].copy_from_slice(&8u32.to_be_bytes());
    data[36..40].copy_from_slice(&8u32.to_be_bytes());
    data
}

fn elf64() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    data[18..20].copy_from_slice(&183u16.to_le_bytes());
    data[54..56].copy_from_slice(&56u16.to_le_bytes());
    data[58..60].copy_from_slice(&64u16.to_le_bytes());
    data
}

fn btf() -> Vec<u8> {
    let mut data = vec![0u8; 32];
    data[0..2].copy_from_slice(&0xeb9fu16.to_le_bytes());
    data[2] = 1;
    data[4..8].copy_from_slice(&24u32.to_le_bytes());
    data[12..16].copy_from_slice(&4u32.to_le_bytes());
    data[16..20].copy_from_slice(&4u32.to_le_bytes());
    data[20..24].copy_from_slice(&4u32.to_le_bytes());
    data
}

fn sparse() -> Vec<u8> {
    let mut data = vec![0u8; 28];
    data[0..4].copy_from_slice(&0xed26ff3au32.to_le_bytes());
    data[4..6].copy_from_slice(&1u16.to_le_bytes());
    data[6..8].copy_from_slice(&0u16.to_le_bytes());
    data[8..10].copy_from_slice(&28u16.to_le_bytes());
    data[10..12].copy_from_slice(&12u16.to_le_bytes());
    data[12..16].copy_from_slice(&4096u32.to_le_bytes());
    data[16..20].copy_from_slice(&1u32.to_le_bytes());
    data[20..24].copy_from_slice(&1u32.to_le_bytes());
    data
}

#[test]
fn exercises_all_cli_commands() {
    let boot = write_fixture("boot.img", &boot_image());
    let kernel = write_fixture("kernel", b"Linux version 5.4.254-test\0");
    let payload = write_fixture("payload.bin", &payload());
    let dtb = write_fixture("board.dtb", &dtb());
    let elf = write_fixture("kernel.elf", &elf64());
    let btf = write_fixture("kernel.btf", &btf());
    let sparse = write_fixture("system.sparse", &sparse());
    let xbl = write_fixture("xbl_config.img", b"xbl_config\0platform=sm7325\0");
    let offsets = write_fixture(
        "offsets.json",
        br#"{"schema_version":1,"source":"test","kernel":{"release":"5.4.254-test","build_id":null},"values":{}}"#,
    );

    let mut ota_cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut ota_cursor);
        zip.start_file("boot.img", SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut zip, &boot_image()).unwrap();
        zip.start_file(
            "META-INF/com/android/metadata",
            SimpleFileOptions::default(),
        )
        .unwrap();
        std::io::Write::write_all(&mut zip, b"post-build=sm7325").unwrap();
        zip.finish().unwrap();
    }
    let ota = write_fixture("ota.zip", ota_cursor.get_ref());

    run("analyze", &[kernel.to_str().unwrap()]);
    run("analyze-boot", &[boot.to_str().unwrap()]);
    run("analyze-kernel", &[kernel.to_str().unwrap()]);
    run("analyze-ota", &[ota.to_str().unwrap()]);
    run("analyze-ota-entry", &[ota.to_str().unwrap(), "boot.img"]);
    run("analyze-payload", &[payload.to_str().unwrap()]);
    run("analyze-dtb", &[dtb.to_str().unwrap()]);
    run("analyze-elf", &[elf.to_str().unwrap()]);
    run("analyze-btf", &[btf.to_str().unwrap()]);
    run("analyze-sparse", &[sparse.to_str().unwrap()]);
    run("analyze-xbl-config", &[xbl.to_str().unwrap()]);
    run("validate-offsets", &[offsets.to_str().unwrap()]);

    for path in [
        boot, kernel, payload, dtb, elf, btf, sparse, xbl, offsets, ota,
    ] {
        let _ = fs::remove_file(path);
    }
}
