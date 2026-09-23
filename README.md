# Universal Kernel Analyzer

A research-oriented Android image and Linux kernel analysis toolkit.

## Goals

- Parse Android boot image headers v0-v4
- Parse vendor_boot and init_boot
- Extract kernels from OTA ZIP and payload.bin
- Detect and decompress common Android kernel formats
- Recover and validate embedded kallsyms using multiple strategies
- Inspect ELF, BTF, DTB/DTBO and Qualcomm firmware metadata
- Import and validate externally supplied JSON metadata
- Produce reproducible JSON analysis reports

This project is intended for kernel/image forensics, compatibility research, debugging, and regression testing. It does not contain an exploit runner or automatic privilege-escalation offset generation.

## Repository layout

- `app/` - Android UI
- `core/` - Rust analysis engine
- `tests/` - regression corpus and fixtures
- `docs/` - design notes and schemas

## Initial target

The first device profile is the OnePlus Nord CE 3 5G / Qualcomm SM7325 / ARM64 / Linux 5.4 family. The engine is designed to remain OEM- and kernel-version-independent.

## Build

Install Rust and run:

```bash
cargo test --workspace
cargo build --workspace
```

Android integration will be added after the core parser APIs stabilize.
