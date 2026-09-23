# Universal Kernel Analyzer

> ⚠️ **WORK IN PROGRESS** — APIs, parsers, heuristics, and report formats are still under active development. Do not treat current analysis results as authoritative without independent validation.

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

## Credits and attribution

This project is an independent implementation and does not claim authorship of upstream tools, research, kernel sources, or device trees that may be used for comparison, regression testing, or compatibility research.

When code, algorithms, documentation, or other implementation details are derived from or directly adapted from another project, that source and its original authors should be credited in the relevant source file and/or documentation, and its license terms must be preserved. Notable research references include **YuKongA / ghostlock-app**, **JoinChang / ghostlock-oneplus**, and **marin-m / vmlinux-to-elf**, along with Android/Linux/Qualcomm/OnePlus community sources. No upstream implementation is copied here unless its applicable license permits it and attribution is retained.

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
