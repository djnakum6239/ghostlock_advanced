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

This project is an independent research/analysis implementation. When ideas, formats, algorithms, or implementation details are derived from existing projects, their original creators and upstream projects are credited here.

### Research and implementation references

- **YuKongA — ghostlock-app**: boot/OTA analysis, kernel extraction, and kallsyms-recovery research.
- **JoinChang — ghostlock-oneplus**: Android boot-image and kallsyms-analysis workflow documentation.
- **marin-m — vmlinux-to-elf**: kernel ELF reconstruction tooling.
- **Android Open Source Project (AOSP)**: Android boot-image, vendor_boot, and init_boot format definitions and tooling.
- **Linux kernel community**: kernel metadata, ELF, kallsyms, BTF, and related format/documentation references.
- **Qualcomm / OnePlus open-source kernel and device-tree projects**: platform-specific reference material for Snapdragon/OnePlus analysis.

No upstream implementation is intentionally copied into this repository unless its license permits reuse. If code is adapted from an upstream project, the relevant source, license, and authors will be identified alongside the implementation.

If you believe a contribution here should receive additional attribution, please open an issue with the relevant upstream project and source location.
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

The CLI currently exposes:
- `uka-cli analyze-boot <boot.img>`
- `uka-cli analyze-kernel <kernel>`
- `uka-cli analyze <image-or-kernel>`
- `uka-cli validate-offsets <offsets.json>`

The unified `analyze` command emits a read-only JSON report covering image type, kernel metadata, compression, symbol summary, and validation fields.

Android integration will be added after the core parser APIs stabilize.
