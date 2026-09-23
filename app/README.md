# Android application

The Android front end will call the Rust core through JNI/UniFFI after the core parsing APIs stabilize.

Planned screens:

- Analyze image
- OTA / payload extraction
- Kernel metadata
- Kallsyms candidates
- DTB/BTF information
- Import JSON
- Export report

The UI should expose provenance and confidence rather than silently presenting uncertain analysis results.

## Planned screens

- Input picker for boot/vendor_boot/init_boot, OTA ZIP, payload.bin, and raw kernel files
- Read-only analysis summary with confidence and validation indicators
- Expandable metadata sections for ELF, BTF, DTB, kallsyms, and firmware metadata
- JSON export/share for reproducible diagnostics

The Android UI will call the Rust core through a stable boundary after parser APIs stabilize.
