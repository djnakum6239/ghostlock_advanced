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
