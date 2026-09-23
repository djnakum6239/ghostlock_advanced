# Roadmap

## Phase 1 — parser foundation

- [x] boot v0-v4 detection and parsing
- [x] vendor_boot v3-v4 metadata parsing
- [x] init_boot v4 parsing
- [x] OTA ZIP inspection and entry extraction
- [x] payload.bin header inspection
- [x] ELF, DTB, BTF and sparse-header inspection
- [x] kernel compression detection/decompression for supported formats
- [x] kernel release/build-ID metadata

## Phase 2 — symbol and firmware analysis

- [x] kallsyms candidate discovery
- [x] compressed symbol-name decoding
- [x] conservative candidate validation
- [x] opaque XBL config inspection
- [ ] broader real-kernel kallsyms regression corpus
- [ ] source-tree matching and provenance scoring

## Phase 3 — Android application

- [ ] file picker/import flow
- [ ] analysis result screens
- [ ] JSON export/share
- [ ] progress and cancellation handling
- [ ] device-safe regression dashboard

## Final verification

After the feature push phase, run the complete workspace test/build workflow, inspect every failure including historical unresolved failures, and perform focused fixes until the repository is clean.
