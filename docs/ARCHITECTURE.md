# Architecture

> ⚠️ **WORK IN PROGRESS** — This architecture is provisional. Parsers and recovery heuristics may change as additional OEM and kernel samples are tested.

The analyzer is organized as a pipeline:
1. Container detection
2. Android image parsing
3. OTA/payload and firmware container inspection
4. Kernel extraction
5. Compression detection/decompression
6. Kernel metadata
7. DTB/DTBO and XBL config inspection
8. Symbol discovery
9. Candidate validation
10. Report generation

## Attribution and implementation provenance

The project draws on publicly available Android/Linux image formats, kernel tooling, and compatibility research. Notable references include **YuKongA / ghostlock-app**, **JoinChang / ghostlock-oneplus**, and **marin-m / vmlinux-to-elf**. These projects are references for research and interoperability; their code is not assumed to be freely reusable without checking the applicable license. Any future directly adapted implementation must retain the upstream copyright/license notices and add explicit attribution.

## Symbol recovery
Kallsyms recovery must not assume a single layout. Candidate discovery and validation are separate stages. Validators should check table bounds, symbol counts, name decoding, address plausibility, and cross-table consistency.

## Offset JSON
External metadata is treated as data for inspection and validation. The application compares kernel identity fields before accepting a document as matching the analyzed image.

## Security boundary
The project intentionally does not execute imported offset data or connect it to privilege-escalation/exploit execution. This keeps the analyzer useful for compatibility research and forensic work without turning it into an automated exploit adaptation framework.

## Qualcomm firmware metadata

The `xbl_config` inspector treats the blob as opaque, read-only metadata. It reports basic blob characteristics and printable-string boundaries; it does not interpret configuration as executable instructions or apply values to a device.
