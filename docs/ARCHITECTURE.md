# Architecture

The analyzer is organized as a pipeline:

1. Container detection
2. Android image parsing
3. Kernel extraction
4. Compression detection/decompression
5. Kernel metadata
6. DTB/DTBO inspection
7. Symbol discovery
8. Candidate validation
9. Report generation

## Symbol recovery

Kallsyms recovery must not assume a single layout. Candidate discovery and validation are separate stages. Validators should check table bounds, symbol counts, name decoding, address plausibility, and cross-table consistency.

## Offset JSON

External metadata is treated as data for inspection and validation. The application compares kernel identity fields before accepting a document as matching the analyzed image.

## Security boundary

The project intentionally does not execute imported offset data or connect it to privilege-escalation/exploit execution. This keeps the analyzer useful for compatibility research and forensic work without turning it into an automated exploit adaptation framework.
