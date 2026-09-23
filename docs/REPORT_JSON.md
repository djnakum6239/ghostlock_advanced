# Analysis JSON

The analyzer emits JSON intended for diagnostics, regression testing, and human inspection.

## Image report

`AnalysisReport` contains:

- `image`: detected image kind, Android header version, and page size
- `kernel`: release string, ELF architecture when detectable, build ID, and compression
- `symbols`: source, recovered symbol count, and heuristic confidence
- `validation`: conservative validation flags

## Unified input result

The `analyze` CLI command wraps recognized inputs in a tagged result:

- `Image`
- `OtaZip`
- `Payload`
- `Elf`
- `Dtb`
- `Btf`
- `Sparse`

Unknown non-empty data is treated as a raw kernel/image candidate and passed through the read-only analyzer.

## Stability

This schema is WIP and may change before the first stable release. Consumers should tolerate missing optional fields and unknown future result variants.
