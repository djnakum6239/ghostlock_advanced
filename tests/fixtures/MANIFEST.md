# Regression fixture manifest

Fixtures are intentionally minimal and synthetic unless redistribution rights for a real image are documented.

| Area | Fixture target |
|---|---|
| boot | v0-v4 headers and malformed bounds |
| vendor_boot | v3/v4 metadata and table bounds |
| init_boot | v4 header and ramdisk bounds |
| kernel | raw, gzip, xz, lz4, zstd metadata |
| kallsyms | token/index/address-table candidates |
| ELF | ELF32/ELF64 little-endian headers |
| DTB | FDT header and region bounds |
| BTF | BTF v1 header and section bounds |
| sparse | Android sparse header |
| OTA | ZIP entry discovery |
| payload | CrAU header |
| firmware | opaque XBL config metadata |

Real device images should be supplied externally for regression testing and must not be committed without appropriate redistribution rights.
