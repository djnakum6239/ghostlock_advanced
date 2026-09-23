# Format coverage matrix

| Format | Detection | Parsing | Extraction | Report |
|---|---|---|---|---|
| boot v0-v2 | yes | yes | yes | yes |
| boot v3-v4 | yes | yes | yes | yes |
| vendor_boot v3-v4 | yes | yes | metadata | yes |
| init_boot v4 | yes | yes | metadata | yes |
| OTA ZIP | yes | yes | entry-level | yes |
| payload.bin | yes | header | WIP | yes |
| ELF | yes | header | n/a | yes |
| DTB | yes | header | n/a | yes |
| BTF | yes | header | n/a | yes |
| Android sparse | yes | header | WIP | yes |
| xbl_config | yes | opaque metadata | n/a | yes |
| kallsyms | heuristic | candidate recovery | n/a | yes |

This matrix is a WIP engineering checklist rather than a compatibility guarantee.
