# SM7325 regression profile

This project uses Qualcomm SM7325-class devices as an important parser regression profile. The goal is to validate image-format detection, kernel metadata, kallsyms discovery, and firmware-container handling across real-world Android kernel layouts.

## Coverage targets

- Android boot header v0-v4
- `vendor_boot` and `init_boot`
- OTA ZIP and `payload.bin`
- raw compressed kernels
- ELF, DTB, and BTF metadata
- embedded kallsyms candidates
- opaque `xbl_config` metadata

Device-specific values belong in sanitized fixtures or externally supplied reports. The analyzer does not generate exploit offsets or execute privileged payloads.
