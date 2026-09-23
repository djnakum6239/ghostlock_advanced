# Kallsyms recovery

The kallsyms subsystem is organized as discovery, validation, and decoding.

## Discovery

The scanner searches for structurally plausible token-index tables and then checks nearby token data, symbol counts, address tables, and bounds.

## Validation

Candidates are rejected when tables overlap or exceed the input, symbol counts are unreasonable, address-table width does not match the selected address mode, token offsets point outside the token table, or confidence is outside the normalized range.

## Decoding

Compressed names can be expanded from the token table and token index. This is diagnostic symbol recovery only; recovered symbols are not converted into privilege-escalation or exploit parameters.

## WIP

The scanner is intentionally conservative and remains subject to additional regression testing against multiple kernel generations.
