# offsets.json

The application accepts externally produced JSON metadata for inspection and kernel-identity validation.

Schema version 1:

```json
{
  "schema_version": 1,
  "kernel": {
    "release": "5.4.254",
    "build_id": "optional-build-id"
  },
  "source": "external-analysis",
  "values": {
    "example_symbol": "0x0"
  }
}
```

The imported values remain data. They are not executed and are not passed to an exploit or privilege-escalation runner.
