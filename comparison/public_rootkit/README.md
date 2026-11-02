# Fixed original CARAXES experiment

Three fresh boots of the original isolated research VM, Linux 6.8.0-138-generic,
ext4. Sample: official CARAXES commit
`899e8be6b5f6c7236bd23b52aa65051de757e0b3`, default getdents64 configuration and
the author's documented filldir configuration. The latter changes only hooks.h.
No filtering function, false return, callback layout or ftrace helper was repaired.

The 300 detector observations include 60 normal controls, 120 original getdents64
observations and 120 original filldir observations. Both attachment orders and
128/65,536-byte buffers are included. Original getdents64: 120 alarms and verified
exact recoveries. Original filldir: 120 real truncated listings but no alarm,
because accepted and returned views both contain the same two entries. Normal
listings have 70 entries. This is a coverage limitation, not evidence of no hiding.

The fixed target-only zygarde adapter has 15 observations per state, rootkit-first
only: 0 normal target alerts, 15 getdents64 alerts, 15 filldir alerts. The last 15
also have missing-canary quality warnings. No complete recovery or new performance
claim is made. Keep its denominators separate from the detector's.

See the [Chinese report](../../docs/ORIGINAL_CARAXES_20261102_zh-TW.md),
[frozen protocol](PROTOCOL.md), [raw archive](public_sample_20261102.tar.gz),
[recomputed verification](verification.json), [configuration patch](filldir_configuration.patch)
and [build manifest](build_manifest.json). Pilot and failed build attempt are retained.

The archive includes original GPL-3.0 source and LICENSE with the build artifacts.
The source is attributed to AIT; its license applies to that material. Our control,
analysis and writing are separate. No persistence or module self-hiding was enabled.

Offline verification does not load a module:

```bash
python comparison/public_rootkit/summarize.py --archive comparison/public_rootkit/public_sample_20261102.tar.gz --extract-to reproduced/public_sample --output reproduced/public_sample_verification.json
```

`prepare_native.py`, `record_build.py`, `run_native.py` and `orchestrate.py` preserve
the actual preparation and execution workflow. The native runner uses paths from
the existing lab; an independent reproduction must explicitly supply equivalent
detector sources and the locked scanner/adapter binaries. No result depends on
claiming that the original filldir hook behaves like the earlier true-returning
controlled module.
