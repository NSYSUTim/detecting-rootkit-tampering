# Detecting Linux Directory-Entry Hiding and Tampering

This research artifact detects changes to Linux directory listings by comparing what the kernel, system call, and application library report. It also identifies which observed entries differ, including replacements that leave the entry count unchanged.

## Try the demo

From the repository root, run the four-scene English replay with Python 3.10 or newer. Press Enter between scenes.

```sh
python -B demo/replay.py --en --interactive
```

The replay recomputes kernel–syscall recovery from saved observations and shows recorded timing and library-layer results. The [demo guide](demo/README.md) also covers live scanning of a test directory.

## How it works

- **Kernel–syscall (K–S)** — eBPF observes accepted `filldir64` entries, which are compared with the entries returned by `getdents64`.
- **Syscall–library (S–L)** — a controlled process supplies `getdents64` and `readdir64()` output from the same listing.
- **Detection and recovery** — fingerprints flag differences. An Invertible Bloom Lookup Table (IBLT) recovers and verifies differing entry identities when decoding succeeds. A separate completion check flags some premature enumeration endings.

## Evaluation

Controlled experiments ran on Ubuntu 22.04.5 LTS and Ubuntu 26.04.1 LTS.

| Evaluation | Observed result |
|---|---|
| [Ubuntu 26.04.1 controlled matrix](ubuntu26/rerun_20261114/README_zh-TW.md) | 576/576 positive batches detected, 0/720 control batches flagged, and exact difference recovery in all 11,520 positive listings in this matrix. |
| Public rootkit tests | Valid tests detected the evaluated CARAXES, [Singularity](ubuntu26_extended_20261115/updates/20261115_singularity/RESULTS.json), and [Medusa](ubuntu26_extended_20261115/updates/20261115_medusa/RESULTS.json) hiding behaviors. For Medusa, 162 valid positive scans alerted and recovered the differences, 180 normal scans raised no alert, and 18 scans were invalid. |
| Separate comparisons | [Trace of the Times](ubuntu26_extended_20261115/updates/20261116_trace_normal/RESULTS.json) flagged 1/10 normal batches under load with function grouping. [Decloaker v0.0.9](docs/D9_DECLOAKER_FORMAL_RESULTS_zh-TW.md) flagged 0/180 hiding scans in a test where the full paths remained accessible. |

## Review scope

Recovery is limited to identities present in an observed view and depends on IBLT decoding. Incomplete observations are reported separately. The rates above describe the tested conditions. See the [artifact scope](ARTIFACT_SCOPE.md) for the evidence and experiment inventory.
