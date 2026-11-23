# Directory Entry Check Demo

## Replay

Run from the [Directory Entry Check](../README.md) repository root with Python 3.10+. Press Enter between scenes.

```sh
python -B demo/replay.py --en --interactive
```

1. **Normal listing.** Kernel and syscall views (K and S) agree on 70 entries.
2. **CARAXES.** S drops to 67 entries. IBLT recovers three verified entries. In a separate comparison, Decloaker flagged 0 of 180 hiding scans.
3. **Timing under load.** Trace of the Times flagged 1 of 10 normal batches in function mode. In separately collected load tests, K–S flagged 0 of 150 normal batches and all 100 hiding batches.
4. **Medusa.** In the archived syscall/library (S–L) case, the library view omits one target. Recovery was verified.

K–S recovery is recomputed from archived observations. Timing and Medusa use recorded results.

## Live scan

On native Linux, use a test directory on the ext4 root filesystem, BCC, GCC, `strace`, `sudo`, and a trusted Decloaker v0.0.9 executable.

```sh
bash demo/scan.sh --en "$DIR" "$DECLOAKER"
```

K–S, S–L and Decloaker scan the directory again. Times displays precomputed results. The last line gives the log directory. On WSL, K–S requires a scanner that handles its PID namespace.

Omit `--en` for Chinese output. When updating results, check the counts and rerun all four scenes. Sources: [Timing comparison](../docs/D9_TRACE_FORMAL_RESULTS_zh-TW.md), [disk comparison](../docs/D9_DECLOAKER_FORMAL_RESULTS_zh-TW.md), [Medusa results](../ubuntu26_extended_20261115/updates/20261115_medusa/RESULTS.json).
