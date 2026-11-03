# Per-call directory completion implementation plan

**Goal:** Detect the observed CARAXES false-rejection/zero-return sequence without flagging a rejection followed by legitimate deletion between calls.

**Approved design:** The author's 2026-11-03 instruction approves implementing and testing the preceding chat design, then publishing passing results. Preserve the accepted-item fingerprint/IBLT branch. Add a separately qualified check of the exact getdents64 call returning zero. Do not classify every final false return as hiding.

**Architecture:** Derive a BPF program from frozen phase2/bpf_packed.c; bracket callbacks with syscall tracepoints. A native collector retains the existing identity gates and separately qualifies new telemetry. A pure Python finalizer emits a completion anomaly only for a balanced zero-return call with rejected attempts and no accepted entries. Missing new telemetry cannot erase an already valid identity alarm.

**Environment:** Existing isolated Ubuntu VM, Linux 6.8.0-138-generic; no upgrades, no historical-source overwrite. Work on fix/call-completion-20261103, in a new call_completion directory. No additional agents. Existing checkpoint ACL limitation remains recorded.

This file records the pre-execution plan. The implemented result, retained shortfalls, verification and publication status are recorded in [the research report](../../CALL_COMPLETION_20261103_zh-TW.md) and its publication receipt, rather than by retroactively rewriting the frozen plan.

## Tasks

- [ ] Write behavioral tests in tests/test_call_completion.py. Cover CARAXES-like EOF rejection, deletion between calls, normal resends, syscall errors, missing/contradictory pairing, witness corruption, preservation of identity alarms/recovery, and new-program counter loss. Run them and retain the expected pre-implementation failures.
- [ ] Implement src/kicba/call_completion.py, call_completion/build_bpf.py and call_completion/measurement.py. Keep frozen collectors and the withdrawn terminal trial byte-identical. Run unit tests and compile/load the actual BPF program in the VM.
- [ ] Freeze call_completion/PROTOCOL.md before confirmation. Pilot original unmodified public samples, controlled old cases, and the known tmpfs benign race. Keep every pilot/failure in the archive. If the candidate fails, investigate before changing criteria; do not promote it.
- [ ] Execute three fresh boots in a new VM directory. Each boot: original public sample with both orders and buffers; old-state regressions; ext4/tmpfs static and concurrent mutation controls; gated deletion race; native syscall error and missing/new-pairing faults. Independently replay verdicts, fingerprints, IBLTs and filesystem oracles from raw captures. Record source hashes and cleanup.
- [ ] Measure the new and accepted-only scanners in randomized paired blocks at 128, 4096 and 65536 entries, five blocks per boot, with the same start/finish boundaries and all checks included. No new superiority claim from historical timings.
- [ ] Only after evidence passes, update scan_directory.py, README and method/comparison/scope documents. Publish an updated formal paper and summary with explicit old/new cohorts, scope, extra state and measured cost. Keep revised39 and the withdrawn revised40 unchanged.
- [ ] Run all unit tests and independent archive verification, verify historical checksums except explicitly updated catalogs, render/check changed documents, regenerate FILE_SHA256.csv, commit, merge and push. Confirm GitHub main matches local HEAD. Do not touch the user's Word lock file.

## Acceptance criteria frozen before confirmation

1. Every exercised old identity mismatch must still alarm; every fully recovered static oracle must match, not merely satisfy the fingerprint.
2. Original getdents64 sample must retain identity alarms/recovery. Original filldir sample must produce the new completion anomaly with its rejected witness; no claim to recover the unseen suffix.
3. All no-rootkit static controls, concurrent normal mutations and the constructed deletion-between-calls controls must avoid completion alerts. Negative syscall returns remain invalid.
4. Pairing/tracepoint/witness faults must never become a valid completion verdict. A valid original identity alarm survives failure of only the added branch.
5. Counts, program/event identities, source hashes, repeated boot IDs, outputs and cleanups must independently validate. Unexercised attacks and failures stay in the denominator accounting with accurate labels.
6. Successful confirmation is finite evidence in the stated environment, not a guarantee against arbitrary kernel adversaries or all filesystem behaviors.
