# Licensing

Copyright (c) 2026 Wei-Ting Chiang for the original code listed below.

## User-space code

The following files are available under the [MIT License](LICENSE).

- [`scan_directory.py`](scan_directory.py)
- [`scan_library.py`](scan_library.py)
- [`src/kicba/`](src/kicba/)
- [`collector/library_probe.c`](collector/library_probe.c)
- [`phase1/coverage.py`](phase1/coverage.py)
- [`phase1/enum_probe.c`](phase1/enum_probe.c)
- [`phase1/run_experiments.py`](phase1/run_experiments.py)
- [`phase2/measurement.py`](phase2/measurement.py)
- [`phase2/oracle.py`](phase2/oracle.py)
- [`finalization/measurement.py`](finalization/measurement.py)
- [`finalization/tracefs_measurement.py`](finalization/tracefs_measurement.py)
- [`call_completion/measurement.py`](call_completion/measurement.py)
- [`demo/replay.py`](demo/replay.py)
- [`demo/scan.sh`](demo/scan.sh)

## Linux eBPF probes

The following files are available under the [GNU General Public License, version 2 only](LICENSES/GPL-2.0-only.txt) (`GPL-2.0-only`).

- [`collector/bpf_d9_exact_map_trace.c`](collector/bpf_d9_exact_map_trace.c)
- [`collector/bpf_d9_reconciliation.c`](collector/bpf_d9_reconciliation.c)
- [`collector/d9_reconciliation_hash.h`](collector/d9_reconciliation_hash.h)
- [`phase1/bpf_measurement.c`](phase1/bpf_measurement.c)
- [`phase2/bpf_packed.c`](phase2/bpf_packed.c)
- [`phase2/name_hash.h`](phase2/name_hash.h)
- [`call_completion/bpf.c`](call_completion/bpf.c)
- [`terminal_rejection/bpf.c`](terminal_rejection/bpf.c)

## Other materials

Third-party materials retain their original licenses and notices. See [Third-Party Notices](THIRD_PARTY_NOTICES.md). The software licenses above cover the listed source files. Reports, datasets, and archived experiments are outside their scope.
