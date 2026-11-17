# Original CARAXES validation protocol — 2026-11-02

Frozen before the first module load. This is an external-sample functional test,
not a rerun or replacement of any earlier experiment or a new timing benchmark.

## Sources and environment

* Upstream: https://github.com/ait-aecid/caraxes
* Fixed commit: `899e8be6b5f6c7236bd23b52aa65051de757e0b3`.
* Linux `6.8.0-138-generic`, original isolated Ubuntu Hyper-V research VM, ext4.
* Default getdents64 configuration: upstream sources unchanged.
* Filldir configuration: only uncomment the five author-provided filldir hook
  entries and include, and comment the getdents64 include/entry in `hooks.h`.
  Retain the original helper, false returns, callback layout and filtering logic.
* No detector changes, package upgrades, persistence, module hiding, privilege
  escalation commands or network capabilities are added to the sample.
* Preserve build stdout/stderr, all source hashes, the configuration diff, module
  hashes, detector hashes and all observed outcomes, including unsuccessful runs.

## Protection

Use a fresh directory; do not modify locked old sources/data. No new Hyper-V
checkpoint could be created: the host account lacks Hyper-V administration rights.
Record this fact instead of claiming a checkpoint exists. Module hiding is disabled
in the original source. Unload in finally blocks, verify `/proc/modules`, verify
the fixture after unload, and reboot between confirmation runs. Stop if cleanup
fails or the guest becomes unhealthy. Never change original sample behavior to
make it detectable.

## Fixture and observations

Create a static ext4 directory containing 64 ordinary files, three files whose

Owner/group must not match upstream ownership-based hiding rules (1001/21).
Store the complete unhooked manifest, including dot entries, inode and type.
All experiments use 256 IBLT cells and the existing fixed evaluation seeds.

First run a separate compatibility pilot, retained outside confirmation counts.
Then use three distinct boot IDs. In each boot:

1. Normal control: 10 complete scans per buffer size (128 and 65,536 bytes).
2. Original getdents64 mode, rootkit before detector: the same 20 scans.
3. Original getdents64 mode, detector before rootkit: the same 20 scans.
4. Original filldir mode, rootkit before detector: the same 20 scans.
5. Original filldir mode, detector before rootkit: the same 20 scans.

This gives 100 detector observations per boot, 300 total if all conditions execute.
Keep independent exact-buffer captures before/after each condition and after
unload. Capture `ls` stdout/stderr as a separate user-visible control. Check the
actual returned rows and errors, rather than assuming only magic names disappear.
The detector's exact dump is the downstream oracle for that same enumeration.

The normal manifest is an external reference, not an assertion that the accepted
kernel view must equal it under all hooks. In particular, original filldir rejects
matching entries (`false`); a missing disk entry need not produce an accepted-item
versus returned-item discrepancy. Describe such cases as boundary limitations or
invalid enumerations as observed; do not count them as correctly detected attacks.

## Closest tool

For each boot and each of normal/getdents64/filldir states, run five target-only
Use the already
fixed `08ccebd8fdcc28c56dc6251cad0683b7c9344bd1` adapter, a shared persistent canary,
4 MiB ring buffer and its existing metrics. Preserve source/binary hashes, results,
errors and event/canary checks. This is 45 observations if every state executes.
These do not test the reverse attachment order and are not cost samples.

## Assessment and reporting

* Normal: require valid equal verdict and an exact match to the unhooked manifest.
* Post-acceptance changes: assess valid alarm and independently recomputed exact
  signed difference against the same enumeration's returned records.
* Rejected entries, syscall errors, probe miss counts and unavailable telemetry:
  report individually; do not relabel invalid as equal or all hiding as in scope.
* A successful decoder alone is insufficient: retain recovery verification and
  compare the recovered tokens with the independent record oracle where defined.
* Distinguish sample loading success, actual missing names, interface error,
  measurement validity, alarm, and verified recovery. Publish all denominators.
* Summaries are derived from raw records. Three boots are repeated observations
  in one VM, not independent hosts or proof of universal rootkit coverage.

Only after evidence verification update the current paper, one-page summary,
README and GitHub. Preserve previous results and their original denominators.
