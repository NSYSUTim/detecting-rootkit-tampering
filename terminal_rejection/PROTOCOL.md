# Terminal rejection rule and native validation

2026-11-03. Authorized addition to the existing accepted-versus-returned check.
Freeze before the pilot. Preserve all previous sources, data and denominators.

## Method

Retain the fingerprint decision, IBLT, recovery verification and quality gates.
Add the result and bounded identity/name of the last outermost filldir64 attempt.
The original C scanner exits successfully only after getdents64 returns zero.
For such a complete, valid scan, a last false return adds a terminal-rejection
alert. Return errors, missing telemetry or quality failures remain invalid.
Keep the original identity verdict and identity alarm separately. An alert caused
only by terminal rejection is not an identity mismatch or a verified IBLT recovery.
Expose the rejected witness separately, with the total missing count unknown.

Do not infer maliciousness, completeness of a directory snapshot, or all hidden
names. A legitimate deletion after a full-buffer rejection can leave the same
terminal observation. Do not claim this is the only possible benign cause or that
rescanning authenticates the first result. A witness requires fixed metadata and
up to 255 name bytes plus terminator, not merely a single extra bit.

## Versions and protection

Original packed source, C scanner and prior public-sample archive remain immutable.
Create a derived BPF source with its exact patch. The current entry point changes
to the new rule, while the old factory retains its default behavior. Use the same
Linux 6.8.0-138-generic isolated VM, no package upgrades or persistence. New guest
directory, finally-based unload, manifest restoration and three new boot IDs.
Host Hyper-V checkpoint rights remain unavailable; do not claim a new checkpoint.

## Native confirmation

First retain an excluded pilot. Then three independent boots of the same VM:

* Original CARAXES: normal, original getdents64, original filldir; both attachment
  orders for each module mode; buffers 128 and 65,536, ten repeats per condition.
  This is 100 observations per boot, 300 total. Independently capture visible
  records with/without probes, module-free manifest, and restored output.
* Regression of previous controlled states: normal, forward-only wrappers,
  compare-only wrappers, hiding, policy filtering, equal-count replacement,
  insertion, longer/shorter names, inode/type changes and reordering. Five repeats
  with four buffers (128, 256, 4,096, 65,536) where compatible. List exact states
  and denominators in the runner metadata. Compare exact returned identities,
  expected fingerprints, signed recovery and terminal witness.
* Normal ext4 and tmpfs directories, small/large buffers, plus concurrent normal
  create/rename/delete churn. Keep all alerts rather than preselecting clean runs.
  Record whether the normal mutator actually ran during scans.
* Controlled benign race: pause the scanner immediately after a buffer-full
  rejection, delete all not-yet-delivered entries using the saved unhooked oracle,
  then resume to EOF. This requires an additive test-only gated scanner, no
  malicious module. If the last false remains, report the resulting alert as a
  benign terminal-rejection alert, not proof of rootkit detection.
* Existing quality-failure handling: synthetic record tests retain invalid over
  either alarm. At least one native missing-telemetry/failed syscall check and
  normal controls. Do not claim a rerun of every historical loss injection.

No new comparison speed claim. Existing timings describe their original version.
Report actual new state size and scan times descriptively if available; preserve
all pilots, invalids, failures and deployment/build logs. Offline recompute from
the archived raw rows before changing the paper, README and GitHub.
