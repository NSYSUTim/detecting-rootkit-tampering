# Pilot adjustments retained before confirmation

The first deployed bundle omitted the new untracked Python module. Its failed
import and deployment tar are retained; the second compile/normal scan succeeded.
The VM wall clock lagged source tar timestamps; no clock or package changes were
made. Experiments use boot identities and monotonic durations, not host/guest
wall-clock alignment.

The first regression pilot completed. Three insertion/longer-name transformations
were not exercised at short-buffer boundaries. The runner now records the actual
module counter delta and separately counts unexercised attempts, as previous
experiments did. These are not converted into successful positives.

The first benign-race fixture had many children. Deleting remaining children still
allowed accepted dot entries (ext4) or repeated ordinary entries (tmpfs), so both
scans correctly ended without a terminal alert. Preserve those results. The second
pilot uses a minimal one-file directory and a 64-byte buffer to test rejection of
the remaining entry followed by its legitimate deletion. Results, including an
unsuccessful construction, remain evidence rather than assumptions.

The second pilot completed with exact output/identity/recovery assessments
matching. In its minimal race, ext4 still delivered the deleted cached entry and
ended equal; tmpfs ended with the rejected candidate absent and raised the new
terminal alert. No malicious module was loaded for either race. Thus benign
terminal alerts are an observed result, not just a hypothetical possibility.
Both forced syscall errors and omitted terminal telemetry were invalid.
