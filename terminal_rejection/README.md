# Terminal rejection signal

**已撤回，僅供歷史重現。** 現行 scan_directory.py 已恢復接受項目比對，預設不使用這條規則。本頁記錄的是撤回前的試驗與正常刪除警報，不是現行功能。

The withdrawn trial scanner retained the original identity fingerprint/IBLT decision and
added a separate alert if a valid complete scan ended after an outermost filldir64
rejection. Its output retained `identity_verdict`, `identity_alarm` and verified
IBLT recovery, and separately exposes `terminal_rejection`, `rejected_entry` and
`alarm_reasons`. The witness is not a complete missing set; its total is unknown.

Three fresh boots: 120 original CARAXES getdents64 observations retain identity
alarms and verified recovery, 120 original filldir observations now have terminal
alerts, and 60 public-sample normal controls remain equal. An additional 960
controlled regressions, 120 normal static, 240 normal churn, 30 benign deletion
races and 12 fault controls are retained. Forty-five short-buffer transformations
were not exercised and are not counted as successful positives.

**A normal deletion can cause the same signal.** In the controlled benign race,
tmpfs has 15/15 terminal alerts and ext4 0/15. This is not an estimate of real-world
frequency. Do not describe the new rule as zero-false-positive rootkit detection,
or the witness as a full IBLT recovery. Ordinary churn's 240 clean scans do not
cancel this counterexample. The [Chinese report](../docs/TERMINAL_REJECTION_20261103_zh-TW.md)
explains the observed mechanism, limits, versions and costs.

The frozen packed BPF source, original scanner, previous tracefs collector and
historical data remain unchanged. [bpf.patch](bpf.patch) records the additive
instrumentation. State value size increases by 296 bytes, from 10,400 to 10,696.
The 24-byte fingerprint and 256-cell IBLT retain their original settings. Previous
timing results are not measurements of this new version.

[Raw archive](terminal_rejection_20261103.tar.gz), [verification](verification.json),
[protocol](PROTOCOL.md) and [pilot notes](PILOT_NOTES.md) preserve failed attempts,
invalids and benign alerts. The archive's `code` directory is the actual deployed
version. `DEPLOYMENT_SOURCES.json` records a host-side prepared package; the last
transfer of notes/controller failed, so this is not the deployment truth. The
offline verifier checks actual archived sources across all three boots and the
current core implementation.

```bash
python terminal_rejection/summarize.py --archive terminal_rejection/terminal_rejection_20261103.tar.gz --extract-to reproduced/terminal_rejection --output reproduced/terminal_rejection_verification.json
```

The test-only gated scanner pauses after a returned batch to permit a legitimate
deletion before the next syscall. It does not install a hiding module or alter the
production C scanner. Native runners refer to the original lab's locked binaries
and modules, whose hashes are included in the raw manifests.
