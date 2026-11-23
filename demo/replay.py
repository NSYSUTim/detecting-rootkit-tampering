"""Display the four demo scenes using the repository's published evidence."""

import argparse
import csv
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
OBSERVATIONS = ROOT / "ubuntu26/rerun_20261114/observations/caraxes_call/boot_01/observations.jsonl"
COMPARISONS = ROOT / "results/d9_external_comparison"
UPDATES = ROOT / "ubuntu26_extended_20261115/updates"
DISK_ENTRY = re.compile(
    r"^(?:-|[dLaTugct?lpsSbD]+)[rwxstST-]{9}\t\s*\d+ \d+ \d+\s*\t\s*\d+\s*\t"
    r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:Z|[+-]\d\d:\d\d)\t.+$"
)
DISK_ERROR = re.compile(r"^\s*(?:\[e\]\s*|unable to (?:read|stat)\b|error listing\b)", re.I)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def show_listing(hidden, tr):
    sys.path.insert(0, str(ROOT / "src"))
    from kicba.reconciliation import IBLT, MultisetFingerprint, token_for_entry
    from kicba.recovery_validation import validate_recovery

    captures = {}
    with OBSERVATIONS.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["dump"] in ("observation_3.jsonl", "observation_27.jsonl"):
                captures[row["mode"]] = row
    baseline = captures["normal"]
    row = captures["getdents64"] if hidden else baseline
    if not row["measurement_valid"]:
        raise ValueError("invalid archived K↔S measurement")

    seed1, seed2, cells, _ = row["configuration"]
    tokens = [token_for_entry(bytes.fromhex(item["name_hex"]), item["inode"], item["d_type"], seed1, seed2)
              for item in row["visible"]]
    syscall = MultisetFingerprint.from_tokens(tokens).as_tuple()
    kernel = tuple(row["kernel_fingerprint"])
    captured = tuple(row["userspace"][key] for key in ("count", "sum1", "sum2"))
    decoded = IBLT.from_rows(row["kernel_rows"], seed1, seed2).subtract(
        IBLT.from_tokens(tokens, cells, seed1, seed2)
    ).decode()
    removed = sorted((item.key_hash, item.inode, item.d_type) for item in decoded.upstream_only)
    added = sorted((item.key_hash, item.inode, item.d_type) for item in decoded.downstream_only)
    check = validate_recovery(kernel, syscall, removed, added, decoded.success, decoded.residual_cells)
    if (not check["verified"] or syscall != captured or (kernel != syscall) != row["alarm"]
            or removed != sorted(map(tuple, row["external_missing"]))
            or added != sorted(map(tuple, row["external_extra"]))):
        raise ValueError("K↔S recovery did not match the archived verification")

    verdict = tr("一致，無告警", "match, no alert") if kernel == syscall else tr("差異，告警", "mismatch, alert")
    print(tr(f"K={kernel[0]}，S={syscall[0]}（含 . 和 ..），{verdict}。",
             f"K={kernel[0]}, S={syscall[0]} (including . and ..): {verdict}."))
    names = {item["inode"]: bytes.fromhex(item["name_hex"]).decode("utf-8", "backslashreplace")
             for item in baseline["visible"]}
    if hidden:
        recovered = [names[inode] for _, inode, _ in removed]
        print(tr(f"已核對還原 {len(removed)} 筆：", f"Verified recovery of {len(removed)} entries: ")
              + tr("、", ", ").join(recovered))
        disk = read_json(COMPARISONS / "decloaker/formal_20260925/validation.json")["confusion"]
        alerts = f"{disk['tp']}/{disk['tp'] + disk['fn']}"
        print(tr(f"磁碟法（另一次正式對照）：{alerts} 次隱藏掃描告警。",
                 f"Decloaker (separate comparison): {alerts} hiding scans raised an alert."))
    else:
        print(tr("代表項目：", "Example entries: ")
              + tr("、", ", ").join(sorted(set(names.values()) - {".", ".."})[:5]))


def show_timing(tr):
    normal = read_json(UPDATES / "20261116_trace_normal/RESULTS.json")
    positive = read_json(UPDATES / "20261116_trace_positive/RESULTS.json")
    print(tr("Times 預跑結果，每批 100 次列舉。", "Trace of the Times (precomputed): 100 listings per batch."))
    for record in normal["predictions"]:
        if record["scenario"] == "system_load" and record["state"] == "false_alarm":
            score = f"p={record['score']:.3g} < {record['threshold']:.3g}"
            print(tr(f"  {record['file']}（正常）：{score}，誤報。",
                     f"  {record['file']} (normal): {score}, false positive."))
    for group, label in (("fun", tr("函式", "Function")), ("seq", tr("序列", "Sequence"))):
        controls = normal["scenario_outcomes"]["system_load"][group]
        cases = positive["scenario_outcomes"]["system_load"][group]
        false_alarms = f"{controls.get('false_alarm', 0)}/{sum(controls.values())}"
        detections = f"{cases.get('correct_rootkit', 0)}/{sum(cases.values())}"
        print(tr(f"  {label}：{false_alarms} 批誤報，{detections} 批樣本告警。",
                 f"  {label}: {false_alarms} normal batches flagged, {detections} hiding batches flagged."))
    formal = read_json(COMPARISONS / "d9/formal_20260925/d9_external_formal_20260925/validation.json")
    per_batch = formal["transactions"] // formal["batches"]
    counts = formal["per_scenario_confusion"]["system_load"]
    fp, tn, tp, fn = (counts.get(key, 0) // per_batch for key in ("fp", "tn", "tp", "fn"))
    print(tr(f"本法（正式比較，另收負載批次）：{fp}/{fp + tn} 批誤報，{tp}/{tp + fn} 批樣本告警。",
             f"K–S comparison (separately collected load batches): {fp}/{fp + tn} normal batches flagged, "
             f"{tp}/{tp + fn} hiding batches flagged."))


def show_medusa(tr):
    folder = UPDATES / "20261115_medusa"
    summary = read_json(folder / "RESULTS.json")["counts"]
    with (folder / "cases/cohort_1.csv").open(newline="", encoding="utf-8") as stream:
        example = next((row for row in csv.DictReader(stream) if row["case"] == "ext4_00_medusa"), None)
    if not example or example["primary_exact_recovery"] != "True":
        raise ValueError("missing verified Medusa case")
    missing = example["targets_absent_from_app"]
    print(tr(f"封存個案：S 端有 {missing} 個目標沒出現在 L 端，還原通過核對。",
             f"Archived case: {missing} target(s) present in S and absent from L. Recovery verified."))
    normal, recovered, invalid = (summary[key] for key in ("normal_no_alarm", "positive_alarm_exact", "invalid"))
    print(tr(f"三次開機 {summary['attempted']} 筆：{normal} 正常無告警，{recovered} 告警且還原，{invalid} 無效。",
             f"Three boots, {summary['attempted']} scans: {normal} normal with no alert, "
             f"{recovered} alerts with verified recovery, {invalid} invalid."))
    print(tr("這組只收 S↔L，時間法和磁碟法未量測。", "This experiment recorded S–L only."))


def show_live_ks(run, tr):
    result = read_json(run / "k-s.json")
    if not result["measurement_valid"] or result["verdict"] in ("inconclusive", "invalid"):
        path = run / "k-s.json"
        print(tr(f"K↔S 無法判定。詳見 {path}。", f"K–S result unavailable. See {path}."))
        return 2
    verdict = tr("告警", "alert") if result["alarm"] else tr("無告警", "no alert")
    counts = f"K={result['kernel_fingerprint'][0]}, S={result['userspace']['count']}"
    print(tr(f"{counts}，{verdict}。", f"{counts}: {verdict}."))
    if result["recovery_verified"]:
        for side, field in ((tr("K 有、S 無", "K only"), "upstream_only"),
                            (tr("S 有、K 無", "S only"), "downstream_only")):
            for identity, inode, kind in result[field]:
                print(tr(f"  已核對還原｜{side}｜inode={inode}｜型態={kind}｜{identity:#018x}",
                         f"  Verified recovery: {side}, inode={inode}, type={kind}, ID={identity:#018x}"))
    return 0


def show_live_disk(run, tr):
    stdout = (run / "decloaker.txt").read_text(encoding="utf-8", errors="replace")
    stderr = (run / "decloaker.stderr").read_text(encoding="utf-8", errors="replace")
    exit_code = int((run / "decloaker.exit").read_text().strip())
    lines = re.sub(r"\x1b\[[0-9;]*m", "", stdout).splitlines()
    if exit_code or stderr.strip() or any(DISK_ERROR.match(line) for line in lines):
        print(tr("磁碟掃描執行錯誤。詳見原始輸出。", "Disk scan failed. See the raw output."))
        return 2
    alerts = [line for line in lines if re.match(r"^HIDDEN:\s+\S", line)]
    if alerts:
        print(*alerts, sep="\n")
        return 0
    entries = sum(bool(DISK_ENTRY.fullmatch(line)) for line in lines)
    if not entries:
        print(tr("磁碟掃描無法判定：沒有可辨識的磁碟列舉。", "Disk scan inconclusive: no recognizable listing."))
        return 2
    print(tr(f"無 HIDDEN 告警（磁碟列舉 {entries} 項）。", f"No HIDDEN alerts ({entries} disk entries listed)."))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("view", nargs="?", default="all", choices=("all", "timing", "ks", "disk"))
    parser.add_argument("run", nargs="?", type=Path)
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--en", action="store_true", help="display output in English")
    args = parser.parse_args()

    def tr(zh, en):
        return en if args.en else zh

    try:
        if args.view in ("ks", "disk"):
            if not args.run:
                parser.error("a results directory is required")
            return (show_live_ks if args.view == "ks" else show_live_disk)(args.run, tr)
        if args.view == "timing":
            show_timing(tr)
            return 0
        scenes = (
            (tr("正常列舉", "Normal directory listing"), lambda: show_listing(False, tr)),
            (tr("CARAXES 差異還原", "CARAXES: recover the missing entries"), lambda: show_listing(True, tr)),
            (tr("時間法負載誤報", "Timing false positives under load"), lambda: show_timing(tr)),
            (tr("Medusa 的 S↔L 差異", "Medusa: syscall vs. library"), lambda: show_medusa(tr)),
        )
        for index, (title, display) in enumerate(scenes, 1):
            if index > 1 and args.interactive:
                input(tr("\n按 Enter 換幕…", "\nPress Enter for the next scene..."))
            print(tr(f"\n【幕 {index}】{title}", f"\nScene {index}: {title}"))
            display()
    except EOFError:
        return 0
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, tr(f"Demo 無法完成：{error}\n", f"Demo failed: {error}\n"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
