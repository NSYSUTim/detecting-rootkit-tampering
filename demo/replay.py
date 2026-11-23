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


def show_listing(hidden):
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

    verdict = "一致，無告警" if kernel == syscall else "差異，告警"
    print(f"K={kernel[0]}，S={syscall[0]}（含 . 和 ..），{verdict}。")
    names = {item["inode"]: bytes.fromhex(item["name_hex"]).decode("utf-8", "backslashreplace")
             for item in baseline["visible"]}
    if hidden:
        print(f"已核對還原 {len(removed)} 筆：" + "、".join(names[inode] for _, inode, _ in removed))
        disk = read_json(COMPARISONS / "decloaker/formal_20260925/validation.json")["confusion"]
        print(f"磁碟法（另一次正式對照）：{disk['tp']}/{disk['tp'] + disk['fn']} 次隱藏掃描告警。")
    else:
        print("代表項目：" + "、".join(sorted(set(names.values()) - {".", ".."})[:5]))


def show_timing():
    normal = read_json(UPDATES / "20261116_trace_normal/RESULTS.json")
    positive = read_json(UPDATES / "20261116_trace_positive/RESULTS.json")
    print("Times 預跑結果，每批 100 次列舉。")
    for record in normal["predictions"]:
        if record["scenario"] == "system_load" and record["state"] == "false_alarm":
            print(f"  {record['file']}（正常）：p={record['score']:.3g} < {record['threshold']:.3g}，誤報。")
    for group, label in (("fun", "函式"), ("seq", "序列")):
        controls = normal["scenario_outcomes"]["system_load"][group]
        cases = positive["scenario_outcomes"]["system_load"][group]
        print(f"  {label}：{controls.get('false_alarm', 0)}/{sum(controls.values())} 批誤報，"
              f"{cases.get('correct_rootkit', 0)}/{sum(cases.values())} 批樣本告警。")
    formal = read_json(COMPARISONS / "d9/formal_20260925/d9_external_formal_20260925/validation.json")
    per_batch = formal["transactions"] // formal["batches"]
    counts = formal["per_scenario_confusion"]["system_load"]
    fp, tn, tp, fn = (counts.get(key, 0) // per_batch for key in ("fp", "tn", "tp", "fn"))
    print(f"本法（正式比較，另收負載批次）：{fp}/{fp + tn} 批誤報，{tp}/{tp + fn} 批樣本告警。")


def show_medusa():
    folder = UPDATES / "20261115_medusa"
    summary = read_json(folder / "RESULTS.json")["counts"]
    with (folder / "cases/cohort_1.csv").open(newline="", encoding="utf-8") as stream:
        example = next((row for row in csv.DictReader(stream) if row["case"] == "ext4_00_medusa"), None)
    if not example or example["primary_exact_recovery"] != "True":
        raise ValueError("missing verified Medusa case")
    print(f"封存個案：S 端有 {example['targets_absent_from_app']} 個目標沒出現在 L 端，還原通過核對。")
    print(f"三次開機 {summary['attempted']} 筆：{summary['normal_no_alarm']} 正常無告警，"
          f"{summary['positive_alarm_exact']} 告警且還原，{summary['invalid']} 無效。")
    print("這組只收 S↔L，時間法和磁碟法未量測。")


def show_live_ks(run):
    result = read_json(run / "k-s.json")
    if not result["measurement_valid"] or result["verdict"] in ("inconclusive", "invalid"):
        print(f"K↔S 無法判定。詳見 {run / 'k-s.json'}。")
        return 2
    print(f"K={result['kernel_fingerprint'][0]}，S={result['userspace']['count']}，"
          f"{'告警' if result['alarm'] else '無告警'}。")
    if result["recovery_verified"]:
        for side, field in (("K 有、S 無", "upstream_only"), ("S 有、K 無", "downstream_only")):
            for identity, inode, kind in result[field]:
                print(f"  已核對還原｜{side}｜inode={inode}｜型態={kind}｜{identity:#018x}")
    return 0


def show_live_disk(run):
    stdout = (run / "decloaker.txt").read_text(encoding="utf-8", errors="replace")
    stderr = (run / "decloaker.stderr").read_text(encoding="utf-8", errors="replace")
    exit_code = int((run / "decloaker.exit").read_text().strip())
    lines = re.sub(r"\x1b\[[0-9;]*m", "", stdout).splitlines()
    if exit_code or stderr.strip() or any(DISK_ERROR.match(line) for line in lines):
        print("磁碟掃描執行錯誤。詳見原始輸出。")
        return 2
    alerts = [line for line in lines if re.match(r"^HIDDEN:\s+\S", line)]
    if alerts:
        print(*alerts, sep="\n")
        return 0
    entries = sum(bool(DISK_ENTRY.fullmatch(line)) for line in lines)
    if not entries:
        print("磁碟掃描無法判定：沒有可辨識的磁碟列舉。")
        return 2
    print(f"無 HIDDEN 告警（磁碟列舉 {entries} 項）。")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("view", nargs="?", default="all", choices=("all", "timing", "ks", "disk"))
    parser.add_argument("run", nargs="?", type=Path)
    parser.add_argument("--interactive", action="store_true")
    args = parser.parse_args()
    try:
        if args.view in ("ks", "disk"):
            if not args.run:
                parser.error("a results directory is required")
            return (show_live_ks if args.view == "ks" else show_live_disk)(args.run)
        if args.view == "timing":
            show_timing()
            return 0
        scenes = (
            ("正常列舉", lambda: show_listing(False)),
            ("CARAXES 差異還原", lambda: show_listing(True)),
            ("時間法負載誤報", show_timing),
            ("Medusa 的 S↔L 差異", show_medusa),
        )
        for index, (title, display) in enumerate(scenes, 1):
            if index > 1 and args.interactive:
                input("\n按 Enter 換幕…")
            print(f"\n【幕 {index}】{title}")
            display()
    except EOFError:
        return 0
    except (OSError, ValueError, KeyError) as error:
        parser.exit(2, f"Demo 無法完成：{error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
