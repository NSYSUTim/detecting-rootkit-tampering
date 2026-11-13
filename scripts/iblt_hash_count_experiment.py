"""Verify or reproduce the frozen 2026-11-13 offline hash-count experiment.

This publication adapter is separate from the byte-preserved original runner.
It changes filesystem locations only, never seeds, conditions, or decision rules.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import shutil
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "results/iblt_hash_count_20261113"
PROTOCOL_SHA256 = "472342278a42d6034ac267100c589a9c8e2b89c88ea9f442232db8916dcba690"
GROUP_FIELDS = ("family", "role", "mode", "difference", "cells", "k")
NUMERIC_FIELDS = ("difference", "cells", "trial", "seed1", "seed2", "k", "order",
                  "exact", "decode_success", "incorrect_success", "residual_cells",
                  "upstream_recovered", "downstream_recovered", "build_ns", "decode_ns")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_runner(path):
    name = "iblt_hash_count_frozen_runner"
    spec = importlib.util.spec_from_file_location(name, path)
    runner = importlib.util.module_from_spec(spec)
    sys.modules[name] = runner
    spec.loader.exec_module(runner)
    return runner


def interval(successes, trials):
    z = 1.959963984540054
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return [max(0, center - half), min(1, center + half)]


def check_statistics(item, rows):
    n = len(rows)
    successes = sum(r["exact"] for r in rows)
    require(item["trials"] == n and item["exact_successes"] == successes, "Summary counts differ")
    require(item["exact_rate"] == successes / n, "Summary recovery rate differs")
    require(item["wilson95"] == interval(successes, n), "Summary Wilson interval differs")
    require(item["incorrect_successes"] == sum(r["incorrect_success"] for r in rows), "Incorrect-success count differs")
    for field in ("build_ns", "decode_ns"):
        require(item["median_" + field] == statistics.median(r[field] for r in rows), "Timing median differs")


def verify(bundle):
    protocol = read_json(bundle / "protocol.json")
    require(sha(bundle / "protocol.json") == PROTOCOL_SHA256, "Frozen protocol hash differs")
    require((bundle / "protocol.sha256").read_text().strip() == PROTOCOL_SHA256, "Protocol sidecar differs")
    manifest = read_json(bundle / "MANIFEST.json")
    for name, record in manifest.items():
        require(Path(name).name == name, "Manifest entry must be a plain filename")
        path = bundle / name
        require(path.stat().st_size == record["bytes"] and sha(path) == record["sha256"], "Manifest mismatch: " + name)
    require(sha(bundle / "run_experiment.py") == protocol["script_sha256"], "Frozen runner differs")
    require(sha(bundle / "reconciliation_snapshot.py") == protocol["source_sha256"] == protocol["snapshot_sha256"], "Frozen implementation differs")
    started = read_json(bundle / "run_started.json")
    summary = read_json(bundle / "summary.json")
    validation = read_json(bundle / "validation.json")
    require(started["protocol_sha256"] == summary["protocol_sha256"] == PROTOCOL_SHA256, "Run is not linked to protocol")
    require(datetime.fromisoformat(protocol["locked_utc"]) < datetime.fromisoformat(started["started_utc"]) < datetime.fromisoformat(summary["completed_utc"]), "Lock/run timestamp order differs")
    require(summary["status"] == "complete" and validation["passed"] is True, "Original run was incomplete")

    with (bundle / "trials.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        for field in NUMERIC_FIELDS:
            row[field] = int(row[field])
        require(row["exact"] in (0, 1) and row["decode_success"] in (0, 1), "Invalid boolean field")
        require(row["incorrect_success"] == row["decode_success"] - row["exact"], "Outcome flags disagree")
        require(row["build_ns"] > 0 and row["decode_ns"] > 0, "Invalid recorded duration")
    cases, groups = defaultdict(list), defaultdict(list)
    for row in rows:
        cases[tuple(row[f] for f in ("family", "mode", "difference", "cells", "trial"))].append(row)
        groups[tuple(row[f] for f in GROUP_FIELDS)].append(row)
    expected_cases = set()
    for condition in protocol["conditions"]:
        for trial in range(condition["trials"]):
            key = (condition["family"], condition["mode"], condition["difference"], condition["cells"], trial)
            expected_cases.add(key)
            pair = cases[key]
            require(len(pair) == 4 and {r["k"] for r in pair} == {2, 3, 4, 5}, "Missing/duplicate parameter variant")
            require({r["order"] for r in pair} == {0, 1, 2, 3}, "Execution order is incomplete")
            require(len({(r["seed1"], r["seed2"]) for r in pair}) == 1, "Variants did not share seeds")
            require(all(r["role"] == condition["role"] for r in pair), "Condition role changed")
    require(set(cases) == expected_cases, "Extra or missing input cases")
    require(len(cases) == protocol["total_input_cases"] == summary["input_cases"] == 9216, "Input count differs")
    require(len(rows) == protocol["total_variant_decodes"] == summary["variant_decodes"] == 36864, "Decode count differs")
    require(len(summary["groups"]) == len(groups), "Summary group count differs")
    for item in summary["groups"]:
        check_statistics(item, groups[tuple(item[f] for f in GROUP_FIELDS)])
    with (bundle / "summary.csv").open(encoding="utf-8", newline="") as stream:
        csv_groups = list(csv.DictReader(stream))
    require(len(csv_groups) == len(summary["groups"]), "CSV summary group count differs")
    for csv_item, json_item in zip(csv_groups, summary["groups"]):
        require(set(csv_item) == set(json_item), "CSV summary fields differ")
        for key, value in json_item.items():
            require((json.loads(csv_item[key]) == value) if key == "wilson95" else (csv_item[key] == str(value)), "CSV/JSON summary differs: " + key)
    primary = [r for r in rows if r["role"] == "primary"]
    require({i["k"] for i in summary["primary"]} == {2, 3, 4, 5}, "Primary parameter count differs")
    for item in summary["primary"]:
        check_statistics(item, [r for r in primary if r["k"] == item["k"]])
    primary_pairs = defaultdict(dict)
    for row in primary:
        primary_pairs[(row["mode"], row["trial"])][row["k"]] = row["exact"]
    tests = []
    for other in (2, 4, 5):
        wins = sum(p[3] and not p[other] for p in primary_pairs.values())
        losses = sum(p[other] and not p[3] for p in primary_pairs.values())
        n = wins + losses
        p = float(min(Fraction(1), Fraction(2 * sum(math.comb(n, i) for i in range(min(wins, losses) + 1)), 2 ** n))) if n else 1.0
        tests.append(dict(other_k=other, k3_only_correct=wins, other_only_correct=losses, two_sided_exact_p=p))
    adjusted = 0.0
    for rank, item in enumerate(sorted(tests, key=lambda t: t["two_sided_exact_p"])):
        adjusted = max(adjusted, min(1.0, (3 - rank) * item["two_sided_exact_p"]))
        item["holm_adjusted_p"] = adjusted
    require(tests == summary["primary_paired_tests"], "Paired test differs")
    superiority = all(t["k3_only_correct"] > t["other_only_correct"] and t["holm_adjusted_p"] < .05 for t in tests) and not any(r["incorrect_success"] for r in primary)
    require(superiority == summary["k3_strict_recovery_superiority_demonstrated"], "Superiority conclusion differs")
    require(summary["universal_optimality_proven"] is False, "Universal-optimality claim is unsupported")
    require(sum(r["incorrect_success"] for r in rows) == summary["incorrect_successes"], "Overall incorrect-success count differs")

    runner = load_runner(bundle / "run_experiment.py")
    runner.HERE = bundle
    module = runner.load_module()
    variant = runner.variant_class(module)
    require(runner.validate(module, variant) == validation["checks"] == summary["validation"], "Self-check result differs")
    replayed = 0
    for condition in protocol["conditions"]:
        trial_ids = (0, 127, 255, 1023) if condition["role"] == "primary" else (0, 127, 255)
        for trial in trial_ids:
            seed1, seed2, upstream, downstream = runner.inputs(module, condition["mode"], condition["difference"], trial)
            key = (condition["family"], condition["mode"], condition["difference"], condition["cells"], trial)
            for row in cases[key]:
                table = variant(condition["cells"], seed1, seed2, row["k"], condition["family"])
                for token in upstream:
                    table.add(token)
                for token in downstream:
                    table.add(token, -1)
                decoded = table.decode()
                exact = decoded.success and Counter(decoded.upstream_only) == Counter(upstream) and Counter(decoded.downstream_only) == Counter(downstream)
                require((seed1, seed2) == (row["seed1"], row["seed2"]), "Regenerated seed differs")
                require(int(exact) == row["exact"] and int(decoded.success) == row["decode_success"], "Replayed oracle result differs")
                require(decoded.residual_cells == row["residual_cells"], "Replayed residual differs")
                require(len(decoded.upstream_only) == row["upstream_recovered"] and len(decoded.downstream_only) == row["downstream_recovered"], "Replayed recovery counts differ")
                replayed += 1
    original_check = read_json(bundle / "verification.json")
    require(original_check["passed"] and original_check["raw_rows"] == len(rows) and original_check["complete_paired_inputs"] == len(cases) and original_check["deterministic_replayed_variants"] == replayed, "Original audit record differs")
    return dict(passed=True, checked_utc=datetime.now(timezone.utc).isoformat(),
                protocol_sha256=PROTOCOL_SHA256, manifest_files_verified=len(manifest),
                raw_rows=len(rows), complete_paired_inputs=len(cases), summary_groups_verified=len(groups),
                deterministic_replayed_variants=replayed, validation=validation["checks"],
                primary_paired_tests=tests, k3_strict_recovery_superiority_demonstrated=superiority,
                limitations="Counts, pairing, hashes and statistics independently checked; sampled replay reuses the locked algorithm. Historical timing values are checked against recorded CSV, not reproduced.")


def reproduce(output):
    # Check the publication before running exactly its frozen settings.
    verify(BUNDLE)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(BUNDLE / "run_experiment.py", output / "run_experiment.py")
    runner = load_runner(output / "run_experiment.py")
    runner.HERE = output
    runner.REPO = ROOT
    runner.SOURCE = BUNDLE / "reconciliation_snapshot.py"
    runner.prepare()
    runner.run()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("verify", help="Verify all original records and replay the fixed 368-variant sample")
    check.add_argument("--bundle", type=Path, default=BUNDLE)
    check.add_argument("--output", type=Path, help="Write a new audit JSON; refuses to overwrite")
    run = commands.add_parser("run", help="Re-run the full frozen grid in a new directory")
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "run":
        reproduce(args.output.resolve())
    else:
        if args.output:
            require(not args.output.exists(), "Audit output already exists")
        result = verify(args.bundle.resolve())
        if args.output:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(result, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
