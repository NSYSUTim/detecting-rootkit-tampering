"""Run the pinned Trace collection, shared D9 matrix, and offline evaluators."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

T = Path("/home/kicba/ubuntu26_20261114")
B = Path("/home/kicba/research_phase2_20261023")
WORK = T / "trace_work"
OUT = T / "observations/trace_of_times"
ACK = "I_UNDERSTAND_THIS_LOADS_A_ROOTKIT_IN_AN_ISOLATED_VM"
sys.path[:0] = [str(B), str(B / "src"), str(B / "collector")]
from phase1.record_environment import inventory


def run(name, argv, cwd=WORK):
    with (OUT / (name + ".stdout")).open("xb") as stdout, (OUT / (name + ".stderr")).open("xb") as stderr:
        print(json.dumps({"started": name, "argv": argv}), flush=True)
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(str(path) for path in (WORK, B / "src", B / "collector", B))}
        started=time.monotonic()
        process=subprocess.Popen(argv, cwd=cwd, stdout=stdout, stderr=stderr, env=env)
        while True:
            try:
                code=process.wait(timeout=55)
                break
            except subprocess.TimeoutExpired:
                progress={'progress':name,'elapsed_seconds':round(time.monotonic()-started,1)}
                log=OUT/('collection.jsonl' if name=='collection' else 'd9/collection.jsonl')
                if name in ('collection','d9_collection') and log.exists():
                    with log.open() as records:progress['batches_completed']=sum(bool(line.strip()) for line in records)
                    progress['batches_total']=1250 if name=='collection' else 1000
                print(json.dumps(progress),flush=True)
    print(json.dumps({"finished": name, "returncode": code}), flush=True)
    if code:
        print((OUT / (name + ".stderr")).read_text(errors="replace")[-3800:], flush=True)
    return code


def collect():
    subprocess.run([sys.executable,str(T/'guest_archive_supplemental.py')],check=True)
    OUT.mkdir(parents=True, exist_ok=True)
    if any((OUT/name).exists() for name in ('collection_environment.json','collection.stdout','collection.jsonl')):
        raise FileExistsError('A previous timing collection exists; preserve it before selecting a new attempt')
    before = inventory()
    sources = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
               for path in WORK.iterdir() if path.is_file()}
    (OUT / "collection_environment.json").write_text(json.dumps({"environment": before, "sources": sources}, indent=2))
    (WORK / "events").mkdir(exist_ok=False)
    code=run("collection", [sys.executable, "run_matrix.py", "--seed", "42",
               "--log", str(OUT / "collection.jsonl"), "--isolated-vm-ack", ACK])
    after=inventory()
    (OUT/'collection_environment_after.json').write_text(json.dumps({'environment':after,
        'same_kernel':before['kernel']==after['kernel'],'same_boot':before['boot_id']==after['boot_id'],
        'same_packages':before['package_inventory_sha256']==after['package_inventory_sha256']},indent=2))
    return code


def d9():
    OUT.mkdir(parents=True, exist_ok=True)
    return run("d9_collection", [sys.executable, "collector/run_d9_external_matrix.py",
               "--output", str(OUT / "d9"), "--probe", str(B / "collector/bin/d9_enum_probe"),
               "--hiding-ko", str(B / "attack_variants/d7_controls_r2/kicba_d7_hiding.ko"),
               "--seed", "42", "--isolated-vm-ack", ACK], B)


def analyze():
    if not (OUT/'collection.jsonl').is_file():
        raise RuntimeError('The upstream timing dataset has not been collected yet')
    events = WORK / "events"
    subset = OUT / "events_four_scenario"
    run("four_scenario_selection", [sys.executable, str(WORK / "prepare_four_scenario_view.py"),
        "--collection", str(OUT / "collection.jsonl"), "--events", str(events), "--output", str(subset)])
    python = T / "analysis_venv/bin/python"
    results = {}
    for scope, dataset in (("five", events), ("four", subset)):
        for grouping in ("fun", "seq"):
            label = f"evaluation_{scope}_{grouping}"
            folder = OUT / label
            folder.mkdir(exist_ok=False)
            results[label] = run(label, [str(python), str(WORK / "evaluate.py"), "--directory", str(dataset),
                "--seed", "42", "--train_ratio", "0.333", "--quantiles", "9", "--repeat", "100",
                "--mode", "offline", "--approach", "shift", "--grouping", grouping], folder)
    if not any(results[name] for name in ("evaluation_four_fun", "evaluation_four_seq")):
        run("fixed_alpha", [sys.executable, str(WORK / "analyze_fixed_alpha.py"),
            "--fun", str(OUT / "evaluation_four_fun/results_offline_all_shift_fun.csv"),
            "--seq", str(OUT / "evaluation_four_seq/results_offline_all_shift_seq.csv"),
            "--alpha", "0.05", "--output", str(OUT / "fixed_alpha_005_four_scenario.json")])
    return int(any(results.values()))


parser = argparse.ArgumentParser()
parser.add_argument("phase", choices=("collect", "d9", "analyze"))
args = parser.parse_args()
raise SystemExit({"collect": collect, "d9": d9, "analyze": analyze}[args.phase]())
