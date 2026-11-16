"""Collect new positive (rootkit-active) Trace timing batches.

Mirror of 20261116_trace_normal/collect_normal.py but runs probing.py
in --rootkit mode. probing.py loads kicba_d7_hiding via the real linux.py
adapter (insmod + rmmod), collects timing events, then unloads.

Each batch is one probing.py --rootkit invocation producing an
events_<ts>_rootkit.json.gz; its label must be 'rootkit'.
"""
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
SCENARIOS = ('default', 'file_count', 'system_load', 'ls_basic', 'filename_length')
SEED = 20261116
ITERATIONS = 100
BATCHES = 10
ROOTKIT_NAME = 'kicba_d7_hiding'


def ensure_module_absent():
    mods = Path('/proc/modules').read_text().splitlines()
    loaded = any(line.split()[:1] == [ROOTKIT_NAME] for line in mods if line.strip())
    if loaded:
        r = subprocess.run(['rmmod', ROOTKIT_NAME], capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise RuntimeError('cannot rmmod leftover ' + ROOTKIT_NAME + ': ' + r.stderr)


def main():
    assert os.geteuid() == 0
    assert Path('/proc/sys/kernel/osrelease').read_text().strip() == '7.0.0-43-generic'
    assert subprocess.check_output(['hostname']).strip() == b'kicba-ubuntu26'
    ensure_module_absent()
    folder = ROOT / 'events'
    folder.mkdir(exist_ok=False)
    (ROOT / 'logs').mkdir(exist_ok=False)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    spec = {'boot': boot, 'kernel': os.uname().release, 'seed': SEED,
            'scenarios': SCENARIOS, 'batches_per_scenario': BATCHES,
            'iterations_per_batch': ITERATIONS,
            'label': 'rootkit', 'rootkit_module': ROOTKIT_NAME,
            'source_sha256': {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest()
                              for n in ('probing.py', 'kernel.c', 'data_classes.py', 'ls-basic', 'linux.py')}}
    (ROOT / 'protocol.json').write_text(json.dumps(spec, indent=2) + '\n')
    plan = [(scenario, index) for scenario in SCENARIOS for index in range(BATCHES)]
    random.Random(SEED).shuffle(plan)
    counts = Counter()
    with (ROOT / 'collection.jsonl').open('x', encoding='utf-8') as log:
        for scenario, index in plan:
            rng = random.Random(f'{SEED}:{scenario}:{index}')
            args = [sys.executable, '-B', 'probing.py', '--rootkit', '--iterations', str(ITERATIONS),
                    '--description', scenario]
            if scenario == 'file_count':
                args += ['--visible-files', str(rng.randint(10, 100)),
                         '--hidden-files', str(rng.randint(10, 100))]
            elif scenario == 'system_load':
                args += ['--load']
            elif scenario == 'ls_basic':
                args += ['--executable', './ls-basic']
            elif scenario == 'filename_length':
                args += ['--file-name-length', str(rng.randint(20, 60))]
            label = f'{scenario}_{index:02}'
            before = set(folder.glob('events_*.json.gz'))
            started = time.monotonic()
            with (ROOT / 'logs' / (label + '.stdout')).open('xb') as out, (
                    ROOT / 'logs' / (label + '.stderr')).open('xb') as err:
                result = subprocess.run(args, cwd=ROOT, stdout=out, stderr=err, timeout=180)
            # If probing crashed, module might still be loaded; try to clear before raising.
            if result.returncode != 0:
                try:
                    ensure_module_absent()
                except BaseException:
                    pass
                raise AssertionError(label + ' returncode=' + str(result.returncode))
            created = set(folder.glob('events_*.json.gz')) - before
            assert len(created) == 1, label
            original = created.pop()
            raw = original.read_bytes()
            data = json.loads(gzip.decompress(raw))
            assert data['label'] == 'rootkit' and data['description'] == scenario
            assert data['iterations'] == ITERATIONS and data['events']
            path = folder / (label + '.json.gz')
            original.rename(path)
            count_pids = len({row['pid'] for row in data['events']})
            row = {'scenario': scenario, 'index': index, 'file': path.name, 'label': 'rootkit',
                   'timestamp_utc': datetime.now(timezone.utc).isoformat(),
                   'sha256': hashlib.sha256(raw).hexdigest(), 'events': len(data['events']),
                   'observed_pids': count_pids, 'elapsed_seconds': time.monotonic() - started,
                   'load': data['load'], 'executable': data['executable']}
            log.write(json.dumps(row) + '\n')
            log.flush()
            counts[scenario] += 1
            # After each batch probing.py removes the rootkit; sanity check.
            try:
                ensure_module_absent()
            except Exception as exc:
                raise AssertionError(label + ' module not absent after batch: ' + str(exc))
            print(json.dumps({'finished_batches': sum(counts.values()), 'total_batches': len(plan),
                              'scenario': scenario, 'seconds': round(row['elapsed_seconds'], 2),
                              'observed_pids': count_pids}), flush=True)
    (ROOT / 'summary.json').write_text(json.dumps({'counts': counts, 'boot': boot,
                                                   'positive_batches': len(plan)}, indent=2) + '\n')


if __name__ == '__main__':
    main()
