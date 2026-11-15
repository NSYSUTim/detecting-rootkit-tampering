"""Small normal/boundary integration check, no rootkit loading or reboot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, ROOT/'src'):
    sys.path.insert(0, str(directory))

from finalization.measurement import CheckedMeasurement, read_program_counters


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0 or platform.release() != '7.0.0-43-generic':
        raise RuntimeError('wrong native environment')
    args.output.resolve().relative_to(ROOT.resolve())
    args.output.mkdir(exist_ok=False)
    known = ('kicba_', 'phase2_', 'diamorphine', 'reptile', 'caraxes')
    loaded = [line.split()[0] for line in Path('/proc/modules').read_text().splitlines()
              if line.split()[0].startswith(known)]
    if loaded:
        raise RuntimeError('existing research/hiding modules: ' + ','.join(loaded))
    route = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, check=True).stdout
    if route.strip():
        raise RuntimeError('research VM unexpectedly has a default route')
    selected = ('src/kicba/reconciliation.py', 'phase2/measurement.py', 'phase2/bpf_packed.c',
                'phase1/run_experiments.py', 'collector/d9_reconciliation_hash.h', 'phase1/bin/d9_enum_probe')
    expected = json.loads((ROOT/'finalization/base_sources.json').read_text())
    before = {name: digest(args.base/name) for name in selected}
    for name in selected:
        if name in expected and before[name] != expected[name]:
            raise RuntimeError('protected reference mismatch: ' + name)
    manifest = {'kernel': platform.release(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'protocol_sha256': digest(ROOT/'finalization/PROTOCOL_20261101.md'),
                'base': str(args.base), 'base_sources_before': before, 'default_route': route,
                'hiding_modules': loaded, 'new_rootkit_trials': False}
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2))
    regular = args.output/'regular'; regular.mkdir()
    for i in range(64): (regular/f'item_{i:05d}').touch()
    (regular/'directory').mkdir(); (regular/'普通檔名').touch()
    boundary = args.output/'boundary'; boundary.mkdir()
    (boundary/('z'*255)).touch()
    descriptor = os.open(os.fsencode(boundary)+b'/\xffname', os.O_CREAT|os.O_WRONLY, 0o600)
    os.close(descriptor)
    from phase2.measurement import Measurement
    attempts = []
    with Measurement('packed', probe=args.base/'phase1/bin/d9_enum_probe') as base:
        manifest['initial_program_counters'] = read_program_counters(base.bpf)
        tool = CheckedMeasurement(base)
        with (args.output/'attempts.jsonl').open('x') as stream:
            cases = [('regular', regular, size, 'equal') for size in (128,256,4096,65536) for _ in range(2)]
            cases += [('boundary', boundary, 4096, 'equal'), ('small_buffer', boundary, 64, 'invalid')]
            for index, (name, directory, size, expected_verdict) in enumerate(cases):
                row = tool.scan(directory, size)
                row.update(case=name, index=index, buffer_size=size, expected_verdict=expected_verdict)
                row['passed'] = (row['verdict'] == expected_verdict
                                 and row.get('alarm') is (False if expected_verdict=='equal' else None))
                stream.write(json.dumps(row)+'\n'); stream.flush()
                attempts.append({'index':index,'case':name,'buffer_size':size,'verdict':row['verdict'],
                                 'alarm':row.get('alarm'),'passed':row['passed']})
        manifest['final_program_counters'] = read_program_counters(base.bpf)
    after = {name:digest(args.base/name) for name in selected}
    summary = {'scope':'normal and boundary integration only; no new hiding-module trials',
               'attempts':attempts,'total':len(attempts),'expected_valid':9,'expected_invalid':1,
               'source_unchanged':before==after,'passed':all(row['passed'] for row in attempts) and before==after}
    manifest['base_sources_after'] = after
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2))
    (args.output/'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))
    return 0 if summary['passed'] else 1


if __name__=='__main__': raise SystemExit(main())
