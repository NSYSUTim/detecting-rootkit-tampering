"""Package the new collector with explicitly selected frozen dependencies."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--git', required=True)
    args = parser.parse_args()
    original = (ROOT/'comparison/public_rootkit/run_native.py').read_text()
    native = original.replace("DETECTOR=Path('/home/kicba/closure_20261102/current')",
                              'DETECTOR=Path(__file__).resolve().parents[1]')
    native = native.replace('from finalization.tracefs_measurement import new_measurement,CompleteMeasurement',
        'from call_completion.measurement import new_call_measurement as new_measurement,CallMeasurement as CompleteMeasurement')
    native = native.replace("DETECTOR/'src/kicba/recovery_validation.py',Path(__file__)",
        "DETECTOR/'src/kicba/recovery_validation.py',DETECTOR/'src/kicba/call_completion.py',DETECTOR/'call_completion/bpf.c',DETECTOR/'call_completion/measurement.py',Path(__file__)")
    (ROOT/'call_completion/run_public_sample.py').write_text(native, encoding='utf-8', newline='\n')
    (ROOT/'call_completion/public_runner.patch').write_text(''.join(difflib.unified_diff(
        original.splitlines(True), native.splitlines(True), fromfile='comparison/public_rootkit/run_native.py',
        tofile='call_completion/run_public_sample.py')), encoding='utf-8', newline='\n')
    names = subprocess.check_output([args.git, 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    chosen = {n for n in names if n and n.split('/')[0] in ('phase1', 'phase2', 'collector', 'src', 'finalization')
              and Path(n).suffix in ('.py', '.c', '.h') and '/evidence/' not in n}
    chosen |= {p.relative_to(ROOT).as_posix() for p in (ROOT/'call_completion').iterdir()
               if p.is_file() and p.name != 'DEPLOYMENT_SOURCES.json'
               and p.suffix in ('.py', '.c', '.md', '.json', '.patch')}
    chosen |= {'src/kicba/call_completion.py', 'terminal_rejection/enum_gated.c', 'scan_directory.py'}
    out = ROOT/'_docx_work/call_completion'
    out.mkdir(parents=True, exist_ok=True)
    hashes = {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(chosen)}
    (ROOT/'call_completion/DEPLOYMENT_SOURCES.json').write_text(json.dumps(hashes, indent=2), encoding='utf-8', newline='\n')
    with tarfile.open(out/'deployment.tar', 'w') as bundle:
        for name in sorted(chosen | {'call_completion/DEPLOYMENT_SOURCES.json'}):
            bundle.add(ROOT/name, arcname=name)
    print('Packaged', len(chosen), 'source files')


if __name__ == '__main__':
    main()
