"""Package additive collector sources and derive the previously frozen test runner."""
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import argparse

ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument('--git',required=True);a=p.parse_args()
    original=(ROOT/'comparison/public_rootkit/run_native.py').read_text()
    native=original.replace("DETECTOR=Path('/home/kicba/closure_20261102/current')",'DETECTOR=Path(__file__).resolve().parents[1]')
    native=native.replace('from finalization.tracefs_measurement import new_measurement,CompleteMeasurement',
        'from terminal_rejection.measurement import new_terminal_measurement as new_measurement,TerminalMeasurement as CompleteMeasurement')
    native=native.replace("DETECTOR/'src/kicba/recovery_validation.py',Path(__file__)",
        "DETECTOR/'src/kicba/recovery_validation.py',DETECTOR/'src/kicba/terminal_rejection.py',DETECTOR/'terminal_rejection/bpf.c',DETECTOR/'terminal_rejection/measurement.py',Path(__file__)")
    (ROOT/'terminal_rejection/run_public_sample.py').write_text(native,encoding='utf-8',newline='\n')
    (ROOT/'terminal_rejection/public_runner.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),
        native.splitlines(True),fromfile='comparison/public_rootkit/run_native.py',tofile='terminal_rejection/run_public_sample.py')),encoding='utf-8',newline='\n')
    source=(ROOT/'phase1/enum_probe.c').read_text()
    marker='        if (result == 0)\n            break;'
    injection=marker+'''
        /* Test-only pause after the first returned batch. No rootkit is used. */
        const char *race_path = getenv("KICBA_RACE_GATE");
        if (race_path && syscalls == 1) {
            int gate_fd = open(race_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (gate_fd < 0 || write(gate_fd, buffer, result) != result || close(gate_fd))
                return 2;
            if (read(STDIN_FILENO, &gate, 1) != 1)
                return 2;
        }
'''
    assert source.count(marker)==1
    gated=source.replace('#include "../collector/d9_reconciliation_hash.h"','#include "../collector/d9_reconciliation_hash.h"').replace(marker,injection)
    (ROOT/'terminal_rejection/enum_gated.c').write_text(gated,encoding='utf-8',newline='\n')
    (ROOT/'terminal_rejection/gated_scanner.patch').write_text(''.join(difflib.unified_diff(source.splitlines(True),
        gated.splitlines(True),fromfile='phase1/enum_probe.c',tofile='terminal_rejection/enum_gated.c')),encoding='utf-8',newline='\n')
    names=subprocess.check_output([a.git,'ls-files','-z'],cwd=ROOT).decode().split('\0')
    chosen={n for n in names if n and n.split('/')[0] in ('phase1','phase2','collector','src','finalization')
            and Path(n).suffix in ('.py','.c','.h') and '/evidence/' not in n}
    chosen|={p.relative_to(ROOT).as_posix() for p in (ROOT/'terminal_rejection').iterdir() if p.is_file() and p.suffix in ('.py','.c','.md','.json','.patch')}
    chosen.add('scan_directory.py')
    chosen.add('src/kicba/terminal_rejection.py')
    out=ROOT/'_docx_work/terminal_rejection';out.mkdir(parents=True,exist_ok=True)
    with tarfile.open(out/'deployment.tar','w') as bundle:
        for n in sorted(chosen):bundle.add(ROOT/n,arcname=n)
    hashes={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in sorted(chosen)}
    (ROOT/'terminal_rejection/DEPLOYMENT_SOURCES.json').write_text(json.dumps(hashes,indent=2),encoding='utf-8',newline='\n')
    print('Packaged',len(chosen),'source files')
if __name__=='__main__':main()
