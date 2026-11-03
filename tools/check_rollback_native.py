"""Read-only normal controls of the unmodified accepted-only VM entry."""
import hashlib,json,subprocess
from pathlib import Path

ROOT=Path('/home/kicba/closure_20261102/current')
OUTPUT=Path('/home/kicba/rollback_accepted_20261103')
PROBE=Path('/home/kicba/research_phase2_20261023/phase1/bin/d9_enum_probe')
DIRECTORY=Path('/home/kicba/public_sample_20261102/boot_03/fixture')
def main():
    OUTPUT.mkdir(exist_ok=False)
    assert not Path('/sys/module/caraxes').exists()
    for buffer in (128,65536):
        result=subprocess.run(['sudo','-n','python3',str(ROOT/'scan_directory.py'),str(DIRECTORY),
            '--probe',str(PROBE),'--buffer-size',str(buffer)],capture_output=True,text=True,timeout=60)
        (OUTPUT/f'normal_{buffer}.stdout').write_text(result.stdout)
        (OUTPUT/f'normal_{buffer}.stderr').write_text(result.stderr)
        row=json.loads(result.stdout)
        assert result.returncode==0 and row['verdict']=='equal' and row['alarm'] is False
        assert 'terminal_rule_version' not in row and 'terminal_rejection' not in row
    status={'entry_sha256':hashlib.sha256((ROOT/'scan_directory.py').read_bytes()).hexdigest(),
            'kernel':subprocess.check_output(['uname','-r'],text=True).strip(),
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'module_absent':not Path('/sys/module/caraxes').exists(),
            'normal_controls':2,'accepted_only':True}
    (OUTPUT/'verification.json').write_text(json.dumps(status,indent=2))
    (Path('/home/kicba/terminal_rejection_20261103')/'RETIRED.txt').write_text(
        'Experimental terminal-rejection rule withdrawn on 2026-11-03. Not the current scanner. '
        'Use /home/kicba/closure_20261102/current/scan_directory.py for accepted-only checking. '
        'Retain this directory as immutable experiment evidence.\n')
    print(json.dumps(status))
if __name__=='__main__':main()
