"""Check the published CLI in the VM, separately from confirmation cohorts."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess

PROBE=Path('/home/kicba/research_phase2_20261023/phase1/bin/d9_enum_probe')
SAMPLE=Path('/home/kicba/public_sample_20261102')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    if platform.release()!='6.8.0-138-generic' or Path('/sys/module/caraxes').exists():raise RuntimeError('wrong environment')
    args.output.mkdir(exist_ok=False)
    fixture=SAMPLE/'boot_03/fixture'
    rows=[]
    def check(mode,accepted_only,buffer):
        tag=mode+'_'+('accepted' if accepted_only else 'current')+'_'+str(buffer)
        command=['python3',str(args.root/'scan_directory.py'),str(fixture),'--probe',str(PROBE),'--buffer-size',str(buffer)]
        if accepted_only:command.append('--accepted-only')
        p=subprocess.run(command,text=True,capture_output=True,timeout=60)
        (args.output/(tag+'.stdout')).write_text(p.stdout)
        (args.output/(tag+'.stderr')).write_text(p.stderr)
        r=json.loads(p.stdout)
        if p.returncode:raise RuntimeError('published CLI invalid: '+tag+' '+p.stderr)
        expected='equal' if mode=='normal' or accepted_only else ('different' if mode=='getdents64' else 'completion_anomaly')
        assert r['verdict']==expected
        assert r['alarm'] is (expected!='equal')
        if mode=='getdents64':assert r['recovery_verified']
        if not accepted_only:assert r['completion_valid']
        rows.append(dict(tag=tag,verdict=r['verdict'],alarm=r['alarm'],accepted_only=accepted_only,buffer=buffer,mode=mode))
    for buffer in (128,65536):
        for old in (False,True):check('normal',old,buffer)
    try:
        for mode in ('getdents64','filldir'):
            subprocess.run(['insmod',str(SAMPLE/'build'/mode/'caraxes.ko')],check=True,capture_output=True)
            try:
                for buffer in (128,65536):check(mode,False,buffer)
                if mode=='filldir':
                    for buffer in (128,65536):check(mode,True,buffer)
            finally:subprocess.run(['rmmod','caraxes'],check=True,capture_output=True)
    finally:
        if Path('/sys/module/caraxes').exists():subprocess.run(['rmmod','caraxes'],check=True)
    names=('scan_directory.py','src/kicba/call_completion.py','call_completion/measurement.py','call_completion/bpf.c')
    result=dict(passed=True,checks=len(rows),rows=rows,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                module_absent=not Path('/sys/module/caraxes').exists(),
                source_sha256={name:hashlib.sha256((args.root/name).read_bytes()).hexdigest() for name in names})
    (args.output/'verification.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result))


if __name__=='__main__':main()
