"""Verify the runnable current CLI separately from the formal cohorts."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import subprocess

G=Path('/home/kicba/ubuntu26_20261114')
K=Path('/home/kicba/call_completion_20261103/code')
P=Path('/home/kicba/public_sample_linux7_port_20261114')
PROBE=Path('/home/kicba/research_phase2_20261023/phase1/bin/d9_enum_probe')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--fixture',type=Path);a=parser.parse_args()
    assert platform.release()=='7.0.0-43-generic' and not Path('/sys/module/caraxes').exists()
    a.output.mkdir(parents=True,exist_ok=False)
    fixture=a.fixture or a.output/'fixture'
    if a.fixture is None:
        fixture.mkdir()
        for i in range(64):(fixture/f'ordinary_{i:03d}').touch()
        for name in ('first_caraxes_item','middle_caraxes_item','last_caraxes_item','scan_control'):(fixture/name).touch()
    assert fixture.is_dir()
    rows=[]
    try:
        for mode in ('normal','getdents64','filldir'):
            if mode!='normal':
                subprocess.run(['insmod',str(P/'build'/mode/'caraxes.ko')],capture_output=True,check=True)
            try:
                for buffer in (128,65536):
                    for accepted in (False,True):
                        tag=f'{mode}_{buffer}_{"accepted" if accepted else "current"}'
                        argv=['python3',str(K/'scan_directory.py'),str(fixture),'--probe',str(PROBE),'--buffer-size',str(buffer)]
                        if accepted:argv+=['--accepted-only']
                        p=subprocess.run(argv,capture_output=True,text=True,timeout=90)
                        (a.output/(tag+'.stdout')).write_text(p.stdout)
                        (a.output/(tag+'.stderr')).write_text(p.stderr)
                        record=json.loads(p.stdout)
                        wanted='equal' if mode=='normal' or (accepted and mode=='filldir') else ('different' if mode=='getdents64' else 'completion_anomaly')
                        assert p.returncode==0 and record['verdict']==wanted and record['alarm'] is (wanted!='equal')
                        if mode=='getdents64':assert record['recovery_verified'] is True
                        if not accepted:assert record['completion_valid'] is True
                        rows.append({'tag':tag,'verdict':record['verdict'],'alarm':record['alarm']})
            finally:
                if mode!='normal':subprocess.run(['rmmod','caraxes'],capture_output=True,check=True)
    finally:
        if Path('/sys/module/caraxes').exists():subprocess.run(['rmmod','caraxes'],check=True)
    source_names=('scan_directory.py','call_completion/measurement.py','call_completion/bpf.c','src/kicba/call_completion.py')
    result={'passed':True,'checks':len(rows),'rows':rows,'kernel':platform.release(),'fixture':str(fixture),
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'source_sha256':{name:hashlib.sha256((K/name).read_bytes()).hexdigest() for name in source_names},
            'module_absent':not Path('/sys/module/caraxes').exists()}
    (a.output/'verification.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))

if __name__=='__main__':main()
