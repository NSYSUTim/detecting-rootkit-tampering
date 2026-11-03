"""Randomized paired ready-state scans with all checks in both intervals."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import random
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from call_completion.measurement import new_call_measurement,CallMeasurement
from finalization.tracefs_measurement import new_measurement,CompleteMeasurement
from finalization.controlled_cases import loaded,OWN

PROBE=Path('/home/kicba/research_phase2_20261023/phase1/bin/d9_enum_probe')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--boot-index',required=True,type=int);parser.add_argument('--pilot',action='store_true')
    args=parser.parse_args()
    if platform.release()!='6.8.0-138-generic' or loaded() & (OWN|{'caraxes'}):raise RuntimeError('wrong cost environment')
    args.output.mkdir(parents=True,exist_ok=False)
    facts={'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot_index':args.boot_index,
           'kernel':platform.release(),'pilot':args.pilot,'blocks':1 if args.pilot else 5,'buffer':65536,
           'boundary':'before scanner registration/start to after all identity and (new version) completion checks; BPF compilation/attachment outside',
           'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
             [ROOT/'call_completion/measurement.py',ROOT/'call_completion/bpf.c',ROOT/'src/kicba/call_completion.py',Path(__file__)]}}
    (args.output/'manifest.json').write_text(json.dumps(facts,indent=2))
    randomizer=random.Random(2026110300+args.boot_index)
    stream=(args.output/'observations.jsonl').open('x')
    try:
        for size in (128,4096,65536):
            fixture=args.output/('entries_'+str(size));fixture.mkdir()
            for index in range(size):(fixture/('entry_%05d'%index)).touch()
            for block in range(-1,1 if args.pilot else 5):
                order=['accepted_only','call_completion'];randomizer.shuffle(order)
                for position,version in enumerate(order):
                    maker,wrapper=(new_measurement,CompleteMeasurement) if version=='accepted_only' else (new_call_measurement,CallMeasurement)
                    with maker(probe=PROBE) as base:
                        measured=wrapper(base)
                        start=time.monotonic_ns();row=measured.scan(fixture,65536)
                        row['paired_ready_ns']=time.monotonic_ns()-start
                        if row['verdict']!='equal' or row['alarm'] is not False:raise RuntimeError('cost control not valid equal')
                        if version=='call_completion' and not row['completion_valid']:raise RuntimeError('cost completion check invalid')
                    row.update(version=version,size=size,block=block,position=position,warmup=block<0)
                    stream.write(json.dumps(row)+'\n');stream.flush()
    finally:stream.close()
    (args.output/'cleanup.json').write_text(json.dumps({'completed':True,'research_modules_absent':not bool(loaded()&(OWN|{'caraxes'}))}))
    print(json.dumps({'completed':True,'output':str(args.output)}),flush=True)


if __name__=='__main__':main()
