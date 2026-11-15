"""Ensure a real rejected regular entry is deleted before the next read.

The original three-boot cohort is preserved. Linux 7 directory order made
15 of its 30 one-file races unexercised, so this supplementary cohort uses
16 regular entries and records the exact rejected witness before deletion.
No detector rule or measurement backend is changed.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

K=Path('/home/kicba/call_completion_20261103/code')
B=Path('/home/kicba/research_phase2_20261023')
sys.path[:0]=[str(K),str(K/'src')]
from call_completion.measurement import new_call_measurement,CallMeasurement
from call_completion.run_regression import parse_raw,readrows
from phase2.measurement import legacy
from phase2.run_campaign import manifest

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--boot-index',type=int,required=True)
    a=p.parse_args()
    assert os.geteuid()==0 and platform.release()=='7.0.0-43-generic'
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'manifest.json').write_text(json.dumps({'boot_index':a.boot_index,
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'kernel':platform.release(),'regular_entries':16,'required_exercised_per_fs':5,
        'buffer_size':64,'retained_original_cohort':True},indent=2))
    memory=a.output/'tmpfs';memory.mkdir()
    subprocess.run(['mount','-t','tmpfs','-o','size=32m','tmpfs',str(memory)],check=True)
    summary={}
    try:
        with (a.output/'observations.jsonl').open('x') as stream:
            for fs,root in (('ext4',a.output),('tmpfs',memory)):
                exercised=0
                for attempt in range(20):
                    directory=root/f'race_{attempt:02d}';directory.mkdir()
                    for n in range(16):(directory/f'candidate_{n:02d}').touch()
                    original=manifest(directory)
                    gate=a.output/f'{fs}_{attempt:02d}.bin'
                    dump=a.output/f'{fs}_{attempt:02d}.jsonl'
                    details={}
                    os.environ['KICBA_RACE_GATE']=str(gate)
                    original_release=legacy.release
                    try:
                        with new_call_measurement(probe=K/'call_completion/enum_gated') as base:
                            process=base.begin(directory,64,dump=dump)
                            def release_after_delete(child):
                                original_release(child)
                                deadline=time.monotonic()+10
                                while not gate.exists() or not gate.stat().st_size:
                                    if time.monotonic()>deadline:raise TimeoutError('gated race did not reach first batch')
                                    time.sleep(0.001)
                                details['first_batch']=parse_raw(gate.read_bytes())
                                details['before_delete']=base._packed_telemetry(child.pid)
                                keep={bytes.fromhex(r['name_hex']) for r in details['first_batch']}
                                details['deleted']=[]
                                for name in os.listdir(directory):
                                    if os.fsencode(name) not in keep:
                                        (directory/name).unlink()
                                        details['deleted'].append(os.fsencode(name).hex())
                                original_release(child)
                            legacy.release=release_after_delete
                            row=CallMeasurement(base).collect_started([process])[0]
                    finally:
                        legacy.release=original_release
                        os.environ.pop('KICBA_RACE_GATE',None)
                    before=details['before_delete']['call_observation']
                    witness=before['name_hex']
                    actual=(before['completed_rejected']>0 and before['witness_valid']==1 and witness in details['deleted'])
                    row.update(fs=fs,attempt=attempt,original=original,visible=readrows(dump),race=details,
                               rejected_regular_entry_deleted=actual)
                    assert row['verdict']=='equal' and row['alarm'] is False and row['completion_valid'] is True
                    stream.write(json.dumps(row)+'\n');stream.flush()
                    exercised+=actual
                    if exercised==5:break
                if exercised!=5:raise RuntimeError('Unable to exercise five real benign races on '+fs)
                summary[fs]={'attempts':attempt+1,'exercised':exercised,'false_alarms':0}
    finally:
        subprocess.run(['umount',str(memory)],check=True)
    (a.output/'summary.json').write_text(json.dumps({'passed':True,'groups':summary},indent=2))
    print(json.dumps({'passed':True,'groups':summary}),flush=True)

if __name__=='__main__':main()
