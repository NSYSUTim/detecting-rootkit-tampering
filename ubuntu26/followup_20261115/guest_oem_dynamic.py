"""Independent full-data follow-up of OEM benign dynamic controls."""
from collections import Counter
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import threading
import time

B=Path('/home/kicba/research_phase2_20261023');T=Path('/home/kicba/ubuntu26_20261114/followup_20261115')
sys.path[:0]=[str(B),str(B/'src'),str(B/'collector')]
from phase2.run_campaign import filesystem_roots,make_fixture,manifest,Measurement
from phase1.record_environment import inventory

def save(p,d):
    with p.open('x') as f:json.dump(d,f,indent=2)

assert os.geteuid()==0 and platform.release()=='7.0.0-1018-oem'
for family in ([],['-6']):assert not subprocess.check_output(['ip',*family,'route','show','default'],text=True).strip()
out=T/'oem_dynamic';out.mkdir()
save(out/'protocol.json',dict(role='independent supplemental control, never replaces original failed overlap criterion',
    filesystems=['ext4','tmpfs'],implementations=['legacy','packed'],buffers=[256,65536],fixed_attempts_per_condition=10,
    preserve='visible name bytes and inodes, kernel and userspace IBLTs, recovered lists, full named churn events and timing overlap'))
save(out/'environment_before.json',inventory())
groups=[]
with (out/'observations.jsonl').open('x') as records:
    with filesystem_roots(out) as roots:
        for fs,base in roots.items():
            fixture=make_fixture(base/'dynamic',512)
            save(out/(fs+'_manifest_before.json'),manifest(fixture))
            events=[];stop=threading.Event();ready=threading.Event();errors=[]
            def churn():
                try:
                    i=0
                    while not stop.is_set():
                        a,b=fixture/f'churn_a_{i%128:03d}',fixture/f'churn_b_{i%128:03d}'
                        a.touch();ino=a.stat().st_ino;events.append(dict(ns=time.monotonic_ns(),op='create',name=a.name,name_hex=os.fsencode(a.name).hex(),inode=ino))
                        a.replace(b);events.append(dict(ns=time.monotonic_ns(),op='rename',name=b.name,name_hex=os.fsencode(b.name).hex(),old_name=a.name,inode=ino))
                        b.unlink();events.append(dict(ns=time.monotonic_ns(),op='delete',name=b.name,name_hex=os.fsencode(b.name).hex(),inode=ino));i+=1;ready.set()
                except Exception as e:errors.append(repr(e));ready.set()
            thread=threading.Thread(target=churn);thread.start();assert ready.wait(10)
            try:
                for implementation in ('legacy','packed'):
                    with Measurement(implementation,probe=B/'phase2/bin/enum_dynamic') as tool:
                        for buffer in (256,65536):
                            count=Counter()
                            for i in range(10):
                                stem=f'{fs}_{implementation}_{buffer}_{i:02d}';dump=out/(stem+'.visible.jsonl')
                                r=tool.scan(fixture,buffer,dump=dump)
                                visible=r.get('userspace',{});start,end=visible.get('scan_started_ns',0),visible.get('scan_finished_ns',0)
                                overlap=Counter(e['op'] for e in list(events) if start<=e['ns']<=end)
                                actual=[json.loads(s) for s in dump.read_text().splitlines()]
                                for a in actual:a['name']=os.fsdecode(bytes.fromhex(a['name_hex']))
                                exercised=all(overlap[op]>0 for op in ('create','rename','delete'))
                                r.update(fs=fs,implementation=implementation,buffer=buffer,index=i,visible_names=actual,
                                    actual_file=dump.name,churn_in_scan=dict(overlap),churn_exercised=exercised,worker_errors=list(errors))
                                records.write(json.dumps(r)+'\n');records.flush()
                                assert r['measurement_valid'] and r['verdict']=='equal' and not errors
                                count['attempts']+=1;count['exercised']+=exercised
                            group=dict(fs=fs,implementation=implementation,buffer=buffer,**count);groups.append(group);print(json.dumps(group),flush=True)
            finally:
                stop.set();thread.join(10)
                save(out/(fs+'_named_churn.json'),dict(events=events,errors=errors,stopped=not thread.is_alive()))
                save(out/(fs+'_manifest_after.json'),manifest(fixture))
            assert not thread.is_alive() and not errors
save(out/'summary.json',dict(completed=True,attempted=sum(g['attempts'] for g in groups),exercised=sum(g['exercised'] for g in groups),groups=groups,all_valid_equal=True))
save(out/'environment_after.json',inventory())
print(json.dumps(dict(oem_dynamic_completed=True,groups=groups)),flush=True)
