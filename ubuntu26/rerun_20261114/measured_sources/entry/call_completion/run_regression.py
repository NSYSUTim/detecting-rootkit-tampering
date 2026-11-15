"""Controlled old-state regressions, normal churn, and a benign terminal race."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from call_completion.measurement import new_call_measurement,CallMeasurement
from finalization import controlled_cases as cases
from phase2.run_campaign import manifest
from phase2.oracle import identities,difference
from phase2.measurement import legacy

BASE=Path('/home/kicba/research_phase2_20261023')
FIRST=Path('/home/kicba/research_phase1_20261023')
PROBE=BASE/'phase1/bin/d9_enum_probe'
DYNAMIC=BASE/'phase2/bin/enum_dynamic'
NOP=('filldir_pass','filldir_active','getdents_pass','getdents_active')
STATES=(*cases.STATES,*NOP)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2))
def emit(f,r):f.write(json.dumps(r)+'\n');f.flush()
def readrows(p):return [json.loads(s) for s in p.read_text().splitlines()] if p.exists() else []
def nop_path(s):
    family='d7_controls_r2' if s.startswith('filldir') else 'd8_getdents_controls'
    name=('kicba_d7_' if s.startswith('filldir') else 'kicba_d8_getdents_')+s.split('_')[-1]+'.ko'
    return FIRST/'attack_variants'/family/name
def load(s):
    if s not in NOP:return cases.load(s,BASE,FIRST)
    args=['counter_comm=d9_enum_probe'] if s.startswith('filldir') else ['target_comm=d9_enum_probe']
    subprocess.run(['insmod',str(nop_path(s)),*args],check=True,capture_output=True)
def unload(s):
    if s not in NOP:return cases.unload(s,BASE,FIRST)
    if nop_path(s).stem in cases.loaded():subprocess.run(['rmmod',nop_path(s).stem],check=True,capture_output=True)
def fixture(p,n=64):
    p.mkdir()
    for i in range(n):(p/f'ordinary_{i:04d}').touch()
    for name in cases.NAMES:(p/name).touch()
    return p
def parse_raw(raw):
    result=[];pos=0
    while pos<len(raw):
        ino,off,length,kind=struct.unpack_from('<QqHB',raw,pos)
        if length<20 or pos+length>len(raw):raise ValueError('bad gated record')
        name=raw[pos+19:pos+length].split(b'\0')[0]
        result.append({'name_hex':name.hex(),'inode':ino,'d_type':kind});pos+=length
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--boot-index',type=int,required=True);p.add_argument('--pilot',action='store_true');a=p.parse_args()
    if os.geteuid()!=0 or platform.release()!='7.0.0-43-generic':raise RuntimeError('wrong environment')
    a.output.mkdir(parents=True,exist_ok=False)
    sources={str(f.relative_to(ROOT)):sha(f) for folder in ('call_completion','src/kicba') for f in (ROOT/folder).iterdir()
             if f.is_file() and f.suffix in ('.py','.c','.md')}
    save(a.output/'manifest.json',{'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'boot_index':a.boot_index,'pilot':a.pilot,'states':STATES,'buffers':[128,256,4096,65536],
        'source_sha256':sources,'probe_sha256':sha(PROBE),'dynamic_sha256':sha(DYNAMIC),
        'modules':{**cases.module_hashes(BASE,FIRST),**{str(nop_path(s)):sha(nop_path(s)) for s in NOP}}})
    output=(a.output/'observations.jsonl').open('x');serial=0
    def scan(checked,path,**extra):
        nonlocal serial
        serial+=1;dump=a.output/f'actual_{serial:05d}.jsonl'
        row=checked.scan(path,extra.get('buffer',65536),dump=dump)
        row.update(extra,dump=dump.name,visible=readrows(dump));emit(output,row);return row
    memory=a.output/'tmpfs';memory.mkdir();mounted=False
    try:
        static=fixture(a.output/'static');original=manifest(static);save(a.output/'static_manifest.json',original)
        with new_call_measurement(probe=PROBE) as base:
            checked=CallMeasurement(base)
            for state in STATES:
                load(state)
                try:
                    for buffer in (128,256,4096,65536):
                        for repeat in range(1 if a.pilot else 5):
                            before=cases.audit(state,BASE,FIRST) if state not in NOP else {}
                            row=scan(checked,static,kind='regression',state=state,buffer=buffer,repeat=repeat)
                            changes=cases.delta(before,cases.audit(state,BASE,FIRST)) if state not in NOP else {}
                            exercised=state not in ('insert','grow','shrink','inode','type','remove','reorder') or changes.get('changed',0)>0
                            expected=original if state in NOP else cases.expected(original,state,exercised)
                            up,down=difference(original,expected)
                            emit(output,{'kind':'assessment','scan_dump':row['dump'],
                                'changes':changes,'mutation_exercised':exercised,
                                'expected_upstream':up,'expected_downstream':down,
                                'output_match':identities(row['visible'])==identities(expected),
                                'identity_match':row.get('identity_verdict')==('different' if up or down else 'equal'),
                                'recovery_match':sorted(row.get('upstream_only',[]))==up and sorted(row.get('downstream_only',[]))==down})
                finally:unload(state)
        subprocess.run(['mount','-t','tmpfs','-o','size=32m','tmpfs',str(memory)],check=True,capture_output=True);mounted=True
        for fs,root in [('ext4',a.output),('tmpfs',memory)]:
            normal=fixture(root/'normal',512);save(a.output/(fs+'_normal_manifest.json'),manifest(normal))
            with new_call_measurement(probe=PROBE) as base:
                checked=CallMeasurement(base)
                for buffer in (128,256,4096,65536):
                    for repeat in range(1 if a.pilot else 5):scan(checked,normal,kind='normal',fs=fs,buffer=buffer,repeat=repeat)
            events=[];errors=[];stop=threading.Event()
            def churn():
                i=0
                try:
                    while not stop.is_set():
                        first=normal/f'create_{i%8}';second=normal/f'renamed_{i%8}'
                        first.touch();events.append((time.monotonic_ns(),'create'))
                        first.rename(second);events.append((time.monotonic_ns(),'rename'))
                        second.unlink();events.append((time.monotonic_ns(),'delete'));i+=1
                        time.sleep(0.0001)
                except BaseException as e:errors.append(repr(e))
            thread=threading.Thread(target=churn);thread.start()
            try:
                with new_call_measurement(probe=DYNAMIC) as base:
                    checked=CallMeasurement(base)
                    for buffer in (128,256,4096,65536):
                        for repeat in range(1 if a.pilot else 10):
                            scan(checked,normal,kind='dynamic',fs=fs,buffer=buffer,repeat=repeat)
            finally:stop.set();thread.join(10);save(a.output/(fs+'_churn.json'),{'events':events,'errors':errors,'stopped':not thread.is_alive()})
            for repeat in range(1 if a.pilot else 5):
                path=root/f'race_{repeat}';path.mkdir();(path/'candidate').touch();original=manifest(path)
                gate=a.output/f'{fs}_race_{repeat}.bin';dump=a.output/f'{fs}_race_{repeat}.jsonl'
                os.environ['KICBA_RACE_GATE']=str(gate)
                gated=ROOT/'call_completion/enum_gated'
                try:
                    with new_call_measurement(probe=gated) as base:
                        checked=CallMeasurement(base);process=base.begin(path,64,dump=dump)
                        actual_release=legacy.release;details={}
                        def release_with_delete(process):
                            actual_release(process)
                            deadline=time.monotonic()+10
                            while not gate.exists():
                                if time.monotonic()>deadline:raise RuntimeError('gated scanner timeout')
                                time.sleep(0.001)
                            # The atomic ready marker is an open file; wait for its
                            # first positive-size batch before parsing.
                            while gate.stat().st_size==0:time.sleep(0.001)
                            first=parse_raw(gate.read_bytes());keep={bytes.fromhex(r['name_hex']) for r in first}
                            details['before_delete']=base._packed_telemetry(process.pid)
                            details['first_batch']=first;details['deleted']=[]
                            for name in list(os.listdir(path)):
                                if os.fsencode(name) not in keep:
                                    (path/name).unlink();details['deleted'].append(os.fsencode(name).hex())
                            actual_release(process)
                        legacy.release=release_with_delete
                        try:row=checked.collect_started([process])[0]
                        finally:legacy.release=actual_release
                        row.update(kind='benign_race',fs=fs,repeat=repeat,original=original,
                            race=details,visible=readrows(dump),dump=dump.name)
                        emit(output,row)
                finally:os.environ.pop('KICBA_RACE_GATE',None)
            # Force a real syscall error; it must remain invalid, not terminal alert.
            longdir=root/'short_buffer_error';longdir.mkdir();(longdir/('x'*255)).touch()
            with new_call_measurement(probe=PROBE) as base:
                scan(CallMeasurement(base),longdir,kind='syscall_error',fs=fs,buffer=128)
            with new_call_measurement(probe=PROBE) as base:
                original_reader=base._packed_telemetry
                def omit_call(pid):
                    row=original_reader(pid);row.pop('call_observation',None);return row
                base._packed_telemetry=omit_call
                scan(CallMeasurement(base),normal,kind='missing_call_telemetry',fs=fs,buffer=65536)

        # New-branch faults are separate from the still-valid identity result.
        for fault in ('bad_pair_count', 'detached_enter', 'detached_exit'):
            for state in ('normal', 'getdents_substitution'):
                load(state)
                try:
                    with new_call_measurement(probe=PROBE) as base:
                        if fault.startswith('detached_'):
                            label = fault.split('_')[1]
                            base.bpf.detach_tracepoint(tp='syscalls:sys_'+label+'_getdents64')
                        else:
                            original_reader=base._packed_telemetry
                            def bad_pair(pid):
                                row=original_reader(pid);row['call_observation']['exits']+=1;return row
                            base._packed_telemetry=bad_pair
                        scan(CallMeasurement(base),static,kind=fault,state=state,buffer=4096)
                finally:unload(state)
        # The original entry and return miss gates must still refuse judgment.
        fault_modules=list(Path('/home/kicba/closure_20261102').rglob('kicba_entry_fault.ko'))
        if not fault_modules:raise RuntimeError('previously validated entry fault fixture unavailable')
        fault_module=fault_modules[0]
        save(a.output/'entry_fault_fixture.json',{'path':str(fault_module),'sha256':sha(fault_module)})
        subprocess.run(['insmod',str(fault_module)],check=True,capture_output=True)
        try:
            with new_call_measurement(probe=PROBE) as base:
                checked=CallMeasurement(base)
                scan(checked,static,kind='entry_fault_control_before',buffer=4096)
                original_scan=base.scan
                def inject(*args,**kwargs):
                    Path('/sys/module/kicba_entry_fault/parameters/trigger').write_text('10\n')
                    return original_scan(*args,**kwargs)
                base.scan=inject
                try:scan(checked,static,kind='entry_probe_miss',buffer=4096)
                finally:base.scan=original_scan
                scan(checked,static,kind='entry_fault_control_after',buffer=4096)
        finally:subprocess.run(['rmmod','kicba_entry_fault'],check=True,capture_output=True)
        pressure=fixture(a.output/'pressure',4096)
        with new_call_measurement(probe=PROBE,maxactive=1) as base:
            processes=[base.begin(pressure,4096) for _ in range(16)]
            for row in CallMeasurement(base).collect_started(processes):
                emit(output,dict(row,kind='return_probe_pressure'))

        save(a.output/'cleanup.json',{'modules_absent':not any(p.stem in cases.loaded() for p in [nop_path(s) for s in NOP]),
            'all_research_modules_absent':not bool(cases.loaded() & cases.OWN),'completed':True})
        print(json.dumps({'completed':True,'output':str(a.output)}),flush=True)
    except BaseException as e:save(a.output/'failure.json',{'error':repr(e)});raise
    finally:
        for s in STATES:unload(s)
        if mounted:subprocess.run(['umount',str(memory)],check=True,capture_output=True)
        output.close()

if __name__=='__main__':main()
