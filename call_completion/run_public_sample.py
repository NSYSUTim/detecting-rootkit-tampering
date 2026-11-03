"""Additive fixed-source public-sample functional experiment; no sample repairs."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import subprocess
import sys
import time

DETECTOR=Path(__file__).resolve().parents[1]
for folder in (DETECTOR,DETECTOR/'src'):sys.path.insert(0,str(folder))
from call_completion.measurement import new_call_measurement as new_measurement,CallMeasurement as CompleteMeasurement
from finalization.controlled_cases import exact_capture,loaded
from finalization.compare_zygarde import execute,zygarde_target
from phase2.run_campaign import manifest
from phase2.oracle import identities,difference

PROBE=Path('/home/kicba/research_phase2_20261023/phase1/bin/d9_enum_probe')
ADAPTER=Path('/home/kicba/scan_cost_20261102/zygarde_adapter')
EXPECTED_PROBE='472e09c5a7d2679d87ee37ca21b68f7266ca62f473e693814155e1e1b3f2f2f0'
EXPECTED_ADAPTER='615397c68c403f833aaf903ac447b8ba15f6a2092e5f8b0396407a14746b0d25'

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2,ensure_ascii=True))
def command(argv):
    p=subprocess.run(argv,text=True,capture_output=True,timeout=30)
    return dict(argv=argv,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
def emit(stream,row):
    stream.write(json.dumps(row,ensure_ascii=True)+'\n');stream.flush()
def dump_rows(path):return [json.loads(s) for s in path.read_text().splitlines()] if path.exists() else []

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--pilot',action='store_true')
    p.add_argument('--boot-index',type=int,required=True)
    a=p.parse_args()
    if os.geteuid()!=0 or platform.release()!='6.8.0-138-generic':raise RuntimeError('environment mismatch')
    if 'caraxes' in loaded():raise RuntimeError('sample already loaded')
    if sha(PROBE)!=EXPECTED_PROBE or sha(ADAPTER)!=EXPECTED_ADAPTER:raise RuntimeError('binary mismatch')
    a.output.mkdir(exist_ok=False,parents=True)
    fixture=a.output/'fixture';fixture.mkdir()
    for i in range(64):(fixture/f'ordinary_{i:04d}').touch()
    for name in ('caraxes_first','middle_caraxes_item','last_caraxes','zygarde-canary-benchmark'):
        (fixture/name).touch()
    original=manifest(fixture)
    assert all((fixture/bytes.fromhex(r['name_hex']).decode()).stat().st_uid!=1001 and
               (fixture/bytes.fromhex(r['name_hex']).decode()).stat().st_gid!=21 for r in original)
    modules={m:a.root/'build'/m/'caraxes.ko' for m in ('getdents64','filldir')}
    sources=[DETECTOR/'finalization/tracefs_measurement.py',DETECTOR/'finalization/measurement.py',
             DETECTOR/'phase2/measurement.py',DETECTOR/'phase2/bpf_packed.c',
             DETECTOR/'src/kicba/recovery_validation.py',DETECTOR/'src/kicba/call_completion.py',DETECTOR/'call_completion/bpf.c',DETECTOR/'call_completion/measurement.py',Path(__file__),Path(__file__).with_name('PROTOCOL.md')]
    meta={'kernel':platform.release(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
          'boot_index':a.boot_index,'pilot':a.pilot,'fixture':str(fixture),'original':original,
          'module_sha256':{m:sha(f) for m,f in modules.items()},
          'probe_sha256':sha(PROBE),'adapter_sha256':sha(ADAPTER),
          'source_sha256':{str(f):sha(f) for f in sources},
          'environment':command(['uname','-a']),
          'package_versions':command(['dpkg-query','-W','bcc','bpfcc-tools','libbpfcc','clang-11','llvm-11','libc6']),
          'tainted_before':Path('/proc/sys/kernel/tainted').read_text().strip(),
          'upstream_commit':'899e8be6b5f6c7236bd23b52aa65051de757e0b3'}
    save(a.output/'manifest.json',meta)
    events=(a.output/'events.jsonl').open('x');observations=(a.output/'observations.jsonl').open('x')
    controls=(a.output/'controls.jsonl').open('x');zygarde=(a.output/'zygarde.jsonl').open('x')
    serial=0
    def control(tag):
        nonlocal serial
        for buffer in (128,65536):
            serial+=1;path=a.output/f'control_{serial}.jsonl'
            row=exact_capture(PROBE,fixture,buffer,path)
            row.update(tag=tag,buffer=buffer,dump=path.name,
                       matches_manifest=identities(row['rows'])==identities(original))
            emit(controls,row)
        emit(events,dict(event='ls_control',tag=tag,result=command(['/bin/ls','-a','--',str(fixture)])))
    def load(mode):
        row=command(['insmod',str(modules[mode])]);emit(events,dict(event='load',mode=mode,result=row))
        if row['returncode'] or 'caraxes' not in loaded():raise RuntimeError('sample load failed: '+json.dumps(row))
    def unload(tag):
        if 'caraxes' in loaded():
            row=command(['rmmod','caraxes']);emit(events,dict(event='unload',tag=tag,result=row))
            if row['returncode'] or 'caraxes' in loaded():raise RuntimeError('sample unload failed')
    def scans(checked,mode,order):
        nonlocal serial
        sizes=[128,65536]*(1 if a.pilot else 10)
        random.Random(2026110200+a.boot_index).shuffle(sizes)
        for repeat,buffer in enumerate(sizes):
            serial+=1;path=a.output/f'observation_{serial}.jsonl'
            try:row=checked.scan(fixture,buffer,dump=path)
            except Exception as e:row={'verdict':'invalid','measurement_valid':False,'exception':repr(e)}
            visible=dump_rows(path)
            up,down=difference(original,visible)
            row.update(mode=mode,attachment_order=order,repeat=repeat,buffer=buffer,dump=path.name,
                visible=visible,external_missing=up,external_extra=down,
                output_matches_manifest=identities(visible)==identities(original),
                exact_recovery_against_disk=(row.get('upstream_only')==up and row.get('downstream_only')==down))
            emit(observations,row)
    def run_zygarde(mode):
        for repeat in range(1 if a.pilot else 5):
            tag=f'zygarde_{mode}_{repeat}';metrics=a.output/(tag+'.metrics.jsonl')
            env=dict(os.environ,KICBA_BENCH_DIR=str(fixture),
                     KICBA_BENCH_CANARY=str(fixture/'zygarde-canary-benchmark'),
                     KICBA_BENCH_METRICS=str(metrics),KICBA_BENCH_RING_BYTES='4194304')
            row=execute([str(ADAPTER),'--cells','hidden_file','--no-isolation','--json'],a.output,tag,env)
            row.update(mode=mode,repeat=repeat,assessment=zygarde_target(row,fixture),
                       metrics=dump_rows(metrics))
            emit(zygarde,row)
    try:
        control('normal_before')
        with new_measurement(probe=PROBE) as base:scans(CompleteMeasurement(base),'normal','no_rootkit')
        run_zygarde('normal')
        for mode in ('getdents64','filldir'):
            for order in ('rootkit_first','detector_first'):
                try:
                    if order=='rootkit_first':
                        load(mode);control(mode+'_'+order+'_unobserved')
                        with new_measurement(probe=PROBE) as base:
                            control(mode+'_'+order+'_attached')
                            scans(CompleteMeasurement(base),mode,order)
                        control(mode+'_'+order+'_detached')
                        run_zygarde(mode)
                    else:
                        with new_measurement(probe=PROBE) as base:
                            control(mode+'_'+order+'_normal_attached')
                            load(mode);control(mode+'_'+order+'_attached')
                            scans(CompleteMeasurement(base),mode,order)
                            unload(mode+'_'+order)
                            control(mode+'_'+order+'_unloaded_attached')
                finally:
                    unload(mode+'_'+order)
                    control(mode+'_'+order+'_restored')
        final=manifest(fixture)
        save(a.output/'cleanup.json',dict(module_absent='caraxes' not in loaded(),
             manifest_restored=identities(final)==identities(original),final_manifest=final,
             tainted_after=Path('/proc/sys/kernel/tainted').read_text().strip()))
        print(json.dumps(dict(output=str(a.output),completed=True,boot_id=meta['boot_id'])),flush=True)
    except BaseException as e:
        save(a.output/'failure.json',dict(error=repr(e)))
        raise
    finally:
        unload('final')
        emit(events,dict(event='final_health',modules=Path('/proc/modules').read_text(),
                        dmesg=command(['dmesg','--level=emerg,alert,crit,err,warn'])))
        for stream in (events,observations,controls,zygarde):stream.close()

if __name__=='__main__':main()
