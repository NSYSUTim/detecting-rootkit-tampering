"""Native regression for the current scanner and explicit entry miss gate."""
import argparse,json,os,platform,subprocess,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
for d in (ROOT,ROOT/'src'):sys.path.insert(0,str(d))
from finalization.tracefs_measurement import new_measurement,CompleteMeasurement
from finalization import controlled_cases as cases
from phase2.run_campaign import manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--base',type=Path,required=True)
    parser.add_argument('--first',type=Path,required=True)
    parser.add_argument('--fault-module',type=Path,required=True)
    args=parser.parse_args()
    if os.geteuid()!=0 or platform.release()!='6.8.0-138-generic':raise RuntimeError('wrong native environment')
    if cases.loaded()&cases.OWN:raise RuntimeError('research module already loaded')
    args.output.mkdir(exist_ok=False)
    hashes=cases.module_hashes(args.base,args.first)
    probe=args.base/'phase1/bin/d9_enum_probe'
    original_sources=json.loads((ROOT/'finalization/base_sources.json').read_text())
    source_before={name:cases.sha(args.base/name) for name in original_sources}
    if source_before!=original_sources:raise RuntimeError('protected reference changed')
    fixture=args.output/'fixture';fixture.mkdir()
    for name in cases.NAMES:(fixture/name).touch()
    original=manifest(fixture)
    meta={'kernel':platform.release(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
          'original':original,'base_sources_before':source_before,'module_sha256':hashes,
          'source_sha256':{p.relative_to(ROOT).as_posix():cases.sha(p) for p in [
              ROOT/'scan_directory.py',ROOT/'finalization/tracefs_measurement.py',
              ROOT/'finalization/controlled_cases.py',Path(__file__),ROOT/'finalization/COMPLETION_PROTOCOL_20261102.md']},
          'fault_module_sha256':cases.sha(args.fault_module)}
    (args.output/'manifest.json').write_text(json.dumps(meta,indent=2))
    attempts=[];controls=[];faults=[];extra=[]
    try:
        with (args.output/'attempts.jsonl').open('x') as stream:
            for state in cases.STATES:
                cases.load(state,args.base,args.first)
                try:
                    for size in (128,4096):
                        before=cases.audit(state,args.base,args.first)
                        c=cases.exact_capture(probe,fixture,size,args.output/f'control_{state}_{size}.jsonl')
                        changes=cases.delta(before,cases.audit(state,args.base,args.first))
                        exercised=state not in cases.ACTIONS[2:] or changes.get('changed',0)>0
                        target=cases.expected(original,state,exercised)
                        c.update(state=state,buffer=size,exercised=exercised,changes=changes,
                                 output_matches=cases.identities(c['rows'])==cases.identities(target))
                        controls.append(c)
                        with new_measurement(probe=probe) as base:
                            tool=CompleteMeasurement(base)
                            for repeat in range(3):
                                before=cases.audit(state,args.base,args.first)
                                dump=args.output/f'measured_{state}_{size}_{repeat}.jsonl'
                                row=tool.scan(fixture,size,dump)
                                changes=cases.delta(before,cases.audit(state,args.base,args.first))
                                exercised=state not in cases.ACTIONS[2:] or changes.get('changed',0)>0
                                target=cases.expected(original,state,exercised)
                                up,down=cases.difference(original,target)
                                actual=[json.loads(s) for s in dump.read_text().splitlines()]
                                verdict='different' if up or down else 'equal'
                                passed=(row['verdict']==verdict and cases.identities(actual)==cases.identities(target)
                                    and row['upstream_only']==up and row['downstream_only']==down
                                    and row.get('recovery_validation',{}).get('verified') is True
                                    and not changes.get('errors') and not changes.get('parse_errors'))
                                row.update(state=state,buffer=size,repeat=repeat,changes=changes,
                                           exercised=exercised,expected_verdict=verdict,passed=passed)
                                stream.write(json.dumps(row)+'\n');stream.flush();attempts.append(row)
                finally:cases.unload(state,args.base,args.first)
        # Preserve a direct reverse-load-order confirmation for the new backend.
        for order in ('probe_first','module_first'):
            if order=='module_first':cases.load('filldir_hiding',args.base,args.first)
            try:
                with new_measurement(probe=probe) as base:
                    if order=='probe_first':cases.load('filldir_hiding',args.base,args.first)
                    for repeat in range(3):
                        row=CompleteMeasurement(base).scan(fixture,4096)
                        row.update(kind='load_order',order=order,repeat=repeat)
                        extra.append(row)
            finally:cases.unload('filldir_hiding',args.base,args.first)
        subprocess.run(['insmod',str(args.fault_module)],check=True)
        try:
            with new_measurement(probe=probe) as base:
                tool=CompleteMeasurement(base);original_scan=base.scan
                for i in range(10):
                    faults.append(dict(kind='entry_control_before',index=i,**tool.scan(fixture)))
                    def inject(*a,**k):
                        Path('/sys/module/kicba_entry_fault/parameters/trigger').write_text('10\n')
                        return original_scan(*a,**k)
                    base.scan=inject
                    try:faults.append(dict(kind='entry_injected',index=i,**tool.scan(fixture)))
                    finally:base.scan=original_scan
                    faults.append(dict(kind='entry_control_after',index=i,**tool.scan(fixture)))
        finally:subprocess.run(['rmmod','kicba_entry_fault'],check=True)
        large=args.output/'large';large.mkdir()
        for i in range(4096):(large/f'file_{i:05d}').touch()
        with new_measurement(probe=probe,maxactive=1) as base:
            rows=CompleteMeasurement(base).collect_started([base.begin(large,4096) for _ in range(16)])
            for row in rows:faults.append(dict(kind='return_injected',**row))
        with new_measurement(probe=probe) as base:
            for i in range(2):faults.append(dict(kind='return_control',**CompleteMeasurement(base).scan(large,4096)))
        small=args.output/'overcapacity';small.mkdir()
        for i in range(16):(small/f'd8_hidden_{i:04d}').touch()
        cases.load('filldir_hiding',args.base,args.first)
        try:
            with new_measurement(probe=probe,cells=8) as base:
                for i in range(2):extra.append(dict(kind='overcapacity',**CompleteMeasurement(base).scan(small,4096)))
        finally:cases.unload('filldir_hiding',args.base,args.first)
        boundary=args.output/'boundary';boundary.mkdir()
        for name in (b'x'*255,b'nonutf8_\xff'):
            fd=os.open(os.fsencode(boundary)+b'/'+name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        with new_measurement(probe=probe) as base:
            for size in (4096,64):extra.append(dict(kind='boundary',buffer=size,**CompleteMeasurement(base).scan(boundary,size)))
        for name,rows in [('controls.json',controls),('faults.json',faults),('extra.json',extra)]:
            (args.output/name).write_text(json.dumps(rows,indent=2))
        injected=[r for r in faults if r['kind']=='entry_injected']
        normal=[r for r in faults if r['kind'].startswith('entry_control') or r['kind']=='return_control']
        returns=[r for r in faults if r['kind']=='return_injected']
        summary={'measured':len(attempts),'actual_differences':sum(r['expected_verdict']=='different' for r in attempts),
            'unexercised':sum(not r['exercised'] for r in attempts),'all_measured_passed':all(r['passed'] for r in attempts),
            'controls':len(controls),'controls_passed':all(r['returncode']==0 and r['output_matches'] for r in controls),
            'entry_injected':len(injected),'entry_rejected':sum(r['verdict']=='invalid' for r in injected),
            'entry_miss_seen_each':all(any(v['missed_delta']>0 for v in r['entry_coverage']['per_event'].values()) for r in injected),
            'entry_pre_gate_equal_each':all(r.get('pre_entry_gate_verdict')=='equal' for r in injected),
            'normal_controls':len(normal),'normal_valid':sum(r['verdict']=='equal' for r in normal),
            'return_injected':len(returns),'return_rejected':sum(r['verdict']=='invalid' for r in returns),
            'return_misses_seen':any(any(v['missed_delta']>0 for v in r['coverage']['per_event'].values()) for r in returns),
            'load_order':sum(r['kind']=='load_order' for r in extra),
            'load_order_passed':all(r['verdict']=='different' and r['recovery_verified'] for r in extra if r['kind']=='load_order'),
            'overcapacity_passed':all(r['verdict']=='different' and not r['recovery_verified'] for r in extra if r['kind']=='overcapacity'),
            'boundary_passed':all(r['verdict']==('equal' if r['buffer']==4096 else 'invalid') for r in extra if r['kind']=='boundary'),
            'protected_sources_unchanged':source_before=={name:cases.sha(args.base/name) for name in source_before}}
        summary['passed']=(summary['all_measured_passed'] and summary['controls_passed'] and summary['entry_rejected']==10
            and summary['entry_miss_seen_each'] and summary['entry_pre_gate_equal_each'] and summary['normal_valid']==22
            and summary['return_rejected']==16 and summary['return_misses_seen'] and summary['load_order_passed']
            and summary['overcapacity_passed'] and summary['boundary_passed'] and summary['protected_sources_unchanged'])
        (args.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
        return 0 if summary['passed'] else 1
    finally:
        if cases.loaded()&cases.OWN:raise RuntimeError('owned module left loaded')


if __name__=='__main__':raise SystemExit(main())
