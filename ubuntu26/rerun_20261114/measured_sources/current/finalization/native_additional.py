"""Retained-fixture regression of the completion wrapper on the same lab VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
for directory in (ROOT,ROOT/'src'):sys.path.insert(0,str(directory))
from finalization.measurement import CheckedMeasurement


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if os.name!='posix' or os.geteuid()!=0 or platform.release()!='7.0.0-43-generic':
        raise RuntimeError('wrong native environment')
    args.output.resolve().relative_to(ROOT.resolve())
    args.output.mkdir(exist_ok=False)
    from phase2.measurement import Measurement
    from phase2 import run_campaign as campaign
    from phase2.oracle import SEED1,SEED2,identities,difference
    if set(campaign.OWN_MODULES)&campaign.loaded():raise RuntimeError('existing research module')
    if subprocess.run(['ip','route','show','default'],capture_output=True,text=True,check=True).stdout.strip():
        raise RuntimeError('default route present')
    expected=json.loads((ROOT/'finalization/base_sources.json').read_text())
    before={name:sha(args.base/name) for name in expected}
    if before!=expected:raise RuntimeError('reference source changed')
    module_dir=args.base/'phase2/bin'/platform.release()
    modules=[module_dir/name for name in ('phase2_transform.ko','kicba_d9_getdents_substitute.ko')]
    module_hashes={str(p.relative_to(args.base)):sha(p) for p in modules}
    lock=json.loads((args.base/'phase2/CONFIRMATION_LOCK.json').read_text())
    for name,digest in module_hashes.items():
        if lock['source_sha256'].get(name)!=digest:raise RuntimeError('module differs from protected lock: '+name)
    fixture=args.output/'fixture';fixture.mkdir()
    for name in ('phase2_subject','d9_swap_a_0000','other_a','other_b'):(fixture/name).touch()
    original=campaign.manifest(fixture)
    manifest={'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),
              'protocol_sha256':sha(ROOT/'finalization/ADDITIONAL_PROTOCOL_20261101.md'),
              'base_sources_before':before,'module_sha256':module_hashes,'original':original,
              'completion_sources':{p.relative_to(ROOT).as_posix():sha(p) for p in [*list((ROOT/'finalization').glob('*.py')),ROOT/'src/kicba/recovery_validation.py']},
              'new_public_rootkits_tested':False}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2))
    measured=[];controls=[];loss_rows=[]
    states=('normal','reorder','insert','grow','shrink','inode','type','remove','getdents_substitution')
    try:
        with (args.output/'attempts.jsonl').open('x') as stream:
            for state in states:
                campaign.load_state(state)
                try:
                    expected_rows=campaign.expected_output(original,state)
                    up,down=difference(original,expected_rows)
                    expected_verdict='different' if up or down else 'equal'
                    for size in (256,4096):
                        dump=args.output/f'control_{state}_{size}.jsonl'
                        cmd=[str(args.base/'phase1/bin/d9_enum_probe'),str(fixture),str(size),'256',str(SEED1),str(SEED2),'2',str(dump)]
                        control=subprocess.run(cmd,input='\n',capture_output=True,text=True)
                        actual=[json.loads(line) for line in dump.read_text().splitlines()] if dump.exists() else []
                        controls.append({'state':state,'buffer':size,'returncode':control.returncode,
                                         'output_matches':identities(actual)==identities(expected_rows)})
                    with Measurement('packed',probe=args.base/'phase1/bin/d9_enum_probe') as base:
                        tool=CheckedMeasurement(base)
                        for size in (256,4096):
                            for repeat in range(2):
                                dump=args.output/f'measured_{state}_{size}_{repeat}.jsonl'
                                row=tool.scan(fixture,size,dump)
                                actual=[json.loads(line) for line in dump.read_text().splitlines()] if dump.exists() else []
                                exact=(row.get('upstream_only')==up and row.get('downstream_only')==down)
                                audit=campaign.counters(state)
                                passed=(not audit.get('errors') and not audit.get('skipped')
                                        and row['verdict']==expected_verdict and identities(actual)==identities(expected_rows)
                                        and exact and (row['recovery_verified'] if expected_verdict=='different' else row['alarm'] is False))
                                row.update(state=state,buffer=size,repeat=repeat,expected_verdict=expected_verdict,
                                           exact_recovery=exact,passed=passed,audit=audit)
                                stream.write(json.dumps(row)+'\n');stream.flush()
                                measured.append({'state':state,'buffer':size,'repeat':repeat,'verdict':row['verdict'],'passed':passed})
                finally:campaign.unload()
        large=args.output/'loss_fixture';large.mkdir()
        for i in range(4096):(large/f'file_{i:05d}').touch()
        with Measurement('packed',maxactive=1,probe=args.base/'phase1/bin/d9_enum_probe') as base:
            tool=CheckedMeasurement(base)
            processes=[base.begin(large,4096) for _ in range(16)]
            loss_rows=tool.collect_started(processes)
        with Measurement('packed',maxactive=256,probe=args.base/'phase1/bin/d9_enum_probe') as base:
            tool=CheckedMeasurement(base)
            sequential=[tool.scan(large,4096) for _ in range(2)]
        with (args.output/'loss_attempts.jsonl').open('x') as stream:
            for row in loss_rows+sequential:stream.write(json.dumps(row)+'\n')
        loss_observed=any(any(r.get('missed_delta',0)>0 for r in row.get('coverage',{}).get('per_event',{}).values()) for row in loss_rows)
        summary={'measured':len(measured),'measured_differences':sum(r['state'] not in ('normal','reorder') for r in measured),
                 'measured_consistent':sum(r['state'] in ('normal','reorder') for r in measured),
                 'controls':len(controls),'controls_passed':all(r['returncode']==0 and r['output_matches'] for r in controls),
                 'measured_passed':all(r['passed'] for r in measured),'loss_window_observed':loss_observed,
                 'loss_window_scans':len(loss_rows),'loss_window_invalid':sum(r['verdict']=='invalid' for r in loss_rows),
                 'sequential_controls':len(sequential),'sequential_valid_equal':sum(r['verdict']=='equal' for r in sequential),
                 'new_public_rootkit_trials':False,'attempts':measured,'controls_details':controls}
        summary['source_unchanged']=before=={name:sha(args.base/name) for name in expected}
        summary['passed']=(summary['controls_passed'] and summary['measured_passed'] and summary['source_unchanged']
                           and loss_observed and summary['loss_window_invalid']==16 and summary['sequential_valid_equal']==2)
        (args.output/'summary.json').write_text(json.dumps(summary,indent=2))
        print(json.dumps({k:v for k,v in summary.items() if k not in ('attempts','controls_details')}))
        return 0 if summary['passed'] else 1
    finally:
        campaign.unload()
        if set(campaign.OWN_MODULES)&campaign.loaded():raise RuntimeError('research module left loaded')


if __name__=='__main__':raise SystemExit(main())
