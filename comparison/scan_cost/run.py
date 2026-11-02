"""Retain all ready-to-verdict observations in randomized three-method blocks."""
import argparse,hashlib,json,os,platform,random,shutil,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
for p in (ROOT,ROOT/'src'):sys.path.insert(0,str(p))
from finalization import controlled_cases as cases
from finalization.compare_zygarde import execute,zygarde_target
from phase1.record_environment import inventory
from phase2.run_campaign import manifest
from phase2.oracle import SEED1,SEED2
from kicba.reconciliation import MultisetFingerprint,token_for_entry

METHODS=('ours','zygarde_4m','zygarde_32m')
CANARY='zygarde-canary-benchmark'


def save(path,value):
    with path.open('x') as f:json.dump(value,f,indent=2)


def fingerprint(rows):
    result=MultisetFingerprint()
    for r in rows:result.add(token_for_entry(bytes.fromhex(r['name_hex']),r['inode'],r['d_type'],SEED1,SEED2))
    return list(result.as_tuple())


def assess(row,method,fixture,original,target,metrics=None):
    up,down=cases.difference(original,target)
    if method=='ours':
        r=row.get('result',{});elapsed=r.get('benchmark',{}).get('scan_to_verdict_ns')
        good=(row['returncode']==0 and r.get('verdict')==('different' if up or down else 'equal')
            and r.get('recovery_validation',{}).get('verified') is True
            and (not (up or down) or r.get('recovery_verified') is True)
            and r.get('upstream_only')==up and r.get('downstream_only')==down
            and r.get('kernel_fingerprint')==fingerprint(original)
            and [r.get('userspace',{}).get(k) for k in ('count','sum1','sum2')]==fingerprint(target))
        return {'execution_valid':row['returncode']==0,'complete':good,
            'correct':good,'scan_to_verdict_ns':elapsed,'eligible':good and type(elapsed)is int and elapsed>0}
    answer=zygarde_target(row,fixture);m=metrics or {};elapsed=m.get('scan_to_verdict_ns')
    views=m.get('views') or [];names=lambda rows:{bytes.fromhex(r['name_hex']).decode() for r in rows if bytes.fromhex(r['name_hex']) not in (b'.',b'..')}
    want_up,want_down=names(original),names(target)
    complete=bool(views) and all(set(v['produced'])==want_up and set(v['returned'])==want_down for v in views)
    correct=answer['valid'] and answer['alarm']==bool(want_up-want_down)
    return {'execution_valid':answer['valid'],'correct':correct,'complete':complete,
        'scan_to_verdict_ns':elapsed,'eligible':correct and complete and type(elapsed)is int and elapsed>0,
        'view_counts':[{'produced':len(v['produced']),'returned':len(v['returned'])} for v in views],
        'ring_bytes':m.get('ring_bytes'),'canary_present_each_view':all(v['produced'].get(CANARY) and v['returned'].get(CANARY) for v in views)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('output','base','first','adapter'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--boot-index',type=int,required=True);p.add_argument('--pilot',action='store_true')
    args=p.parse_args()
    if os.geteuid()!=0 or platform.release()!='6.8.0-138-generic':raise RuntimeError('wrong environment')
    if cases.loaded()&cases.OWN:raise RuntimeError('research module still loaded')
    args.output.mkdir(exist_ok=False)
    probe=args.base/'phase1/bin/d9_enum_probe';binary=args.output/'bin'/'d9_enum_probe';binary.parent.mkdir()
    shutil.copyfile(args.adapter,binary);binary.chmod(0o700);binary=binary.resolve()
    files=['comparison/scan_cost/run.py','comparison/scan_cost/scan_entry.py','comparison/scan_cost/PROTOCOL.md',
           'comparison/scan_cost/TIMING_BOUNDARY.md','comparison/scan_cost/PILOT_CORRECTION.md',
           'comparison/scan_cost/BUILD.json','finalization/tracefs_measurement.py','finalization/measurement.py',
           'finalization/compare_zygarde.py','finalization/controlled_cases.py','src/kicba/recovery_validation.py',
           'phase2/measurement.py','phase2/bpf_packed.c','phase1/enum_probe.c']
    meta={'boot_index':args.boot_index,'environment':inventory(),'sources':{n:cases.sha(ROOT/n) for n in files},
          'adapter_sha256':cases.sha(binary),'probe_sha256':cases.sha(probe),
          'module_sha256':cases.module_hashes(args.base,args.first),
          'random_seed':202611021000+args.boot_index,'pilot':args.pilot}
    save(args.output/'manifest.json',meta);rng=random.Random(meta['random_seed'])
    def invoke(method,directory,tag,original,target):
        env=None;metrics=None
        if method=='ours':command=['python3',str(ROOT/'comparison/scan_cost/scan_entry.py'),str(directory),'--probe',str(probe)]
        else:
            metrics=args.output/(tag+'.scan.json')
            command=[str(binary),'--cells','hidden_file','--no-isolation','--json']
            env=dict(os.environ,KICBA_BENCH_DIR=str(directory),KICBA_BENCH_CANARY=str(directory/CANARY),
                KICBA_BENCH_METRICS=str(metrics),KICBA_BENCH_RING_BYTES=str(4194304 if method=='zygarde_4m' else 33554432))
        row=execute(command,args.output,tag,env)
        data=json.loads(metrics.read_text()) if metrics is not None and metrics.exists() else None
        row.update(method=method,assessment=assess(row,method,directory,original,target,data))
        return row
    if args.pilot:
        directory=(args.output/'fixture').resolve();directory.mkdir()
        for name in (*cases.NAMES,CANARY):(directory/name).touch()
        original=manifest(directory);save(args.output/'fixture.json',original);rows=[];controls=[]
        try:
            for state in cases.STATES:
                cases.load(state,args.base,args.first)
                try:
                    target=cases.expected(original,state)
                    control=cases.exact_capture(probe,directory,65536,args.output/f'control_{state}.jsonl')
                    control.update(state=state,correct=cases.identities(control['rows'])==cases.identities(target));controls.append(control)
                    order=list(METHODS);rng.shuffle(order)
                    for method in order:
                        row=invoke(method,directory,f'{state}_{method}',original,target);row['state']=state;rows.append(row)
                finally:cases.unload(state,args.base,args.first)
        finally:
            for state in cases.STATES:cases.unload(state,args.base,args.first)
        save(args.output/'observations.json',rows);save(args.output/'controls.json',controls)
        summary={'observations':len(rows),'controls':len(controls),'passed':all(r['assessment']['eligible'] for r in rows) and all(c['correct'] and c['returncode']==0 for c in controls)}
        save(args.output/'summary.json',summary);print(json.dumps(summary),flush=True)
        return 0 if summary['passed'] else 1
    rows=[];fixtures={}
    with (args.output/'observations.jsonl').open('x') as stream:
        for size in (128,4096,65536):
            directory=(args.output/f'fixture_{size}').resolve();directory.mkdir()
            for i in range(size):(directory/f'entry_{i:08d}').touch()
            (directory/CANARY).touch();original=manifest(directory);save(args.output/f'fixture_{size}.json',original)
            fixtures[size]=original
            for repeat in range(6):
                order=list(METHODS);rng.shuffle(order)
                for position,method in enumerate(order):
                    before=manifest(directory)
                    row=invoke(method,directory,f'size_{size}_repeat_{repeat}_{method}',original,original)
                    after=manifest(directory)
                    row.update(size=size,repeat=repeat,warmup=repeat==0,position=position,
                        fixture_unchanged=cases.identities(before)==cases.identities(after)==cases.identities(original))
                    if not row['fixture_unchanged']:row['assessment']['eligible']=False
                    stream.write(json.dumps(row)+'\n');stream.flush();rows.append(row)
                print(json.dumps({'boot_index':args.boot_index,'size':size,'repeat':repeat,'completed':len(rows)}),flush=True)
            save(args.output/f'fixture_{size}_after.json',manifest(directory))
    sources_unchanged=all(cases.sha(ROOT/n)==v for n,v in meta['sources'].items())
    modules_unchanged=cases.module_hashes(args.base,args.first)==meta['module_sha256']
    summary={'observations':len(rows),'main_observations':sum(not r['warmup'] for r in rows),
        'sources_unchanged':sources_unchanged,'modules_unchanged':modules_unchanged,
        'per_method':{m:{'eligible':sum(r['assessment']['eligible'] for r in rows if r['method']==m),
            'incomplete':sum(not r['assessment']['complete'] for r in rows if r['method']==m)} for m in METHODS},
        'finished':len(rows)==54 and sources_unchanged and modules_unchanged and all(r['fixture_unchanged'] for r in rows)}
    save(args.output/'summary.json',summary);print(json.dumps(summary),flush=True)
    return 0 if summary['finished'] else 1


if __name__=='__main__':raise SystemExit(main())
