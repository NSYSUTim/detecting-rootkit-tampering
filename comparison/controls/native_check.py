"""Confirm the control-fixture length fix with mixed short and long records."""
import argparse,json,os,platform,shutil,subprocess,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
for d in (ROOT,ROOT/'src'):sys.path.insert(0,str(d))
from finalization.tracefs_measurement import new_measurement,CompleteMeasurement
from finalization.controlled_cases import exact_capture,identities,difference,sha,loaded
from phase2.run_campaign import manifest


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--base',type=Path,required=True);args=p.parse_args()
    if os.geteuid()!=0 or platform.release()!='6.8.0-138-generic':raise RuntimeError('wrong native environment')
    if loaded()&{'getdents_hiding_fixed','getdents_policy_fixed'}:raise RuntimeError('fixture already loaded')
    args.output.mkdir(exist_ok=False);fixture=(args.output/'fixture').resolve();fixture.mkdir()
    for name in ('d8_hidden_0000','a'*76,'d8_policy_0000','b'*128,'ordinary'):(fixture/name).touch()
    original=manifest(fixture);probe=args.base/'phase1/bin/d9_enum_probe'
    observations=[];modules={}
    for mode in ('hiding','policy'):
        module=Path(__file__).parent/f'getdents_{mode}_fixed.ko';modules[mode]=sha(module)
        params=['target_comm=d9_enum_probe']+(['policy_authorized=1'] if mode=='policy' else [])
        subprocess.run(['insmod',str(module),*params],check=True)
        try:
            prefix=b'd8_hidden_' if mode=='hiding' else b'd8_policy_'
            target=[r for r in original if not bytes.fromhex(r['name_hex']).startswith(prefix)]
            up,down=difference(original,target)
            for size in (256,4096,8192):
                for repeat in range(2):
                    row=exact_capture(probe,fixture,size,args.output/f'{mode}_{size}_{repeat}.jsonl')
                    observations.append({'method':'unprobed','mode':mode,'buffer':size,
                        'passed':row['returncode']==0 and identities(row['rows'])==identities(target),**row})
            with new_measurement(probe=probe) as base:
                for repeat in range(2):
                    row=CompleteMeasurement(base).scan(fixture,8192)
                    observations.append({'method':'ours','mode':mode,'passed':row['verdict']=='different'
                        and row['recovery_verified'] and row['upstream_only']==up and row['downstream_only']==down,**row})
        finally:subprocess.run(['rmmod',module.stem],check=True)
    result={'scope':'separate control repair verification; excluded from comparison and original denominators',
        'kernel':platform.release(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'original':original,'modules':modules,'observations':observations,'passed':all(r['passed'] for r in observations),
        'sources':{p.relative_to(ROOT).as_posix():sha(p) for p in [Path(__file__),Path(__file__).parent/'getdents_common_fixed.inc']}}
    (args.output/'results.json').write_text(json.dumps(result,indent=2))
    print(json.dumps({'passed':result['passed'],'observations':len(observations),'modules':modules}))
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
