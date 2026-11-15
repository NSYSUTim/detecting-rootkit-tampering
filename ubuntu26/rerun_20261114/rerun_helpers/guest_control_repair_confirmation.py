"""Keep repaired compaction controls separate from the frozen main matrix."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

B=Path('/home/kicba/research_phase2_20261023')
K=Path('/home/kicba/call_completion_20261103/code')
sys.path[:0]=[str(K),str(K/'src')]
from call_completion.measurement import new_call_measurement,CallMeasurement
from phase2.run_campaign import manifest
from phase2.oracle import identities,difference

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    assert platform.release()=='7.0.0-43-generic'
    a.output.mkdir(parents=True,exist_ok=False)
    fixture=a.output/'fixture';fixture.mkdir()
    for prefix,count in (('ordinary_',64),('d8_hidden_',16),('d8_policy_',16)):
        for n in range(count):(fixture/f'{prefix}{n:04d}').touch()
    original=manifest(fixture)
    module_dir=B/'comparison/controls'
    meta={'kernel':platform.release(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
          'scope':'Fixed-compaction controls only; never pooled into the frozen main matrix',
          'original':original,'modules':{name:hashlib.sha256((module_dir/name).read_bytes()).hexdigest()
                      for name in ('getdents_hiding_fixed.ko','getdents_policy_fixed.ko')}}
    (a.output/'manifest.json').write_text(json.dumps(meta,indent=2))
    rows=[]
    with (a.output/'observations.jsonl').open('x') as stream:
        for kind,prefix in (('hiding',b'd8_hidden_'),('policy',b'd8_policy_')):
            module=module_dir/f'getdents_{kind}_fixed.ko'
            argv=['insmod',str(module),'target_comm=d9_enum_probe']
            if kind=='policy':argv+=['policy_authorized=1']
            subprocess.run(argv,capture_output=True,check=True)
            try:
                wanted=[r for r in original if not bytes.fromhex(r['name_hex']).startswith(prefix)]
                up,down=difference(original,wanted)
                with new_call_measurement(probe=B/'phase1/bin/d9_enum_probe') as base:
                    for buffer in (128,65536):
                        for repeat in range(3):
                            dump=a.output/f'{kind}_{buffer}_{repeat}.jsonl'
                            row=CallMeasurement(base).scan(fixture,buffer,dump=dump)
                            visible=[json.loads(s) for s in dump.read_text().splitlines()]
                            assert identities(visible)==identities(wanted)
                            assert row['verdict']=='different' and row['alarm'] is True and row['completion_valid'] is True
                            assert sorted(row['upstream_only'])==up and sorted(row['downstream_only'])==down and row['recovery_verified'] is True
                            row.update(kind=kind,buffer=buffer,repeat=repeat,visible=visible)
                            stream.write(json.dumps(row)+'\n');stream.flush();rows.append(row)
            finally:subprocess.run(['rmmod',module.stem],capture_output=True,check=True)
    result={'passed':True,'scans':len(rows),'all_modules_absent':all(not Path('/sys/module',f'getdents_{k}_fixed').exists() for k in ('hiding','policy'))}
    (a.output/'results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))

if __name__=='__main__':main()
