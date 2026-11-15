"""Repeat only the original OEM dynamic control after one missed overlap.

This is additional evidence, not a replacement for the failed formal criterion.
"""
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import platform
import sys

B=Path('/home/kicba/research_phase2_20261023')
G=Path('/home/kicba/ubuntu26_20261114')
sys.path[:0]=[str(B),str(B/'src'),str(B/'collector')]
from phase2.run_campaign import filesystem_roots,run_dynamic
from phase1 import run_experiments as legacy
from phase1.record_environment import inventory

assert platform.release()=='7.0.0-1018-oem'
out=G/'observations/phase2_oem_dynamic_supplement_01';out.mkdir(parents=True,exist_ok=False)
before=inventory()
(out/'manifest.json').write_text(json.dumps({'environment':before,
    'scope':'Additional OEM dynamic-only cohort; original failed formal criterion is retained',
    'source_sha256':{name:hashlib.sha256((B/name).read_bytes()).hexdigest()
        for name in ('phase2/run_campaign.py','phase2/measurement.py','phase2/bpf_packed.c')}},indent=2))
legacy.runtime()
with (out/'attempts.jsonl').open('x') as stream:
    with filesystem_roots(out) as roots:run_dynamic(out,stream,roots,10)
rows=[json.loads(s) for s in (out/'attempts.jsonl').read_text().splitlines()]
groups=defaultdict(list)
for r in rows:groups[(r['fs'],r['implementation'],r['buffer'])].append(r)
summary={'scans':len(rows),'exercised':sum(r['churn_exercised'] for r in rows),
    'all_valid_equal':all(r['verdict']=='equal' and r['measurement_valid'] for r in rows),
    'groups':{'/'.join(map(str,k)):{'n':len(v),'exercised':sum(r['churn_exercised'] for r in v)} for k,v in groups.items()}}
summary['passed']=summary['scans']==80 and summary['all_valid_equal'] and len(groups)==8 and all(v['exercised']>0 for v in summary['groups'].values())
(out/'summary.json').write_text(json.dumps(summary,indent=2))
(out/'environment_after.json').write_text(json.dumps(inventory(),indent=2))
print(json.dumps(summary),flush=True)
raise SystemExit(0 if summary['passed'] else 1)
