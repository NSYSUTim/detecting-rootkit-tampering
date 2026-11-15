"""Check the nine-boot baseline and three-boot quality confirmations."""
import gzip
import hashlib
import json
from pathlib import Path
from report_ubuntu26_inputs import decloaker,phase1

T=Path(__file__).resolve().parents[1]
d=decloaker()
assert d['boots']==9 and d['rows']==720 and d['positive']==180 and d['negative']==540 and d['failed']==0
p=phase1()
for row in p['coverage']:
    forced=row['maxactive_1'];capacity=row['maxactive_256'];normal=row['normal']
    assert forced['windows']==30 and forced['missed_windows']==30 and forced['transactions']==560
    assert forced['invalid_transactions']==560 and forced['false_valid_when_missed']==0
    assert capacity['missed_windows']==0 and capacity['invalid_transactions']==0
    assert normal['equal']==30 and normal['invalid']==0 and normal['different']==0
for row in p['fidelity']:
    assert row['trials']==600 and row['full_trials']==240
    assert all(row[k]==0 for k in ('setup_failures','output_mismatch','verdict_mismatch','decode_mismatch'))
result={'passed':True,'decloaker':d,'phase1':p}
(T/'observations/decloaker_phase1_verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'decloaker':d,'phase1_quality_boots':3}))
