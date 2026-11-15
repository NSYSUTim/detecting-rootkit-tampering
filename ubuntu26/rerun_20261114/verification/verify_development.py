"""Verify recorded development outcomes and independently aggregate offline trials."""
from collections import Counter,defaultdict
import csv
import hashlib
import json
from pathlib import Path
from statistics import median

T=Path(__file__).resolve().parents[1]
O=T/'observations'
def read(name):return json.loads((O/name).read_text(encoding='utf-8'))
counts={}
for folder,file,n in (('boundary','boundary_suite',219),('robustness','robustness_pilot',30),('filesystem_namespace','filesystem_namespace_pilot',24)):
    d=read(f'{folder}/{file}.json')
    assert d['success'] is True and not d['failures'] and len(d['rows'])==n
    for row in d['rows']:
        if folder=='boundary':assert not row['row_failures']
        else:assert row['pass'] is True
        assert not row.get('incorrect_success',False)
    counts[folder]=n
for folder,file,n,iterations in (('legacy_cost','overhead',108,10),('exact_trace','exact_trace_baseline',54,2)):
    d=read(f'{folder}/{file}.json')
    assert len(d['rows'])==n
    keys=[(r['cardinality'],r['condition'],r['repeat'],r['mode']) for r in d['rows']]
    assert len(set(keys))==n
    assert all(r['iterations']==iterations and r['wall_ns']>0 for r in d['rows'])
    if folder=='exact_trace':
        for row in d['rows']:
            assert len(row['detail'])==(0 if row['mode']=='raw_count' else iterations)
            if row['mode']=='full_d9':
                assert all(v['logical_payload_bytes']==12312 and v['accepted_events']==row['cardinality']+2 for v in row['detail'])
    counts[folder]=n
capacity=read('iblt_capacity/capacity.json')
assert capacity['seed']==12009 and capacity['trials_per_cell']==128 and len(capacity['rows'])==80
assert all(r['incorrect_successes']==0 and r['fingerprint_false_equals']==0 for r in capacity['rows'])
counts['capacity_trials']=sum(r['trials'] for r in capacity['rows'])
table=read('iblt_table8_2/summary.json')
trials=[json.loads(s) for s in (O/'iblt_table8_2/trials.jsonl').read_text().splitlines() if s]
assert len(trials)==1600
assert read('iblt_table8_2/protocol.json')['master_seed']==20261114
for group in table:
    rows=[r for r in trials if (r['cells'],r['differences'])==(group['cells'],group['differences'])]
    assert len(rows)==group['trials']
    assert sum(r['decode_success'] and r['exact'] for r in rows)==group['fully_recovered']
    assert sum(r['decode_success'] and not r['exact'] for r in rows)==group['incorrect_successes']==0
counts['additional_capacity_trials']=len(trials)
root=O/'iblt_hash_count'
manifest=read('iblt_hash_count/MANIFEST.json')
for name,meta in manifest.items():
    p=root/name
    assert p.stat().st_size==meta['bytes'] and hashlib.sha256(p.read_bytes()).hexdigest()==meta['sha256']
protocol=read('iblt_hash_count/protocol.json');summary=read('iblt_hash_count/summary.json')
assert hashlib.sha256((root/'protocol.json').read_bytes()).hexdigest()==(root/'protocol.sha256').read_text().strip()
assert hashlib.sha256((root/'run_experiment.py').read_bytes()).hexdigest()==protocol['script_sha256']
assert hashlib.sha256((root/'reconciliation_snapshot.py').read_bytes()).hexdigest()==protocol['snapshot_sha256']
with (root/'trials.csv').open(newline='',encoding='utf-8') as f:rows=list(csv.DictReader(f))
assert len(rows)==protocol['total_variant_decodes']==36864
assert summary['variant_decodes']==len(rows) and summary['incorrect_successes']==0
assert all(int(r['incorrect_success'])==0 for r in rows)
paired=defaultdict(list)
for row in rows:paired[tuple(row[k] for k in ('family','role','mode','difference','cells','trial'))].append(row)
assert len(paired)==9216
for values in paired.values():
    assert {int(r['k']) for r in values}=={2,3,4,5} and {int(r['order']) for r in values}=={0,1,2,3}
    assert len({(r['seed1'],r['seed2']) for r in values})==1
for reported in summary['groups']:
    selected=[r for r in rows if all(str(reported[k])==r[k] for k in ('family','role','mode','difference','cells','k'))]
    assert len(selected)==reported['trials']
    assert sum(int(r['exact']) for r in selected)==reported['exact_successes']
    assert median(int(r['build_ns']) for r in selected)==reported['median_build_ns']
    assert median(int(r['decode_ns']) for r in selected)==reported['median_decode_ns']
counts['hash_count_variant_decodes']=len(rows)
result={'passed':True,'counts':counts,'capacity_source_seed':12009,'additional_capacity_new_seed':20261114,
        'offline_scope':'Recorded offline trial aggregation; does not assert Linux integration for hash-count variants'}
(O/'development_verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result),flush=True)
