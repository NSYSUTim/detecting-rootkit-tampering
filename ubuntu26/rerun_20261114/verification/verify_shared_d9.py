"""Verify all preserved D9 batches; keep strict recovery failures distinct."""
from collections import Counter,defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import random
T=Path(__file__).resolve().parents[1]
root=T/'observations/trace_of_times/d9'
records=[json.loads(s) for s in (root/'collection.jsonl').read_text().splitlines() if s]
assert len(records)==1000
assert len({(r['scenario'],r['label'],r['index']) for r in records})==1000
assert {r['file'] for r in records}=={p.name for p in root.glob('batch_*.json.gz')}
scenarios=('default','file_count','system_load','filename_length')
groups=defaultdict(list);boots=set();sources=set();failed=[]
metrics=Counter()
rng=random.Random(42^0xD9D9);seeds=(rng.getrandbits(64) or 1,rng.getrandbits(64) or 2)
manifest={}
for record in records:
    path=root/record['file'];digest=hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest==record['sha256'];manifest[path.name]=digest
    with gzip.open(path,'rt') as f:d=json.load(f)
    scenario,label,index=(d[k] for k in ('scenario','label','index'))
    assert (scenario,label,index)==tuple(record[k] for k in ('scenario','label','index'))
    assert scenario in scenarios and label in ('normal','rootkit')
    assert (d['hash_seed1'],d['hash_seed2'])==seeds and d['cell_count']==256 and d['buffer_size']==65536
    seed=int.from_bytes(hashlib.sha256(f'42:{scenario}:{label}:{index}'.encode()).digest()[:8],'big')
    randomizer=random.Random(seed)
    visible,hidden=(randomizer.randint(10,100),randomizer.randint(10,100)) if scenario=='file_count' else (1,1)
    length=randomizer.randint(20,60) if scenario=='filename_length' else 8
    assert d['parameters']=={'visible_files':visible,'hidden_files':hidden,'file_name_length':length,'system_load':scenario=='system_load'}
    positive=label=='rootkit'
    assert d['expected_difference_count']==(hidden if positive else 0)
    rows=d['transactions'];assert len(rows)==d['iterations']==100
    strict=all(r['measurement_valid'] and r['decoded_exact'] and r['difference_detected']==positive for r in rows)
    assert d['valid']==record['valid']==strict
    assert d['batch_detected']==any(r['difference_detected'] for r in rows)
    all_exact=all(r['decoded_exact'] for r in rows)
    if not strict:failed.append({'scenario':scenario,'label':label,'index':index,'differences':d['expected_difference_count'],
        'invalid_measurements':sum(not r['measurement_valid'] for r in rows),'incomplete_recovery_listings':sum(not r['decoded_exact'] for r in rows)})
    for r in rows:
        assert r['measurement_valid'] is True
        k,u=r['kernel_fingerprint'],r['visible_fingerprint']
        assert r['difference_detected']==(k!=u)==positive
        assert k[0]==visible+hidden+2 and u[0]==(visible+2 if positive else visible+hidden+2)
        assert r['kernel_stats']['accepted_entries']==k[0]
        assert all(r['kernel_stats'][name]==0 for name in ('name_read_errors','invalid_name_lengths','pending_update_failures','fingerprint_update_failures','iblt_update_failures','return_underflows'))
        if r['decoded_exact']:
            assert r['decode_success'] and r['residual_cells']==0
            assert r['upstream_only_count']==(hidden if positive else 0) and r['downstream_only_count']==0
        else:
            assert not r['decode_success'],'A successful but inexact decode needs separate investigation'
        metrics['listings']+=1
        metrics['positive_listings_full_recovery' if r['decoded_exact'] else 'positive_listings_incomplete_recovery']+=positive
    metrics['tp' if positive and d['batch_detected'] else 'fn' if positive else 'fp' if d['batch_detected'] else 'tn']+=1
    if positive:metrics['positive_batches_full_recovery' if all_exact else 'positive_batches_incomplete_recovery']+=1
    groups[(scenario,label)].append(index)
    assert d['environment']['kernel']=='7.0.0-43-generic';boots.add(d['environment']['boot_id'])
    sources.add(json.dumps(d['source_hashes'],sort_keys=True))
for scenario in scenarios:
    for label,count in (('normal',150),('rootkit',100)):assert sorted(groups[(scenario,label)])==list(range(count))
assert len(sources)==1
result={'passed':True,'batches':1000,'metrics':dict(metrics),**dict(metrics),
    'boot_ids':sorted(boots),'strict_acceptance_all_passed':not failed,'original_strict_failures':failed,
    'record_sha256':manifest,'source_hashes':json.loads(next(iter(sources))),
    'scope':'Hash, index, protocol, counts, fingerprints, quality and recorded recovery-flag verification. Compact records do not preserve the kernel IBLT rows or recovered identities for independent full decoder replay.'}
(T/'observations/D9_SHARED_VERIFICATION.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'batches':1000,'metrics':dict(metrics),'strict_failure_batches':failed}),flush=True)
