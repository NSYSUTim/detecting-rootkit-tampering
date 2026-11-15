"""Independently replay all preserved native and offline diagnostic records."""
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True

H=Path(__file__).resolve().parent
E=H/'evidence'
R=E/'sources/frozen_existing'
sys.path.insert(0,str(R/'src'))
from kicba.reconciliation import IBLT,MultisetFingerprint,token_for_entry,EntryToken

def load(p):return json.loads(p.read_text())
def toks(rows,seeds):return [token_for_entry(bytes.fromhex(r['name_hex']),r['inode'],r['d_type'],*seeds) for r in rows]
def key(t):return (t.key_hash,t.inode,t.d_type)
def ordered(rows):return sorted(tuple(r) for r in rows)

def parse_pages(path):
    data=path.read_bytes();cursor=0;rows=[];pages=[]
    while cursor<len(data):
        n=struct.unpack_from('<Q',data,cursor)[0];cursor+=8;page=data[cursor:cursor+n];cursor+=n;offset=0;pages.append(n)
        while offset<n:
            ino,cookie,length,kind=struct.unpack_from('<QqHB',page,offset)
            assert length>=20 and offset+length<=n
            name=page[offset+19:offset+length].split(b'\0',1)[0]
            rows.append(dict(name_hex=name.hex(),inode=ino,d_type=kind));offset+=length
    assert cursor==len(data) and pages[-1]==0
    return rows,pages

def check_model(m,rows,cells,seeds):
    all_tokens=toks(rows,seeds);visible=toks([r for r in rows if not r['hidden']],seeds)
    k=IBLT.from_tokens(all_tokens,cells,*seeds);u=IBLT.from_tokens(visible,cells,*seeds);d=k.subtract(u);res=d.decode()
    for field,table in (('kernel_rows',k),('visible_rows',u),('difference_rows',d)):
        assert m[field]==[list(x) for x in table.to_rows()],field
    assert res.success==m['decode_success'] and res.residual_cells==m['residual_cells']
    assert ordered([key(t) for t in res.upstream_only])==ordered([r['token'] for r in m['recovered']])
    residual=IBLT.from_rows(d.to_rows(),*seeds)
    for t in res.upstream_only:residual.add(t,-1)
    for t in res.downstream_only:residual.add(t,1)
    assert m['residual_rows']==[list(x) for x in residual.to_rows()]
    missing={key(t) for r,t in zip(rows,all_tokens) if r['hidden']}-{key(t) for t in res.upstream_only}
    assert missing=={tuple(r['token']) for r in m['unrecovered']}
    for item in m['identity_map']:
        t=token_for_entry(bytes.fromhex(item['name_hex']),item['inode'],item['d_type'],*seeds)
        assert tuple(item['token'])==key(t) and item['positions']==list(k._positions(t.key_hash))

hashes=load(E/'EVIDENCE_MANIFEST.json')
for name,digest in hashes.items():assert hashlib.sha256((E/name).read_bytes()).hexdigest()==digest,name
source_manifest=load(H/'SOURCE_DOWNLOAD_VERIFICATION.json')['files']
for name,digest in source_manifest.items():assert hashlib.sha256((R/name).read_bytes()).hexdigest()==digest,name
counts=Counter();native=[]
for folder in ('primary_256','selected_failure_256','same_fixture_512','same_fixture_1024'):
    root=E/folder;meta=load(root/'manifest.json');rows=meta['rows'];cells=meta['cell_count'];seeds=meta['seeds']
    m=load(root/'expected_model.json');check_model(m,rows,cells,seeds)
    records=[json.loads(s) for s in (root/'observations.jsonl').read_text().splitlines()]
    assert len(records)==meta['repeats']
    for record in records:
        visible,pages=parse_pages(root/record['raw_capture'])
        expected=[r for r in rows if not r['hidden']]
        identities=lambda rs:sorted((r['name_hex'],r['inode'],r['d_type']) for r in rs)
        assert identities(visible)==identities(record['actual_visible'])==identities(expected)
        assert record['page_lengths']==pages
        assert record['kernel_rows']==m['kernel_rows'] and record['visible_iblt_rows']==m['visible_rows']
        assert record['measurement_valid'] and not record['fingerprint_equal']
        assert record['decode_success']==m['decode_success']
        assert tuple(record['kernel_fingerprint'])==MultisetFingerprint.from_tokens(toks(rows,seeds)).as_tuple()
        assert tuple(record['visible_fingerprint'])==MultisetFingerprint.from_tokens(toks(visible,seeds)).as_tuple()
        assert record['residual_rows']==m['residual_rows'] and record['unrecovered']==m['unrecovered']
        counts['native_capture_scans']+=1
    native.append(dict(folder=folder,scans=len(records),complete=sum(r['decode_success'] for r in records),unrecovered=m['unrecovered']))

index=[json.loads(s) for s in (E/'search/index.jsonl').read_text().splitlines()]
for r in index:
    assert 'seed_attempt' not in r,'This run should have reproduced under original fixed seeds'
    path=E/'search'/r['file'];assert hashlib.sha256(path.read_bytes()).hexdigest()==r['sha256']
    with gzip.open(path,'rt') as f:m=json.load(f)
    check_model(m,m['rows'],m['cell_count'],m['seeds']);counts['offline_real_inode_fixtures']+=1
assert all(r['decode_success'] for r in index[:-1]) and not index[-1]['decode_success']

control=E/'original_probe_control';meta=load(control/'protocol.json')
records=[json.loads(s) for s in (control/'observations.jsonl').read_text().splitlines()]
for r in records:
    cells=r['cells'];rows=meta['rows'];seeds=meta['seeds'];k=IBLT.from_tokens(toks(rows,seeds),cells,*seeds)
    u=IBLT.from_tokens(toks([x for x in rows if not x['hidden']],seeds),cells,*seeds);decoded=k.subtract(u).decode()
    assert r['kernel_rows']==[list(x) for x in k.to_rows()] and r['visible_iblt_rows']==[list(x) for x in u.to_rows()]
    assert r['decode_success']==decoded.success and r['measurement_valid'] and not r['fingerprint_equal']
    counts['unmodified_probe_scans']+=1

model256=load(E/'selected_failure_256/expected_model.json')
missing=model256['unrecovered'];assert len(missing)==2 and len(model256['recovered'])==71
assert sorted(missing[0]['positions'])==sorted(missing[1]['positions'])
resid=[dict(index=i,fields=r) for i,r in enumerate(model256['residual_rows']) if any(r)]
assert sorted(r['index'] for r in resid)==sorted(missing[0]['positions'])
assert all(r['fields'][0]==2 for r in resid)

oem=E/'oem_dynamic';rows=[json.loads(s) for s in (oem/'observations.jsonl').read_text().splitlines()]
events={fs:load(oem/(fs+'_named_churn.json'))['events'] for fs in ('ext4','tmpfs')}
groups=Counter();exercised=Counter()
for r in rows:
    assert r['measurement_valid'] and r['verdict']=='equal'
    seeds=(0x0123456789ABCDEF,0xF0E1D2C3B4A59687)
    visible=toks(r['visible_names'],seeds);u=IBLT.from_tokens(visible,256,*seeds)
    assert tuple(r['kernel_fingerprint'])==MultisetFingerprint.from_tokens(visible).as_tuple()
    assert r['kernel_rows']==[list(x) for x in u.to_rows()]
    start,end=(r['userspace'][k] for k in ('scan_started_ns','scan_finished_ns'))
    overlap=Counter(e['op'] for e in events[r['fs']] if start<=e['ns']<=end)
    assert dict(overlap)==r['churn_in_scan']
    actual=all(overlap[op]>0 for op in ('create','rename','delete'))
    assert actual==r['churn_exercised'];g=(r['fs'],r['implementation'],r['buffer']);groups[g]+=1;exercised[g]+=actual
assert len(groups)==8 and all(n==10 for n in groups.values())
counts['oem_dynamic_scans']=len(rows);counts['oem_dynamic_exercised']=sum(exercised.values())
health=load(E/'final_health.json');assert health['passed']
result=dict(passed=True,hash_verified_files=len(hashes),counts=dict(counts),native_cohorts=native,
    collision=dict(unrecovered=missing,residual_cells=resid,explanation='Two distinct tokens occupy the same three cells; every remaining cell has count +2, so no pure cell remains.'),
    oem_groups=[dict(fs=k[0],implementation=k[1],buffer=k[2],attempted=v,exercised=exercised[k]) for k,v in groups.items()],
    historical_missing_names_known=False,formal_results_replaced=False,final_guest_health=health)
(H/'VERIFIED_FINDINGS.json').write_text(json.dumps(result,ensure_ascii=True,indent=2))
print(json.dumps(dict(passed=True,counts=dict(counts),unrecovered=missing,oem_exercised=sum(exercised.values())),ensure_ascii=True))
