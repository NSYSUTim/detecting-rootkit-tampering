"""Recompute public-sample fingerprints, IBLT recovery and completion decisions."""
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

T=Path(__file__).resolve().parents[1]
_project_parent=next(parent for parent in T.parents if (parent/'scan_directory.py').is_file() or (parent/'kicba-thesis-artifact/scan_directory.py').is_file())
_project_root=_project_parent if (_project_parent/'scan_directory.py').is_file() else _project_parent/'kicba-thesis-artifact'
R=_project_root
sys.path.insert(0,str(R/'src'))
from kicba.reconciliation import IBLT,MultisetFingerprint,token_for_entry
from kicba.call_completion import finalize_call_record

def load(path):
    return json.loads(path.read_text())

def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

def identities(rows):
    return Counter((r['name_hex'],r['inode'],r['d_type']) for r in rows)

def tokens(rows,seed1,seed2):
    return [token_for_entry(bytes.fromhex(r['name_hex']),r['inode'],r['d_type'],seed1,seed2) for r in rows]

groups=defaultdict(list)
boot_sets={}
checks=0
for suite in ('caraxes_accepted','caraxes_call'):
    ids=[]
    for index in (1,2,3):
        directory=T/'observations'/suite/f'boot_{index:02d}'
        meta=load(directory/'manifest.json')
        rows=lines(directory/'observations.jsonl')
        original=meta['original']
        ids.append(meta['boot_id'])
        assert len(rows)==100 and len(original)==70
        assert Counter(r['mode'] for r in rows)=={'normal':20,'getdents64':40,'filldir':40}
        for row in rows:
            seed1,seed2,cells=row['configuration'][:3]
            visible=tokens(row['visible'],seed1,seed2)
            fp=MultisetFingerprint.from_tokens(visible).as_tuple()
            assert tuple(row['userspace'][k] for k in ('count','sum1','sum2'))==fp
            local=IBLT.from_tokens(visible,cells,seed1,seed2)
            assert len(row['kernel_rows'])==cells
            kernel=IBLT.from_rows(row['kernel_rows'],seed1,seed2)
            decoded=kernel.subtract(local).decode()
            assert decoded.success==row['decode_success']
            assert sorted((t.key_hash,t.inode,t.d_type) for t in decoded.upstream_only)==sorted(map(tuple,row['upstream_only']))
            assert sorted((t.key_hash,t.inode,t.d_type) for t in decoded.downstream_only)==sorted(map(tuple,row['downstream_only']))
            if row['mode'] in ('normal','getdents64'):
                wanted=[r for r in original if row['mode']=='normal' or b'caraxes' not in bytes.fromhex(r['name_hex'])]
                assert identities(row['visible'])==identities(wanted)
                assert tuple(row['kernel_fingerprint'])==MultisetFingerprint.from_tokens(tokens(original,seed1,seed2)).as_tuple()
            else:
                assert not any(b'caraxes' in bytes.fromhex(r['name_hex']) for r in row['visible'])
                assert tuple(row['kernel_fingerprint'])==fp
            if suite=='caraxes_call':
                checked=finalize_call_record(dict(row,verdict=row['identity_verdict'],alarm=row['identity_alarm']))
                for name in ('verdict','alarm','completion_valid','completion_anomaly','rejected_entry','alarm_reasons'):
                    assert checked[name]==row[name],name
                if row['mode']=='filldir':
                    assert row['verdict']=='completion_anomaly' and row['alarm'] is True
                    witness=row['rejected_entry']
                    assert b'caraxes' in bytes.fromhex(witness['name_hex'])
                    assert (witness['name_hex'],witness['inode'],witness['d_type']) in identities(original)
                    assert row['total_missing_count'] is None
            groups[(suite,row['mode'])].append(row)
            checks+=1
        for control in lines(directory/'controls.jsonl'):
            assert control['matches_manifest']==(identities(control['rows'])==identities(original))
            assert control['returncode']==0
            checks+=1
        clean=load(directory/'cleanup.json')
        assert clean['module_absent'] and clean['manifest_restored']
    assert len(set(ids))==3
    boot_sets[suite]=ids
assert boot_sets['caraxes_accepted']==boot_sets['caraxes_call']
summary=[]
for (suite,mode),rows in groups.items():
    summary.append({'suite':suite,'mode':mode,'n':len(rows),
        'verdicts':dict(Counter(r['verdict'] for r in rows)),
        'alarms':sum(r['alarm'] is True for r in rows),
        'verified_recovery':sum(r.get('recovery_verified') is True for r in rows),
        'accepted_range':[min(r['kernel_stats']['accepted_entries'] for r in rows),max(r['kernel_stats']['accepted_entries'] for r in rows)],
        'received_range':[min(len(r['visible']) for r in rows),max(len(r['visible']) for r in rows)],
        'external_missing_range':[min(len(r['external_missing']) for r in rows),max(len(r['external_missing']) for r in rows)]})
result={'passed':True,'checked_observations_and_controls':checks,'boot_ids':boot_sets,'groups':summary}
(T/'observations/public_sample_verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result),flush=True)
