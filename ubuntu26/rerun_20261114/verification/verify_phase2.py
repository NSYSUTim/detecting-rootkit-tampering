"""Recompute six campaigns, retaining an explicitly unmet overlap criterion."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import tarfile

T=Path(__file__).resolve().parents[1]
_project_parent=next(parent for parent in T.parents if (parent/'scan_directory.py').is_file() or (parent/'kicba-thesis-artifact/scan_directory.py').is_file())
_project_root=_project_parent if (_project_parent/'scan_directory.py').is_file() else _project_parent/'kicba-thesis-artifact'
R=_project_root
sys.path[:0]=[str(R),str(R/'src')]
from phase2.summary import summarize
from phase2.run_confirmation import criteria
from phase2.run_campaign import expected_output
from phase2.oracle import identities,difference
from kicba.reconciliation import IBLT,MultisetFingerprint,token_for_entry

def tokens(rows,s1,s2):
    return [token_for_entry(bytes.fromhex(r['name_hex']),r['inode'],r['d_type'],s1,s2) for r in rows]

def encoded(items):return sorted((t.key_hash,t.inode,t.d_type) for t in items)

results=[];boot_ids=[];replayed=0
for env in ('ubuntu26_generic','ubuntu26_oem'):
    for index in (1,2,3):
        path=T/f'observations/phase2/confirmation_{env}_boot_{index:02d}.tar.gz'
        side=json.loads(path.with_name(path.name+'.sha256.json').read_text())
        assert hashlib.sha256(path.read_bytes()).hexdigest()==side['sha256']
        with tarfile.open(path,'r:gz') as bundle:
            files={m.name:bundle.extractfile(m).read() for m in bundle if m.isfile() and m.name.endswith(('.json','.jsonl'))}
        base=f'phase2/evidence/{env}/confirmation_boot_{index:02d}'
        load=lambda name:json.loads(files[base+'/'+name])
        summary=load('summary.json')
        rows=[json.loads(s) for s in files[base+'/campaign/attempts.jsonl'].splitlines() if s]
        fresh=summarize(rows)
        assert fresh['quality']==summary['quality'] and fresh['cost']==summary['cost']
        tests=criteria(fresh,rows)
        tests['environment_and_timers']=all(summary['campaign_completion'][k] is True for k in ('completed','environment_unchanged','timers_restored'))
        assert tests==summary['criteria']
        failed=[k for k,v in tests.items() if not v]
        assert set(failed)<= {'dynamic_not_exercised'},(env,index,failed)
        assert summary['completed']==(not failed)
        boot_ids.append(summary['boot_id'])
        originals={fs:load('campaign/oracle_'+fs+'.json') for fs in ('ext4','tmpfs')}
        events={fs:load('campaign/churn_events_'+fs+'.json') for fs in ('ext4','tmpfs')}
        for ev in events.values():assert ev['worker_stopped'] and not ev['errors']
        for row in rows:
            if row['kind'] not in ('static','dynamic'):continue
            actual=[json.loads(s) for s in files[base+'/campaign/'+row['actual_file']].splitlines() if s]
            if row['kind']=='static':
                original=originals[row['fs']]
                wanted=expected_output(original,row['state'],row['mutation_exercised'])
                assert identities(actual)==identities(wanted)
                up,down=difference(original,wanted)
                assert row['expected_difference']==bool(up or down)
                assert row['expected_upstream']==up and row['expected_downstream']==down
                if row['implementation']!='parse':
                    assert row['verdict']==('different' if up or down else 'equal')
                    assert sorted(row['upstream_only'])==up and sorted(row['downstream_only'])==down
            else:
                start,end=(row['userspace'][k] for k in ('scan_started_ns','scan_finished_ns'))
                overlap=Counter(op for time,op in events[row['fs']]['events'] if start<=time<=end)
                assert dict(overlap)==row['churn_in_scan']
                assert row['churn_exercised']==all(overlap[op]>0 for op in ('create','rename','delete'))
                assert row['verdict']=='equal'
            if row['implementation']!='parse':
                assert row['measurement_valid'] is True
                s1,s2,cells=row['configuration'][:3]
                visible=tokens(actual,s1,s2)
                assert MultisetFingerprint.from_tokens(visible).as_tuple()==tuple(row['userspace'][k] for k in ('count','sum1','sum2'))
                decoded=IBLT.from_rows(row['kernel_rows'],s1,s2).subtract(IBLT.from_tokens(visible,cells,s1,s2)).decode()
                assert decoded.success==row['decode_success']
                assert encoded(decoded.upstream_only)==sorted(map(tuple,row['upstream_only']))
                assert encoded(decoded.downstream_only)==sorted(map(tuple,row['downstream_only']))
            replayed+=1
        results.append({'environment':env,'boot_index':index,'boot_id':summary['boot_id'],
            'formal_acceptance_passed':summary['completed'],'failed_criteria':failed,
            'static_measured':fresh['quality']['static_measured'],
            'static_differences':sum(g.get('different',0) for g in fresh['quality']['static_groups'].values()),
            'dynamic':fresh['quality']['dynamic'],'dynamic_unexercised':fresh['quality']['dynamic_not_exercised'],
            'paired_costs':fresh['cost']['paired']})
        print(json.dumps({'verified':env,'boot':index,'formal_acceptance_passed':not failed,'failed_criteria':failed}),flush=True)
assert len(set(boot_ids))==6
result={'passed':True,'scope':'Evidence and oracle verification; does not override unmet formal acceptance criteria',
        'rows_replayed':replayed,'campaigns':results,
        'formal_campaigns_passed':sum(r['formal_acceptance_passed'] for r in results),
        'formal_campaigns_not_fully_passed':sum(not r['formal_acceptance_passed'] for r in results)}
(T/'observations/phase2_verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'rows_replayed':replayed,'formal_campaigns_not_fully_passed':result['formal_campaigns_not_fully_passed']}),flush=True)
