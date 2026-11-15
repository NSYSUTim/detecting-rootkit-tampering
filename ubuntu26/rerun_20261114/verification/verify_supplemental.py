"""Replay supplementary controls without pooling their formal denominators."""
from collections import Counter,defaultdict
import hashlib,json,sys
from pathlib import Path
T=Path(__file__).resolve().parents[1]
_project_parent=next(parent for parent in T.parents if (parent/'scan_directory.py').is_file() or (parent/'kicba-thesis-artifact/scan_directory.py').is_file())
_project_root=_project_parent if (_project_parent/'scan_directory.py').is_file() else _project_parent/'kicba-thesis-artifact'
R=_project_root
sys.path[:0]=[str(R),str(R/'src')]
from finalization.controlled_cases import expected
from phase2.oracle import identities,difference
from kicba.reconciliation import IBLT,MultisetFingerprint,token_for_entry
from kicba.call_completion import finalize_call_record

def read(p):return json.loads(p.read_text(encoding='utf-8'))
def lines(p):return [json.loads(s) for s in p.read_text(encoding='utf-8').splitlines() if s]
def tokens(rows,s1,s2):return [token_for_entry(bytes.fromhex(r['name_hex']),r['inode'],r['d_type'],s1,s2) for r in rows]
def encoded(items):return sorted((t.key_hash,t.inode,t.d_type) for t in items)
def replay_identity(row,visible):
    assert row['measurement_valid'] is True
    s1,s2,cells=row['configuration'][:3]
    actual=tokens(visible,s1,s2)
    assert MultisetFingerprint.from_tokens(actual).as_tuple()==tuple(row['userspace'][k] for k in ('count','sum1','sum2'))
    decoded=IBLT.from_rows(row['kernel_rows'],s1,s2).subtract(IBLT.from_tokens(actual,cells,s1,s2)).decode()
    assert decoded.success==row['decode_success']
    assert encoded(decoded.upstream_only)==sorted(map(tuple,row['upstream_only']))
    assert encoded(decoded.downstream_only)==sorted(map(tuple,row['downstream_only']))
def replay_call(row):
    actual=finalize_call_record(dict(row,verdict=row['identity_verdict'],alarm=row['identity_alarm']))
    for key in ('verdict','alarm','completion_valid','completion_anomaly','rejected_entry','alarm_reasons'):
        assert actual[key]==row[key],key

result={'passed':False,'scope':'Supplementary cohorts are separate from original formal measurements'}
boots=[];races=0
for index in (1,2,3):
    folder=T/f'observations/benign_race_supplement/boot_{index:02d}'
    meta=read(folder/'manifest.json');boots.append(meta['boot_id'])
    assert meta['kernel']=='7.0.0-43-generic' and meta['retained_original_cohort']
    rows=lines(folder/'observations.jsonl');assert len(rows)==10
    groups=Counter()
    for row in rows:
        assert row['rejected_regular_entry_deleted'] is True
        before=row['race']['before_delete']['call_observation']
        assert before['completed_rejected']>0 and before['witness_valid']==1
        assert before['name_hex'] in row['race']['deleted']
        witness=[r for r in row['original'] if r['name_hex']==before['name_hex']]
        assert len(witness)==1 and witness[0]['d_type']==8
        first={r['name_hex'] for r in row['race']['first_batch']}
        assert before['name_hex'] not in first and not first.intersection(row['race']['deleted'])
        visible=lines(folder/f"{row['fs']}_{row['attempt']:02d}.jsonl")
        assert identities(visible)==identities(row['visible'])
        replay_identity(row,visible);replay_call(row)
        assert row['verdict']=='equal' and row['alarm'] is False and row['completion_valid'] is True
        groups[row['fs']]+=1;races+=1
    assert groups=={'ext4':5,'tmpfs':5} and read(folder/'summary.json')['passed']
assert len(set(boots))==3
result.update(exercised_benign_races=races,benign_race_boot_ids=boots)

folder=T/'observations/phase2_oem_dynamic_supplement_01'
meta=read(folder/'manifest.json')['environment'];after=read(folder/'environment_after.json')
for key in ('kernel','boot_id','package_inventory_sha256','python'):assert meta[key]==after[key]
assert meta['kernel']=='7.0.0-1018-oem'
rows=lines(folder/'attempts.jsonl');assert len(rows)==80
events={fs:read(folder/f'churn_events_{fs}.json') for fs in ('ext4','tmpfs')}
for e in events.values():assert e['worker_stopped'] and not e['errors']
groups=defaultdict(list)
for row in rows:
    assert row['kind']=='dynamic' and row['verdict']=='equal'
    start,end=(row['userspace'][k] for k in ('scan_started_ns','scan_finished_ns'))
    overlap=Counter(op for ns,op in events[row['fs']]['events'] if start<=ns<=end)
    assert dict(overlap)==row['churn_in_scan']
    assert row['churn_exercised']==all(overlap[op]>0 for op in ('create','rename','delete'))
    replay_identity(row,lines(folder/row['actual_file']))
    groups[(row['fs'],row['implementation'],row['buffer'])].append(row)
assert len(groups)==8 and all(len(v)==10 and any(r['churn_exercised'] for r in v) for v in groups.values())
result['oem_dynamic']={'scans':80,'exercised':sum(r['churn_exercised'] for r in rows),'boot_id':meta['boot_id'],'python':meta['python']}

entry_boots=[];entry_rows=0
for index in (1,2,3):
    folder=T/f'observations/entry_gate/boot_{index:02d}'
    meta=read(folder/'manifest.json');entry_boots.append(meta['boot_id'])
    assert meta['kernel']=='7.0.0-43-generic'
    rows=lines(folder/'attempts.jsonl');controls=read(folder/'controls.json')
    faults=read(folder/'faults.json');extra=read(folder/'extra.json');summary=read(folder/'summary.json')
    assert len(rows)==72 and len(controls)==24 and len(faults)==48 and len(extra)==10
    for row in rows:
        wanted=expected(meta['original'],row['state'],row['exercised'])
        up,down=difference(meta['original'],wanted)
        assert row['verdict']==('different' if up or down else 'equal')
        assert sorted(row['upstream_only'])==up and sorted(row['downstream_only'])==down
        replay_identity(row,wanted)
        dump=folder/f"measured_{row['state']}_{row['buffer']}_{row['repeat']}.jsonl"
        if dump.exists():assert identities(lines(dump))==identities(wanted)
        assert row['passed'] and row['recovery_validation']['verified']
    for row in controls:
        assert row['returncode']==0 and identities(row['rows'])==identities(expected(meta['original'],row['state'],row['exercised']))
    kinds=Counter(r['kind'] for r in faults)
    assert kinds=={'entry_control_before':10,'entry_injected':10,'entry_control_after':10,'return_injected':16,'return_control':2}
    for row in faults:
        if row['kind'] in ('entry_injected','return_injected'):
            assert row['verdict']=='invalid' and row['alarm'] is None
            if row['kind']=='entry_injected':
                assert row['pre_entry_gate_verdict']=='equal'
                assert any(v['missed_delta']>0 for v in row['entry_coverage']['per_event'].values())
        else:assert row['measurement_valid'] and row['verdict']=='equal' and row['alarm'] is False
    for row in extra:
        if row['kind']=='load_order':assert row['verdict']=='different' and row['recovery_verified']
        if row['kind']=='overcapacity':assert row['verdict']=='different' and not row['recovery_verified']
        if row['kind']=='boundary':assert row['verdict']==('equal' if row['buffer']==4096 else 'invalid')
    assert summary['passed'] and summary['protected_sources_unchanged']
    entry_rows+=len(rows)+len(faults)+len(extra)
assert len(set(entry_boots))==3
result['entry_gate']={'boot_ids':entry_boots,'telemetry_rows_checked':entry_rows,'controlled_measured':216,'unprobed_controls':72,'entry_faults_invalid':30,'return_faults_invalid':48}

folder=T/'observations/current_cli_native_02';meta=read(folder/'verification.json')
assert meta['passed'] and meta['checks']==12 and meta['module_absent']
for check in meta['rows']:
    row=read(folder/(check['tag']+'.stdout'))
    assert (row['verdict'],row['alarm'])==(check['verdict'],check['alarm'])
    if not check['tag'].endswith('accepted'):replay_call(row)
    if check['tag'].startswith('getdents64'):assert row['recovery_verified']
failed=read(T/'observations/current_cli_native_01/getdents64_128_current.stdout')
assert failed['returncode']==2 and failed['verdict']=='invalid' and failed['alarm'] is None and 'malformed getdents64 record' in failed['stderr']
result['cli']={'passing_checks':12,'extra_fixture_failure_retained':True,'malformed_result_correctly_invalid':True}

folder=T/'observations/control_repair';meta=read(folder/'manifest.json');summary=read(folder/'results.json')
assert summary['passed'] and summary['all_modules_absent']
rows=lines(folder/'observations.jsonl');assert len(rows)==12
for row in rows:
    prefix=('d8_hidden_' if row['kind']=='hiding' else 'd8_policy_').encode()
    wanted=[r for r in meta['original'] if not bytes.fromhex(r['name_hex']).startswith(prefix)]
    up,down=difference(meta['original'],wanted)
    visible=lines(folder/f"{row['kind']}_{row['buffer']}_{row['repeat']}.jsonl")
    assert identities(visible)==identities(wanted)==identities(row['visible'])
    replay_identity(row,visible);replay_call(row)
    assert row['verdict']=='different' and row['alarm'] is True and row['completion_valid'] and row['recovery_verified']
    assert sorted(row['upstream_only'])==up and sorted(row['downstream_only'])==down
result['fixed_compaction_controls']={'scans':12,'all_modules_absent':True}
result['passed']=True
(T/'observations/supplemental_verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result),flush=True)
