"""Replay controlled identities and the final decision from the recorded telemetry."""
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

T = Path(__file__).resolve().parents[1]
_project_parent=next(parent for parent in T.parents if (parent/'scan_directory.py').is_file() or (parent/'kicba-thesis-artifact/scan_directory.py').is_file())
_project_root=_project_parent if (_project_parent/'scan_directory.py').is_file() else _project_parent/'kicba-thesis-artifact'
R=_project_root
sys.path[:0] = [str(R), str(R/'src')]
from finalization.controlled_cases import expected
from phase2.oracle import identities, difference
from kicba.reconciliation import IBLT, MultisetFingerprint, token_for_entry
from kicba.call_completion import finalize_call_record

def read(path):
    return json.loads(path.read_text())

def lines(path):
    return [json.loads(s) for s in path.read_text().splitlines() if s]

def tokens(rows, seed1, seed2):
    return [token_for_entry(bytes.fromhex(r['name_hex']), r['inode'], r['d_type'], seed1, seed2) for r in rows]

def tuples(items):
    return sorted((t.key_hash,t.inode,t.d_type) for t in items)

groups = defaultdict(list)
boot_ids = []
checked, assessments = 0, 0
for index in (1,2,3):
    folder = T / f'observations/call_regression/boot_{index:02d}'
    meta = read(folder/'manifest.json')
    boot_ids.append(meta['boot_id'])
    original = read(folder/'static_manifest.json')
    rows = lines(folder/'observations.jsonl')
    by_dump = {r['dump']:r for r in rows if 'dump' in r}
    assert len([r for r in rows if r['kind']=='regression']) == 320
    for assessment in (r for r in rows if r['kind']=='assessment'):
        row = by_dump[assessment['scan_dump']]
        wanted = expected(original,row['state'],assessment['mutation_exercised']) if row['state'] in meta['states'][:12] else original
        assert identities(row['visible']) == identities(wanted), (index,row['state'],row['buffer'])
        up,down = difference(original,wanted)
        assert sorted(row['upstream_only'])==up and sorted(row['downstream_only'])==down
        assert row['identity_verdict']==('different' if up or down else 'equal')
        assert all(assessment[k] is True for k in ('output_match','identity_match','recovery_match'))
        seed1,seed2 = row['configuration'][:2]
        assert tuple(row['kernel_fingerprint'])==MultisetFingerprint.from_tokens(tokens(original,seed1,seed2)).as_tuple()
        assessments+=1
    for row in rows:
        if row['kind']=='assessment':
            continue
        kind = row['kind']
        if row.get('measurement_valid') is True and 'kernel_rows' in row:
            seed1,seed2,cells = row['configuration'][:3]
            visible = tokens(row['visible'],seed1,seed2)
            fingerprint = MultisetFingerprint.from_tokens(visible).as_tuple()
            assert fingerprint==tuple(row['userspace'][k] for k in ('count','sum1','sum2'))
            decoded = IBLT.from_rows(row['kernel_rows'],seed1,seed2).subtract(IBLT.from_tokens(visible,cells,seed1,seed2)).decode()
            assert decoded.success==row['decode_success']
            assert tuples(decoded.upstream_only)==sorted(map(tuple,row['upstream_only']))
            assert tuples(decoded.downstream_only)==sorted(map(tuple,row['downstream_only']))
        replay = finalize_call_record(dict(row,verdict=row['identity_verdict'],alarm=row['identity_alarm']))
        for key in ('verdict','alarm','completion_valid','completion_anomaly','rejected_entry','alarm_reasons'):
            assert replay[key]==row[key], (index,kind,key)
        if kind in ('normal','dynamic','benign_race','entry_fault_control_before','entry_fault_control_after'):
            assert row['verdict']=='equal' and row['alarm'] is False and row['completion_valid'] is True
        if kind in ('syscall_error','entry_probe_miss','return_probe_pressure'):
            assert row['verdict']=='invalid' and row['alarm'] is None
        if kind=='benign_race':
            assert row['race']['before_delete']['call_observation']['completed_rejected'] > 0
        if kind=='missing_call_telemetry':
            assert row['verdict']=='inconclusive' and row['alarm'] is None
        if kind in ('bad_pair_count','detached_enter','detached_exit'):
            assert row['completion_valid'] is False
            assert row['verdict']==('different' if row['state']=='getdents_substitution' else 'inconclusive')
            assert row['alarm'] is (True if row['state']=='getdents_substitution' else None)
        groups[kind].append(row)
        checked+=1
    for fs in ('ext4','tmpfs'):
        churn=read(folder/f'{fs}_churn.json')
        assert churn['stopped'] is True and not churn['errors']
        assert {'create','rename','delete'} <= {event[1] for event in churn['events']}
    cleanup=read(folder/'cleanup.json')
    assert cleanup['completed'] and cleanup['all_research_modules_absent']
assert len(set(boot_ids))==3
result={'passed':True,'boot_ids':boot_ids,'telemetry_rows_replayed':checked,'controlled_assessments':assessments,
        'benign_race_exercised':sum(bool(r['race']['deleted']) for r in groups['benign_race']),
        'benign_race_unexercised':sum(not r['race']['deleted'] for r in groups['benign_race']),
        'groups':{key:{'n':len(rows),'verdicts':dict(Counter(r['verdict'] for r in rows)),
                       'alarms':sum(r['alarm'] is True for r in rows)} for key,rows in groups.items()}}
(T/'observations/current_regression_verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result),flush=True)
