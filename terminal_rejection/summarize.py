"""Recompute the new rule and retain benign alerts, invalids and unexercised cases."""
import argparse
from collections import Counter,defaultdict
import hashlib,json
from pathlib import Path
import sys,tarfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from kicba.terminal_rejection import finalize_terminal_record
from kicba.reconciliation import token_for_entry,MultisetFingerprint,IBLT
from phase2.oracle import identities,difference,SEED1,SEED2

def read(p):return json.loads(p.read_text(encoding='utf-8'))
def lines(p):return [json.loads(s) for s in p.read_text(encoding='utf-8').splitlines()]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fp(rows):
    tokens=[token_for_entry(n,i,t,SEED1,SEED2) for n,i,t in identities(rows)]
    return list(MultisetFingerprint.from_tokens(tokens).as_tuple()),[list(x) for x in IBLT.from_tokens(tokens,256,SEED1,SEED2).to_rows()]

def verify_record(row,folder):
    if row.get('dump'):assert lines(folder/row['dump'])==row['visible']
    # Replay the added rule over the retained original identity verdict.
    base=dict(row);base['verdict']=row.get('identity_verdict');base['alarm']=row.get('identity_alarm')
    if row.get('kind')=='missing_terminal_telemetry':
        base['measurement_valid']=True
    derived=finalize_terminal_record(base)
    for key in ('verdict','alarm','terminal_rejection','rejected_entry','alarm_reasons'):
        assert derived[key]==row[key],(key,derived[key],row[key])
    if row['verdict']=='invalid':assert row['alarm'] is None;return
    assert row['measurement_valid'] is True
    for gate in ('entry_coverage','coverage','program_coverage'):assert row[gate]['valid']
    actual,_=fp(row['visible']);user=row['userspace']
    assert actual==[user['count'],user['sum1'],user['sum2']]
    assert row['identity_verdict']==('equal' if actual==row['kernel_fingerprint'] else 'different')
    assert row['terminal_rejection']==(row['terminal_observation']['last_accepted']==0)


def archived_source_matches(path, original_digest):
    digest = sha(path)
    if digest == original_digest:
        return True
    manifest = read(ROOT / 'docs/PUBLIC_CLEANUP_20261117.json')
    copies = manifest['public_copies_by_original_sha256']
    return digest in copies.get(original_digest, ())


def summarize(root):
    groups=defaultdict(list);regress=[];dynamics=[];normal=[];races=[];faults=[];boots=[];unexercised=[];source_sets=[]
    count=0
    for index in (1,2,3):
        public=root/f'boot_{index:02d}_public';other=root/f'boot_{index:02d}_regression'
        pm=read(public/'manifest.json');rm=read(other/'manifest.json')
        assert pm['boot_id']==rm['boot_id'] and not pm['pilot'] and not rm['pilot']
        boots.append({'index':index,'boot_id':pm['boot_id']})
        source_sets.append(rm['source_sha256'])
        # The actual deployed sources, not a later host-side preparation package.
        for name,digest in rm['source_sha256'].items():assert archived_source_matches(root/'code'/name, digest)
        original=pm['original'];public_rows=lines(public/'observations.jsonl');assert len(public_rows)==100
        for row in public_rows:
            verify_record(row,public);count+=1
            up,down=difference(original,row['visible']);assert up==row['external_missing'] and down==row['external_extra']
            if row['mode'] in ('normal','getdents64'):
                original_fp,original_table=fp(original)
                assert row['kernel_fingerprint']==original_fp and row['kernel_rows']==original_table
                assert sorted(row['upstream_only'])==up and sorted(row['downstream_only'])==down
            else:
                actual,table=fp(row['visible']);assert actual==row['kernel_fingerprint'] and table==row['kernel_rows']
                witness=row['rejected_entry'];assert witness
                assert any(bytes.fromhex(r['name_hex'])==bytes.fromhex(witness['name_hex']) and r['inode']==witness['inode'] and r['d_type']==witness['d_type'] for r in original)
                assert not any(r['name_hex']==witness['name_hex'] for r in row['visible'])
            groups[row['mode'],row['attachment_order']].append(row)
        controls=lines(public/'controls.jsonl');assert len(controls)==34
        for row in controls:
            assert lines(public/row['dump'])==row['rows'];count+=1
            if 'restored' in row['tag'] or 'normal' in row['tag'] or 'unloaded' in row['tag']:
                assert row['matches_manifest'] and row['returncode']==0
        rows=lines(other/'observations.jsonl')
        scans=[r for r in rows if r['kind']!='assessment'];assert len(scans)==454,len(scans)
        assessments={r['scan_dump']:r for r in rows if r['kind']=='assessment'};assert len(assessments)==320
        for row in scans:
            verify_record(row,other);count+=1
            if row['kind']=='regression':
                assessment=assessments[row['dump']]
                assert all(assessment[k] for k in ('output_match','identity_match','recovery_match'))
                assert sorted(row['upstream_only'])==assessment['expected_upstream']
                assert sorted(row['downstream_only'])==assessment['expected_downstream']
                regress.append(row)
                if not assessment['mutation_exercised']:unexercised.append({'boot':index,'state':row['state'],'buffer':row['buffer']})
            elif row['kind']=='normal':
                normal.append(row);oracle=read(other/(row['fs']+'_normal_manifest.json'))
                assert identities(row['visible'])==identities(oracle)
            elif row['kind']=='dynamic':
                churn=read(other/(row['fs']+'_churn.json'));assert churn['stopped'] and not churn['errors']
                user=row.get('userspace',{});start=user.get('scan_started_ns',0);end=user.get('scan_finished_ns',0)
                row['churn_overlap']=dict(Counter(op for t,op in churn['events'] if start<=t<=end))
                actual,table=fp(row['visible']);assert actual==row['kernel_fingerprint'] and table==row['kernel_rows']
                dynamics.append(row)
            elif row['kind']=='benign_race':
                prior=row['race']['before_delete'];assert prior['terminal_observation']['last_accepted']==0
                assert row['identity_verdict']=='equal';races.append(row)
            else:faults.append(row)
        for folder in (public,other):assert read(folder/'cleanup.json').get('completed',True)
        assert read(public/'cleanup.json')['module_absent'] and read(public/'cleanup.json')['manifest_restored']
        assert read(other/'cleanup.json')['modules_absent']
    assert len({b['boot_id'] for b in boots})==3
    assert all(s==source_sets[0] for s in source_sets)
    for name in ('src/kicba/terminal_rejection.py','terminal_rejection/measurement.py','terminal_rejection/bpf.c','terminal_rejection/run_regression.py'):
        assert sha(ROOT/name)==sha(root/'code'/name)
    def stats(rows):
        return {'n':len(rows),'verdicts':dict(Counter(r['verdict'] for r in rows)),
                'identity_alarms':sum(r.get('identity_alarm') is True for r in rows),
                'terminal_alerts':sum(r.get('terminal_rejection') is True for r in rows),
                'alarms':sum(r.get('alarm') is True for r in rows),
                'verified_recovery':sum(r.get('recovery_verified') is True for r in rows)}
    return {'verified':True,'boots':boots,'recomputed_observations_and_controls':count,
        'public_sample':[dict(mode=m,order=o,**stats(v)) for (m,o),v in groups.items()],
        'regression':stats(regress),'unexercised_attempts':len(unexercised),
        'unexercised_conditions':dict(Counter(r['state']+'/'+str(r['buffer']) for r in unexercised)),
        'normal':stats(normal),'dynamic':stats(dynamics),
        'dynamic_all_three_operations_overlap':sum(all(r['churn_overlap'].get(k,0)>0 for k in ('create','rename','delete')) for r in dynamics),
        'benign_race':{fs:stats([r for r in races if r['fs']==fs]) for fs in ('ext4','tmpfs')},
        'faults':{k:stats([r for r in faults if r['kind']==k]) for k in ('syscall_error','missing_terminal_telemetry')},
        'state_value_bytes':sorted({r['state_value_bytes'] for r in regress}),
        'pilots_excluded':True,'historical_results_relabelled_as_new_version':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--extract-to',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.extract_to.mkdir(parents=True,exist_ok=True)
    def data_filter(member,destination):
        # Empty fixture files are not evidence inputs. Avoid Windows MAX_PATH
        # for the intentionally 255-byte filename in the real syscall-error test.
        if member.isfile() and member.size==0 and len(member.name.rsplit('/',1)[-1])>200:return None
        return tarfile.data_filter(member,destination)
    with tarfile.open(a.archive) as bundle:bundle.extractall(a.extract_to,filter=data_filter)
    result=summarize(a.extract_to/'terminal_rejection_20261103');result['archive_sha256']=sha(a.archive)
    a.output.write_text(json.dumps(result,indent=2),encoding='utf-8',newline='\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
