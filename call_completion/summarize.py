"""Independently check native oracles, replay verdicts, and retain all failures."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import statistics
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from kicba.call_completion import finalize_call_record
from kicba.reconciliation import token_for_entry, MultisetFingerprint, IBLT
from kicba.recovery_validation import finalize_record
from finalization.tracefs_measurement import CompleteMeasurement
from finalization.controlled_cases import expected as expected_entries
from phase2.oracle import identities, difference, SEED1, SEED2


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def lines(path):return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint(rows):
    tokens=[token_for_entry(n,i,t,SEED1,SEED2) for n,i,t in identities(rows)]
    return list(MultisetFingerprint.from_tokens(tokens).as_tuple()),[list(r) for r in IBLT.from_tokens(tokens,256,SEED1,SEED2).to_rows()]


def verify_row(row,folder):
    if row.get('dump'):assert lines(folder/row['dump'])==row['visible']
    # Replay retained quality/recovery gates before the newly added branch.
    original=dict(row,verdict=row['identity_verdict'],alarm=row['identity_alarm'])
    verify_identity(original)
    replay=finalize_call_record(original)
    for field in ('verdict','alarm','completion_valid','completion_anomaly','rejected_entry','alarm_reasons'):
        assert replay[field]==row[field],(field,replay[field],row[field])
    if row['identity_verdict']=='invalid':
        assert row['verdict']=='invalid' and row['alarm'] is None
        return
    for gate in ('entry_coverage','coverage','program_coverage'):assert row[gate]['valid']
    actual,_=fingerprint(row['visible']) if 'visible' in row else (None,None)
    if actual is not None:
        assert actual==[row['userspace'][n] for n in ('count','sum1','sum2')]
        assert row['identity_verdict']==('equal' if actual==row['kernel_fingerprint'] else 'different')
    if row['completion_valid']:
        c=row['call_observation'];s=row['kernel_stats']
        assert row['call_coverage']['valid']
        assert c['enters']==c['exits']==row['userspace']['syscalls']
        assert c['last_return']==0 and c['zero_calls']==1 and c['negative_calls']==0
        assert not any(c[n] for n in ('active','pair_errors','outside_entries','outside_returns'))
        assert [c[n] for n in ('completed_entries','completed_accepted','completed_rejected')]==[s[n] for n in ('outer_entries','accepted_entries','rejected_entries')]
        assert c['last_entries']==c['last_accepted']+c['last_rejected']
        anomaly=c['last_entries']>0 and c['last_rejected']==c['last_entries']
        assert row['completion_anomaly'] is anomaly
    else:
        assert row['verdict']==('different' if row['identity_alarm'] else 'inconclusive')


def verify_identity(row):
    original=finalize_record(row,row.get('program_coverage'))
    original=CompleteMeasurement._apply(original,row.get('entry_coverage',{}))
    for name in ('verdict','alarm','recovery_verified','recovery_status'):
        assert original[name]==row[name],('original gate mismatch',name,original[name],row[name])
    if row['verdict']!='invalid':
        for gate in ('entry_coverage','coverage'):
            quality=row[gate]
            assert quality['available'] and quality['valid'] and not quality['reasons']
            assert quality['per_event']
            for event in quality['per_event'].values():assert event['missed_delta']==0
        quality=row['program_coverage']
        assert quality['available'] and quality['valid'] and not quality['reasons']
        assert set(quality['per_program'])=={'packed_enter','packed_return'}
        for program in quality['per_program'].values():
            assert program['recursion_misses_delta']==0
            assert program['program_id_before']==program['program_id_after']
            assert program['prog_tag_before']==program['prog_tag_after']


def check_sources(manifest,root):
    normalized={}
    for name,digest in manifest['source_sha256'].items():
        if name.startswith('/'):
            prefix='/home/kicba/call_completion_20261103/deployments/r4/'
            assert name.startswith(prefix),name
            name=name[len(prefix):]
        assert '..' not in name.split('/')
        assert sha(root/'code'/name)==digest,name
        assert sha(ROOT/name)==digest,('current source differs from confirmed source',name)
        normalized[name]=digest
    return normalized


def stats(rows):
    return {'n':len(rows),'verdicts':dict(Counter(r['verdict'] for r in rows)),
            'identity_alarms':sum(r.get('identity_alarm') is True for r in rows),
            'completion_alerts':sum(r.get('completion_anomaly') is True for r in rows),
            'completion_valid':sum(r.get('completion_valid') is True for r in rows),
            'alarms':sum(r.get('alarm') is True for r in rows),
            'verified_recovery':sum(r.get('recovery_verified') is True for r in rows)}


def summarize(root):
    public_groups=defaultdict(list);by_kind=defaultdict(list);tools=defaultdict(list)
    boots=[];sources=[];unexercised=[];costs=[];sample_count=control_count=tool_count=0;cost_warmups=0
    reporting_errors=[]
    dynamic_overlap=[]
    states=('normal','reorder','insert','grow','shrink','inode','type','remove','filldir_hiding',
            'getdents_hiding','policy_filter','getdents_substitution','filldir_pass','filldir_active','getdents_pass','getdents_active')
    for index in (1,2,3):
        public=root/f'boot_{index:02d}_public';other=root/f'boot_{index:02d}_regression';cost=root/f'boot_{index:02d}_cost'
        pm,rm,cm=(read(p/'manifest.json') for p in (public,other,cost))
        assert pm['boot_id']==rm['boot_id']==cm['boot_id'] and not any(m['pilot'] for m in (pm,rm,cm))
        boots.append({'index':index,'boot_id':pm['boot_id']})
        sources.append([check_sources(m,root) for m in (pm,rm,cm)])
        assert pm['module_sha256']=={'getdents64':'cc2684f690776b578e1e6f136901faf7632b87b5a5ea556735d55e95a2931618',
                                     'filldir':'63ca0aca328391129cf49182733f829f39db1602adefcdafb4d0d798df1d5099'}
        original=pm['original'];observations=lines(public/'observations.jsonl');assert len(observations)==100
        public_conditions={('normal','no_rootkit',b):10 for b in (128,65536)}
        public_conditions.update({(m,o,b):10 for m in ('getdents64','filldir') for o in ('rootkit_first','detector_first') for b in (128,65536)})
        assert Counter((r['mode'],r['attachment_order'],r['buffer']) for r in observations)==public_conditions
        assert len({r['dump'] for r in observations})==100
        original_fp,original_table=fingerprint(original)
        for row in observations:
            verify_row(row,public);sample_count+=1
            up,down=difference(original,row['visible'])
            assert up==row['external_missing'] and down==row['external_extra']
            if row['mode'] in ('normal','getdents64'):
                assert row['kernel_fingerprint']==original_fp and row['kernel_rows']==original_table
                assert sorted(row['upstream_only'])==up and sorted(row['downstream_only'])==down
                assert row['completion_valid'] and not row['completion_anomaly']
                if row['mode']=='normal':assert row['verdict']=='equal' and row['alarm'] is False
                else:assert row['verdict']=='different' and row['alarm'] is True and row['recovery_verified']
            else:
                actual,table=fingerprint(row['visible']);assert actual==row['kernel_fingerprint'] and table==row['kernel_rows']
                assert row['verdict']=='completion_anomaly' and row['identity_verdict']=='equal'
                assert row['completion_valid'] and row['completion_anomaly']
                witness=row['rejected_entry'];assert witness
                assert any(r['name_hex']==witness['name_hex'] and r['inode']==witness['inode'] and r['d_type']==witness['d_type'] for r in original)
                assert not any(r['name_hex']==witness['name_hex'] for r in row['visible'])
                assert len(up)==68 and not down and row['total_missing_count'] is None
                assert not row['upstream_only'] and not row['downstream_only']
            public_groups[row['mode'],row['attachment_order']].append(row)
        controls=lines(public/'controls.jsonl');assert len(controls)==34
        for row in controls:
            assert lines(public/row['dump'])==row['rows'];control_count+=1
            if any(word in row['tag'] for word in ('restored','normal','unloaded')):
                assert row['matches_manifest'] and row['returncode']==0
        tool_rows=lines(public/'zygarde.jsonl');assert len(tool_rows)==15
        for row in tool_rows:
            views=row['metrics'][0]['views']
            missing=set.intersection(*(set(v['produced'])-set(v['returned']) for v in views))
            found={Path(f['details']['path']).name for f in row['assessment']['target_findings']}
            assert missing==found;tools[row['mode']].append(row);tool_count+=1
        rows=lines(other/'observations.jsonl');assessments={r['scan_dump']:r for r in rows if r['kind']=='assessment'}
        churn_cache={fs:read(other/(fs+'_churn.json')) for fs in ('ext4','tmpfs')}
        scans=[r for r in rows if r['kind']!='assessment'];assert len(scans)==479,len(scans)
        regress=[r for r in scans if r['kind']=='regression']
        assert Counter((r['state'],r['buffer']) for r in regress)=={(s,b):5 for s in states for b in (128,256,4096,65536)}
        assert len({(r['state'],r['buffer'],r['repeat']) for r in regress})==320 and len(assessments)==320
        assert len({r['dump'] for r in scans if 'dump' in r})==463
        for kind,repeats in (('normal',5),('dynamic',10)):
            subset=[r for r in scans if r['kind']==kind]
            assert Counter((r['fs'],r['buffer']) for r in subset)=={(fs,b):repeats for fs in ('ext4','tmpfs') for b in (128,256,4096,65536)}
            assert len({(r['fs'],r['buffer'],r['repeat']) for r in subset})==len(subset)
        assert Counter(r['fs'] for r in scans if r['kind']=='benign_race')=={'ext4':5,'tmpfs':5}
        for kind in ('syscall_error','missing_call_telemetry'):
            assert Counter(r['fs'] for r in scans if r['kind']==kind)=={'ext4':1,'tmpfs':1}
        for kind in ('bad_pair_count','detached_enter','detached_exit'):
            assert Counter(r['state'] for r in scans if r['kind']==kind)=={'normal':1,'getdents_substitution':1}
        for row in scans:
            verify_row(row,other);by_kind[row['kind']].append(row)
            if row['kind']=='regression':
                a=assessments[row['dump']]
                assert all(a[k] for k in ('output_match','identity_match','recovery_match'))
                original_static=read(other/'static_manifest.json')
                injected=row['state'] not in ('insert','grow','shrink','inode','type','remove','reorder') or a['changes'].get('changed',0)>0
                assert a['mutation_exercised'] is injected
                target=original_static if row['state'].endswith(('_pass','_active')) else expected_entries(original_static,row['state'],injected)
                assert identities(row['visible'])==identities(target)
                # Reconstruct the expected difference again from actual capture and the static manifest.
                expected_up,expected_down=difference(read(other/'static_manifest.json'),row['visible'])
                assert expected_up==a['expected_upstream'] and expected_down==a['expected_downstream']
                assert sorted(row['upstream_only'])==expected_up and sorted(row['downstream_only'])==expected_down
                assert row['completion_valid'] and not row['completion_anomaly']
                if expected_up or expected_down:assert row['alarm'] and row['recovery_verified']
                else:assert row['alarm'] is False
                if not a['mutation_exercised']:unexercised.append({'boot':index,'state':row['state'],'buffer':row['buffer']})
            elif row['kind'] in ('normal','dynamic','benign_race','entry_fault_control_before','entry_fault_control_after'):
                assert row['verdict']=='equal' and row['alarm'] is False and row['completion_valid']
                if row['kind']=='normal':assert identities(row['visible'])==identities(read(other/(row['fs']+'_normal_manifest.json')))
                if row['kind']=='dynamic':
                    churn=churn_cache[row['fs']];assert churn['stopped'] and not churn['errors']
                    start,end=(row['userspace'][n] for n in ('scan_started_ns','scan_finished_ns'))
                    overlap=Counter(op for t,op in churn['events'] if start<=t<=end)
                    dynamic_overlap.append(dict(boot=index,fs=row['fs'],buffer=row['buffer'],repeat=row['repeat'],
                        all_three=all(overlap[n]>0 for n in ('create','rename','delete')),events=dict(overlap)))
                    actual,table=fingerprint(row['visible']);assert actual==row['kernel_fingerprint'] and table==row['kernel_rows']
                if row['kind']=='benign_race':
                    assert row['race']['deleted']==[b'candidate'.hex()]
                    prior=row['race']['before_delete']['call_observation']
                    assert prior['last_rejected']>=1 and prior['last_return']>0
                    assert row['call_observation']['last_rejected']==0
            elif row['kind'] in ('syscall_error','entry_probe_miss','return_probe_pressure'):
                assert row['verdict']=='invalid' and row['alarm'] is None
                if row['kind']=='entry_probe_miss':assert any(v['missed_delta']>0 for v in row['entry_coverage']['per_event'].values())
                if row['kind']=='return_probe_pressure':assert row['coverage']['available'] and not row['coverage']['valid']
            else:
                assert not row['completion_valid'] and not row['completion_anomaly']
                if row.get('state')=='getdents_substitution':
                    assert row['verdict']=='different' and row['alarm'] and row['recovery_verified']
                else:assert row['verdict']=='inconclusive' and row['alarm'] is None
        for folder in (public,other,cost):assert read(folder/'cleanup.json').get('completed',True)
        for folder in (public,other,cost):
            if (folder/'failure.json').exists():
                failure=read(folder/'failure.json')
                assert index==3 and folder==other and failure['error']=="BrokenPipeError(32, 'Broken pipe')"
                recovery=read(root/'TRANSPORT_RECOVERY.json')
                assert recovery['boot_id']==pm['boot_id'] and recovery['rows']==799 and recovery['assessments']==320
                assert recovery['cleanup']==read(other/'cleanup.json') and recovery['failure']==failure
                reporting_errors.append(dict(boot=index,stage='regression completion report',error=failure['error'],
                                             complete_measurements_retained=True,regression_rerun=False))
        assert read(public/'cleanup.json')['module_absent'] and read(public/'cleanup.json')['manifest_restored']
        assert read(other/'cleanup.json')['modules_absent'] and read(other/'cleanup.json')['all_research_modules_absent']
        assert read(cost/'cleanup.json')['research_modules_absent']
        cr=lines(cost/'observations.jsonl');assert len(cr)==36
        assert Counter((r['size'],r['version'],r['block']) for r in cr)=={
            (size,version,block):1 for size in (128,4096,65536) for version in ('accepted_only','call_completion') for block in range(-1,5)}
        for row in cr:
            if row['version']=='call_completion':verify_row(row,cost)
            else:verify_identity(row)
            assert row['verdict']=='equal' and row['alarm'] is False
            assert row['userspace']['count']==row['size']+2
            for gate in ('entry_coverage','coverage','program_coverage'):assert row[gate]['valid']
            if row['version']=='call_completion':assert row['completion_valid']
            if row['warmup']:cost_warmups+=1
        for size in (128,4096,65536):
            pairs=[]
            for block in range(5):
                values={r['version']:r['paired_ready_ns'] for r in cr if r['size']==size and r['block']==block}
                assert len(values)==2
                pairs.append((values['accepted_only'],values['call_completion']))
            ratios=[b/a for a,b in pairs]
            costs.append(dict(boot=index,size=size,paired_blocks=5,
                accepted_only_median_ms=statistics.median(a for a,b in pairs)/1e6,
                call_completion_median_ms=statistics.median(b for a,b in pairs)/1e6,
                paired_ratio_median=statistics.median(ratios),paired_ratio_min=min(ratios),paired_ratio_max=max(ratios)))
    assert len({b['boot_id'] for b in boots})==3 and all(s==sources[0] for s in sources)
    assert len(unexercised)==45
    native_scans=sample_count+sum(len(r) for r in by_kind.values())
    return {'verified':True,'boots':boots,'native_functional_scans':native_scans,
        'independent_controls':control_count,'zygarde_observations':tool_count,
        'functional_observations_and_controls':native_scans+control_count+tool_count,
        'cost_observations':90,'cost_warmups_excluded':cost_warmups,'cost_pairs':45,
        'public_sample':[dict(mode=m,order=o,**stats(rows)) for (m,o),rows in public_groups.items()],
        'regression':stats(by_kind['regression']),'unexercised_attempts':len(unexercised),
        'unexercised_conditions':dict(Counter(r['state']+'/'+str(r['buffer']) for r in unexercised)),
        'normal':stats(by_kind['normal']),'dynamic':stats(by_kind['dynamic']),
        'dynamic_all_three_operations_overlap':sum(r['all_three'] for r in dynamic_overlap),
        'dynamic_without_confirmed_overlap':[r for r in dynamic_overlap if not r['all_three']],
        'benign_race':{fs:stats([r for r in by_kind['benign_race'] if r['fs']==fs]) for fs in ('ext4','tmpfs')},
        'faults':{kind:stats(rows) for kind,rows in by_kind.items() if kind not in ('regression','normal','dynamic','benign_race')},
        'zygarde':{mode:{'n':len(rows),'target_alerts':sum(r['assessment']['alarm'] for r in rows),
                          'quality_warnings':sum(bool(r['assessment']['other_findings']) for r in rows)} for mode,rows in tools.items()},
        'state_value_bytes':sorted({r['state_value_bytes'] for r in by_kind['regression']}),
        'paired_cost':costs,'actual_source_constant_across_boots':True,'pilots_excluded':True,
        'reporting_errors_retained':reporting_errors,
        'historical_results_relabelled_as_new_version':False}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--archive',required=True,type=Path)
    parser.add_argument('--extract-to',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();args.extract_to.mkdir(parents=True,exist_ok=True)
    def data_filter(member,destination):
        if member.isfile() and member.size==0 and len(member.name.rsplit('/',1)[-1])>200:return None
        return tarfile.data_filter(member,destination)
    with tarfile.open(args.archive) as archive:archive.extractall(args.extract_to,filter=data_filter)
    facts=summarize(args.extract_to/'call_completion_20261103');facts['archive_sha256']=sha(args.archive)
    args.output.write_text(json.dumps(facts,indent=2),encoding='utf-8',newline='\n')
    with args.output.with_name('paired_cost.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(facts['paired_cost'][0]),lineterminator='\n');writer.writeheader();writer.writerows(facts['paired_cost'])
    print(json.dumps(facts,indent=2))


if __name__=='__main__':main()
