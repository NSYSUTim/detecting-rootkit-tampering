"""Recompute current-entry confirmation and the separate three-boot comparison."""
import argparse,hashlib,json,statistics,sys,tarfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
for d in (ROOT,ROOT/'src'):sys.path.insert(0,str(d))
from finalization.controlled_cases import STATES,expected,difference,identities
from kicba.reconciliation import MultisetFingerprint,token_for_entry
from phase2.oracle import SEED1,SEED2


def fp(rows):
    result=MultisetFingerprint()
    for name,inode,kind in identities(rows):result.add(token_for_entry(name,inode,kind,SEED1,SEED2))
    return list(result.as_tuple())


def recompute():
    receipt=json.loads((ROOT/'comparison/evidence/RECEIPT.json').read_text(encoding='utf-8'))
    path=ROOT/'comparison/evidence'/receipt['archive']
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    if digest!=receipt['sha256']:raise RuntimeError('archive hash mismatch')
    failures=[];boots=[]
    with tarfile.open(path) as tar:
        def read(name):return json.load(tar.extractfile(name))
        def rows(name):return [json.loads(s) for s in tar.extractfile(name) if s.strip()]
        def source_check(mapping):
            for name,wanted in mapping.items():
                if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=wanted:failures.append('source:'+name)
        prefix='current/entry_confirmation';meta=read(prefix+'/manifest.json');source_check(meta['source_sha256'])
        current=rows(prefix+'/attempts.jsonl');control=read(prefix+'/controls.json')
        for row in current:
            target=expected(meta['original'],row['state'],row['exercised'])
            up,down=difference(meta['original'],target)
            actual=rows(f"{prefix}/measured_{row['state']}_{row['buffer']}_{row['repeat']}.jsonl")
            if not (identities(actual)==identities(target) and row['upstream_only']==up and row['downstream_only']==down
                and row['kernel_fingerprint']==fp(meta['original'])
                and [row['userspace'][k] for k in ('count','sum1','sum2')]==fp(target)
                and row['verdict']==('different' if up or down else 'equal')
                and row['entry_coverage']['valid'] and row['recovery_validation']['verified']):failures.append('entry_attempt')
        for c in control:
            if c['returncode'] or identities(c['rows'])!=identities(expected(meta['original'],c['state'],c['exercised'])):failures.append('entry_control')
        faults=read(prefix+'/faults.json');extras=read(prefix+'/extra.json')
        entry_bad=[r for r in faults if r['kind']=='entry_injected']
        normal=[r for r in faults if r['kind'].startswith('entry_control') or r['kind']=='return_control']
        return_bad=[r for r in faults if r['kind']=='return_injected']
        if len(current)!=72 or len(control)!=24 or len(entry_bad)!=10 or len(normal)!=22 or len(return_bad)!=16:failures.append('entry_denominator')
        if not all(r['verdict']=='invalid' and any(e['missed_delta']>0 for e in r['entry_coverage']['per_event'].values()) for r in entry_bad):failures.append('entry_fault_gate')
        if not all(r['verdict']=='equal' for r in normal):failures.append('normal_quality_controls')
        if not all(r['verdict']=='invalid' for r in return_bad) or not any(any(e['missed_delta']>0 for e in r['coverage']['per_event'].values()) for r in return_bad):failures.append('return_fault_gate')
        if not all(r['verdict']=='different' and r['recovery_verified'] for r in extras if r['kind']=='load_order'):failures.append('load_order')
        if not all(r['verdict']=='different' and not r['recovery_verified'] for r in extras if r['kind']=='overcapacity'):failures.append('small_capacity')
        if not all(r['verdict']==('equal' if r['buffer']==4096 else 'invalid') for r in extras if r['kind']=='boundary'):failures.append('boundary')
        entry_result={'measured':len(current),'actual_differences':sum(r['expected_verdict']=='different' for r in current),
            'unexercised':sum(not r['exercised'] for r in current),'controls':len(control),
            'entry_fault_windows':len(entry_bad),'return_window_scans':len(return_bad),'normal_fault_controls':len(normal),
            'extra_counts':{kind:sum(r['kind']==kind for r in extras) for kind in ('load_order','overcapacity','boundary')}}
        for index in (1,2,3):
            prefix=f'current/comparison_boot_{index:02d}_r2';m=read(prefix+'/manifest.json');source_check(m['sources'])
            observations=rows(prefix+'/functional.jsonl');controls=read(prefix+'/controls.json')
            if len(observations)!=120 or len(controls)!=12:failures.append('comparison_denominator')
            for c in controls:
                if c['returncode'] or identities(c['rows'])!=identities(expected(m['original'],c['state'])):failures.append('comparison_control')
            rates={}
            for method in ('ours','zygarde'):
                selected=[r for r in observations if r['method']==method]
                for row in selected:
                    target=expected(m['original'],row['state']);up,down=difference(m['original'],target)
                    saved=json.load(tar.extractfile(f"{prefix}/{row['state']}_{row['repeat']}_{method}.stdout"))
                    if saved!=row['result']:failures.append('stdout_record_mismatch')
                    if not row['assessment']['valid']:failures.append('incomplete_comparison')
                    if method=='ours' and not (saved.get('upstream_only')==up and saved.get('downstream_only')==down
                        and saved['kernel_fingerprint']==fp(m['original'])
                        and [saved['userspace'][k] for k in ('count','sum1','sum2')]==fp(target)
                        and saved['alarm']==bool(up or down) and saved['recovery_validation']['verified']):failures.append('ours_comparison_recovery')
                common=[r for r in selected if r['common_scope']]
                positive=[r for r in common if r['expected_name_loss']];negative=[r for r in common if not r['expected_name_loss']]
                rates[method]={'positive':len(positive),'detected':sum(r['assessment']['alarm'] is True for r in positive),
                    'negative':len(negative),'false_alerts':sum(r['assessment']['alarm'] is True for r in negative),
                    'identity_only':{s:{'trials':sum(r['state']==s for r in selected),
                        'alerts':sum(r['state']==s and r['assessment']['alarm'] is True for r in selected)} for s in ('insert','inode','type')}}
            adapters=read(prefix+'/adapter.json')
            if not all(r['assessment']['valid'] and all(q['assessment']['alarm']==r['assessment']['alarm'] for q in observations if q['state']==r['state'] and q['method']=='zygarde') for r in adapters):failures.append('adapter_disagrees')
            raw_cost=read(prefix+'/cost.json');costs=[]
            for size in (128,4096,65536):
                ours=sorted([r for r in raw_cost if r['size']==size and r['method']=='ours' and not r['warmup']],key=lambda r:r['repeat'])
                theirs=sorted([r for r in raw_cost if r['size']==size and r['method']=='zygarde_adapter' and not r['warmup']],key=lambda r:r['repeat'])
                if len(ours)!=5 or len(theirs)!=5 or any(not r['valid'] for r in ours+theirs):failures.append('cost_denominator')
                ratios=[a['wall_ns']/b['wall_ns'] for a,b in zip(ours,theirs)]
                audited=rows(f'{prefix}/cost_{size}.audit.jsonl')
                counts=[{'produced':len(r['produced']),'returned':len(r['returned'])} for r in audited]
                costs.append({'size':size,'pairs':len(ratios),'ours_median_ms':statistics.median(r['wall_ns'] for r in ours)/1e6,
                    'zygarde_adapter_median_ms':statistics.median(r['wall_ns'] for r in theirs)/1e6,
                    'paired_ours_over_adapter_median':statistics.median(ratios),
                    'paired_ratio_quartiles':statistics.quantiles(ratios,n=4,method='inclusive')[::2],
                    'ours_maxrss_median_kib':statistics.median(r['maxrss_kib'] for r in ours),
                    'adapter_maxrss_median_kib':statistics.median(r['maxrss_kib'] for r in theirs),
                    'separate_name_count_audit':counts})
            boots.append({'boot_index':index,'boot_id':m['boot_id'],'rates':rates,'costs':costs,'adapter_cases':len(adapters)})
        if len({b['boot_id'] for b in boots})!=3:failures.append('boot_ids_not_distinct')
        repair=read('current/control_repair/results.json');source_check(repair['sources'])
        repair_counts={method:sum(r['method']==method for r in repair['observations']) for method in ('unprobed','ours','zygarde')}
        if repair_counts!={'unprobed':12,'ours':4,'zygarde':4}:failures.append('repair_denominator')
        for row in repair['observations']:
            prefix=b'd8_hidden_' if row['mode']=='hiding' else b'd8_policy_'
            target=[r for r in repair['original'] if not bytes.fromhex(r['name_hex']).startswith(prefix)]
            up,down=difference(repair['original'],target)
            if row['method']=='unprobed':
                valid=row['returncode']==0 and identities(row['rows'])==identities(target)
            elif row['method']=='ours':
                valid=row['verdict']=='different' and row['upstream_only']==up and row['downstream_only']==down and row['recovery_verified']
            else:
                cell=next(c for c in row['result']['results'] if c['cell']=='hidden_file')
                valid=row['returncode']==2 and cell['status']==2 and any(
                    f.get('details',{}).get('directory','').endswith('/control_repair/fixture') for f in cell.get('findings',[]))
            if not valid:failures.append('repair_observation')
        for mode,digest_ko in repair['modules'].items():
            if hashlib.sha256(tar.extractfile('current/comparison/controls/getdents_'+mode+'_fixed.ko').read()).hexdigest()!=digest_ko:failures.append('repair_binary_hash')
        incomplete=rows('current/comparison_boot_01/functional.jsonl')
        failed_control=rows('current/comparison_boot_01/control_getdents_hiding.jsonl')
        incomplete_info={'completed_observations':len(incomplete),'getdents_control_rows':len(failed_control),
            'status':'unfinished original-protocol attempt; excluded from amended confirmation denominators'}
        unit_log=tar.extractfile('entry_pilot_r2/unit_tests.log').read().decode()
        if 'Ran 41 tests' not in unit_log or not unit_log.rstrip().endswith('OK'):failures.append('native_unit_log')
    return {'schema':1,'archive_sha256':digest,'entry_confirmation':entry_result,'comparison_boots':boots,
        'control_repair':{'counts':repair_counts,'verified':not any(s.startswith('repair') for s in failures)},
        'incomplete_original_attempt':incomplete_info,'unit_tests':41,
        'failed_mixed_attempt_separate':True,'historical_denominators_unchanged':True,
        'failures':failures,'passed':not failures}


def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--output',type=Path);g.add_argument('--check',type=Path);args=p.parse_args()
    result=recompute()
    if args.check:
        if json.loads(args.check.read_text(encoding='utf-8'))!=result:raise RuntimeError('saved derived evidence differs')
    else:
        with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2)
    print(json.dumps({'passed':result['passed'],'entry':result['entry_confirmation'],'boots':len(result['comparison_boots']),'failures':result['failures']}))
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
