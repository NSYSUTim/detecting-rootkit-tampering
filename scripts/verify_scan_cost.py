"""Recompute matched ready-to-verdict timings and exact observation coverage."""
import argparse,gzip,hashlib,io,json,random,statistics,sys,tarfile
from collections import Counter
from pathlib import Path,PurePosixPath

ROOT=Path(__file__).resolve().parents[1]
for p in (ROOT,ROOT/'src'):sys.path.insert(0,str(p))
from comparison.scan_cost.run import METHODS,CANARY,assess,fingerprint
from finalization.controlled_cases import expected,identities
from finalization.compare_zygarde import zygarde_target


def distribution(values):
    if not values:return None
    q=statistics.quantiles(values,n=4,method='inclusive') if len(values)>1 else [values[0]]*3
    return {'n':len(values),'median':statistics.median(values),'q1':q[0],'q3':q[2],'min':min(values),'max':max(values)}


def assess_normal(row,method,wanted_fp,wanted_names,metrics):
    """Independently audit normal scans without rehashing each full input twice."""
    if method=='ours':
        result=row['result'];elapsed=result.get('benchmark',{}).get('scan_to_verdict_ns')
        complete=(row['returncode']==0 and result.get('verdict')=='equal'
            and result.get('recovery_validation',{}).get('verified') is True
            and result.get('upstream_only')==[] and result.get('downstream_only')==[]
            and result.get('kernel_fingerprint')==wanted_fp
            and [result.get('userspace',{}).get(k) for k in ('count','sum1','sum2')]==wanted_fp)
        return {'execution_valid':row['returncode']==0,'complete':complete,'correct':complete,
            'scan_to_verdict_ns':elapsed,'eligible':complete and type(elapsed)is int and elapsed>0}
    views=metrics.get('views') or [];elapsed=metrics.get('scan_to_verdict_ns')
    fixture=PurePosixPath(views[0]['directory']) if views else PurePosixPath('/no-view')
    decision=zygarde_target(row,fixture)
    complete=bool(views) and all(set(v['produced'])==wanted_names and set(v['returned'])==wanted_names for v in views)
    correct=decision['valid'] and decision['alarm'] is False
    return {'execution_valid':decision['valid'],'correct':correct,'complete':complete,
        'scan_to_verdict_ns':elapsed,'eligible':correct and complete and type(elapsed)is int and elapsed>0,
        'view_counts':[{'produced':len(v['produced']),'returned':len(v['returned'])} for v in views],
        'ring_bytes':metrics.get('ring_bytes'),
        'canary_present_each_view':all(v['produced'].get(CANARY) and v['returned'].get(CANARY) for v in views)}


def recompute():
    receipt=json.loads((ROOT/'comparison/scan_cost/RECEIPT.json').read_text())
    archive=ROOT/'comparison/scan_cost'/receipt['archive']
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=receipt['sha256']:raise RuntimeError('archive hash mismatch')
    failures=[];boots=[];manifest_hashes=[];total=Counter()
    # Decode once: random member reads on a gzip stream otherwise repeatedly
    # decompress all preceding observations. Nothing is extracted to disk.
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(archive.read_bytes())),mode='r:') as tar:
        def read(n):return json.load(tar.extractfile(n))
        def rows(n):return [json.loads(line) for line in tar.extractfile(n) if line.strip()]
        def check_sources(meta,prefix):
            for n,digest in meta['sources'].items():
                if hashlib.sha256((ROOT/n).read_bytes()).hexdigest()!=digest:failures.append(prefix+':source:'+n)
        final_build=json.loads((ROOT/'comparison/scan_cost/BUILD.json').read_text())
        p='pilot_03';meta=read(p+'/manifest.json');check_sources(meta,p)
        original=read(p+'/fixture.json');pilot=read(p+'/observations.json');controls=read(p+'/controls.json')
        if len(pilot)!=36 or len(controls)!=12:failures.append('pilot_denominator')
        for row in pilot:
            tag=row['state']+'_'+row['method'];raw=read(p+'/'+tag+'.stdout')
            metrics=read(p+'/'+tag+'.scan.json') if row['method']!='ours' else None
            fixture=(PurePosixPath(row['command'][2]) if row['method']=='ours' else
                PurePosixPath(next((v['directory'] for v in (metrics or {}).get('views',[])),'/no-view')))
            derived=assess(row,row['method'],fixture,original,expected(original,row['state']),metrics)
            # The source fixture path is explicitly recorded in each Go view.
            # Ours does not use this path for the assessment.
            if raw!=row['result'] or derived!=row['assessment'] or not derived['eligible']:failures.append('pilot_observation')
        if not all(c['returncode']==0 and identities(c['rows'])==identities(expected(original,c['state'])) for c in controls):failures.append('pilot_control')
        pilot_info={'final_observations':len(pilot),'final_controls':len(controls),'final_passed':not any(f.startswith('pilot') for f in failures),
            'retained_first_summary':read('pilot_01/summary.json'),'retained_second_summary':read('pilot_02/summary.json')}
        for package in ('core','file'):
            log=tar.extractfile(package+'_tests.log').read().decode()
            if not log.rstrip().endswith('PASS'):failures.append('go_tests:'+package)
        for index in (1,2,3):
            prefix=f'boot_{index:02d}';meta=read(prefix+'/manifest.json');check_sources(meta,prefix)
            if meta['adapter_sha256']!=final_build['binary_sha256']:failures.append('binary_identity')
            env=meta['environment']
            if env['kernel']!='6.8.0-138-generic':failures.append('kernel_changed')
            manifest_hashes.append(env['package_inventory_sha256'])
            observations=rows(prefix+'/observations.jsonl')
            if len(observations)!=54:failures.append('denominator:'+prefix)
            keys=Counter((r['size'],r['repeat'],r['method']) for r in observations)
            if set(keys)!={(s,r,m) for s in (128,4096,65536) for r in range(6) for m in METHODS} or set(keys.values())!={1}:failures.append('observation_identity')
            rng=random.Random(meta['random_seed'])
            for size in (128,4096,65536):
                for repeat in range(6):
                    order=list(METHODS);rng.shuffle(order)
                    group=[r for r in observations if r['size']==size and r['repeat']==repeat]
                    if [r['method'] for r in group]!=order or [r['position'] for r in group]!=[0,1,2]:failures.append('randomized_order')
            output=[]
            for size in (128,4096,65536):
                fixture=read(f'{prefix}/fixture_{size}.json');after=read(f'{prefix}/fixture_{size}_after.json')
                if identities(fixture)!=identities(after) or len(fixture)!=size+3:failures.append('fixture_changed')
                wanted_fp=fingerprint(fixture)
                wanted_names={bytes.fromhex(r['name_hex']).decode() for r in fixture if bytes.fromhex(r['name_hex']) not in (b'.',b'..')}
                selected=[r for r in observations if r['size']==size]
                samples={m:[] for m in METHODS};raw_samples={m:[] for m in METHODS}
                all_counts={m:[] for m in METHODS};eligibility={}
                for row in selected:
                    tag=f"size_{size}_repeat_{row['repeat']}_{row['method']}";result=read(prefix+'/'+tag+'.stdout')
                    if result!=row['result']:failures.append('raw_stdout_mismatch')
                    metrics=read(prefix+'/'+tag+'.scan.json') if row['method']!='ours' else None
                    if row['method']=='ours':
                        derived=assess_normal(row,'ours',wanted_fp,wanted_names,None)
                        if result.get('kernel_fingerprint')!=wanted_fp:failures.append('independent_fingerprint')
                        if not all(result.get(key,{}).get('valid') is True for key in ('coverage','entry_coverage','program_coverage')):failures.append('required_quality_gate')
                    else:
                        views=metrics.get('views') or []
                        derived=assess_normal(row,row['method'],wanted_fp,wanted_names,metrics)
                        if metrics['scan_to_verdict_ns']!=metrics['scan_ns']+metrics['decision_postprocess_ns']:failures.append('timing_sum')
                        want_capacity=4194304 if row['method']=='zygarde_4m' else 33554432
                        if metrics.get('ring_bytes')!=want_capacity:failures.append('ring_configuration')
                    if derived!=row['assessment'] or not row['fixture_unchanged']:failures.append('assessment_mismatch')
                    elapsed=derived['scan_to_verdict_ns']
                    if type(elapsed)is not int or not 0<elapsed<row['wall_ns']:failures.append('timing_bounds')
                    if not row['warmup']:
                        key=(row['repeat'],row['method']);eligibility[key]=derived['eligible']
                        if derived['eligible']:samples[row['method']].append(derived['scan_to_verdict_ns']/1e6)
                        raw_samples[row['method']].append(derived['scan_to_verdict_ns']/1e6)
                        details={k:derived.get(k) for k in ('complete','correct','view_counts','canary_present_each_view')}
                        details['cell_statuses']=[c['status'] for c in result.get('results',[])]
                        details['unobserved_canaries']=sum(not c['observed'] for cell in result.get('results',[]) for c in cell.get('canaries',[]))
                        all_counts[row['method']].append(details)
                        total['main']+=1;total['eligible']+=derived['eligible']
                    else:total['warmup']+=1
                comparisons={}
                for method in ('zygarde_4m','zygarde_32m'):
                    ratios=[]
                    for repeat in range(1,6):
                        by={r['method']:r for r in selected if r['repeat']==repeat}
                        if eligibility[repeat,'ours'] and eligibility[repeat,method]:
                            ratios.append(by['ours']['assessment']['scan_to_verdict_ns']/by[method]['assessment']['scan_to_verdict_ns'])
                    comparisons[method]=distribution(ratios)
                output.append({'size':size,'milliseconds':{m:distribution(samples[m]) for m in METHODS},
                    'all_recorded_milliseconds_not_necessarily_complete':{m:distribution(raw_samples[m]) for m in METHODS},
                    'eligible_pairs_ours_over_baseline':comparisons,'completeness':all_counts})
            boots.append({'boot_index':index,'boot_id':env['boot_id'],'conditions':output})
        if len({b['boot_id'] for b in boots})!=3 or len(set(manifest_hashes))!=1:failures.append('boot_or_packages')
        if total['main']!=135 or total['warmup']!=27:failures.append('total_denominator')
    return {'schema':1,'archive_sha256':receipt['sha256'],'pilot':pilot_info,'boots':boots,'totals':dict(total),
        'main_paired_blocks':45,'algorithm_not_rewritten':True,'historical_results_unchanged':True,
        'all_timed_results_same_algorithmic_features':False,
        'scope':'ready observation to verdict including each method required checks; actual implementations, not pure algorithm speed',
        'failures':failures,'passed':not failures}


def main():
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--output',type=Path);g.add_argument('--check',type=Path);args=p.parse_args();result=recompute()
    if args.check:
        if json.loads(args.check.read_text())!=result:raise RuntimeError('saved results differ')
    else:
        with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(result,f,indent=2)
    print(json.dumps({'passed':result['passed'],'totals':result['totals'],'failures':result['failures']}))
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
