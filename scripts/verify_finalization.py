"""Replay saved outputs through the new recovery check, without a VM."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT/'scripts'))
from kicba.recovery_validation import validate_recovery
from verify_paper_review_checks import duplicate_cases
from kicba.recovery_validation import finalize_record
from phase2.oracle import identities, transform, difference


def native_confirmation():
    receipt=json.loads((ROOT/'finalization/evidence/native_receipt.json').read_text(encoding='utf-8'))
    path=ROOT/'finalization/evidence'/receipt['archive']
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    checks={'archive_hash':digest==receipt['sha256'], 'archive_bytes':path.stat().st_size==receipt['bytes']}
    with tarfile.open(path) as archive:
        def read(name):return json.load(archive.extractfile(name))
        def rows(name):return [json.loads(line) for line in archive.extractfile(name)]
        prefix=receipt['additional_confirmation']; normal=receipt['normal_confirmation']
        manifest=read(prefix+'/manifest.json')
        checks['tested_source_hashes']=all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==value
            for name,value in manifest['completion_sources'].items())
        checks['frozen_source_hashes']=all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==value
            for name,value in manifest['base_sources_before'].items())
        checks['protocol_hash']=hashlib.sha256((ROOT/'finalization/ADDITIONAL_PROTOCOL_20261101.md').read_bytes()).hexdigest()==manifest['protocol_sha256']
        measured=rows(prefix+'/attempts.jsonl'); failed=[]; controls=0
        for state in ('normal','reorder','insert','grow','shrink','inode','type','remove','getdents_substitution'):
            original=manifest['original']
            if state=='getdents_substitution':
                expected=[dict(row) for row in original]
                for row in expected:
                    name=bytes.fromhex(row['name_hex'])
                    if name.startswith(b'd9_swap_a_'):row['name_hex']=(b'd9_swap_b_'+name[len(b'd9_swap_a_'):]).hex()
            else:expected=transform(original,state)
            up,down=difference(original,expected)
            for size in (256,4096):
                actual=rows(f'{prefix}/control_{state}_{size}.jsonl')
                controls+=1
                if identities(actual)!=identities(expected):failed.append('control:'+state+':'+str(size))
                for repeat in range(2):
                    matches=[r for r in measured if (r['state'],r['buffer'],r['repeat'])==(state,size,repeat)]
                    if len(matches)!=1:failed.append('missing_or_duplicate_attempt');continue
                    r=matches[0];actual=rows(f'{prefix}/measured_{state}_{size}_{repeat}.jsonl')
                    recalculated=finalize_record(r,r['program_coverage'])
                    wanted='different' if up or down else 'equal'
                    passed=(r['returncode']==0 and not r['audit'].get('errors') and not r['audit'].get('skipped')
                        and identities(actual)==identities(expected) and r['upstream_only']==up and r['downstream_only']==down
                        and recalculated['verdict']==wanted and recalculated['alarm']==bool(up or down)
                        and recalculated['recovery_validation']['verified'])
                    if not passed:failed.append(f'{state}:{size}:{repeat}')
        regular=rows(normal+'/attempts.jsonl')
        normal_checks=[]
        for r in regular:
            checked=finalize_record(r,r.get('program_coverage',{}))
            expected='invalid' if r['case']=='small_buffer' else 'equal'
            normal_checks.append(checked['verdict']==expected and checked['alarm']==(None if expected=='invalid' else False))
        losses=rows(prefix+'/loss_attempts.jsonl')
        window=losses[:16]; sequential=losses[16:]
        missed=any(any(event.get('missed_delta',0)>0 for event in r.get('coverage',{}).get('per_event',{}).values()) for r in window)
        checks.update(measured_count=len(measured)==36, exact_output_and_recovery=not failed,
            control_count=controls==18, normal_count=len(regular)==10,
            normal_and_boundary=all(normal_checks), native_return_misses=missed,
            loss_window_count=len(window)==16,
            loss_window_rejected=all(finalize_record(r,r.get('program_coverage',{}))['verdict']=='invalid' for r in window),
            sequential_controls=len(sequential)==2 and all(finalize_record(r,r['program_coverage'])['verdict']=='equal' for r in sequential),
            source_unchanged=read(prefix+'/summary.json')['source_unchanged'] and read(normal+'/summary.json')['source_unchanged'])
    return {'checks':checks,'failures':failed,'archive_sha256':digest,'kernel':manifest['kernel'],
            'boot_id':manifest['boot_id'],'counts':{'measured':len(measured),'differences':28,'consistent':8,
            'unprobed_controls':controls,'normal_boundary_valid':9,'small_buffer_invalid':1,
            'miss_window_invalid':len(window),'sequential_valid':len(sequential)},'passed':all(checks.values())}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    if args.output.exists() and not args.check: raise FileExistsError(args.output)
    counts={'batches':0,'transactions':0,'difference_transactions':0,'recovery_matches':0}
    sources=[]; failures=[]
    for path in sorted((ROOT/'results/d9_formal/raw').glob('boot_*/campaign.json.gz')):
        with gzip.open(path,'rt',encoding='utf-8') as stream: campaign=json.load(stream)
        sources.append({'path':path.relative_to(ROOT).as_posix(),
                        'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        for batch in campaign['batches']:
            counts['batches']+=1
            for tx in batch['transactions']:
                checked=validate_recovery(tx['kernel_fingerprint'],tx['visible_fingerprint'],
                    tx['upstream_only'],tx['downstream_only'],tx['decode_success'],tx['residual_cells'])
                counts['transactions']+=1
                counts['difference_transactions']+=bool(tx['expected_difference'])
                counts['recovery_matches']+=checked['verified']
                if not checked['verified']: failures.append({'source':path.parent.name,'state':batch['state'],'iteration':tx['iteration']})
    fixtures=[]
    for row in duplicate_cases()['cases']:
        checked=validate_recovery(row['upstream_fingerprint'],row['downstream_fingerprint'],[],[],
                                   row['decode_success'],row['residual_cells'])
        fixtures.append({'case':row['case'],'cells':row['cells'],'raw_decode_success':row['decode_success'],
                         'check':checked})
    native=native_confirmation()
    passed=(native['passed'] and len(sources)==9 and counts=={'batches':1296,'transactions':25920,
            'difference_transactions':11520,'recovery_matches':25920}
            and not failures and all(not r['check']['verified'] for r in fixtures))
    result={'scope':'historical offline replay and separately counted completion-version native confirmation','counts':counts,
            'source_archives':sources,'failures':failures,'duplicate_fixtures':fixtures,'native_confirmation':native,'passed':passed}
    if args.check:
        if json.loads(args.output.read_text(encoding='utf-8'))!=result:raise ValueError('saved verification differs from recomputation')
    else:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('x',encoding='utf-8',newline='\n') as stream: json.dump(result,stream,indent=2)
    print(json.dumps({'passed':passed,'counts':counts,'known_counterexamples':len(fixtures)}))
    return 0 if passed else 1


if __name__=='__main__': raise SystemExit(main())
