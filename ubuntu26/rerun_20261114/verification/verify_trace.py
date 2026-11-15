"""Verify the completed timing dataset and reproduce all report statistics."""
from collections import Counter,defaultdict
import csv,gzip,hashlib,importlib.util,json,math,subprocess,sys
from pathlib import Path
T=Path(__file__).resolve().parents[1]
_project_parent=next(parent for parent in T.parents if (parent/'scan_directory.py').is_file() or (parent/'kicba-thesis-artifact/scan_directory.py').is_file())
_project_root=_project_parent if (_project_parent/'scan_directory.py').is_file() else _project_parent/'kicba-thesis-artifact'
R=_project_root
O=T/'observations';D=O/'trace_of_times';S=O/'trace_sources'
BASE=R/'tools/external_baselines/trace_of_times_d9'
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def rows(p):
    with p.open(encoding='utf-8',newline='') as f:return list(csv.DictReader(f))
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def close(a,b):assert math.isclose(float(a),float(b),rel_tol=1e-6,abs_tol=1e-8),(a,b)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

before=read(D/'collection_environment.json');after=read(D/'collection_environment_after.json')
assert all(after[k] for k in ('same_kernel','same_boot','same_packages'))
for key in ('kernel','boot_id','package_inventory_sha256','python'):assert before['environment'][key]==after['environment'][key]
assert before['environment']['kernel']=='7.0.0-43-generic'
source_hashes={p.name:digest(p) for p in S.iterdir() if p.is_file()}
assert source_hashes==before['sources']
original=read(D/'collection_validation.json')
assert original['status']=='valid' and original['records']==1250
matrix=load('trace_matrix_protocol',S/'run_matrix.py')
collection=[json.loads(s) for s in (D/'collection.jsonl').read_text(encoding='utf-8').splitlines() if s]
name_map=read(O/'trace_event_filename_map.json')
assert len(collection)==len(name_map)==1250 and set(name_map)=={r['file'] for r in collection}
assert set(name_map.values())=={p.name for p in (O/'trace_events').glob('*.json.gz')}
group_counts=Counter()
indices=defaultdict(list)
event_count=0
for record in collection:
    assert record['command']==matrix.batch_args(record['scenario'],record['label'],record['index'],42,100)
    path=O/'trace_events'/name_map[record['file']]
    assert digest(path)==record['sha256']
    with gzip.open(path,'rt',encoding='utf-8') as stream:payload=json.load(stream)
    assert (payload['description'],payload['label'],payload['iterations'])==(record['scenario'],record['label'],100)
    assert len(payload['events'])==record['metadata']['events']>0
    group=(record['scenario'],record['label'])
    group_counts[group]+=1
    indices[group].append(record['index'])
    event_count+=len(payload['events'])
for scenario in matrix.SCENARIOS:
    for label,count in matrix.LABEL_COUNTS:assert sorted(indices[(scenario,label)])==list(range(count))
assert len(group_counts)==10 and original['events']==event_count and original['log_sha256']==digest(D/'collection.jsonl')
replay={**original,'host_sha_metadata_and_index_replay_passed':True,'filename_map':'trace_event_filename_map.json'}
manifest=read(D/'events_four_scenario_manifest.json')
assert manifest['collection_sha256']==digest(D/'collection.jsonl') and manifest['event_count']==1000
selected={r['file']:r for r in collection if r['scenario']!='ls_basic'}
assert set(selected)=={r['file'] for r in manifest['records']}
for row in manifest['records']:
    assert all(row[k]==selected[row['file']][k] for k in ('scenario','label','sha256'))

evaluations={}
for scope in ('four','five'):
    for grouping in ('fun','seq'):
        name=f'evaluation_{scope}_{grouping}';folder=D/name
        best=rows(folder/f'results_offline_best_shift_{grouping}.csv')
        all_rows=rows(folder/f'results_offline_all_shift_{grouping}.csv')
        assert len(best)==100 and sorted(int(r['run']) for r in best)==list(range(1,101))
        grouped=defaultdict(list)
        for row in all_rows:grouped[int(row['run'])].append(row)
        assert set(grouped)==set(range(1,101))
        for row in best:
            candidates=grouped[int(row['run'])]
            close(row['fone'],max(float(r['fone']) for r in candidates))
            matches=[r for r in candidates if r['thresh']==row['thresh']]
            assert len(matches)==1
            for key in ('tp','fp','tn','fn','tpr','fpr','p','fone','acc'):close(row[key],matches[0][key])
            tp,fp,tn,fn=(int(row[k]) for k in ('tp','fp','tn','fn'))
            recall=tp/(tp+fn);fpr=fp/(fp+tn);precision=tp/(tp+fp) if tp+fp else 0
            close(row['tpr'],recall);close(row['fpr'],fpr);close(row['p'],precision)
            close(row['fone'],2*precision*recall/(precision+recall) if precision+recall else 0)
            close(row['acc'],(tp+tn)/(tp+fp+tn+fn))
        stdout=(D/(name+'.stdout')).read_text(encoding='utf-8',errors='replace')
        assert stdout.count('Results (Run')==100
        subprocess.run([sys.executable,str(BASE/'summarize_offline.py'),'--best',str(folder/f'results_offline_best_shift_{grouping}.csv'),'--confusion',str(folder/f'results_offline_confusion_shift_{grouping}.csv'),'--output',str(folder/'host_summary.json')],capture_output=True,text=True,check=True)
        summary=read(folder/'host_summary.json')
        expected=set(matrix.SCENARIOS)-({'ls_basic'} if scope=='four' else set())
        assert set(summary['by_same_scenario'])==expected
        evaluations[name]={'runs':100,'test_label_optimized':True,
            'mean_recall':summary['overall']['tpr']['mean'],'mean_fpr':summary['overall']['fpr']['mean'],
            'csv_sha256':{p.name:digest(p) for p in folder.glob('results_*.csv')}}
fixed=load('fixed_alpha_replay',BASE/'analyze_fixed_alpha.py')
original=read(D/'fixed_alpha_005_four_scenario.json')
for grouping in ('fun','seq'):
    fresh=fixed.summarize(D/f'evaluation_four_{grouping}/results_offline_all_shift_{grouping}.csv',0.05)
    assert {k:v for k,v in fresh.items() if k!='source_csv'}=={k:v for k,v in original[grouping].items() if k!='source_csv'}
d9=read(O/'D9_SHARED_VERIFICATION.json');assert d9['passed']
result={'passed':True,'scope':'Evidence verification preserves original strict D9 recovery failures',
    'timing_batches':1250,'timing_listings':125000,'environment':before['environment'],
    'source_hashes':source_hashes,'collection_validation':replay,'evaluations':evaluations,
    'fixed_alpha_recomputed':True,'d9':{**d9['metrics'],'strict_acceptance_all_passed':d9['strict_acceptance_all_passed'],'original_strict_failures':d9['original_strict_failures']}}
(O/'trace_verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({'passed':True,'batches':1250,'evaluations':evaluations,'d9':result['d9']}),flush=True)
