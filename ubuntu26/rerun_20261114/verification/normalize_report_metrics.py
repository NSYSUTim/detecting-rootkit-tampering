"""Normalize only complete and independently checked results for authoring."""
import hashlib,json
from pathlib import Path
from report_ubuntu26_inputs import calculate

T=Path(__file__).resolve().parents[1]
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def percent(n,d):return f'{100*n/d:.2f}%'
def span(values,divisor=1):return f'{min(values)/divisor:.2f}–{max(values)/divisor:.2f}'

def main():
    evidence=calculate()
    if evidence['missing']:raise RuntimeError('Still missing: '+', '.join(evidence['missing']))
    d=evidence['results']
    for name in ('public_sample_verification','current_regression_verification','decloaker_phase1_verification',
                 'phase2_verification','supplemental_verification','development_verification','trace_verification','measured_source_verification'):
        if read(T/f'observations/{name}.json').get('passed') is not True:raise RuntimeError('Verification failed: '+name)
    _project_parent=next(parent for parent in T.parents if (parent/'scan_directory.py').is_file() or (parent/'kicba-thesis-artifact/scan_directory.py').is_file())
    _project_root=_project_parent if (_project_parent/'scan_directory.py').is_file() else _project_parent/'kicba-thesis-artifact'
    repository=_project_root
    for source in read(T/'observations/measured_source_verification.json')['canonical_critical_source_checks']:
        assert hashlib.sha256((repository/source['path']).read_bytes()).hexdigest()==source['sha256'],source['path']
    m={}
    methods=d['matrix']['methods']
    for key,method in (('mad','timing_mad_alert'),('envelope','timing_envelope_alert')):
        r=methods[method]
        m[key+'_recall']=percent(r['tp'],r['tp']+r['fn'])
        m[key+'_fpr']=percent(r['fp'],r['fp']+r['tn'])
    for key in ('static_measured','static_controls','static_differences','dynamic'):
        m[key]=sum(r[key] for rows in d['phase2'].values() for r in rows)
    m['dynamic_not_exercised']=sum(r['dynamic_not_exercised'] for rows in d['phase2'].values() for r in rows)
    m['dynamic_exercised']=m['dynamic']-m['dynamic_not_exercised']
    m['phase2_failed_campaigns']=sum(not r['completed'] for rows in d['phase2'].values() for r in rows)
    dynamic_supp=read(T/'observations/phase2_oem_dynamic_supplement_01/summary.json')
    assert dynamic_supp['passed']
    m['supp_dynamic_scans']=dynamic_supp['scans']
    m['supp_dynamic_exercised']=dynamic_supp['exercised']
    shared=read(T/'observations/trace_verification.json')['d9']
    m['shared_incomplete_recovery_batches']=shared['positive_batches_incomplete_recovery']
    fs=read(T/'observations/filesystem_namespace/filesystem_namespace_pilot.json')
    assert fs['success'] and not fs['failures']
    m['fs_measured']=sum(r['axis']=='namespace' and r['supported'] for r in fs['rows'])
    m['fs_controls']=sum(r['axis']=='pseudo_filesystem' and r['supported'] for r in fs['rows'])
    cost=d['call_cost']
    m['accepted_ms_range']=span(cost[65536]['accepted_ns'],1e6)
    m['completion_ms_range']=span(cost[65536]['completion_ns'],1e6)
    m['large_ratio_range']=span(cost[65536]['paired_ratios'])
    m['small_ratio_range']=span(cost[128]['paired_ratios'])
    m['supplement_races']=read(T/'observations/supplemental_verification.json')['exercised_benign_races']
    for grouping in ('fun','seq'):
        for field in ('recall','fpr'):
            m[f'trace_{grouping}_{field}']=f"{100*d['trace'][grouping][field]:.2f}%"
    m['decloaker_detected']=d['decloaker']['detected']
    m['decloaker_false']=d['decloaker']['false_alerts']
    for size in (8192,65536):
        for label,mode in (('d9','full_d9'),('log','exact_accepted_map_trace')):
            r=d['exact_trace'][f'{size}/{mode}']
            m[f'exact_{size}_{label}_ms']=f"{r['time_ms']:,.2f} ms"
            m[f'exact_{size}_{label}_kib']=f"{r['logical_kib']:,.2f} KiB"
    baseline=d['exact_trace']['65536/exact_accepted_map_trace'];full=d['exact_trace']['65536/full_d9']
    m['trace_time_ratio']=f"{baseline['time_ms']/full['time_ms']:.2f}"
    m['trace_data_ratio']=f"{baseline['logical_kib']/full['logical_kib']:.0f}"
    m['full_over_raw']=f"{d['legacy_cost']['full_over_raw']:.2f}"
    for factor in (1,2,4,8):
        rows=[r for r in d['capacity']['rows'] if r['requested_cell_factor']==factor]
        assert sum(r['trials'] for r in rows)==2560
        assert sum(r['incorrect_successes'] for r in rows)==0
        assert sum(r['fingerprint_false_equals'] for r in rows)==0
        m[f'capacity_{factor}']=f"{sum(r['decode_successes'] for r in rows):,}"
    for row in d['capacity_additional']:
        n,den=row['fully_recovered'],row['trials']
        assert row['incorrect_successes']==0
        m[f"additional_{row['cells']}_{row['differences']}"]=f'{100*n/den:.1f}% ({n}/{den})'
        if row['differences']==1500:m['additional_1500']=n
    m['all_required_evidence_verified']=True
    m['evidence_root']='observations'
    (T/'REPORT_EVIDENCE_VALUES.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding='utf-8')
    (T/'REPORT_NORMALIZED_METRICS.json').write_text(json.dumps(m,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(m,ensure_ascii=True))

if __name__=='__main__':main()
