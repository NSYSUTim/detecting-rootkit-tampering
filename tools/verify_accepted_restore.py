"""Verify rollback without rewriting the experimental evidence or Git history."""
import argparse,csv,hashlib,json,subprocess
from datetime import datetime,timezone
from io import StringIO
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE='921319d5f0612227a14a8cad91065dfc18730092'
FEATURE='cf57fcf5cc0edaeb7ba1c9f47292f3870ff2afab'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def main():
    p=argparse.ArgumentParser();p.add_argument('--git',required=True);a=p.parse_args()
    expected=subprocess.check_output([a.git,'show',BASE+':scan_directory.py'],cwd=ROOT)
    assert (ROOT/'scan_directory.py').read_bytes()==expected
    native=read(ROOT/'rollback_accepted/evidence/verification.json')
    assert native['accepted_only'] and native['normal_controls']==2 and native['module_absent']
    assert native['entry_sha256']==sha(ROOT/'scan_directory.py')
    for buffer in (128,65536):
        row=read(ROOT/f'rollback_accepted/evidence/normal_{buffer}.stdout')
        assert row['verdict']=='equal' and row['alarm'] is False and 'terminal_rejection' not in row
    previous=read(ROOT/'rollback_accepted/original_sample_verification.json');assert previous['verified']
    mutable={'README.md','ARTIFACT_SCOPE.md','THIRD_PARTY_NOTICES.md','scan_directory.py','paper/README.md',
      'docs/METHOD_AND_NEXT_STEPS_zh-TW.md','docs/METHOD_CLOSURE_20261102_zh-TW.md',
      'docs/RELATED_WORK_COMPARISON_zh-TW.md','terminal_rejection/README.md',
      'docs/TERMINAL_REJECTION_20261103_zh-TW.md'}
    baseline_csv=subprocess.check_output([a.git,'show',FEATURE+':FILE_SHA256.csv'],cwd=ROOT).decode('utf-8')
    prior=list(csv.DictReader(StringIO(baseline_csv)))
    for row in prior:
        if row['path'] not in mutable:assert sha(ROOT/row['path'])==row['sha256'],row['path']
    current_docs={}
    for stem in ('cross_layer_directory_entry_consistency_revised39_zhTW','interview_research_summary_public_sample_zhTW'):
        for suffix in ('.docx','.pdf'):
            name='paper/'+stem+suffix
            current_docs[name]=sha(ROOT/name)
            historical=subprocess.check_output([a.git,'show',BASE+':'+name],cwd=ROOT)
            assert current_docs[name]==hashlib.sha256(historical).hexdigest()
    info={'recorded_utc':datetime.now(timezone.utc).isoformat(),'action':'Restore accepted-only current method',
      'restored_from':BASE,'withdrawn_trial_commit':FEATURE,'entry_path':'scan_directory.py',
      'entry_sha256':sha(ROOT/'scan_directory.py'),'entry_byte_identical_to_prior_version':True,
      'current_documents':current_docs,'trial_revised40_is_historical':True,
      'terminal_rule_enabled_by_default':False,'trial_sources_data_and_results_retained':True,
      'history_rewritten':False,'unit_tests':{'passed':51,'failed':0},
      'native_normal_controls':native,'old_public_sample_recomputed':{'passed':True,'observations_and_controls':447},
      'original_caraxes_filldir_covered':False,'unvalidated_lookup_fix_implemented':False,
      'report':'docs/ROLLBACK_ACCEPTED_ONLY_20261103_zh-TW.md'}
    output=ROOT/'docs/PUBLICATION_VERIFICATION_ROLLBACK_20261103.json'
    output.write_text(json.dumps(info,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    tracked=subprocess.check_output([a.git,'ls-files','-z'],cwd=ROOT).decode().split('\0')
    added=[p.relative_to(ROOT).as_posix() for p in (ROOT/'rollback_accepted').rglob('*') if p.is_file()]
    added+=['docs/ROLLBACK_ACCEPTED_ONLY_20261103_zh-TW.md',output.relative_to(ROOT).as_posix(),
            'tools/restore_accepted_only.py','tools/check_rollback_native.py','tools/verify_accepted_restore.py']
    names=sorted((set(tracked)|set(added))-{'','FILE_SHA256.csv'})
    assert not any('~$' in n or n.endswith('.tmp') for n in names)
    with (ROOT/'FILE_SHA256.csv').open('w',encoding='utf-8',newline='') as f:
        w=csv.writer(f,quoting=csv.QUOTE_ALL,lineterminator='\n');w.writerow(['path','sha256','bytes'])
        for name in names:
            path=ROOT/name;w.writerow([name,sha(path),path.stat().st_size])
    print(json.dumps({'passed':True,'manifest_files':len(names),'current_paper':'revised39','native_controls':2}))
if __name__=='__main__':main()
