"""Verify tested sources, preserved evidence, documents and the publication manifest."""
import argparse
import ast
import csv
from datetime import datetime,timezone
import hashlib
from io import StringIO
import json
from pathlib import Path
import re
import subprocess
import sys
from zipfile import ZipFile
from lxml import etree as E
import pypdfium2 as pdf

ROOT=Path(__file__).resolve().parents[1]
BASE='333b62687d88ed7b44c01b794a2789bdfadf536e'

def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--git',required=True);args=parser.parse_args()
    facts=read(ROOT/'call_completion/verification.json');assert facts['verified']
    assert facts['native_functional_scans']==1737 and facts['functional_observations_and_controls']==1884
    assert facts['dynamic_all_three_operations_overlap']==237 and len(facts['dynamic_without_confirmed_overlap'])==3
    assert len(facts['reporting_errors_retained'])==1
    assert facts['regression']['identity_alarms']==facts['regression']['verified_recovery']==555
    assert facts['normal']['alarms']==facts['dynamic']['alarms']==0
    assert all(g['alarms']==0 for g in facts['benign_race'].values())
    assert facts['archive_sha256']==sha(ROOT/'call_completion/call_completion_20261103.tar.gz')
    smoke=read(ROOT/'call_completion/entry_evidence/verification.json')
    assert smoke['passed'] and smoke['checks']==10 and smoke['module_absent']
    for name,digest in smoke['source_sha256'].items():assert sha(ROOT/name)==digest,name
    assert read(ROOT/'_docx_work/call_completion/original_verification.json')['recomputed_observations_and_controls']==447
    assert read(ROOT/'_docx_work/call_completion/withdrawn_verification.json')['benign_race']['tmpfs']['terminal_alerts']==15
    allowed={'README.md','ARTIFACT_SCOPE.md','THIRD_PARTY_NOTICES.md','scan_directory.py','paper/README.md',
             'docs/METHOD_AND_NEXT_STEPS_zh-TW.md','docs/METHOD_CLOSURE_20261102_zh-TW.md','docs/RELATED_WORK_COMPARISON_zh-TW.md'}
    prior=subprocess.check_output([args.git,'show',BASE+':FILE_SHA256.csv'],cwd=ROOT).decode('utf-8')
    previous=list(csv.DictReader(StringIO(prior)))
    for row in previous:
        if row['path'] not in allowed:assert sha(ROOT/row['path'])==row['sha256'],row['path']
    actual=ROOT/'_docx_work/call_completion/recomputed/call_completion_20261103/code'
    source_names=read(actual/'call_completion/DEPLOYMENT_SOURCES.json')
    for name,digest in source_names.items():assert sha(actual/name)==digest,('archive deployment manifest',name)
    for name in ('call_completion/bpf.c','call_completion/measurement.py','src/kicba/call_completion.py',
                 'phase2/bpf_packed.c','finalization/tracefs_measurement.py','phase1/enum_probe.c'):
        assert sha(actual/name)==sha(ROOT/name),name
    (ROOT/'call_completion/ACTUAL_DEPLOYED_SOURCES.json').write_text(json.dumps(source_names,indent=2),encoding='utf-8',newline='\n')
    before=ROOT/'paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx'
    after=ROOT/'paper/cross_layer_directory_entry_consistency_revised41_zhTW.docx'
    with ZipFile(before) as z:a={n:z.read(n) for n in z.namelist()}
    with ZipFile(after) as z:b={n:z.read(n) for n in z.namelist()}
    assert a.keys()==b.keys() and [n for n in a if a[n]!=b[n]]==['word/document.xml']
    ns={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    first,last=(E.fromstring(parts['word/document.xml']) for parts in (a,b))
    assert [E.tostring(t,method='c14n') for t in first.findall('.//w:tbl',ns)]==[E.tostring(t,method='c14n') for t in last.findall('.//w:tbl',ns)]
    full=''.join(last.xpath('.//w:t/text()',namespaces=ns))
    assert not any(t in full for t in ('；',';','補充實驗','主實驗'))
    documents={}
    for stem,one_page in [('cross_layer_directory_entry_consistency_revised41_zhTW',False),
                          ('interview_research_summary_call_completion_zhTW',True)]:
        for suffix in ('.docx','.pdf'):
            name='paper/'+stem+suffix;documents[name]=dict(sha256=sha(ROOT/name),bytes=(ROOT/name).stat().st_size)
        document=pdf.PdfDocument(ROOT/'paper'/(stem+'.pdf'))
        assert len(document)==1 if one_page else 29<=len(document)<=36
        documents['paper/'+stem+'.pdf']['pages']=len(document)
        text=''.join(page.get_textpage().get_text_range() for page in document)
        for term in ('CARAXES','237','120','getdents64'):assert term in text,(stem,term)
    env=dict(__import__('os').environ,PYTHONPATH=str(ROOT/'src'))
    tests=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-q'],cwd=ROOT,env=env,capture_output=True,text=True)
    (ROOT/'_docx_work/call_completion/unit_tests.stdout').write_text(tests.stdout,encoding='utf-8')
    (ROOT/'_docx_work/call_completion/unit_tests.stderr').write_text(tests.stderr,encoding='utf-8')
    assert tests.returncode==0,tests.stderr
    match=re.search(r'Ran (\d+) tests',tests.stderr);assert match
    count=int(match.group(1));assert count==67
    additions=[p.relative_to(ROOT).as_posix() for p in (ROOT/'call_completion').rglob('*')
               if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.pyo')]
    additions += ['docs/CALL_COMPLETION_20261103_zh-TW.md','src/kicba/call_completion.py',
                  'tests/test_call_completion.py','tests/test_call_verification.py',
                  'docs/superpowers/plans/2026-11-03-call-completion.md']
    additions += [p.relative_to(ROOT).as_posix() for p in (ROOT/'tools').glob('*call*.py')
                  if p.name in ('build_interview_call_completion.py','update_call_completion_catalog.py',
                                'resume_call_confirmation.py','verify_call_entry_native.py','verify_call_publication.py')]
    additions += ['tools/build_revised41.py',*documents]
    for name in additions:
        if name.endswith('.py'):ast.parse((ROOT/name).read_text(encoding='utf-8'),filename=name)
    receipt=dict(recorded_utc=datetime.now(timezone.utc).isoformat(),base_commit=BASE,
        scope='Accepted-item identity branch plus qualified per-getdents64 completion anomaly',
        raw_archive_sha256=facts['archive_sha256'],native_functional_scans=1737,
        functional_observations_and_controls=1884,cost_pairs=45,cost_observations=90,warmups_excluded=18,
        public_sample=facts['public_sample'],regression=facts['regression'],normal=facts['normal'],
        dynamic_scheduled=facts['dynamic'],dynamic_actual_three_operations=237,dynamic_unexercised_conditions=facts['dynamic_without_confirmed_overlap'],
        benign_race=facts['benign_race'],faults=facts['faults'],reporting_errors_retained=facts['reporting_errors_retained'],
        unit_tests=dict(passed=count,failed=0),published_entry_checks=smoke,
        historical_checksums_preserved=True,historical_original_sample_recomputed=447,
        withdrawn_heuristic_normal_tmpfs_alerts_preserved=15,old_tables_figures_and_package_parts_retained=True,
        documents=documents,visual_review_completed=True,raw_source_binding='actual deployed r4 sources; entry verified separately',
        verifier_review_fixes=['replay original recovery gates','all cohort source hashes','exact condition matrices and repetitions'],
        previously_unexercised_dynamic_attempts_not_counted_as_dynamic_success=True,
        old_timing_claims_reused_for_new_version=False,checkpoint_created=False,
        report='docs/CALL_COMPLETION_20261103_zh-TW.md')
    output=ROOT/'docs/PUBLICATION_VERIFICATION_CALL_COMPLETION_20261103.json'
    output.write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    tracked=subprocess.check_output([args.git,'ls-files','-z'],cwd=ROOT).decode().split('\0')
    names=sorted((set(tracked)|set(additions)|{output.relative_to(ROOT).as_posix()})-{'','FILE_SHA256.csv'})
    assert not any('~$' in name or name.endswith('.tmp') for name in names)
    with (ROOT/'FILE_SHA256.csv').open('w',encoding='utf-8',newline='') as stream:
        writer=csv.writer(stream,quoting=csv.QUOTE_ALL,lineterminator='\n');writer.writerow(['path','sha256','bytes'])
        for name in names:writer.writerow([name,sha(ROOT/name),(ROOT/name).stat().st_size])
    print(json.dumps(dict(passed=True,manifest_files=len(names),tests=count,documents=documents),ensure_ascii=False))


if __name__=='__main__':main()
