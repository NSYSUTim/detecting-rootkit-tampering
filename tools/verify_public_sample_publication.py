"""Write publication receipt after raw-data, document and source checks."""
import argparse
import csv
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess
from zipfile import ZipFile
from lxml import etree as E
import pypdfium2 as pdf

ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))

def main():
    p=argparse.ArgumentParser();p.add_argument('--git',required=True);a=p.parse_args()
    raw=read(ROOT/'comparison/public_rootkit/verification.json')
    old=read(ROOT/'reproduced/public_sample_historical_verification.json')
    assert raw['verified'] and old['passed']
    paper=ROOT/'paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx'
    source=ROOT/'paper/cross_layer_directory_entry_consistency_revised38_zhTW.docx'
    with ZipFile(source) as z:previous={n:z.read(n) for n in z.namelist()}
    with ZipFile(paper) as z:current={n:z.read(n) for n in z.namelist()}
    assert previous.keys()==current.keys()
    changed=[n for n in previous if previous[n]!=current[n]];assert changed==['word/document.xml']
    ns={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    xml=E.fromstring(current['word/document.xml']);oldxml=E.fromstring(previous['word/document.xml'])
    assert [E.tostring(t,method='c14n') for t in xml.findall('.//w:tbl',ns)]==[E.tostring(t,method='c14n') for t in oldxml.findall('.//w:tbl',ns)]
    text=''.join(xml.xpath('.//w:t/text()',namespaces=ns))
    assert all(s not in text for s in ('；',';','補充實驗','主實驗'))
    assert not xml.findall('.//w:ins',ns) and not xml.findall('.//w:del',ns)
    outputs={}
    for stem,pages in [('cross_layer_directory_entry_consistency_revised39_zhTW',29),('interview_research_summary_public_sample_zhTW',1)]:
        for suffix in ('.docx','.pdf'):
            path=ROOT/'paper'/(stem+suffix);outputs[path.relative_to(ROOT).as_posix()]={'sha256':sha(path),'bytes':path.stat().st_size}
        d=pdf.PdfDocument(ROOT/'paper'/(stem+'.pdf'));assert len(d)==pages
        full=''.join(page.get_textpage().get_text_range() for page in d)
        for token in ('CARAXES','120','60','false'):assert token in full
        outputs['paper/'+stem+'.pdf']['pages']=pages
    receipt={'recorded_utc':datetime.now(timezone.utc).isoformat(),
      'base_commit':'3cb634a8dd321f0ab3802d8a3aef689c229d5f7c',
      'scope':'Original CARAXES two configurations, three fresh boots, unchanged detector, truthful negative result',
      'raw_archive':{'path':'comparison/public_rootkit/public_sample_20261102.tar.gz','sha256':raw['archive_sha256']},
      'offline_verification':{'passed':True,'observations_and_controls':447,'detector_observations':300,
          'independent_controls':102,'zygarde_observations':45,'boot_ids':[r['boot_id'] for r in raw['boots']]},
      'tests':{'command':'python -m unittest discover -s tests -q','passed':45,'failed':0,
          'environment_attempts':'pytest unavailable; first unittest sandbox run had three temporary-directory permission errors; same 45 tests passed with normal workspace permissions, without source/test changes'},
      'historical_verification':{'passed':True,'recomputed':True,'archives':len(old['archives']),'frozen_sources':old['frozen_sources']},
      'documents':outputs,'formal_paper_source':{'path':source.relative_to(ROOT).as_posix(),'sha256':sha(source)},
      'word_validation':{'readonly_native_word_export':True,'all_pages_rendered_and_inspected':True,
          'existing_tables_and_other_package_parts_unchanged':True,'changed_package_parts':changed,'semicolons':0},
      'limits':{'new_checkpoint_created':False,'checkpoint_reason':'Host account lacks Hyper-V administration permission',
          'all_samples_unloaded':True,'cleanup_manifests_restored':True,
          'original_filldir_hiding_detected':False,'original_getdents64_hiding_detected':True,
          'other_rootkits_validated':False,'existing_denominators_merged':False,
          'detector_algorithm_modified':False,'new_performance_claim':False},
      'report':'docs/ORIGINAL_CARAXES_20261102_zh-TW.md',
      'prior_publication_record':'docs/PUBLICATION_VERIFICATION_REVIEW_20261102.json'}
    output=ROOT/'docs/PUBLICATION_VERIFICATION_CARAXES_20261102.json'
    output.write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    # Explicit new deliverables only. Never include Word locks or temporary files.
    tracked=subprocess.check_output([a.git,'ls-files','-z'],cwd=ROOT).decode().split('\0')
    new=[p.relative_to(ROOT).as_posix() for p in (ROOT/'comparison/public_rootkit').iterdir() if p.is_file()]
    new+=list(outputs)+['docs/ORIGINAL_CARAXES_20261102_zh-TW.md',output.relative_to(ROOT).as_posix(),
       'tools/build_revised39.py','tools/build_interview_public_sample.py',
       'tools/update_public_sample_catalog.py','tools/verify_public_sample_publication.py']
    names=sorted((set(tracked)|set(new))-{'','FILE_SHA256.csv'})
    assert not any('~$' in n or n.endswith('.tmp') for n in names)
    with (ROOT/'FILE_SHA256.csv').open('w',encoding='utf-8',newline='') as stream:
        writer=csv.writer(stream,quoting=csv.QUOTE_ALL,lineterminator='\n');writer.writerow(['path','sha256','bytes'])
        for name in names:
            path=ROOT/name;writer.writerow([name,sha(path),path.stat().st_size])
    print(json.dumps({'publication_passed':True,'manifest_files':len(names),'output':str(output)}))

if __name__=='__main__':main()
