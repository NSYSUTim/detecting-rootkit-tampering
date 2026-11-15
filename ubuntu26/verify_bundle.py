"""Verify the additive Ubuntu 26 evidence bundle and restore into a new folder."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

ROOT=Path(__file__).resolve().parent

def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def require(condition,message):
    if not condition:raise ValueError(message)

def safe_path(root,name):
    require('\\' not in name,'Archive path contains backslash')
    target=(root/name).resolve()
    require(target==root.resolve() or root.resolve() in target.parents,'Path escapes output directory')
    return target

def extract(archive,destination):
    destination.mkdir(parents=True,exist_ok=False)
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar.getmembers():
            safe_path(destination,member.name)
            require(member.isdir() or member.isfile(),'Unsupported archive member')
            require(not member.issym() and not member.islnk(),'Archive links are not allowed')
        tar.extractall(destination,filter='data')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restore',type=Path,help='New output directory; existing paths are refused')
    args=parser.parse_args()
    manifest=json.loads((ROOT/'FILE_SHA256.json').read_text(encoding='utf-8'))['files']
    present={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()
             and ('__pycache__' not in p.parts or p.relative_to(ROOT).as_posix() in manifest)}
    require(present==set(manifest)|{'FILE_SHA256.json'},'Unexpected or missing published files')
    for name,record in manifest.items():
        p=safe_path(ROOT,name)
        require(p.stat().st_size==record['bytes'] and sha(p)==record['sha256'],'File mismatch: '+name)
    layout=json.loads((ROOT/'STORAGE_LAYOUT.json').read_text())
    source=ROOT/'rerun_20261114';archive=layout['archive'];digest=hashlib.sha256();total=0
    for part in archive['parts']:
        path=safe_path(source,part['path'])
        require(sha(path)==part['sha256'] and path.stat().st_size==part['bytes'],'Part mismatch')
        with path.open('rb') as f:
            while data:=f.read(1024*1024):digest.update(data);total+=len(data)
    require(total==archive['bytes'] and digest.hexdigest()==archive['sha256'],'Reassembled archive mismatch')
    followup=ROOT/'followup_20261115'
    expected=json.loads((followup/'DOWNLOAD_VERIFICATION.json').read_text())['archive_sha256']
    require(sha(followup/'followup_evidence.tar.gz')==expected,'Follow-up archive mismatch')
    require(json.loads((followup/'VERIFIED_FINDINGS.json').read_text())['passed'],'Follow-up replay not verified')
    print(json.dumps(dict(passed=True,physical_files=len(manifest)+1,original_trace_archive_sha256=digest.hexdigest())))
    if args.restore is None:return
    dest=args.restore.resolve();require(not dest.exists(),'Refuse to overwrite existing output')
    require(dest!=ROOT.resolve() and ROOT.resolve() not in dest.parents,'Restore outside the published folder')
    dest.mkdir(parents=True)
    rerun=dest/'rerun_20261114';shutil.copytree(source,rerun)
    combined=safe_path(rerun,archive['path'])
    with combined.open('xb') as out:
        for part in archive['parts']:
            with safe_path(source,part['path']).open('rb') as f:shutil.copyfileobj(f,out,1024*1024)
    mapping=json.loads((rerun/'observations/trace_event_filename_map.json').read_text())
    restored=0
    with tarfile.open(combined,'r:gz') as tar:
        for member in tar:
            if not member.name.startswith('trace_events/'):continue
            require(member.isfile() and not member.issym() and not member.islnk(),'Invalid event archive member')
            original=Path(member.name).name;safe=mapping[original]
            require(safe==original.replace(':','-'),'Invalid filename mapping')
            target=safe_path(rerun/'observations/trace_events',safe);target.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(member) as f,target.open('xb') as out:shutil.copyfileobj(f,out)
            restored+=1
    require(restored==1250,'Unexpected event file count')
    for record in layout['byte_identical_files_reconstructed_on_restore']:
        p=safe_path(rerun,record['path']);require(p.stat().st_size==record['bytes'] and sha(p)==record['sha256'],'Restored file mismatch')
    original=json.loads((rerun/'EVIDENCE_MANIFEST.json').read_text())
    for record in original['files']:
        p=safe_path(rerun,record['path']);require(p.stat().st_size==record['bytes'] and sha(p)==record['sha256'],'Original evidence mismatch: '+record['path'])
    extra=dest/'followup_20261115';shutil.copytree(followup,extra)
    evidence=extra/'evidence';extract(extra/'followup_evidence.tar.gz',evidence)
    extract(extra/'frozen_existing_sources.tar.gz',evidence/'sources/frozen_existing')
    for name,expected in json.loads((evidence/'EVIDENCE_MANIFEST.json').read_text()).items():
        require(sha(safe_path(evidence,name))==expected,'Restored follow-up mismatch: '+name)
    for name,expected in json.loads((extra/'SOURCE_DOWNLOAD_VERIFICATION.json').read_text())['files'].items():
        require(sha(safe_path(evidence/'sources/frozen_existing',name))==expected,'Measured source mismatch: '+name)
    print(json.dumps(dict(restored=True,output=str(dest),original_rerun_files=len(original['files']),event_files=restored)))

if __name__=='__main__':main()
