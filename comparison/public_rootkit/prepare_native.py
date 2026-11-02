"""Build the unchanged default and author-documented alternate configuration."""
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

root=Path('/home/kicba/public_sample_20261102')
source=root/'upstream';source.mkdir()
with tarfile.open(root/'setup/upstream.tar') as archive:archive.extractall(source,filter='data')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
files={p.relative_to(source).as_posix():sha(p) for p in source.rglob('*') if p.is_file()}
original=(source/'hooks.h').read_text()
result={'upstream_commit':'899e8be6b5f6c7236bd23b52aa65051de757e0b3','source_sha256':files,'builds':{}}
for mode in ('getdents64','filldir'):
    target=root/'build'/mode;shutil.copytree(source,target)
    if mode=='filldir':
        changed=original.replace('#include "hooks_getdents64.h"','//#include "hooks_getdents64.h"')
        changed=changed.replace('//#include "hooks_filldir.h"','#include "hooks_filldir.h"')
        changed=changed.replace('\tHOOK("sys_getdents64"','\t//HOOK("sys_getdents64"')
        changed=changed.replace('//HOOK_NOSYS','HOOK_NOSYS')
        (target/'hooks.h').write_text(changed)
        (root/'setup/filldir_configuration.patch').write_text(''.join(difflib.unified_diff(
            original.splitlines(True),changed.splitlines(True),fromfile='upstream/hooks.h',tofile='filldir/hooks.h')))
    # Upstream Makefile uses the shell PWD variable; subprocess cwd does not
    # update that inherited variable. Pass it explicitly without editing sources.
    p=subprocess.run(['make','PWD='+str(target)],cwd=target,text=True,capture_output=True)
    (root/'setup'/(mode+'.build.stdout')).write_text(p.stdout)
    (root/'setup'/(mode+'.build.stderr')).write_text(p.stderr)
    row={'returncode':p.returncode,'source_sha256':{f:sha(target/f) for f in files}}
    if (target/'caraxes.ko').exists():row['module_sha256']=sha(target/'caraxes.ko')
    result['builds'][mode]=row
    (root/'setup/build_manifest.json').write_text(json.dumps(result,indent=2))
    print(mode,p.returncode,row.get('module_sha256'),flush=True)
    if p.returncode:print(p.stderr[-4000:])
if any(r['returncode'] for r in result['builds'].values()):raise SystemExit(1)
