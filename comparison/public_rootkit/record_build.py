"""Record the successful explicit-PWD build without altering the original source."""
import hashlib
import json
from pathlib import Path

root=Path('/home/kicba/public_sample_20261102')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=root/'upstream'
files={p.relative_to(source).as_posix():sha(p) for p in source.rglob('*') if p.is_file()}
data={'upstream_commit':'899e8be6b5f6c7236bd23b52aa65051de757e0b3',
      'source_sha256':files,'builds':{},'attempt1':'build_manifest_attempt1.json',
      'correction':'Pass the actual module directory as make PWD, without a source edit.'}
for mode in ('getdents64','filldir'):
    directory=root/'build'/mode
    hashes={name:sha(directory/name) for name in files}
    changes=[name for name in files if files[name]!=hashes[name]]
    assert changes==([] if mode=='getdents64' else ['hooks.h']),changes
    data['builds'][mode]={'returncode':0,'source_sha256':hashes,'changed_files':changes,
        'module_sha256':sha(directory/'caraxes.ko'),
        'command':['make','PWD='+str(directory)]}
(root/'setup/build_manifest.json').write_text(json.dumps(data,indent=2))
print(json.dumps({m:r['changed_files'] for m,r in data['builds'].items()}))
