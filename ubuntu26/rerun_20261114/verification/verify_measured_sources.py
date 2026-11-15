"""Check the clean frozen source archive against its recorded inventory."""
import hashlib,json
from pathlib import Path
T=Path(__file__).resolve().parents[1];_project_parent=next(parent for parent in T.parents if (parent/'scan_directory.py').is_file() or (parent/'kicba-thesis-artifact/scan_directory.py').is_file())
_project_root=_project_parent if (_project_parent/'scan_directory.py').is_file() else _project_parent/'kicba-thesis-artifact'
R=_project_root
root=T/'measured_sources'
inventory=json.loads((root/'inventory.json').read_text(encoding='utf-8'))
counts={}
for label,info in inventory['trees'].items():
    for name,wanted in info['source_sha256'].items():
        p=(root/label/name).resolve();p.relative_to((root/label).resolve())
        assert hashlib.sha256(p.read_bytes()).hexdigest()==wanted,(label,name)
    counts[label]=len(info['source_sha256'])
critical=('src/kicba/reconciliation.py','src/kicba/call_completion.py','collector/bpf_d9_reconciliation.c',
          'phase2/bpf_packed.c','call_completion/bpf.c','phase1/enum_probe.c','collector/d9_enum_probe.c',
          'scan_directory.py','call_completion/measurement.py','finalization/tracefs_measurement.py','phase2/measurement.py')
checked=[]
for name in critical:
    actual=hashlib.sha256((R/name).read_bytes()).hexdigest()
    available={label:info['source_sha256'][name] for label,info in inventory['trees'].items() if name in info['source_sha256']}
    assert available and all(value==actual for value in available.values()),name
    checked.append({'path':name,'sha256':actual,'matching_trees':sorted(available)})
result={'passed':True,'source_files_by_tree':counts,'checked_source_files':sum(counts.values()),
    'canonical_critical_source_checks':checked,'scope':'Exact archived-file hashes and current critical algorithms; preserves distinct historical runners rather than overwriting them wholesale'}
(T/'observations/measured_source_verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({'passed':True,'files':sum(counts.values()),'trees':counts,'canonical_critical_files':len(checked)}))
