"""Recompute public-sample evidence from the retained native archive."""
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from phase2.oracle import identities,difference,SEED1,SEED2
from kicba.reconciliation import token_for_entry,MultisetFingerprint,IBLT

def read(path):return json.loads(path.read_text(encoding='utf-8'))
def lines(path):return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines()]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def fp_table(rows):
    tokens=[token_for_entry(name,ino,kind,SEED1,SEED2) for name,ino,kind in identities(rows)]
    return list(MultisetFingerprint.from_tokens(tokens).as_tuple()),[list(r) for r in IBLT.from_tokens(tokens,256,SEED1,SEED2).to_rows()]


def archived_source_matches(path, original_digest):
    digest = sha(path)
    if digest == original_digest:
        return True
    manifest = read(ROOT / 'docs/PUBLIC_CLEANUP_20261117.json')
    copies = manifest['public_copies_by_original_sha256']
    return digest in copies.get(original_digest, ())


def summarize(root):
    groups=defaultdict(list);ids=[];boots=[];checks=0;package_inventory=None
    builds=read(root/'setup/build_manifest.json')
    assert builds['upstream_commit']=='899e8be6b5f6c7236bd23b52aa65051de757e0b3'
    for name,digest in builds['source_sha256'].items():assert sha(root/'upstream'/name)==digest
    for mode,row in builds['builds'].items():
        assert row['changed_files']==([] if mode=='getdents64' else ['hooks.h'])
        for name,digest in row['source_sha256'].items():assert sha(root/'build'/mode/name)==digest
        assert sha(root/'build'/mode/'caraxes.ko')==row['module_sha256']
    for index in (1,2,3):
        folder=root/f'boot_{index:02d}';meta=read(folder/'manifest.json');original=meta['original']
        assert meta['boot_index']==index and not meta['pilot'] and meta['kernel']=='6.8.0-138-generic'
        assert meta['tainted_before']=='0'
        package_text=meta['package_versions']['stdout']
        if package_inventory is None:package_inventory=package_text
        assert package_inventory==package_text
        for name,digest in meta['source_sha256'].items():
            prefix='/home/kicba/closure_20261102/current/'
            if name.startswith(prefix):assert sha(ROOT/name[len(prefix):])==digest
        ids.append(meta['boot_id'])
        assert meta['module_sha256']=={m:r['module_sha256'] for m,r in builds['builds'].items()}
        for name in ('run_native.py','PROTOCOL.md'):
            assert archived_source_matches(root/'setup'/name, meta['source_sha256']['/home/kicba/public_sample_20261102/setup/'+name])
        controls=lines(folder/'controls.jsonl');rows=lines(folder/'observations.jsonl')
        assert len(rows)==100
        expected_groups=Counter({('normal','no_rootkit',b):10 for b in (128,65536)})
        expected_groups.update({(m,o,b):10 for m in ('getdents64','filldir') for o in ('rootkit_first','detector_first') for b in (128,65536)})
        assert Counter((r['mode'],r['attachment_order'],r['buffer']) for r in rows)==expected_groups
        for row in rows:
            assert lines(folder/row['dump'])==row['visible']
            up,down=difference(original,row['visible'])
            assert up==row['external_missing'] and down==row['external_extra']
            assert row['output_matches_manifest']==(identities(original)==identities(row['visible']))
            fp,table=fp_table(row['visible'])
            user=row.get('userspace',{})
            if row.get('returncode')==0:
                assert fp==[user['count'],user['sum1'],user['sum2']]
            if row.get('measurement_valid'):
                expected='equal' if fp==row['kernel_fingerprint'] else 'different'
                assert row['verdict']==expected
                for gate in ('entry_coverage','coverage','program_coverage'):
                    if gate in row:assert row[gate]['valid']
                if row['mode'] in ('normal','getdents64'):
                    original_fp,original_table=fp_table(original)
                    assert row['kernel_fingerprint']==original_fp and row['kernel_rows']==original_table
                    assert sorted(row['upstream_only'])==sorted(up) and sorted(row['downstream_only'])==sorted(down)
                    assert row['recovery_validation']['verified'] is True
                elif row['verdict']=='equal':
                    assert row['kernel_rows']==table
            groups[(row['mode'],row['attachment_order'])].append(row);checks+=1
        for row in controls:
            assert lines(folder/row['dump'])==row['rows']
            assert row['matches_manifest']==(identities(row['rows'])==identities(original))
            if 'restored' in row['tag'] or 'normal' in row['tag'] or 'unloaded' in row['tag']:
                assert row['matches_manifest'] and row['returncode']==0
            checks+=1
        cleanup=read(folder/'cleanup.json');assert cleanup['module_absent'] and cleanup['manifest_restored']
        boots.append({'boot_index':index,'boot_id':meta['boot_id'],'observations':len(rows),
                      'controls':len(controls),'cleanup':True})
    assert len(set(ids))==3
    def extent(values):return [min(values),max(values)]
    results=[]
    for (mode,order),rows in groups.items():
        results.append({'mode':mode,'attachment_order':order,'n':len(rows),
            'verdicts':dict(Counter(r['verdict'] for r in rows)),
            'alarms':sum(r.get('alarm') is True for r in rows),
            'verified_recovery':sum(r.get('recovery_verified') is True for r in rows),
            'returned_count_range':extent([len(r['visible']) for r in rows]),
            'externally_missing_count_range':extent([len(r['external_missing']) for r in rows]),
            'accepted_count_range':extent([r['kernel_stats']['accepted_entries'] for r in rows if 'kernel_stats' in r])})
    return {'verified':True,'recomputed_observations_and_controls':checks,'boots':boots,
            'detector':results,
            'pilot_excluded':True,'full_matrix_denominators_unchanged':True,
            'upstream_commit':builds['upstream_commit'],'detector_sources_match_current':True,
            'recorded_package_versions_same':True,'clean_kernel_taint_before_each_confirmation':True}

def main():
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True)
    p.add_argument('--extract-to',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.extract_to.mkdir(parents=True,exist_ok=True)
    with tarfile.open(a.archive) as archive:archive.extractall(a.extract_to,filter='data')
    result=summarize(a.extract_to/'public_sample_20261102')
    result['archive_sha256']=sha(a.archive)
    a.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
