"""Additional diagnostics only; never replace the preserved formal batches."""
import ctypes as ct
import difflib
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import struct
import subprocess
import sys
import time

B = Path('/home/kicba/research_phase2_20261023')
T = Path('/home/kicba/ubuntu26_20261114/followup_20261115')
sys.path[:0] = [str(B), str(B/'src'), str(B/'collector')]
from bcc import BPF
from kicba.reconciliation import IBLT, MultisetFingerprint, token_for_entry, EntryToken
from run_d9_external_matrix import build_fixture, scenario_parameters, set_treatment
from run_d9_reconciliation_smoke import _set_array, _kernel_rows, result_for_pid, cleanup_pid, _rows_from_sparse
from phase1.record_environment import inventory

SEEDS = (17799924945220832399, 9117976559146228272)
PARAMS = dict(visible_files=20, hidden_files=73, file_name_length=8, system_load=False)
MODULE = B/'attack_variants/d7_controls_r2/kicba_d7_hiding.ko'

def save(path, data):
    with path.open('x', encoding='utf-8') as f: json.dump(data, f, ensure_ascii=True, indent=2)

def event(name, **values):
    row = dict(event=name, utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **values)
    with (T/'progress.jsonl').open('a') as f: f.write(json.dumps(row)+'\n')
    print(json.dumps(row), flush=True)

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def manifest(path):
    rows=[]
    for name in ['.', '..', *sorted(os.listdir(path))]:
        st=os.lstat(path/name)
        rows.append(dict(name=name, name_hex=os.fsencode(name).hex(), inode=st.st_ino,
                         d_type=4 if name in ('.','..') else 8, hidden='caraxes' in name))
    return rows

def tokens(rows, seeds):
    return [token_for_entry(bytes.fromhex(r['name_hex']), r['inode'], r['d_type'], *seeds) for r in rows]

def token_key(t): return (t.key_hash,t.inode,t.d_type)

def model(rows, cells, seeds):
    all_tokens=tokens(rows,seeds)
    visible_rows=[r for r in rows if not r['hidden']]
    visible_tokens=tokens(visible_rows,seeds)
    kernel=IBLT.from_tokens(all_tokens,cells,*seeds)
    downstream=IBLT.from_tokens(visible_tokens,cells,*seeds)
    diff=kernel.subtract(downstream); decoded=diff.decode()
    residual=IBLT.from_rows(diff.to_rows(),*seeds)
    for t in decoded.upstream_only: residual.add(t,-1)
    for t in decoded.downstream_only: residual.add(t,1)
    identities={token_key(t):dict(r,token=list(token_key(t)),positions=list(kernel._positions(t.key_hash)))
                for r,t in zip(rows,all_tokens)}
    recovered={token_key(t) for t in decoded.upstream_only}
    missing=[identities[token_key(t)] for r,t in zip(rows,all_tokens) if r['hidden'] and token_key(t) not in recovered]
    return dict(kernel_rows=kernel.to_rows(),visible_rows=downstream.to_rows(),difference_rows=diff.to_rows(),
                residual_rows=residual.to_rows(),decode_success=decoded.success,
                recovered=[identities[token_key(t)] for t in decoded.upstream_only],unrecovered=missing,
                residual_cells=decoded.residual_cells,identity_map=list(identities.values()))

def parse_pages(path):
    data=path.read_bytes(); cursor=0; rows=[]; pages=[]
    while cursor<len(data):
        length=struct.unpack_from('<Q',data,cursor)[0];cursor+=8
        page=data[cursor:cursor+length];cursor+=length
        assert len(page)==length
        pages.append(length); offset=0
        while offset<length:
            ino,cookie,reclen,dtype=struct.unpack_from('<QqHB',page,offset)
            assert reclen>=20 and offset+reclen<=length
            name=page[offset+19:offset+reclen].split(b'\0',1)[0]
            rows.append(dict(name=os.fsdecode(name),name_hex=name.hex(),inode=ino,d_type=dtype,cookie=cookie,record_length=reclen))
            offset+=reclen
    assert cursor==len(data) and pages[-1]==0
    return rows,pages

def build_capture_probe():
    original=B/'collector/d9_enum_probe.c'
    src=original.read_text()
    assert src.count('    clock_gettime(CLOCK_MONOTONIC, &started);')==1
    src=src.replace('    int fd;','    int fd;\n    FILE *raw_capture = NULL;\n    const char *capture_path = getenv("KICBA_FORENSIC_RAW_PATH");',1)
    src=src.replace('    clock_gettime(CLOCK_MONOTONIC, &started);',
        '    if (capture_path) { raw_capture = fopen(capture_path, "wx"); if (!raw_capture) return 2; }\n    clock_gettime(CLOCK_MONOTONIC, &started);',1)
    src=src.replace('        if (result == 0)\n            break;',
        '        if (raw_capture) { uint64_t n = (uint64_t)result;\n'
        '            if (fwrite(&n, sizeof(n), 1, raw_capture) != 1 ||\n'
        '                (n && fwrite(buffer, 1, (size_t)n, raw_capture) != n)) return 2; }\n'
        '        if (result == 0)\n            break;',1)
    src=src.replace('    close(fd);\n\n    printf(',
        '    close(fd);\n    if (raw_capture && fclose(raw_capture)) return 2;\n\n    printf(',1)
    source=T/'sources/d9_enum_probe_capture.c';source.write_text(src)
    (T/'sources/capture_only.patch').write_text(''.join(difflib.unified_diff(original.read_text().splitlines(True),src.splitlines(True),fromfile=str(original),tofile=str(source))))
    binary=T/'bin/d9_enum_probe'
    command=['gcc','-O2','-Wall','-Wextra','-Werror','-I'+str(B/'collector'),str(source),'-o',str(binary)]
    r=subprocess.run(command,capture_output=True,text=True)
    save(T/'sources/build.json',dict(argv=command,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr,
        source_sha256=sha(source),original_source_sha256=sha(original),binary_sha256=sha(binary) if binary.exists() else None))
    r.check_returncode();return binary

def configure(bpf,cells,seeds):
    _set_array(bpf['hash_seeds'],0,ct.c_ulonglong(seeds[0]))
    _set_array(bpf['hash_seeds'],1,ct.c_ulonglong(seeds[1]))
    _set_array(bpf['iblt_cell_count'],0,ct.c_uint(cells))
    _set_array(bpf['collection_enabled'],0,ct.c_ubyte(1))

def collect(bpf,probe,fixture,rows,folder,cells,seeds,repeats,label):
    folder.mkdir(); expected=model(rows,cells,seeds)
    save(folder/'expected_model.json',expected)
    save(folder/'manifest.json',dict(fixture=str(fixture),rows=rows,cell_count=cells,seeds=seeds,repeats=repeats,
                                   label=label,probe=str(probe),probe_sha256=sha(probe)))
    set_treatment('rootkit',MODULE)
    outcomes=[]
    try:
        with (folder/'observations.jsonl').open('x') as stream:
            for i in range(repeats):
                prefix=f'scan_{i:03d}'; raw=folder/(prefix+'.getdents.bin')
                process=subprocess.Popen([str(probe),str(fixture),'65536',str(cells),*map(str,seeds)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    env={**os.environ,'KICBA_FORENSIC_RAW_PATH':str(raw)},text=True)
                bpf['monitored_pids'][ct.c_uint(process.pid)]=ct.c_ubyte(1)
                try:
                    stdout,stderr=process.communicate('\n',timeout=60)
                    (folder/(prefix+'.stdout.json')).write_text(stdout)
                    (folder/(prefix+'.stderr.txt')).write_text(stderr)
                    assert process.returncode==0,stderr
                    visible=json.loads(stdout);visible['_stdout_bytes']=len(stdout.encode())
                    result=result_for_pid(bpf,process.pid,visible,cells,*seeds)
                    kernel_rows,_=_kernel_rows(bpf['kernel_iblt'],process.pid,cells)
                    visible_iblt=_rows_from_sparse(cells,visible['cells'])
                    actual,pages=parse_pages(raw)
                    actual_keys=sorted((r['name_hex'],r['inode'],r['d_type']) for r in actual)
                    expected_keys=sorted((r['name_hex'],r['inode'],r['d_type']) for r in rows if not r['hidden'])
                    assert actual_keys==expected_keys
                    assert [list(r) for r in kernel_rows]==[list(r) for r in expected['kernel_rows']]
                    assert [list(r) for r in visible_iblt]==[list(r) for r in expected['visible_rows']]
                    assert result['measurement_valid'] and not result['fingerprint_equal']
                    assert result['decode_success']==expected['decode_success']
                    assert sorted(map(tuple,result['upstream_only']))==sorted(tuple(r['token']) for r in expected['recovered'])
                    record=dict(index=i,**result,kernel_rows=kernel_rows,visible_iblt_rows=visible_iblt,
                        actual_visible=actual,page_lengths=pages,raw_capture=raw.name,
                        recovered=expected['recovered'],unrecovered=expected['unrecovered'],
                        difference_rows=expected['difference_rows'],residual_rows=expected['residual_rows'])
                    stream.write(json.dumps(record)+'\n');stream.flush();outcomes.append(result['decode_success'])
                finally: cleanup_pid(bpf,process.pid)
    finally: set_treatment('normal',MODULE)
    save(folder/'summary.json',dict(scans=len(outcomes),full_recovery=sum(outcomes),
        unrecovered=expected['unrecovered'],residual_cells=expected['residual_cells'],all_measurements_valid_and_alerted=True))
    event('native_cohort_completed',label=label,scans=len(outcomes),full_recovery=sum(outcomes),
          unrecovered_names=[r['name'] for r in expected['unrecovered']])

def main():
    assert os.geteuid()==0 and platform.release()=='7.0.0-43-generic'
    assert subprocess.check_output(['hostname'],text=True).strip()=='kicba-ubuntu26'
    for family in ([],['-6']):assert not subprocess.check_output(['ip',*family,'route','show','default'],text=True).strip()
    assert 'kicba_d7_hiding' not in Path('/proc/modules').read_text()
    for p in ('sources','bin','fixtures','search'): (T/p).mkdir(parents=True,exist_ok=False)
    protocol=dict(role='additional diagnostic, not replacement or unbiased recovery-rate estimate',
        original_missing_identities='not recoverable from compact historical records',scenario='file_count',label='rootkit',index=9,
        parameters=PARAMS,seeds=SEEDS,cell_count=256,primary_repeats=100,
        natural_fixture_search_max=4096,search_stop='first offline incomplete decode',
        fallback_seed_search_max=16384,fallback_seed_rng=20261115,
        selected_failure_native_repeats=100,larger_table_cells=[512,1024],larger_table_repeats=10,
        preserve='all manifests, names, inodes, per-entry positions, raw returned buffers, stdout, both IBLTs, difference and residual rows, recovered and unrecovered identities')
    save(T/'PROTOCOL.json',protocol);save(T/'environment_before.json',inventory())
    expected_hashes={'bpf':('collector/bpf_d9_reconciliation.c','9e0c09c8d90810515b4144c8c405e5210eb6e275ca73db754e0b64bdbd24c500'),
        'probe':('collector/bin/d9_enum_probe','de974b6c2c83afea0f2d05cf979bd05295e6dee30f5f5e8a59c09b484e1a7ed6'),
        'module':('attack_variants/d7_controls_r2/kicba_d7_hiding.ko','084be099c87bde42df0f8a957f5cd17c42e212451e9ac1cfde1b328ab96e6e19')}
    save(T/'source_lock.json',{k:dict(path=str(B/p),sha256=sha(B/p),expected_sha256=h) for k,(p,h) in expected_hashes.items()})
    assert all(sha(B/p)==h for p,h in expected_hashes.values())
    probe=build_capture_probe()
    parent=T/'fixtures/primary';parent.mkdir()
    fixture,_=build_fixture(parent,42,'file_count','rootkit',9,PARAMS)
    rows=manifest(fixture);save(T/'primary_manifest.json',rows)
    source=B/'collector/bpf_d9_reconciliation.c'
    bpf=BPF(src_file=str(source),cflags=['-I'+str(source.parent)])
    bpf.attach_kprobe(event='filldir64',fn_name='d9_filldir64_enter')
    bpf.attach_kretprobe(event='filldir64',fn_name='d9_filldir64_return',maxactive=256)
    try:
        configure(bpf,256,SEEDS)
        collect(bpf,probe,fixture,rows,T/'primary_256',256,SEEDS,100,'same_parameters_new_inodes')
        selected=(fixture,rows,SEEDS,'primary') if not model(rows,256,SEEDS)['decode_success'] else None
        started=time.monotonic()
        with (T/'search/index.jsonl').open('x') as log:
            if selected is None:
                for i in range(4096):
                    parent=T/f'fixtures/natural_{i:04d}';parent.mkdir()
                    candidate,_=build_fixture(parent,42,'file_count','rootkit',9,PARAMS)
                    candidate_rows=manifest(candidate);m=model(candidate_rows,256,SEEDS)
                    record=dict(index=i,fixture=str(candidate),rows=candidate_rows,seeds=SEEDS,cell_count=256,**m)
                    path=T/f'search/natural_{i:04d}.json.gz'
                    with gzip.open(path,'xt',encoding='utf-8') as f: json.dump(record,f)
                    log.write(json.dumps(dict(index=i,file=path.name,sha256=sha(path),decode_success=m['decode_success'],
                                              recovered=len(m['recovered']),residual_cells=m['residual_cells']))+'\n');log.flush()
                    if not m['decode_success']:
                        selected=(candidate,candidate_rows,SEEDS,f'natural_{i:04d}');break
                    if i%100==0:event('natural_fixture_search',completed=i+1,elapsed_seconds=round(time.monotonic()-started,1))
            if selected is None:
                rng=random.Random(20261115)
                for i in range(16384):
                    seeds=(rng.getrandbits(64),rng.getrandbits(64));m=model(rows,256,seeds)
                    log.write(json.dumps(dict(seed_attempt=i,seeds=seeds,decode_success=m['decode_success'],recovered=len(m['recovered'])))+'\n')
                    if not m['decode_success']:
                        selected=(fixture,rows,seeds,f'deliberately_selected_seed_{i:05d}')
                        save(T/'search/selected_seed_full.json',dict(rows=rows,seeds=seeds,**m));break
        if selected is None:raise RuntimeError('Bounded diagnostic search found no failure; do not invent a reproduction')
        fixture,rows,seeds,selection=selected
        save(T/'selection.json',dict(selection=selection,fixture=str(fixture),seeds=seeds,
             original_fixed_seeds_used=seeds==SEEDS,not_an_unbiased_rate_estimate=True))
        configure(bpf,256,seeds)
        if selection!='primary':collect(bpf,probe,fixture,rows,T/'selected_failure_256',256,seeds,100,selection)
        for cells in (512,1024):
            configure(bpf,cells,seeds)
            collect(bpf,probe,fixture,rows,T/f'same_fixture_{cells}',cells,seeds,10,'same_names_inodes_seeds_larger_table')
        save(T/'forensics_complete.json',dict(completed=True,selected=selection,original_batch_preserved=True))
    finally:
        set_treatment('normal',MODULE)
        _set_array(bpf['collection_enabled'],0,ct.c_ubyte(0));bpf.cleanup()
        save(T/'environment_after.json',inventory())
    event('forensics_completed')

if __name__=='__main__':main()
