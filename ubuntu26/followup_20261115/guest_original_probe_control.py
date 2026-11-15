"""Cross-check the reproduced collision with the unmodified measured binary."""
import ctypes as ct
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from guest_forensics import B,T,SEEDS,MODULE,save,model,configure,set_treatment,BPF,cleanup_pid,result_for_pid,_kernel_rows,_rows_from_sparse,sha

selected=json.loads((T/'selection.json').read_text())
fixture=Path(selected['fixture']);seeds=tuple(selected['seeds'])
meta=json.loads((T/'selected_failure_256/manifest.json').read_text())
rows=meta['rows'];out=T/'original_probe_control';out.mkdir()
probe=B/'collector/bin/d9_enum_probe';source=B/'collector/bpf_d9_reconciliation.c'
save(out/'protocol.json',dict(original_binary_sha256=sha(probe),fixture=str(fixture),rows=rows,seeds=seeds,cells=[256,512,1024],repeats_per_cells=5))
bpf=BPF(src_file=str(source),cflags=['-I'+str(source.parent)])
bpf.attach_kprobe(event='filldir64',fn_name='d9_filldir64_enter')
bpf.attach_kretprobe(event='filldir64',fn_name='d9_filldir64_return',maxactive=256)
summary=[]
try:
    set_treatment('rootkit',MODULE)
    with (out/'observations.jsonl').open('x') as f:
        for cells in (256,512,1024):
            configure(bpf,cells,seeds);expected=model(rows,cells,seeds)
            for i in range(5):
                p=subprocess.Popen([str(probe),str(fixture),'65536',str(cells),*map(str,seeds)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                bpf['monitored_pids'][ct.c_uint(p.pid)]=ct.c_ubyte(1)
                try:
                    stdout,stderr=p.communicate('\n',timeout=60)
                    (out/f'{cells}_{i}.stdout.json').write_text(stdout);(out/f'{cells}_{i}.stderr.txt').write_text(stderr)
                    assert p.returncode==0,stderr
                    visible=json.loads(stdout);visible['_stdout_bytes']=len(stdout.encode())
                    r=result_for_pid(bpf,p.pid,visible,cells,*seeds);kernel,_=_kernel_rows(bpf['kernel_iblt'],p.pid,cells)
                    downstream=_rows_from_sparse(cells,visible['cells'])
                    assert [list(x) for x in kernel]==[list(x) for x in expected['kernel_rows']]
                    assert [list(x) for x in downstream]==[list(x) for x in expected['visible_rows']]
                    assert r['measurement_valid'] and not r['fingerprint_equal'] and r['decode_success']==expected['decode_success']
                    r.update(cells=cells,index=i,kernel_rows=kernel,visible_iblt_rows=downstream,recovered=expected['recovered'],unrecovered=expected['unrecovered'],difference_rows=expected['difference_rows'],residual_rows=expected['residual_rows'])
                    f.write(json.dumps(r)+'\n');f.flush();summary.append(dict(cells=cells,decode_success=r['decode_success'],recovered=len(r['upstream_only'])))
                finally:cleanup_pid(bpf,p.pid)
finally:
    set_treatment('normal',MODULE);_set=None;bpf.cleanup()
save(out/'summary.json',dict(completed=True,observations=summary))
print(json.dumps(dict(original_probe_control_completed=True,observations=summary)),flush=True)
