"""Seal finished timing data and the remaining raw controls, never a live run."""
import hashlib,json,platform,socket,subprocess,tarfile
from pathlib import Path
G=Path('/home/kicba/ubuntu26_20261114')
O=G/'observations/trace_of_times';W=G/'trace_work';E=G/'evidence_exports'
after=json.loads((O/'collection_environment_after.json').read_text())
assert all(after[k] for k in ('same_kernel','same_boot','same_packages'))
records=[json.loads(s) for s in (O/'collection.jsonl').read_text().splitlines() if s]
assert len(records)==1250
for scope in ('four','five'):
    for grouping in ('fun','seq'):
        import csv
        with (O/f'evaluation_{scope}_{grouping}/results_offline_best_shift_{grouping}.csv').open() as f:assert len(list(csv.DictReader(f)))==100
subprocess.run(['python3',str(W/'validate_collection.py'),'--events',str(W/'events'),'--log',str(O/'collection.jsonl'),'--output',str(O/'collection_validation.json')],check=True)
def command(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=30)
    return {'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
modules=[line.split()[0] for line in Path('/proc/modules').read_text().splitlines()]
research=[name for name in modules if name.startswith(('kicba_','phase2_','getdents_hiding_fixed','getdents_policy_fixed')) or name in ('caraxes','diamorphine')]
probe_file=next((p for p in (Path('/sys/kernel/tracing/kprobe_events'),Path('/sys/kernel/debug/tracing/kprobe_events')) if p.exists()),None)
probes=probe_file.read_text() if probe_file else ''
owned_probes=[line for line in probes.splitlines() if 'bcc_' in line or 'kicba_' in line]
routes4=command(['ip','route','show','default']);routes6=command(['ip','-6','route','show','default'])
nopass=command(['runuser','-u','kicba','--','sudo','-n','true'])
grub=command(['grub-editenv','list'])
health={'hostname':socket.gethostname(),'kernel':platform.release(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'research_modules_remaining':research,'research_probe_definitions_remaining':owned_probes,
    'all_loaded_modules':modules,'ipv4_default_route':routes4,'ipv6_default_route':routes6,
    'experiment_user_passwordless_sudo':nopass['returncode']==0,'grub_environment':grub,
    'primary_kernel_default_recorded':'7.0.0-43-generic' in grub['stdout'],
    'update_units':after['environment']['update_units']}
health['passed']=(health['hostname']=='kicba-ubuntu26' and health['kernel']=='7.0.0-43-generic' and not research and not owned_probes
    and probe_file is not None and not routes4['stdout'].strip() and not routes6['stdout'].strip()
    and routes4['returncode']==routes6['returncode']==0 and health['experiment_user_passwordless_sudo'])
(O/'final_guest_state.json').write_text(json.dumps(health,indent=2))
archive=E/'trace_final_01.tar.gz'
assert not archive.exists()
members=[]
with tarfile.open(archive,'w:gz',compresslevel=1,dereference=False) as tar:
    for p in sorted(O.rglob('*')):
        rel=p.relative_to(O)
        if p.is_file() and not p.is_symlink() and rel.parts[0] not in ('d9','events_four_scenario'):
            name='trace_of_times/'+rel.as_posix();tar.add(p,arcname=name,recursive=False);members.append(name)
    for p in sorted(W.iterdir()):
        if p.is_file():
            name='trace_sources/'+p.name;tar.add(p,arcname=name,recursive=False);members.append(name)
    for p in sorted((W/'events').glob('events_*.json.gz')):
        name='trace_events/'+p.name;tar.add(p,arcname=name,recursive=False);members.append(name)
    for i in (2,3):
        folder=G/f'observations/entry_gate_boot_{i:02d}'
        assert folder.is_dir()
        for p in sorted(folder.rglob('*')):
            if p.is_file() and not p.is_symlink() and p.suffix in ('.json','.jsonl'):
                name=f'entry_gate/boot_{i:02d}/'+p.relative_to(folder).as_posix()
                tar.add(p,arcname=name,recursive=False);members.append(name)
h=hashlib.sha256()
with archive.open('rb') as f:
    for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
meta={'sha256':h.hexdigest(),'bytes':archive.stat().st_size,'files':len(members),'members':members,'complete_collection':True,'batch_count':1250}
(E/'trace_final_01.sha256.json').write_text(json.dumps(meta,indent=2))
subprocess.run(['chmod','a+r',str(archive),str(E/'trace_final_01.sha256.json')],check=True)
print(json.dumps({k:v for k,v in meta.items() if k!='members'}),flush=True)
