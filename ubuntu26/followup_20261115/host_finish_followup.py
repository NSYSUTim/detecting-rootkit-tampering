import ast
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from remote_job import SSH,OPTIONS,HOST
G='/home/kicba/ubuntu26_20261114/followup_20261115'
M=json.loads((HERE.parent/'KERNEL_MATRIX.json').read_text(encoding='utf-8-sig'))

def remote(command,timeout=30):return subprocess.run([SSH,'-n',*OPTIONS,HOST,command],capture_output=True,text=True,timeout=timeout)

def event(event_name,**data):
    r=dict(event=event_name,**data)
    with (HERE/'finish_events.jsonl').open('a') as f:f.write(json.dumps(r)+'\n')
    print(json.dumps(r),flush=True)

def checked(command,timeout=30):
    r=remote(command,timeout);r.check_returncode();return r.stdout

def job(name):
    p=HERE/name;ast.parse(p.read_text(encoding='utf-8'))
    folder={'guest_original_probe_control.py':'original_probe_control','guest_oem_dynamic.py':'oem_dynamic'}[name]
    done=remote('test -f '+shlex.quote(G+'/'+folder+'/summary.json'))
    if done.returncode==0:
        summary=json.loads(checked('cat '+shlex.quote(G+'/'+folder+'/summary.json')))
        assert summary['completed']
        event('completed_job_retained',name=name)
        return
    r=subprocess.run([SSH,*OPTIONS,HOST,'test ! -e '+shlex.quote(G+'/'+name)+' && cat > '+shlex.quote(G+'/'+name)],input=p.read_bytes(),capture_output=True)
    r.check_returncode()
    with (HERE/(name+'.stdout')).open('xb') as out,(HERE/(name+'.stderr')).open('xb') as err:
        proc=subprocess.Popen([SSH,'-n',*OPTIONS,HOST,'sudo -n env PYTHONDONTWRITEBYTECODE=1 python3 -u '+shlex.quote(G+'/'+name)],stdout=out,stderr=err)
        while True:
            try:code=proc.wait(timeout=45);break
            except subprocess.TimeoutExpired:event('job_running',name=name,latest=(HERE/(name+'.stdout')).read_text().splitlines()[-1:])
    event('job_completed',name=name,returncode=code)
    if code:
        print((HERE/(name+'.stderr')).read_text()[-5000:],flush=True)
        raise RuntimeError('Guest follow-up failed: '+name)

def reboot(which):
    old=checked('cat /proc/sys/kernel/random/boot_id').strip()
    checked('sudo -n grub-reboot '+shlex.quote(M[which]['grub_entry']))
    try:remote('sudo -n reboot',20)
    except subprocess.TimeoutExpired:pass
    event('reboot_requested',kernel=M[which]['kernel'])
    end=time.monotonic()+300
    while time.monotonic()<end:
        time.sleep(4)
        try:r=remote('cat /proc/sys/kernel/random/boot_id && uname -r',12)
        except subprocess.TimeoutExpired:continue
        lines=r.stdout.splitlines()
        if r.returncode==0 and len(lines)==2 and lines[0]!=old:
            assert lines[1]==M[which]['kernel'],lines
            event('reboot_ready',boot_id=lines[0],kernel=lines[1]);return
    raise TimeoutError('Guest did not return on requested kernel')

assert checked('hostname').strip()=='kicba-ubuntu26'
assert checked('uname -r').strip()==M['primary']['kernel']
job('guest_original_probe_control.py')
try:
    reboot('secondary');job('guest_oem_dynamic.py')
finally:
    running=checked('uname -r').strip()
    if running!=M['primary']['kernel']:reboot('primary')

health_code="""import json,subprocess;from pathlib import Path
modules=[r.split()[0] for r in Path('/proc/modules').read_text().splitlines()]
research=[m for m in modules if m.startswith(('kicba_','phase2_','caraxes','diamorphine'))]
routes=[subprocess.check_output(['ip',*v,'route','show','default'],text=True).strip() for v in ([],['-6'])]
probes=Path('/sys/kernel/tracing/kprobe_events').read_text()
owned=[r for r in probes.splitlines() if any(x in r for x in ('bcc_','kicba_','packed_enter','packed_return','d9_filldir'))]
d=dict(kernel=subprocess.check_output(['uname','-r'],text=True).strip(),boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),research_modules=research,default_routes=routes,research_probes=owned)
d['passed']=not research and not any(routes) and not owned and d['kernel']=='7.0.0-43-generic'
Path('/home/kicba/ubuntu26_20261114/followup_20261115/final_health.json').write_text(json.dumps(d,indent=2));print(json.dumps(d));assert d['passed']
"""
event('final_health',record=checked('sudo -n python3 -c '+shlex.quote(health_code)))
manifest_code="""import json,hashlib,shutil;from pathlib import Path
t=Path('/home/kicba/ubuntu26_20261114/followup_20261115')
b=Path('/home/kicba/research_phase2_20261023')
frozen=t/'sources/frozen_existing';frozen.mkdir()
for name in ('collector/bpf_d9_reconciliation.c','collector/d9_reconciliation_hash.h','collector/d9_enum_probe.c','collector/bin/d9_enum_probe','src/kicba/reconciliation.py','attack_variants/d7_controls_r2/kicba_d7_hiding.ko','phase2/measurement.py','phase2/run_campaign.py','phase2/bpf_packed.c','phase2/enum_dynamic.c','phase2/bin/enum_dynamic','phase1/run_experiments.py','phase1/coverage.py'):
 p=frozen/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(b/name,p)
excluded=[t/'fixtures',t/'oem_dynamic/fixture_ext4',t/'oem_dynamic/fixture_tmpfs']
files={p.relative_to(t).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in t.rglob('*') if p.is_file() and not p.is_symlink() and not any(x in p.parents for x in excluded)}
(t/'EVIDENCE_MANIFEST.json').write_text(json.dumps(files,indent=2));print(len(files))
"""
checked('sudo -n python3 -c '+shlex.quote(manifest_code),60)
archive=G+'_evidence.tar.gz'
checked('test ! -e '+shlex.quote(archive)+' && sudo -n tar --exclude=./fixtures --exclude=./oem_dynamic/fixture_ext4 --exclude=./oem_dynamic/fixture_tmpfs -czf '+shlex.quote(archive)+' -C '+shlex.quote(G)+' . && sudo -n chmod 0644 '+shlex.quote(archive),120)
expected=checked('sha256sum '+shlex.quote(archive)).split()[0]
local=HERE/'followup_evidence.tar.gz';assert not local.exists()
scp=str(Path(SSH).with_name('scp.exe'))
subprocess.run([scp,'-q',*OPTIONS,HOST+':'+archive,str(local)],check=True,timeout=180)
assert hashlib.sha256(local.read_bytes()).hexdigest()==expected
dest=HERE/'evidence';dest.mkdir()
with tarfile.open(local,'r:gz') as tar:
    for member in tar.getmembers():
        path=(dest/member.name).resolve()
        assert path==dest.resolve() or dest.resolve() in path.parents
        assert not member.issym() and not member.islnk()
        assert member.isdir() or member.isfile()
    tar.extractall(dest,filter='data')
manifest=json.loads((dest/'EVIDENCE_MANIFEST.json').read_text())
for name,digest in manifest.items():assert hashlib.sha256((dest/name).read_bytes()).hexdigest()==digest,name
(HERE/'DOWNLOAD_VERIFICATION.json').write_text(json.dumps(dict(passed=True,archive_sha256=expected,files_checked=len(manifest)),indent=2))
event('evidence_downloaded_verified',files=len(manifest),archive_sha256=expected)
