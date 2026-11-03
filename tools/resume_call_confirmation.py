"""Retain complete third-boot data after reporting-pipe failure; finish cost."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    parser=argparse.ArgumentParser()
    for key in ('ssh','scp','key','known-hosts','host'):parser.add_argument('--'+key,required=True)
    parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    opts=['-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+args.known_hosts,
          '-o','ConnectTimeout=5','-o','LogLevel=ERROR','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=4','-i',args.key]
    root='/home/kicba/call_completion_20261103'
    def remote(command,stdin=None,timeout=1200):
        return subprocess.run([args.ssh,*opts,args.host,command],input=stdin,capture_output=True,text=True,timeout=timeout)
    inspection='''import json,subprocess
from pathlib import Path
root=Path('/home/kicba/call_completion_20261103')
folder=root/'boot_03_regression'
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
assert boot==json.loads((folder/'manifest.json').read_text())['boot_id']
assert boot==json.loads((root/'boot_03_public/manifest.json').read_text())['boot_id']
rows=[json.loads(s) for s in (folder/'observations.jsonl').read_text().splitlines()]
assert len(rows)==799 and sum(r['kind']=='assessment' for r in rows)==320
cleanup=json.loads((folder/'cleanup.json').read_text());assert all(cleanup.values())
failure=json.loads((folder/'failure.json').read_text());assert failure['error']=="BrokenPipeError(32, 'Broken pipe')"
modules=Path('/proc/modules').read_text();assert not any(s in modules for s in ('caraxes ','kicba_entry_fault ','phase2_transform ','kicba_d7_','kicba_d8_','kicba_d9_'))
assert str(root/'boot_03_regression/tmpfs') not in Path('/proc/mounts').read_text()
result=dict(boot_id=boot,rows=len(rows),assessments=320,cleanup=cleanup,failure=failure,process_completed=True,continuation='complete only the unstarted cost run; no regression replacement')
(root/'TRANSPORT_RECOVERY.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result))
'''
    first=remote('sudo -n python3 -',inspection)
    (args.output/'transport_recovery_inspection.stdout').write_text(first.stdout,encoding='utf-8')
    (args.output/'transport_recovery_inspection.stderr').write_text(first.stderr,encoding='utf-8')
    if first.returncode:raise RuntimeError(first.stderr)
    print(first.stdout,flush=True)
    start=time.monotonic()
    result=remote(f'cd {root}/code && sudo -n python3 call_completion/run_cost.py --output {root}/boot_03_cost --boot-index 3 > {root}/boot_03_cost.runner.stdout 2> {root}/boot_03_cost.runner.stderr')
    for stream in ('stdout','stderr'):(args.output/('resumed_cost.'+stream)).write_text(getattr(result,stream),encoding='utf-8')
    if result.returncode:raise RuntimeError('resumed cost failed: '+result.stderr)
    print(json.dumps(dict(event='cost_completed',elapsed_seconds=time.monotonic()-start)),flush=True)
    result=remote(f'sudo -n chown -R kicba:kicba {root} && tar -h --exclude="*/boot_*_cost/entries_*" --exclude="*/pilot_cost_*/entries_*" -czf {root}.tar.gz -C /home/kicba call_completion_20261103 && sha256sum {root}.tar.gz')
    if result.returncode:raise RuntimeError(result.stderr)
    archive=args.output/'call_completion_20261103.tar.gz'
    subprocess.run([args.scp,'-q',*opts,args.host+':'+root+'.tar.gz',str(archive)],check=True)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest();assert digest==result.stdout.split()[0]
    receipt=dict(archive_sha256=digest,bytes=archive.stat().st_size,third_regression_not_rerun=True,original_transport_failure_retained=True)
    (args.output/'continuation.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8',newline='\n')
    print(json.dumps(receipt),flush=True)


if __name__=='__main__':main()
