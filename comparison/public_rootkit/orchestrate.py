"""Windows controller for three fresh boots of the authorized isolated VM."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--ssh',required=True);p.add_argument('--scp',required=True)
    p.add_argument('--key',required=True);p.add_argument('--known-hosts',required=True)
    p.add_argument('--host',required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(exist_ok=True,parents=True)
    opts=['-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+a.known_hosts,
          '-o','ConnectTimeout=4','-o','LogLevel=ERROR','-i',a.key]
    def remote(command,timeout=300):
        return subprocess.run([a.ssh,*opts,a.host,command],text=True,capture_output=True,timeout=timeout)
    log=[]
    def emit(row):
        log.append(row);(a.output/'orchestration.json').write_text(json.dumps(log,indent=2))
        print(json.dumps(row),flush=True)
    previous=remote('cat /proc/sys/kernel/random/boot_id').stdout.strip()
    for index in (1,2,3):
        result=remote('sudo -n reboot',timeout=15)
        emit(dict(event='reboot_requested',index=index,returncode=result.returncode,previous_boot=previous))
        boot=None
        for attempt in range(60):
            time.sleep(2)
            result=remote('cat /proc/sys/kernel/random/boot_id',timeout=8)
            candidate=result.stdout.strip()
            if result.returncode==0 and candidate and candidate!=previous:
                boot=candidate;break
        if boot is None:raise RuntimeError('guest did not return with a fresh boot')
        previous=boot;emit(dict(event='fresh_boot',index=index,boot_id=boot))
        tag=f'boot_{index:02d}'
        command=(f'sudo -n python3 /home/kicba/public_sample_20261102/setup/run_native.py '
                 f'--root /home/kicba/public_sample_20261102 '
                 f'--output /home/kicba/public_sample_20261102/{tag} --boot-index {index}')
        result=remote(command)
        (a.output/(tag+'.stdout')).write_text(result.stdout)
        (a.output/(tag+'.stderr')).write_text(result.stderr)
        emit(dict(event='confirmation_completed',index=index,boot_id=boot,returncode=result.returncode,
                  stdout=result.stdout[-600:],stderr=result.stderr[-600:]))
        if result.returncode:raise RuntimeError('confirmation failed; retained, no automatic replacement')
    result=remote('sudo -n chown -R kicba:kicba /home/kicba/public_sample_20261102; '
                  'tar -czf /home/kicba/public_sample_20261102.tar.gz -C /home/kicba public_sample_20261102; '
                  'sha256sum /home/kicba/public_sample_20261102.tar.gz')
    if result.returncode:raise RuntimeError(result.stderr)
    emit(dict(event='archive',guest_sha256=result.stdout.strip()))
    archive=a.output/'public_sample_20261102.tar.gz'
    subprocess.run([a.scp,'-q',*opts,a.host+':/home/kicba/public_sample_20261102.tar.gz',str(archive)],check=True)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    if result.stdout.split()[0]!=digest:raise RuntimeError('archive transfer hash mismatch')
    emit(dict(event='download_verified',sha256=digest,bytes=archive.stat().st_size))

if __name__=='__main__':main()
