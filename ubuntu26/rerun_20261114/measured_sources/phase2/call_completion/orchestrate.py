"""Run three new confirmation boots and preserve every earlier pilot directory."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    parser=argparse.ArgumentParser()
    for key in ('ssh','scp','key','known-hosts','host'):parser.add_argument('--'+key,required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    opts=['-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+args.known_hosts,
          '-o','ConnectTimeout=4','-o','LogLevel=ERROR','-i',args.key]
    root='/home/kicba/call_completion_20261103'
    def remote(command,timeout=1200):
        return subprocess.run([args.ssh,*opts,args.host,command],capture_output=True,text=True,timeout=timeout)
    records=[]
    def emit(record):
        records.append(record)
        (args.output/'orchestration.json').write_text(json.dumps(records,indent=2),encoding='utf-8',newline='\n')
        print(json.dumps(record),flush=True)
    previous=remote('cat /proc/sys/kernel/random/boot_id').stdout.strip()
    for index in (1,2,3):
        result=remote('sudo -n reboot',20)
        emit(dict(event='reboot',index=index,returncode=result.returncode))
        for attempt in range(65):
            time.sleep(2)
            result=remote('cat /proc/sys/kernel/random/boot_id',10)
            boot=result.stdout.strip()
            if result.returncode==0 and boot and boot!=previous:break
        else:raise RuntimeError('fresh boot unavailable')
        previous=boot;emit(dict(event='fresh_boot',index=index,boot_id=boot))
        for kind,script,extra in [('public','run_public_sample.py','--root /home/kicba/public_sample_20261102 '),
                                  ('regression','run_regression.py',''),('cost','run_cost.py','')]:
            start=time.monotonic()
            result=remote(f'cd {root}/code && sudo -n python3 call_completion/{script} {extra}--output {root}/boot_{index:02d}_{kind} --boot-index {index}')
            for stream in ('stdout','stderr'):
                (args.output/f'boot_{index:02d}_{kind}.{stream}').write_text(getattr(result,stream),encoding='utf-8',newline='\n')
            emit(dict(event='completed',index=index,kind=kind,returncode=result.returncode,
                      elapsed_seconds=round(time.monotonic()-start,2),stderr=result.stderr[-1500:]))
            if result.returncode:raise RuntimeError('confirmation failed; failed attempt preserved')
    # Empty timing fixtures are omitted, not observations or source files.
    result=remote(f'sudo -n chown -R kicba:kicba {root} && tar -h --exclude="*/boot_*_cost/entries_*" --exclude="*/pilot_cost_*/entries_*" -czf {root}.tar.gz -C /home/kicba call_completion_20261103 && sha256sum {root}.tar.gz')
    if result.returncode:raise RuntimeError(result.stderr)
    archive=args.output/'call_completion_20261103.tar.gz'
    subprocess.run([args.scp,'-q',*opts,args.host+':'+root+'.tar.gz',str(archive)],check=True)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest!=result.stdout.split()[0]:raise RuntimeError('transfer checksum mismatch')
    emit(dict(event='download_verified',sha256=digest,bytes=archive.stat().st_size))


if __name__=='__main__':main()
