"""Run three fresh confirmation boots, preserving failures and transfer hashes."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    for k in ('ssh','scp','key','known-hosts','host'):p.add_argument('--'+k,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    opts=['-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+a.known_hosts,
          '-o','ConnectTimeout=4','-o','LogLevel=ERROR','-i',a.key]
    def remote(command,timeout=900):return subprocess.run([a.ssh,*opts,a.host,command],text=True,capture_output=True,timeout=timeout)
    records=[]
    def emit(row):
        records.append(row);(a.output/'orchestration.json').write_text(json.dumps(records,indent=2),newline='\n')
        print(json.dumps(row),flush=True)
    root='/home/kicba/terminal_rejection_20261103'
    previous=remote('cat /proc/sys/kernel/random/boot_id').stdout.strip()
    for index in (1,2,3):
        r=remote('sudo -n reboot',20);emit({'event':'reboot','index':index,'returncode':r.returncode})
        for attempt in range(65):
            time.sleep(2);r=remote('cat /proc/sys/kernel/random/boot_id',10)
            boot=r.stdout.strip()
            if r.returncode==0 and boot and boot!=previous:break
        else:raise RuntimeError('fresh boot unavailable')
        previous=boot;emit({'event':'fresh_boot','index':index,'boot_id':boot})
        for kind in ('public','regression'):
            name='run_public_sample.py' if kind=='public' else 'run_regression.py'
            args='--root /home/kicba/public_sample_20261102 ' if kind=='public' else ''
            command=f'cd {root}/code && sudo -n python3 terminal_rejection/{name} {args}--output {root}/boot_{index:02d}_{kind} --boot-index {index}'
            r=remote(command)
            for stream in ('stdout','stderr'):(a.output/f'boot_{index:02d}_{kind}.{stream}').write_text(getattr(r,stream),newline='\n')
            emit({'event':'completed','index':index,'kind':kind,'returncode':r.returncode,'stderr':r.stderr[-1000:]})
            if r.returncode:raise RuntimeError('confirmation failed; original attempt retained')
    r=remote(f'sudo -n chown -R kicba:kicba {root} && tar -czf {root}.tar.gz -C /home/kicba terminal_rejection_20261103 && sha256sum {root}.tar.gz')
    if r.returncode:raise RuntimeError(r.stderr)
    archive=a.output/'terminal_rejection_20261103.tar.gz'
    subprocess.run([a.scp,'-q',*opts,a.host+':'+root+'.tar.gz',str(archive)],check=True)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest();assert digest==r.stdout.split()[0]
    emit({'event':'download_verified','sha256':digest,'bytes':archive.stat().st_size})
if __name__=='__main__':main()
