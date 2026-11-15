import ast
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from remote_job import SSH,OPTIONS,HOST
G='/home/kicba/ubuntu26_20261114/followup_20261115'

def remote(command,timeout=30):
    return subprocess.run([SSH,'-n',*OPTIONS,HOST,command],capture_output=True,text=True,timeout=timeout)

def main():
    source=HERE/'guest_forensics.py';ast.parse(source.read_text(encoding='utf-8'))
    before=remote('hostname && uname -r && cat /proc/sys/kernel/random/boot_id')
    assert before.returncode==0 and before.stdout.splitlines()[:2]==['kicba-ubuntu26','7.0.0-43-generic']
    check=remote('test ! -e '+shlex.quote(G)+' && mkdir '+shlex.quote(G))
    check.check_returncode()
    upload=subprocess.run([SSH,*OPTIONS,HOST,'cat > '+shlex.quote(G+'/guest_forensics.py')],input=source.read_bytes(),capture_output=True)
    upload.check_returncode()
    (HERE/'HOST_START.json').write_text(json.dumps(dict(guest_before=before.stdout,
        guest_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())),indent=2))
    command='sudo -n env PYTHONDONTWRITEBYTECODE=1 python3 -u '+shlex.quote(G+'/guest_forensics.py')
    with (HERE/'forensics.stdout').open('xb') as out,(HERE/'forensics.stderr').open('xb') as err:
        p=subprocess.Popen([SSH,'-n',*OPTIONS,HOST,command],stdout=out,stderr=err)
        while True:
            try:rc=p.wait(timeout=45);break
            except subprocess.TimeoutExpired:
                lines=(HERE/'forensics.stdout').read_text().splitlines()
                print(json.dumps(dict(running=True,latest=lines[-1:])),flush=True)
    result=dict(returncode=rc,finished_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
    (HERE/'HOST_FINISH.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
    if rc:print((HERE/'forensics.stderr').read_text()[-4000:]);raise SystemExit(rc)

if __name__=='__main__':main()
