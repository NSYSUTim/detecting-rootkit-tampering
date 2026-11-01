"""Continue the predeclared three-boot comparison on one existing lab VM."""
import argparse,json,subprocess,time
from datetime import datetime,timezone
from pathlib import Path


def main():
    p=argparse.ArgumentParser();p.add_argument('--ssh',required=True);p.add_argument('--key',required=True)
    p.add_argument('--known-hosts',required=True);p.add_argument('--host',required=True)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    ssh=[args.ssh,'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
         '-o','UserKnownHostsFile='+args.known_hosts,'-o','ConnectTimeout=5','-o','LogLevel=ERROR','-i',args.key,args.host]
    root='/home/kicba/closure_20261102/current'
    def remote(cmd,timeout=20):return subprocess.run([*ssh,cmd],capture_output=True,text=True,timeout=timeout)
    with args.output.open('x',encoding='utf-8',newline='\n') as stream:
        def log(kind,**data):
            row=dict(time=datetime.now(timezone.utc).isoformat(),kind=kind,**data)
            stream.write(json.dumps(row)+'\n');stream.flush();print(json.dumps(row),flush=True)
        deadline=time.monotonic()+1200
        while time.monotonic()<deadline:
            row=remote(f'cat {root}/comparison_boot_01_r2/summary.json')
            if row.returncode==0:
                summary=json.loads(row.stdout)
                if not summary['execution_passed'] or not summary['adapter_agrees_each_state']:raise RuntimeError('first confirmation did not qualify')
                log('completed',boot_index=1,summary=summary);break
            time.sleep(5)
        else:raise TimeoutError('first confirmation unavailable')
        for index in (2,3):
            before=remote('cat /proc/sys/kernel/random/boot_id').stdout.strip()
            check=remote("ps -eo comm | grep -x d9_enum_probe; lsmod | grep -E '^(phase2_transform|kicba_d7|kicba_d8|kicba_d9|kicba_entry_fault) ' || true")
            if check.stdout.strip():raise RuntimeError('scanner or controlled module still active: '+check.stdout)
            log('reboot_requested',boot_index=index,old_boot_id=before)
            remote('sudo -n reboot')
            deadline=time.monotonic()+240;fresh=None
            while time.monotonic()<deadline:
                time.sleep(3);row=remote('uname -r; cat /proc/sys/kernel/random/boot_id')
                values=row.stdout.splitlines()
                if row.returncode==0 and len(values)==2 and values[1]!=before:
                    if values[0]!='6.8.0-138-generic':raise RuntimeError('kernel changed')
                    fresh=values[1];break
            if not fresh:raise RuntimeError('fresh boot unavailable')
            log('started',boot_index=index,boot_id=fresh)
            name=f'comparison_boot_{index:02d}_r2'
            cmd=(f'cd {root} && sudo -n env PYTHONDONTWRITEBYTECODE=1 python3 finalization/compare_zygarde.py '
                f'--output {name} --base /home/kicba/research_phase2_20261023 --first /home/kicba/research_phase1_20261023 '
                f'--official /home/kicba/closure_20261102/zygarde --adapter /home/kicba/closure_20261102/zygarde_adapter '
                f'--boot-index {index} > {name}.stdout 2> {name}.stderr')
            result=remote(cmd,timeout=1200)
            summary=json.loads(remote(f'cat {root}/{name}/summary.json').stdout)
            log('completed',boot_index=index,returncode=result.returncode,summary=summary)
            if result.returncode or not summary['execution_passed'] or not summary['adapter_agrees_each_state']:raise RuntimeError('confirmation did not qualify')
        log('all_three_complete')


if __name__=='__main__':main()
