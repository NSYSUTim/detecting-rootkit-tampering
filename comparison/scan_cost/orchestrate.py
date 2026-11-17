# Historical source retained after a comparison was withdrawn.
# Its original paragraph offsets and archived source hashes no longer
# describe the public copy. Do not regenerate historical reports.
if __name__ == "__main__":
    raise SystemExit("Historical generator retired after selective public cleanup")
"""Run three additive confirmation boots, with bounded SSH calls and logs."""
import argparse, json, subprocess, time
from pathlib import Path
from datetime import datetime, timezone

def main():
    p = argparse.ArgumentParser()
    for name in ('ssh', 'key', 'known-hosts', 'host', 'output'):
        p.add_argument('--' + name, required=True)
    args = p.parse_args()
    ssh = [args.ssh, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + args.known_hosts, '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR', '-i', args.key, args.host]
    root = '/home/kicba/scan_cost_20261102/confirmation_r3'

    def remote(cmd, timeout=30):
        return subprocess.run([*ssh, cmd], capture_output=True, text=True, timeout=timeout)
    with Path(args.output).open('x', encoding='utf-8', newline='\n') as log:

        def emit(kind, **data):
            row = {'time': datetime.now(timezone.utc).isoformat(), 'kind': kind, **data}
            log.write(json.dumps(row) + '\n')
            log.flush()
            print(json.dumps(row), flush=True)
        package_hash = None
        ids = []
        for index in (1, 2, 3):
            pre = remote("uname -r; cat /proc/sys/kernel/random/boot_id; dpkg-query -W | sha256sum; lsmod | grep -E '^(phase2_transform|kicba_d7|kicba_d8|kicba_d9|kicba_entry_fault) ' || true")
            values = pre.stdout.splitlines()
            if pre.returncode or len(values) != 3 or values[0] != '6.8.0-138-generic' or (values[1] in ids):
                raise RuntimeError('preflight failed ' + pre.stdout)
            if package_hash is None:
                package_hash = values[2]
            if values[2] != package_hash:
                raise RuntimeError('packages changed')
            ids.append(values[1])
            emit('start', index=index, boot_id=values[1], packages=package_hash)
            cmd = f'cd {root} && sudo -n env PYTHONDONTWRITEBYTECODE=1 python3 comparison/scan_cost/run.py --output /home/kicba/scan_cost_20261102/boot_{index:02d}{index} > /home/kicba/scan_cost_20261102/boot_{index:02d}.stdout 2> /home/kicba/scan_cost_20261102/boot_{index:02d}.stderr'
            result = remote(cmd, timeout=1200)
            if result.returncode:
                raise RuntimeError('campaign failed ' + result.stderr)
            summary = json.loads(remote(f'cat /home/kicba/scan_cost_20261102/boot_{index:02d}/summary.json').stdout)
            emit('complete', index=index, summary=summary)
            if not summary['finished']:
                raise RuntimeError('confirmation did not finish')
            if index == 3:
                break
            remaining = remote("ps -eo comm | grep -x d9_enum_probe; lsmod | grep -E '^(phase2_transform|kicba_d7|kicba_d8|kicba_d9|kicba_entry_fault) ' || true")
            if remaining.stdout.strip():
                raise RuntimeError('research process remains')
            remote('sudo -n reboot')
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                time.sleep(3)
                r = remote('cat /proc/sys/kernel/random/boot_id')
                if r.returncode == 0 and r.stdout.strip() not in ids:
                    break
            else:
                raise RuntimeError('new boot unavailable')
        emit('all_complete', boot_ids=ids)
if __name__ == '__main__':
    main()
