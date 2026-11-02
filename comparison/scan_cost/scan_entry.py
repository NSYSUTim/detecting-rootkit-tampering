"""Time the unchanged current collector from ready observation to verdict."""
import argparse,json,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
for p in (ROOT,ROOT/'src'):sys.path.insert(0,str(p))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path);p.add_argument('--probe',type=Path,required=True)
    args=p.parse_args()
    from finalization.tracefs_measurement import new_measurement,CompleteMeasurement
    prepared=time.monotonic_ns()
    with new_measurement(probe=args.probe) as base:
        checked=CompleteMeasurement(base)
        preparation_ns=time.monotonic_ns()-prepared
        start=time.monotonic_ns()
        row=checked.scan(args.directory,65536)
        elapsed=time.monotonic_ns()-start
        row['benchmark']={'scan_to_verdict_ns':elapsed,'preparation_ns':preparation_ns,
            'scope':'ready observation through complete scan, comparison and required checks; final report IO and detach excluded'}
    print(json.dumps(row))
    return 2 if row['verdict']=='invalid' else 0


if __name__=='__main__':raise SystemExit(main())
