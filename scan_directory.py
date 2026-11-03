"""Current scanner entry point; historical campaign entry points stay frozen."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent
for directory in (ROOT,ROOT/'src'):sys.path.insert(0,str(directory))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--probe',type=Path,required=True)
    parser.add_argument('--buffer-size',type=int,default=65536)
    parser.add_argument('--accepted-only',action='store_true',
                        help='run only the retained accepted-item identity check')
    args=parser.parse_args()
    if os.name!='posix' or os.geteuid()!=0:parser.error('requires root in the Linux research VM')
    if not args.directory.is_dir() or not args.probe.is_file():parser.error('directory or scanner unavailable')
    if args.accepted_only:
        from finalization.tracefs_measurement import new_measurement,CompleteMeasurement
    else:
        from call_completion.measurement import new_call_measurement as new_measurement,CallMeasurement as CompleteMeasurement
    try:
        with new_measurement(probe=args.probe) as base:
            result=CompleteMeasurement(base).scan(args.directory,args.buffer_size)
    except Exception as error:
        result={'verdict':'invalid','measurement_valid':False,'alarm':None,
                'recovery_verified':False,'error':str(error)}
    print(json.dumps(result,ensure_ascii=True))
    return 2 if result['verdict'] in ('invalid','inconclusive') else 0


if __name__=='__main__':raise SystemExit(main())
