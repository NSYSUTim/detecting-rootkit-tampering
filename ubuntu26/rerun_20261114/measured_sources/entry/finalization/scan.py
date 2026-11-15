"""Read one directory with the retained collector and completion checks."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, ROOT / "src"):
    sys.path.insert(0, str(directory))

from finalization.measurement import CheckedMeasurement


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--probe", required=True, type=Path,
                        help="Existing phase1/enum_probe.c executable; no installation or upgrade")
    parser.add_argument("--buffer-size", type=int, default=65536)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("requires root inside the existing Linux research VM")
    if not args.probe.is_file():
        parser.error("scanner executable unavailable")
    from phase2.measurement import Measurement
    with Measurement("packed", probe=args.probe) as base:
        result = CheckedMeasurement(base).scan(args.directory, args.buffer_size)
    print(json.dumps(result, ensure_ascii=True))
    return 2 if result["verdict"] == "invalid" else 0


if __name__ == "__main__":
    raise SystemExit(main())
