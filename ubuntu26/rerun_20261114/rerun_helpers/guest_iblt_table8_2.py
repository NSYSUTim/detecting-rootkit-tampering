"""Repeat the report's six pure-removal settings with recorded seeds."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import random
import sys

B = Path("/home/kicba/research_phase2_20261023")
G = Path("/home/kicba/ubuntu26_20261114")
sys.path[:0] = [str(B / "src"), str(B / "scripts")]
from evaluate_d9_iblt_capacity import _tokens
from kicba.reconciliation import IBLT

settings = [(64, 32, 400), (256, 32, 400), (2048, 1000, 200),
            (2048, 1500, 200), (2048, 1600, 200), (2048, 1700, 200)]
master_seed = 20261114
out = G / "observations/iblt_table8_2"
out.mkdir(parents=True, exist_ok=False)
protocol = {"master_seed": master_seed, "settings": settings, "kernel": platform.release(),
            "python": sys.version, "scope": "Report Table 8-2 design with newly seeded independent pure-removal trials",
            "iblt_sha256": hashlib.sha256((B / "src/kicba/reconciliation.py").read_bytes()).hexdigest(),
            "started_utc": datetime.now(timezone.utc).isoformat()}
(out / "protocol.json").write_text(json.dumps(protocol, indent=2))
rows = []
with (out / "trials.jsonl").open("x") as stream:
    for group, (cells, differences, count) in enumerate(settings):
        totals = {"fully_recovered": 0, "incorrect_successes": 0}
        for trial in range(count):
            seed = master_seed + group * 10000019 + trial * 104729
            rng = random.Random(seed)
            seed1, seed2 = rng.getrandbits(64), rng.getrandbits(64)
            expected = _tokens(rng, differences, set())
            table = IBLT(cells, seed1, seed2)
            for token in expected:
                table.add(token, 1)
            recovered = table.decode()
            exact = set(recovered.upstream_only) == set(expected) and not recovered.downstream_only
            totals["fully_recovered"] += recovered.success and exact
            totals["incorrect_successes"] += recovered.success and not exact
            stream.write(json.dumps({"cells": cells, "differences": differences, "trial": trial,
                                     "seed": seed, "decode_success": recovered.success, "exact": exact,
                                     "residual_cells": recovered.residual_cells}) + "\n")
        stream.flush()
        row = {"cells": cells, "differences": differences, "trials": count, **totals}
        rows.append(row)
        print(json.dumps(row), flush=True)
(out / "summary.json").write_text(json.dumps(rows, indent=2))
