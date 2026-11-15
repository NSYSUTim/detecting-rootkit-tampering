"""Execute the locked IBLT grid on the Ubuntu 26 interpreter."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import sys

T = Path("/home/kicba/ubuntu26_20261114")
B = Path("/home/kicba/research_phase2_20261023")
bundle = B / "results/iblt_hash_count_20261113"
out = T / "observations/iblt_hash_count"
out.mkdir(parents=True, exist_ok=False)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

protocol = json.loads((bundle / "protocol.json").read_text())
original_hash = sha(bundle / "protocol.json")
if original_hash != "472342278a42d6034ac267100c589a9c8e2b89c88ea9f442232db8916dcba690":
    raise RuntimeError("Frozen protocol differs")
for name, field in (("reconciliation_snapshot.py", "snapshot_sha256"), ("run_experiment.py", "script_sha256")):
    if sha(bundle / name) != protocol[field]:
        raise RuntimeError("Frozen input changed: " + name)
    shutil.copy2(bundle / name, out / name)
protocol.update(original_protocol_sha256=original_hash,
                locked_utc=datetime.now(timezone.utc).isoformat(),
                environment={"python": sys.version, "platform": platform.platform(), "processor": platform.processor()})
protocol_path = out / "protocol.json"
protocol_path.write_text(json.dumps(protocol, indent=2, ensure_ascii=False) + "\n")
(out / "protocol.sha256").write_text(sha(protocol_path) + "\n")
spec = importlib.util.spec_from_file_location("ubuntu26_iblt_grid", out / "run_experiment.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
runner.SOURCE = bundle / "reconciliation_snapshot.py"
runner.run()
