"""Resume the unchanged collector after its already recorded strict failure.

No failed batch is replaced. The original valid flag (including exact recovery)
is retained, while collection continues to all prospectively specified indices.
"""
import json
from pathlib import Path
import runpy
import sys
import time

B=Path('/home/kicba/research_phase2_20261023')
sys.path[:0]=[str(B),str(B/'collector'),str(B/'src')]
source=B/'collector/run_d9_external_matrix.py'
namespace=runpy.run_path(str(source),run_name='locked_d9_collector')
output=Path(sys.argv[sys.argv.index('--output')+1])
before=len(list(output.glob('batch_*.json.gz')))
for attempt in range(1001):
    try:
        namespace['main']()
        print(json.dumps({'resumed_collection_complete':True,'preserved_initial_batches':before,
            'final_batches':len(list(output.glob('batch_*.json.gz'))),'strict_failures_retained':True}),flush=True)
        break
    except RuntimeError as exc:
        if not str(exc).startswith('invalid D9 batch:'):raise
        after=len(list(output.glob('batch_*.json.gz')))
        if after<=before:raise RuntimeError('Collector failed without recording a new batch') from exc
        print(json.dumps({'recorded_strict_failure':str(exc),'batches_preserved':after}),flush=True)
        before=after
else:
    raise RuntimeError('Collection exceeded the original batch grid')
