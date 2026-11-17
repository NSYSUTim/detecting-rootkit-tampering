"""Retained detector-only timing and exact-coverage assessment helpers.

The mixed-method recomputation was withdrawn with its external comparison.
Archive preservation is verified by docs/PUBLIC_CLEANUP_20261117.json.
"""
import argparse, gzip, hashlib, io, json, random, statistics, sys, tarfile
from collections import Counter
from pathlib import Path, PurePosixPath
ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / 'src'):
    sys.path.insert(0, str(p))
from comparison.scan_cost.run import METHODS, assess, fingerprint
from finalization.controlled_cases import expected, identities

def distribution(values):
    if not values:
        return None
    q = statistics.quantiles(values, n=4, method='inclusive') if len(values) > 1 else [values[0]] * 3
    return {'n': len(values), 'median': statistics.median(values), 'q1': q[0], 'q3': q[2], 'min': min(values), 'max': max(values)}

def assess_normal(row, method, wanted_fp, wanted_names, metrics):
    """Independently audit normal scans without rehashing each full input twice."""
    if method == 'ours':
        result = row['result']
        elapsed = result.get('benchmark', {}).get('scan_to_verdict_ns')
        complete = row['returncode'] == 0 and result.get('verdict') == 'equal' and (result.get('recovery_validation', {}).get('verified') is True) and (result.get('upstream_only') == []) and (result.get('downstream_only') == []) and (result.get('kernel_fingerprint') == wanted_fp) and ([result.get('userspace', {}).get(k) for k in ('count', 'sum1', 'sum2')] == wanted_fp)
        return {'execution_valid': row['returncode'] == 0, 'complete': complete, 'correct': complete, 'scan_to_verdict_ns': elapsed, 'eligible': complete and type(elapsed) is int and (elapsed > 0)}
    raise ValueError('External comparison withdrawn')
