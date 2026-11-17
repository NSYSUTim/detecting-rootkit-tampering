"""Retained detector-only assessment from the historical timing protocol."""
import argparse, hashlib, json, os, platform, random, shutil, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / 'src'):
    sys.path.insert(0, str(p))
from finalization import controlled_cases as cases
from phase1.record_environment import inventory
from phase2.run_campaign import manifest
from phase2.oracle import SEED1, SEED2
from kicba.reconciliation import MultisetFingerprint, token_for_entry

def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)

def fingerprint(rows):
    result = MultisetFingerprint()
    for r in rows:
        result.add(token_for_entry(bytes.fromhex(r['name_hex']), r['inode'], r['d_type'], SEED1, SEED2))
    return list(result.as_tuple())

def assess(row, method, fixture, original, target, metrics=None):
    up, down = cases.difference(original, target)
    if method == 'ours':
        r = row.get('result', {})
        elapsed = r.get('benchmark', {}).get('scan_to_verdict_ns')
        good = row['returncode'] == 0 and r.get('verdict') == ('different' if up or down else 'equal') and (r.get('recovery_validation', {}).get('verified') is True) and (not (up or down) or r.get('recovery_verified') is True) and (r.get('upstream_only') == up) and (r.get('downstream_only') == down) and (r.get('kernel_fingerprint') == fingerprint(original)) and ([r.get('userspace', {}).get(k) for k in ('count', 'sum1', 'sum2')] == fingerprint(target))
        return {'execution_valid': row['returncode'] == 0, 'complete': good, 'correct': good, 'scan_to_verdict_ns': elapsed, 'eligible': good and type(elapsed) is int and (elapsed > 0)}
    raise ValueError('External comparison withdrawn')
METHODS = ("ours",)
