"""Calculate report values from the downloaded Ubuntu 26 observations."""
import csv
import gzip
import hashlib
import json
from pathlib import Path
from statistics import median, mean
import tarfile
TASK = Path(__file__).resolve().parents[1]
OBS = TASK / 'observations'

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def jsonlines(path):
    with path.open(encoding='utf-8') as data:
        return [json.loads(line) for line in data if line.strip()]

def boots(suite, file):
    return [OBS / suite / f'boot_{index:02d}' / file for index in (1, 2, 3)]

def rows_by_boot(suite, file):
    return [jsonlines(path) for path in boots(suite, file)]

def summaries(suite, file='summary.json'):
    return [read(path) for path in boots(suite, file)]

def archived_json(archive, suffix):
    with tarfile.open(archive, 'r:gz') as bundle:
        selected = [member for member in bundle.getmembers() if member.isfile() and member.name.endswith(suffix)]
        if len(selected) != 1:
            raise RuntimeError(f'{archive.name} has {len(selected)} copies of {suffix}')
        with bundle.extractfile(selected[0]) as stream:
            return json.load(stream)

def span(values, divisor=1):
    return [min(values) / divisor, max(values) / divisor] if values else None

def exact_trace():
    data = read(OBS / 'exact_trace/exact_trace_baseline.json')
    values = {}
    for size in (8192, 65536):
        for mode in ('full_d9', 'exact_accepted_map_trace'):
            rows = [r for r in data['rows'] if r['cardinality'] == size and r['condition'] == 'baseline' and (r['mode'] == mode)]
            byte_key = 'logical_payload_bytes' if mode == 'full_d9' else 'logical_trace_payload_bytes'
            values[f'{size}/{mode}'] = {'time_ms': median((r['wall_ns'] / r['iterations'] / 1000000.0 for r in rows)), 'logical_kib': median((t[byte_key] / 1024 for r in rows for t in r['detail']))}
    return values

def phase1():
    coverage, fidelity = ([], [])
    for index in (1, 2, 3):
        package = OBS / f'phase1/confirmation_boot_{index:02d}.tar.gz'
        coverage.append(archived_json(package, '/coverage_summary.json'))
        fidelity.append(archived_json(package, '/fidelity_summary.json'))
    return {'coverage': coverage, 'fidelity': fidelity}

def phase2():
    results = {}
    for env in ('ubuntu26_generic', 'ubuntu26_oem'):
        rows = []
        for index in (1, 2, 3):
            archive = OBS / f'phase2/confirmation_{env}_boot_{index:02d}.tar.gz'
            summary = archived_json(archive, f'/confirmation_boot_{index:02d}/summary.json')
            quality = summary['quality']
            differences = sum((g.get('different', 0) for g in quality['static_groups'].values()))
            rows.append({'completed': summary['completed'], 'boot_id': summary['boot_id'], 'static_measured': quality['static_measured'], 'static_controls': quality['static_controls'], 'static_differences': differences, 'dynamic': quality['dynamic'], 'dynamic_invalid': quality['dynamic_invalid'], 'dynamic_difference': quality['dynamic_difference'], 'dynamic_not_exercised':quality['dynamic_not_exercised'], 'not_exercised': quality['not_exercised'], 'criteria': summary['criteria']})
        results[env] = rows
    return results

def decloaker():
    batches = []
    ids = set()
    for idx in range(1, 10):
        path = OBS / f'decloaker/boot_{idx:02d}/campaign.json.gz'
        sidecar = path.with_name('campaign.sha256').read_text().split()[0]
        if hashlib.sha256(path.read_bytes()).hexdigest() != sidecar:
            raise RuntimeError('Decloaker checksum mismatch')
        with gzip.open(path, 'rt') as stream:
            data = json.load(stream)
        ids.add(data['environment']['boot_id'])
        batches.extend(data['rows'])
    positive = [row for row in batches if row['expected_positive']]
    negative = [row for row in batches if not row['expected_positive']]
    return {'boots': len(ids), 'rows': len(batches), 'positive': len(positive), 'negative': len(negative), 'detected': sum((r['detected'] is True for r in positive)), 'false_alerts': sum((r['detected'] is True for r in negative)), 'failed': sum((r['returncode'] != 0 for r in batches))}

def call_cost():
    groups = (128, 4096, 65536)
    data = {size: {'accepted_ns': [], 'completion_ns': [], 'paired_ratios': []} for size in groups}
    for boot in rows_by_boot('call_cost', 'observations.jsonl'):
        for size in groups:
            timings = {}
            for row in boot:
                if row['size'] == size and (not row['warmup']):
                    timings.setdefault(row['block'], {})[row['version']] = row['paired_ready_ns']
            if len(timings) != 5 or any((set(t) != {'accepted_only', 'call_completion'} for t in timings.values())):
                raise RuntimeError('Incomplete paired timing')
            data[size]['accepted_ns'].append(median((t['accepted_only'] for t in timings.values())))
            data[size]['completion_ns'].append(median((t['call_completion'] for t in timings.values())))
            data[size]['paired_ratios'].append(median((t['call_completion'] / t['accepted_only'] for t in timings.values())))
    return data

def regression_counts():
    from collections import Counter
    output = {}
    for key in ('call_regression', 'caraxes_call', 'caraxes_accepted'):
        rows = [row for boot in rows_by_boot(key, 'observations.jsonl') for row in boot]
        groups = {}
        for row in rows:
            mode = row.get('mode', row.get('kind'))
            group = groups.setdefault(mode, {'n': 0, 'verdicts': Counter(), 'alarms': 0})
            group['n'] += 1
            group['verdicts'][row.get('verdict')] += 1
            group['alarms'] += row.get('alarm') is True
        output[key] = groups
    return output

def legacy_cost():
    rows = read(OBS / 'legacy_cost/overhead.json')['rows']
    baseline = [r for r in rows if r['condition'] == 'baseline' and r['cardinality'] == 65536]
    times = {mode: median((r['wall_ns'] / r['iterations'] for r in baseline if r['mode'] == mode)) for mode in ('raw_count', 'full_d9')}
    return {'full_over_raw': times['full_d9'] / times['raw_count']}

def trace():
    result = {}
    for method in ('fun', 'seq'):
        path = OBS / f'trace_of_times/evaluation_four_{method}/results_offline_best_shift_{method}.csv'
        with path.open(encoding='utf-8', newline='') as file:
            records = list(csv.DictReader(file))
        if len(records) != 100:
            raise RuntimeError('Trace evaluator did not complete 100 repeats')
        result[method] = {'recall':mean(float(row['tpr']) for row in records),
                          'fpr':mean(float(row['fpr']) for row in records)}
    return result

def calculate():
    sections = {'matrix': lambda: read(OBS / 'matrix/results.json'), 'phase1': phase1, 'phase2': phase2, 'decloaker': decloaker, 'exact_trace': exact_trace, 'legacy_cost': legacy_cost, 'call_cost': call_cost, 'regressions': regression_counts, 'trace': trace, 'capacity': lambda: read(OBS / 'iblt_capacity/capacity.json'), 'capacity_additional': lambda: read(OBS / 'iblt_table8_2/summary.json')}
    output = {}
    missing = {}
    for name, calculate_section in sections.items():
        try:
            output[name] = calculate_section()
        except (FileNotFoundError, RuntimeError, KeyError, ValueError) as exc:
            missing[name] = str(exc)
    return {'results': output, 'missing': missing}
if __name__ == '__main__':
    report = calculate()
    target = TASK / 'REPORT_EVIDENCE_VALUES.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'available': list(report['results']), 'missing': report['missing']}, ensure_ascii=False))
