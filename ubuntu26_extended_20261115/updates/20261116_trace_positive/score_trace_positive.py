"""Score new positive (rootkit) batches with the archived frozen models.

Mirrors 20261116_trace_normal/score_trace.py but for label='rootkit':
a batch is 'correct_rootkit' when score < threshold (detected) and
'missed_rootkit' otherwise. ls_basic has no model in the original
four-scenario locked split; those batches are descriptive only.
"""
from collections import Counter, defaultdict
import gzip
import hashlib
import json
import math
from pathlib import Path
from statistics import median
import sys

HERE = Path(__file__).resolve().parent
PRIOR = HERE.with_name('ubuntu26_extended_20261115_run02')
sys.dont_write_bytecode = True
sys.path.insert(0, str(PRIOR))
import trace_heldout as frozen
import numpy as np


def read(path):
    return json.loads(path.read_bytes())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def features(raw):
    ordered = defaultdict(list)
    for event in raw['events']:
        ordered[event['pid']].append((event['probe_point'], int(event['timestamp'])))
    paired = {'fun': defaultdict(list), 'seq': defaultdict(list)}
    for events in ordered.values():
        for (first, stamp), (last, end) in zip(events, events[1:]):
            assert end >= stamp
            paired['seq'][f'{first}:{last}'].append(end - stamp)
        starts = {}
        for name, stamp in events:
            if name.endswith('-enter'):
                starts[name] = stamp
            elif name.endswith('-return'):
                first = name.replace('-return', '-enter')
                if (earlier := starts.get(first)) is not None:
                    paired['fun'][f'{first}:{name}'].append(stamp - earlier)
                    starts[first] = None
            else:
                raise ValueError('Unrecognized probe point')
    observations = {mode: {key: (np.quantile(values, frozen.QUANTILES), len(values))
                           for key, values in by_probe.items()} for mode, by_probe in paired.items()}
    return observations, len(ordered), {key: median(samples) for key, samples in paired['fun'].items()}


def rebuild_models():
    original = read(frozen.MANIFEST)
    protocol = read(PRIOR / 'trace_heldout_protocol.json')
    assert protocol['manifest_sha256'] == sha(frozen.MANIFEST.read_bytes())
    split = frozen.split_batches(original)
    assert protocol['splits'] == {s: {part: [r['file'] for r in rows] for part, rows in data.items()}
                                  for s, data in split.items()}
    previous = read(PRIOR / 'trace_frozen_thresholds.json')
    thresholds = {name: values['threshold'] for name, values in previous['thresholds'].items()}
    previous_calibration = {kind: {r['file']: r['min_p'] for r in rows}
                            for kind, rows in previous['calibration_scores'].items()}
    models = {}
    for scenario, parts in split.items():
        learn = [frozen.observations(row) for row in parts['train_normal']]
        models[scenario] = {kind: frozen.fit([x[kind] for x in learn]) for kind in thresholds}
        for row in parts['calibration_normal']:
            sample = frozen.observations(row)
            for kind, threshold in thresholds.items():
                actual = frozen.score(models[scenario][kind], sample[kind])
                expected = previous_calibration[kind][row['file']]
                assert math.isclose(actual, expected, rel_tol=2e-5, abs_tol=1e-40), (actual, expected)
                assert (actual < threshold) == (expected < threshold)
        print(json.dumps({'archived_fit_verified': scenario}), flush=True)
    return models, thresholds


def main():
    folder = HERE / 'evidence'
    protocol = read(folder / 'protocol.json')
    acquisition = read(folder / 'summary.json')
    original_count = protocol['batches_per_scenario']
    assert original_count == 10 and protocol['iterations_per_batch'] == 100
    records = [json.loads(line) for line in (folder / 'collection.jsonl').read_bytes().splitlines()]
    sizes = Counter(r['scenario'] for r in records)
    assert sizes == acquisition['counts'] == {s: original_count for s in protocol['scenarios']}
    assert len({r['file'] for r in records}) == len(records) == 50
    assert {p.name for p in (folder / 'events').glob('*.json.gz')} == {r['file'] for r in records}
    models, thresholds = rebuild_models()
    summary = defaultdict(lambda: defaultdict(Counter))
    features_by_scenario = defaultdict(lambda: defaultdict(list))
    predictions = []
    for row in records:
        compressed = (folder / 'events' / row['file']).read_bytes()
        assert sha(compressed) == row['sha256']
        raw = json.loads(gzip.decompress(compressed))
        scenario = row['scenario']
        assert raw['label'] == 'rootkit' and raw['description'] == scenario and len(raw['events']) == row['events']
        observation, pids, function_durations = features(raw)
        assert raw['iterations'] == pids == row['observed_pids'] == 100
        for key, value in function_durations.items():
            features_by_scenario[scenario][key].append(value)
        for kind, threshold in thresholds.items():
            score = frozen.score(models[scenario][kind], observation[kind]) if scenario in models else None
            state = ('outside_calibrated_scenarios' if scenario not in models else 'invalid'
                     if score is None else 'correct_rootkit' if score < threshold else 'missed_rootkit')
            summary[scenario][kind][state] += 1
            predictions.append({'scenario': scenario, 'file': row['file'], 'sha256': row['sha256'],
                                'method': kind, 'score': score, 'threshold': threshold, 'state': state})
    # Aggregate per-method true positive counts across the four calibrated scenarios.
    per_method = {kind: {'attempted_in_calibrated_scenarios': 0, 'correct_rootkit': 0, 'missed_rootkit': 0}
                  for kind in thresholds}
    for p in predictions:
        if p['state'] in ('correct_rootkit', 'missed_rootkit'):
            per_method[p['method']]['attempted_in_calibrated_scenarios'] += 1
            per_method[p['method']][p['state']] += 1
    for k, c in per_method.items():
        att = c['attempted_in_calibrated_scenarios']
        c['sensitivity'] = c['correct_rootkit'] / att if att else None
    result = {
        'scope': '50 new positive (rootkit-active) batches with 100 listing runs per batch. Single Ubuntu 26 boot.',
        'rootkit_module': protocol.get('rootkit_module'),
        'positive_batches_captured': len(records), 'listing_runs': sum(r['observed_pids'] for r in records),
        'boot': protocol['boot'],
        'positive_batches_in_calibrated_scenarios': 40,
        'full_j19_experiment_complete': False,
        'thresholds': thresholds, 'scenario_outcomes': summary, 'acquisition_counts': sizes,
        'per_method_true_positive_rate': per_method,
        'median_of_batch_function_interval_medians_ns': {
            s: {k: median(values) for k, values in groups.items()}
            for s, groups in features_by_scenario.items()
        },
        'protocol_sha256': sha((folder / 'protocol.json').read_bytes()),
        'collection_sha256': sha((folder / 'collection.jsonl').read_bytes()),
        'archived_model_split_sha256': sha((PRIOR / 'trace_heldout_protocol.json').read_bytes()),
        'archived_thresholds_sha256': sha((PRIOR / 'trace_frozen_thresholds.json').read_bytes()),
        'decision_rule': 'old per-scenario feature model and old fixed threshold; score < threshold -> correct_rootkit',
        'notes': 'ls_basic has no model in the original four-scenario locked split; those positive batches are outside_calibrated_scenarios and not included in sensitivity. No new threshold refit was performed; this is a point measurement on new positive data under a single new boot.',
        'predictions': predictions,
    }
    (HERE / 'VERIFIED_TRACE_NEW_POSITIVE.json').write_bytes((json.dumps(result, indent=2) + '\n').encode())
    print(json.dumps({key: value for key, value in result.items()
                      if key not in ('predictions', 'median_of_batch_function_interval_medians_ns')}, indent=2),
          flush=True)


if __name__ == '__main__':
    main()
