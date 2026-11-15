"""Prospectively locked, paired offline sensitivity experiment; no native changes."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import importlib.util
import itertools
import json
import math
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1] / 'kicba-thesis-artifact'
SOURCE = REPO / 'src/kicba/reconciliation.py'
KS = (2, 3, 4, 5)
MASTER_SEED = 20261113


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    with Path(path).open('x', encoding='utf-8', newline='\n') as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.write('\n')


def now():
    return datetime.now(timezone.utc).isoformat()


def prepare():
    # This phase performs no decoding or experimental outcome calculation.
    if (HERE / 'protocol.json').exists():
        raise FileExistsError('Protocol already exists; it must not be overwritten')
    snapshot = HERE / 'reconciliation_snapshot.py'
    with snapshot.open('xb') as f:
        f.write(SOURCE.read_bytes())
    conditions = []
    for mode in ('missing', 'substitution'):
        for d in (1, 4, 16, 32, 64, 128, 256, 512):
            conditions.append(dict(family='deployed_prefix', mode=mode, difference=d,
                cells=256, trials=1024 if d == 32 else 256,
                role='primary' if d == 32 else 'difference_stress'))
        for cells in (32, 64, 128, 512):
            conditions.append(dict(family='deployed_prefix', mode=mode, difference=32,
                cells=cells, trials=256, role='capacity_sensitivity'))
        for d in (32, 128, 256):
            conditions.append(dict(family='symmetric_salts', mode=mode, difference=d,
                cells=256, trials=256, role='hash_family_sensitivity'))
    protocol = dict(
        schema_version=1, locked_utc=now(), evidence_role='new_offline_exploratory_sensitivity_not_native_confirmatory',
        master_seed=MASTER_SEED, position_counts=list(KS), conditions=conditions,
        total_input_cases=sum(c['trials'] for c in conditions),
        total_variant_decodes=4 * sum(c['trials'] for c in conditions),
        pairing='Same input tokens and seeds for all k; token generation excludes k, capacity, and hash family. Randomize execution order per paired trial.',
        mapping='deployed_prefix: preserve original first 2/3 positions exactly; append position 4/5 with SHA256-derived fixed label salts and identical linear distinctness correction. symmetric_salts: all positions use the same seeded mix64 scheme. Nested positions within each family.',
        oracle='Distinct random 64-bit keys; compare complete signed token multisets with Counter. success flag alone is insufficient. Record false success, partial result, residual and timing for every variant.',
        endpoints=['exact_recovery_rate', 'incorrect_success_count', 'paired_exact_McNemar', 'build_ns', 'decode_ns', 'deterministic_k_updates_per_token'],
        primary_rule='At deployed_prefix, m=256,d=32, equal-weight pooling of 1024 trials per mode. Claim strict recovery superiority of k=3 only if its exact recovery is greater than EACH of k=2,4,5 and all two-sided paired exact McNemar tests pass Holm alpha=0.05, with zero incorrect successes. Otherwise superiority is NOT demonstrated. No universal optimality claim even if this passes.',
        statistics='Wilson 95% intervals describe independent generated token/seed cases; exact binomial McNemar conditional on discordances. Holm across 3 primary comparisons only. Secondary grid descriptive, no selection of favorable subset. Timing medians, no native performance claim.',
        stopping_rule='Fixed complete grid, no early stopping for results. Runtime or correctness error => keep partial files and label incomplete; do not change trials, seeds or grid.',
        validation='Before the grid: original k=3 row/decode parity; distinct and nested positions for all k; cancellation with common tokens; repeated-token failure control. Validation cases excluded from outcome denominator.',
        limits=['Offline Python simulation, not Linux/eBPF integration or rootkit detection accuracy',
            'Random unique-token inputs; no proof for adversarial hashes or general multisets',
            'Net difference is inserted directly as in original capacity sweep; common-stream cancellation separately checked',
            '3 vs 4/5 uses a predeclared extension of deployed hashing; second family checks limited sensitivity',
            'Zero observed failures does not imply zero population failure probability; timings specific to this process and host'],
        source_sha256=sha(SOURCE), snapshot_sha256=sha(snapshot), script_sha256=sha(__file__),
        git_head=subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
        environment=dict(python=sys.version, platform=platform.platform(), processor=platform.processor()),
    )
    save(HERE / 'protocol.json', protocol)
    with (HERE / 'protocol.sha256').open('x', encoding='ascii') as f:
        f.write(sha(HERE / 'protocol.json') + '\n')
    print(json.dumps({'locked': str(HERE / 'protocol.json'), 'sha256': sha(HERE / 'protocol.json'),
        'inputs': protocol['total_input_cases'], 'decodes': protocol['total_variant_decodes']}), flush=True)


def derive(*parts):
    raw = '|'.join(map(str, (MASTER_SEED,) + parts)).encode('ascii')
    return int.from_bytes(hashlib.sha256(raw).digest()[:16], 'big')


def load_module():
    spec = importlib.util.spec_from_file_location('locked_reconciliation', HERE / 'reconciliation_snapshot.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def variant_class(mod):
    extra = [int.from_bytes(hashlib.sha256(f'IBLT-k-sensitivity-position-{i}'.encode()).digest()[:8], 'big') for i in (4, 5)]

    class Variant(mod.IBLT):
        def __init__(self, cells, seed1, seed2, k, family):
            super().__init__(cells, seed1, seed2)
            self.k, self.family = k, family
            self.salts = [mod.mix64(seed1 ^ mod.mix64(seed2 ^ i ^ 0x243F6A8885A308D3)) for i in range(k)] if family == 'symmetric_salts' else []

        def _positions(self, key_hash):
            mask = self.cell_count - 1
            if self.family == 'deployed_prefix':
                # Avoid doing the unused third hash for k=2; k=3 is bit-identical.
                first = mod.mix64(key_hash ^ self.seed1) & mask
                second = mod.mix64(key_hash ^ self.seed2) & mask
                if second == first:
                    second = (second + 1) & mask
                positions = [first, second]
                if self.k >= 3:
                    third = mod.mix64(key_hash ^ self.seed1 ^ self.seed2 ^ mod.POS3_SALT) & mask
                    while third in positions:
                        third = (third + 1) & mask
                    positions.append(third)
                salts = extra[:max(0, self.k - 3)]
                candidates = (mod.mix64(key_hash ^ self.seed1 ^ self.seed2 ^ salt) & mask for salt in salts)
            else:
                positions = []
                candidates = (mod.mix64(key_hash ^ salt) & mask for salt in self.salts)
            for position in candidates:
                while position in positions:
                    position = (position + 1) & mask
                positions.append(position)
            return tuple(positions)

    return Variant


def inputs(mod, mode, d, trial):
    rng = random.Random(derive('input', mode, d, trial))
    seed1, seed2 = rng.getrandbits(64), rng.getrandbits(64)
    tokens, used = [], set()
    while len(tokens) < d:
        key = rng.getrandbits(64)
        if key not in used:
            used.add(key)
            tokens.append(mod.EntryToken(key, rng.getrandbits(63) + 1, rng.randrange(16)))
    split = d if mode == 'missing' else (d + 1) // 2
    return seed1, seed2, tokens[:split], tokens[split:]


def validate(mod, Variant):
    checks = Counter()
    for trial in range(32):
        s1, s2, up, down = inputs(mod, 'substitution', 32, trial + 1000000)
        for cells in (32, 64, 256):
            original, candidate = mod.IBLT(cells, s1, s2), Variant(cells, s1, s2, 3, 'deployed_prefix')
            for token, sign in [(t, 1) for t in up] + [(t, -1) for t in down]:
                original.add(token, sign)
                candidate.add(token, sign)
            assert original.to_rows() == candidate.to_rows()
            assert original.decode() == candidate.decode()
            checks['baseline_row_and_decode_parity'] += 1
        for family in ('deployed_prefix', 'symmetric_salts'):
            last = ()
            for k in KS:
                table = Variant(64, s1, s2, k, family)
                positions = table._positions(up[0].key_hash)
                assert len(positions) == len(set(positions)) == k
                assert positions[:len(last)] == last
                last = positions
                checks['positions_distinct_and_nested'] += 1
                for token in up:
                    table.add(token)
                    table.add(token, -1)
                assert all(c.is_empty() for c in table.cells)
                for token in up:
                    table.add(token)
                for token in down:
                    table.add(token, -1)
                direct = Variant(64, s1, s2, k, family)
                for token in up:
                    direct.add(token)
                for token in down:
                    direct.add(token, -1)
                assert table.to_rows() == direct.to_rows()
                checks['common_stream_cancellation'] += 1
                repeated = Variant(64, s1, s2, k, family)
                repeated.add(up[0]); repeated.add(up[0])
                assert not repeated.decode().success
                checks['duplicate_failure_control'] += 1
    return dict(checks)


def wilson(s, n):
    z = 1.959963984540054
    p = s / n
    den = 1 + z*z/n
    center = (p + z*z/(2*n))/den
    delta = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n))/den
    return [max(0, center-delta), min(1, center+delta)]


def paired_test(rows, other):
    keyed = {}
    for row in rows:
        if row['k'] in (3, other):
            keyed.setdefault((row['mode'], row['trial']), {})[row['k']] = row['exact']
    wins = sum(x[3] and not x[other] for x in keyed.values())
    losses = sum(x[other] and not x[3] for x in keyed.values())
    n, tail = wins + losses, min(wins, losses)
    p = min(1.0, math.ldexp(float(sum(math.comb(n, i) for i in range(tail + 1))), 1-n)) if 0 < n < 1000 else (1.0 if n == 0 else min(1.0, 2*sum(math.exp(math.lgamma(n+1)-math.lgamma(i+1)-math.lgamma(n-i+1)-n*math.log(2)) for i in range(tail+1))))
    return dict(other_k=other, k3_only_correct=wins, other_only_correct=losses, two_sided_exact_p=p)


def summarize(rows, protocol, validation, elapsed):
    groups = {}
    for row in rows:
        key = tuple(row[x] for x in ('family', 'role', 'mode', 'difference', 'cells', 'k'))
        groups.setdefault(key, []).append(row)
    summaries = []
    for key, values in groups.items():
        item = dict(zip(('family', 'role', 'mode', 'difference', 'cells', 'k'), key))
        successes = sum(v['exact'] for v in values)
        item.update(trials=len(values), exact_successes=successes, exact_rate=successes/len(values),
            wilson95=wilson(successes, len(values)), incorrect_successes=sum(v['incorrect_success'] for v in values),
            median_build_ns=statistics.median(v['build_ns'] for v in values),
            median_decode_ns=statistics.median(v['decode_ns'] for v in values))
        summaries.append(item)
    primary = [r for r in rows if r['role'] == 'primary']
    primary_summary = []
    for k in KS:
        values = [r for r in primary if r['k'] == k]
        n, s = len(values), sum(v['exact'] for v in values)
        primary_summary.append(dict(k=k, trials=n, exact_successes=s, exact_rate=s/n, wilson95=wilson(s, n),
            incorrect_successes=sum(v['incorrect_success'] for v in values),
            median_build_ns=statistics.median(v['build_ns'] for v in values),
            median_decode_ns=statistics.median(v['decode_ns'] for v in values)))
    tests = [paired_test(primary, k) for k in (2, 4, 5)]
    running = 0.0
    for rank, test in enumerate(sorted(tests, key=lambda t: t['two_sided_exact_p'])):
        running = max(running, min(1.0, (3-rank)*test['two_sided_exact_p']))
        test['holm_adjusted_p'] = running
    superiority = all(t['k3_only_correct'] > t['other_only_correct'] and t['holm_adjusted_p'] < .05 for t in tests) and not any(r['incorrect_success'] for r in primary)
    result = dict(completed_utc=now(), status='complete', elapsed_seconds=elapsed,
        protocol_sha256=sha(HERE/'protocol.json'), validation=validation,
        variant_decodes=len(rows), input_cases=len(rows)//4,
        incorrect_successes=sum(r['incorrect_success'] for r in rows),
        primary=primary_summary, primary_paired_tests=tests,
        k3_strict_recovery_superiority_demonstrated=superiority,
        universal_optimality_proven=False, groups=summaries, limits=protocol['limits'])
    save(HERE/'summary.json', result)
    with (HERE/'summary.csv').open('x', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(summaries[0]))
        writer.writeheader(); writer.writerows(summaries)
    report = [
        '# IBLT 位置數離線比較（2026-11-13）', '',
        '這是新做的離線敏感度實驗，不是先前研究的事前證據，也不是 Linux/eBPF 原生驗證。',
        f"規約 SHA-256：`{result['protocol_sha256']}`。完整完成 {len(rows):,} 次版本解碼，共 {len(rows)//4:,} 組配對輸入。",
        f"程式執行 {elapsed:.1f} 秒。所有錯誤成功解碼：{result['incorrect_successes']}。", '',
        '## 事前指定主要條件：256 格、32 個差異項目', '',
        'missing 與 substitution 各 1,024 次。四種 k 使用同一批輸入與種子。', '',
        '| 位置數 | 正確完整還原 | 還原率 | Wilson 95% 區間 | 建表中位數 ms | 解碼中位數 ms |',
        '|---:|---:|---:|---:|---:|---:|',
    ]
    for item in primary_summary:
        lo, hi = item['wilson95']
        report.append(f"| {item['k']} | {item['exact_successes']}/{item['trials']} | {item['exact_rate']:.4%} | {lo:.4%}–{hi:.4%} | {item['median_build_ns']/1e6:.4f} | {item['median_decode_ns']/1e6:.4f} |")
    report += ['', '主要比較採配對 exact McNemar 檢定，三項比較使用 Holm 校正。']
    for t in tests:
        report.append(f"- 3 對 {t['other_k']}：只有 3 正確 {t['k3_only_correct']} 次，只有對方正確 {t['other_only_correct']} 次；校正 p={t['holm_adjusted_p']:.6g}。")
    report += ['', f"依事前規則，3 個位置的嚴格還原優勢：{'成立（僅限本條件）' if superiority else '未獲證明'}。沒有證明全域最佳參數。", '',
        '## 完整受測條件', '',
        '下列不挑選情境；數字合併兩種模式，詳見 summary.csv 的分模式結果。', '',
        '| 雜湊方式 | 角色 | 差異量 | 格數 | k=2 | k=3 | k=4 | k=5 |',
        '|---|---|---:|---:|---:|---:|---:|---:|']
    keys = list(dict.fromkeys((s['family'], s['role'], s['difference'], s['cells']) for s in summaries))
    for family, role, d, m in keys:
        rates = []
        for k in KS:
            values = [s for s in summaries if (s['family'],s['role'],s['difference'],s['cells'],s['k']) == (family,role,d,m,k)]
            rates.append(f"{sum(v['exact_successes'] for v in values)/sum(v['trials'] for v in values):.2%}")
        report.append(f"| {family} | {role} | {d} | {m} | " + ' | '.join(rates) + ' |')
    report += ['', '## 解讀限制', ''] + ['- '+x for x in protocol['limits']]
    report += ['', '所有原始試次保存在 trials.csv；完整規則、驗證、統計及每條件時間保存在 protocol.json、validation.json、summary.json 與 summary.csv。',
        '重現：在此資料夾保留原檔，再複製 run_experiment.py 至新的同層資料夾，依序執行 python run_experiment.py prepare 與 python run_experiment.py run。固定種子應重現還原結果，時間不會逐位元相同。', '']
    with (HERE/'REPORT_zh-TW.md').open('x', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(report))
    return result


def run():
    start = time.perf_counter()
    protocol = json.loads((HERE/'protocol.json').read_text(encoding='utf-8'))
    assert sha(HERE/'protocol.json') == (HERE/'protocol.sha256').read_text().strip()
    assert sha(__file__) == protocol['script_sha256']
    assert sha(SOURCE) == protocol['source_sha256']
    assert sha(HERE/'reconciliation_snapshot.py') == protocol['snapshot_sha256']
    save(HERE/'run_started.json', dict(started_utc=now(), protocol_sha256=sha(HERE/'protocol.json')))
    mod = load_module()
    Variant = variant_class(mod)
    validation = validate(mod, Variant)
    save(HERE/'validation.json', dict(passed=True, checks=validation, completed_utc=now()))
    print('Validation passed; starting locked grid.', flush=True)
    rows = []
    fields = ['family','role','mode','difference','cells','trial','seed1','seed2','k','order','exact','decode_success','incorrect_success','residual_cells','upstream_recovered','downstream_recovered','build_ns','decode_ns']
    conditions = list(protocol['conditions'])
    random.Random(derive('condition-order')).shuffle(conditions)
    with (HERE/'trials.csv').open('x', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for number, c in enumerate(conditions):
            for trial in range(c['trials']):
                s1, s2, up, down = inputs(mod, c['mode'], c['difference'], trial)
                expected_up, expected_down = Counter(up), Counter(down)
                order = list(KS)
                random.Random(derive('variant-order', c['family'], c['mode'], c['difference'], c['cells'], trial)).shuffle(order)
                for index, k in enumerate(order):
                    t0 = time.perf_counter_ns()
                    table = Variant(c['cells'], s1, s2, k, c['family'])
                    for token in up:
                        table.add(token)
                    for token in down:
                        table.add(token, -1)
                    t1 = time.perf_counter_ns()
                    decoded = table.decode()
                    t2 = time.perf_counter_ns()
                    exact_lists = Counter(decoded.upstream_only) == expected_up and Counter(decoded.downstream_only) == expected_down
                    row = dict(c)
                    row.pop('trials')
                    row.update(trial=trial, seed1=s1, seed2=s2, k=k, order=index,
                        exact=int(decoded.success and exact_lists), decode_success=int(decoded.success),
                        incorrect_success=int(decoded.success and not exact_lists), residual_cells=decoded.residual_cells,
                        upstream_recovered=len(decoded.upstream_only), downstream_recovered=len(decoded.downstream_only),
                        build_ns=t1-t0, decode_ns=t2-t1)
                    rows.append(row); writer.writerow(row)
            f.flush()
            print(json.dumps(dict(condition=number+1, total_conditions=len(conditions), elapsed_seconds=round(time.perf_counter()-start,1), **c)), flush=True)
    assert len(rows) == protocol['total_variant_decodes']
    result = summarize(rows, protocol, validation, time.perf_counter()-start)
    files = [p for p in HERE.iterdir() if p.is_file() and p.name != 'MANIFEST.json']
    save(HERE/'MANIFEST.json', {p.name: dict(sha256=sha(p), bytes=p.stat().st_size) for p in sorted(files)})
    print(json.dumps({k: result[k] for k in ('status','elapsed_seconds','variant_decodes','incorrect_successes','primary','primary_paired_tests','k3_strict_recovery_superiority_demonstrated')}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('prepare', 'run'))
    args = parser.parse_args()
    prepare() if args.phase == 'prepare' else run()
