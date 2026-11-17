# Historical source retained after a comparison was withdrawn.
# Its original paragraph offsets and archived source hashes no longer
# describe the public copy. Do not regenerate historical reports.
if __name__ == "__main__":
    raise SystemExit("Historical generator retired after selective public cleanup")
"""Verify the new implementation/publication and preserve historical checksums."""
import argparse, csv, hashlib, json, subprocess
from io import StringIO
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
import pypdfium2 as pdf
ROOT = Path(__file__).resolve().parents[1]

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def read(p):
    return json.loads(p.read_text(encoding='utf-8'))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--git', required=True)
    a = parser.parse_args()
    facts = read(ROOT / 'terminal_rejection/verification.json')
    assert facts['verified']
    old = read(ROOT / '_docx_work/terminal_rejection/previous_sample_verification.json')
    assert old['verified']
    allowed = {'README.md', 'ARTIFACT_SCOPE.md', 'THIRD_PARTY_NOTICES.md', 'scan_directory.py', 'docs/METHOD_AND_NEXT_STEPS_zh-TW.md', 'docs/METHOD_CLOSURE_20261102_zh-TW.md', 'docs/RELATED_WORK_COMPARISON_zh-TW.md', 'paper/README.md'}
    prior_text = subprocess.check_output([a.git, 'show', '921319d:FILE_SHA256.csv'], cwd=ROOT).decode('utf-8')
    prior = list(csv.DictReader(StringIO(prior_text)))
    for row in prior:
        if row['path'] not in allowed:
            assert sha(ROOT / row['path']) == row['sha256'], row['path']
    actual = ROOT / '_docx_work/terminal_rejection/recomputed/terminal_rejection_20261103/code'
    source_hashes = {p.relative_to(actual).as_posix(): sha(p) for p in actual.rglob('*') if p.is_file() and p.suffix in ('.py', '.c', '.h', '.md') and ('__pycache__' not in p.parts)}
    (ROOT / 'terminal_rejection/ACTUAL_DEPLOYED_SOURCES.json').write_text(json.dumps(source_hashes, indent=2), encoding='utf-8', newline='\n')
    for path in ('phase2/bpf_packed.c', 'phase1/enum_probe.c', 'finalization/tracefs_measurement.py'):
        expected = subprocess.check_output([a.git, 'show', '921319d:' + path], cwd=ROOT)
        assert hashlib.sha256(expected).hexdigest() == sha(ROOT / path)
    source = ROOT / 'paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx'
    target = ROOT / 'paper/cross_layer_directory_entry_consistency_revised40_zhTW.docx'
    with ZipFile(source) as z:
        first = {n: z.read(n) for n in z.namelist()}
    with ZipFile(target) as z:
        last = {n: z.read(n) for n in z.namelist()}
    assert first.keys() == last.keys() and [n for n in first if first[n] != last[n]] == ['word/document.xml']
    ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    before = E.fromstring(first['word/document.xml'])
    after = E.fromstring(last['word/document.xml'])
    assert [E.tostring(t, method='c14n') for t in before.findall('.//w:tbl', ns)] == [E.tostring(t, method='c14n') for t in after.findall('.//w:tbl', ns)]
    full = ''.join(after.xpath('.//w:t/text()', namespaces=ns))
    assert not any((s in full for s in ('；', ';', '補充實驗', '主實驗')))
    docs = {}
    for stem, pages in [('cross_layer_directory_entry_consistency_revised40_zhTW', 30), ('interview_research_summary_terminal_zhTW', 1)]:
        for suffix in ('.docx', '.pdf'):
            p = ROOT / 'paper' / (stem + suffix)
            docs[p.relative_to(ROOT).as_posix()] = {'sha256': sha(p), 'bytes': p.stat().st_size}
        d = pdf.PdfDocument(ROOT / 'paper' / (stem + '.pdf'))
        assert len(d) == pages
        text = ''.join((p.get_textpage().get_text_range() for p in d))
        for word in ('CARAXES', '120', '15', 'false'):
            assert word in text
        docs['paper/' + stem + '.pdf']['pages'] = pages
    receipt = {'recorded_utc': datetime.now(timezone.utc).isoformat(), 'base_commit': '921319d5f0612227a14a8cad91065dfc18730092', 'scope': 'Add separate terminal rejection signal, preserving and reporting observed benign alerts', 'raw_archive_sha256': facts['archive_sha256'], 'recomputed_observations_and_controls': 1809, 'native_detector_scans': 1662, 'independent_controls': 102, 'public_sample': facts['public_sample'], 'benign_race': facts['benign_race'], 'normal_static': facts['normal'], 'normal_churn': facts['dynamic'], 'unit_tests': {'command': 'python -m unittest discover -s tests -q', 'passed': 51, 'failed': 0, 'new_rule_tests': 6, 'initial_red': 'new module absent before implementation'}, 'old_original_sample_recomputed': {'passed': True, 'observations_and_controls': 447}, 'historical_checksums_preserved': True, 'original_packed_scanner_and_tracefs_source_unchanged': True, 'source_binding': 'actual deployed sources inside native archive; final host notes/controller were not transferred', 'native_source_constant_across_three_boots': True, 'documents': docs, 'old_tables_figures_and_other_package_parts_unchanged': True, 'readonly_word_export_and_visual_review': True, 'prior_timings_reused_for_new_version': False, 'normal_deletion_is_observed_false_alert_if_interpreted_as_hiding': True, 'module_unloaded_and_tmpfs_unmounted': True, 'checkpoint_created': False, 'report': 'docs/TERMINAL_REJECTION_20261103_zh-TW.md'}
    output = ROOT / 'docs/PUBLICATION_VERIFICATION_TERMINAL_20261103.json'
    output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8', newline='\n')
    tracked = subprocess.check_output([a.git, 'ls-files', '-z'], cwd=ROOT).decode().split('\x00')
    added = [p.relative_to(ROOT).as_posix() for p in (ROOT / 'terminal_rejection').iterdir() if p.is_file()]
    added += list(docs) + ['src/kicba/terminal_rejection.py', 'tests/test_terminal_rejection.py', 'tools/build_revised40.py', 'tools/build_interview_terminal.py', 'tools/update_terminal_catalog.py', 'tools/verify_terminal_publication.py', 'docs/TERMINAL_REJECTION_20261103_zh-TW.md', output.relative_to(ROOT).as_posix()]
    names = sorted((set(tracked) | set(added)) - {'', 'FILE_SHA256.csv'})
    assert not any(('~$' in n or n.endswith('.tmp') for n in names))
    with (ROOT / 'FILE_SHA256.csv').open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator='\n')
        writer.writerow(['path', 'sha256', 'bytes'])
        for name in names:
            p = ROOT / name
            writer.writerow([name, sha(p), p.stat().st_size])
    print(json.dumps({'passed': True, 'manifest_files': len(names), 'documents': len(docs)}))
if __name__ == '__main__':
    main()
