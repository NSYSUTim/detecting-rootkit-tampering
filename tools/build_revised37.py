"""Use experiment purposes rather than primary/supplementary labels in revised36."""
from bisect import bisect_right
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import re
from zipfile import ZipFile

from lxml import etree as E

ROOT = Path(__file__).resolve().parents[1]
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
SOURCE = ROOT / "paper/cross_layer_directory_entry_consistency_revised36_zhTW.docx"
OUTPUT = ROOT / "paper/cross_layer_directory_entry_consistency_revised37_zhTW.docx"
SOURCE_SHA = "b11fefb1394dbbcccb797bdcebe02e73b64235515023472579e7070d29895583"

REPLACEMENTS = [
    ("補充實驗另確認", "實驗也檢驗"),
    ("6.1 正式資料完整性與主要成效", "6.1 矩陣實驗的資料完整性與偵測結果"),
    ("5.6 還原核對與量測品質補強設計", "5.6 還原核對與量測品質檢查設計"),
    ("6.7 補強實作確認結果", "6.7 還原核對與量測品質檢查結果"),
    ("九次開機正式主實驗", "九次開機矩陣實驗"),
    ("原九次開機主實驗", "九次開機矩陣實驗"),
    ("九次開機主實驗", "九次開機矩陣實驗"),
    ("原九開機主實驗", "九次開機矩陣實驗"),
    ("原主實驗", "九次開機矩陣實驗"),
    ("九開機主矩陣", "九次開機矩陣"),
    ("原主矩陣", "九次開機矩陣"),
    ("主實驗的環境", "該矩陣的環境"),
    ("主實驗", "矩陣實驗"),
    ("正式實驗前", "矩陣實驗前"),
    ("正式實驗", "矩陣實驗"),
    ("正式矩陣", "矩陣實驗"),
    ("正式結果", "矩陣實驗結果"),
    ("正式資料", "矩陣實驗資料"),
    ("正式差異列舉", "矩陣差異列舉"),
    ("正式 25,920", "矩陣的 25,920"),
    ("正式設定", "受測設定"),
    ("正式計時", "成本計時"),
    ("原正式輸出", "原矩陣輸出"),
    ("原正式實作", "初版實作"),
    ("原正式版", "初版實作"),
    ("補充診斷版", "診斷版"),
    ("本輪補強版", "整合版"),
    ("現行補強版", "現行整合版"),
    ("新補強版", "現行整合版"),
    ("補強版本", "整合版本"),
    ("補強實作", "整合實作"),
    ("補強版", "整合版"),
    ("歷史補強", "先前確認資料"),
    ("補強確認", "整合確認"),
    ("主要成本觀察", "成本計時樣本"),
    ("主要配對區組", "計時配對區組"),
    ("主要區組", "計時區組"),
    ("主要配對", "計時配對"),
    ("主要觀察", "計時樣本"),
    ("兩組補充與本輪補強分母互不合併", "各組實驗的分母分開計算"),
    ("兩組補充", "量測完整性與適用條件實驗"),
    ("範圍補充掃描判讀成本", "範圍比較掃描判讀成本"),
    ("九次開機矩陣實驗主要驗證的是", "九次開機矩陣實驗檢驗的是"),
]


def patch_text(paragraph, before, after):
    """Apply text-only differences while preserving runs, fields, math, and formatting."""
    nodes = paragraph.xpath(".//w:t", namespaces=NS)
    starts, offset = [], 0
    for node in nodes:
        starts.append(offset)
        offset += len(node.text or "")
    edits = [op for op in SequenceMatcher(None, before, after, autojunk=False).get_opcodes() if op[0] != "equal"]
    for _, a, b, c, d in reversed(edits):
        first = min(bisect_right(starts, a) - 1, len(nodes) - 1)
        last = min(bisect_right(starts, b - 1) - 1, len(nodes) - 1) if b > a else first
        first = max(first, 0)
        prefix = (nodes[first].text or "")[:a - starts[first]]
        suffix = (nodes[last].text or "")[b - starts[last]:]
        nodes[first].text = prefix + after[c:d] + (suffix if first == last else "")
        for index in range(first + 1, last):
            nodes[index].text = ""
        if last != first:
            nodes[last].text = suffix
    assert "".join(paragraph.xpath(".//w:t/text()", namespaces=NS)) == after


def main():
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == SOURCE_SHA
    with ZipFile(SOURCE) as archive:
        parts = {info.filename: (info, archive.read(info.filename)) for info in archive.infolist()}
    document = E.fromstring(parts["word/document.xml"][1])
    changes = []
    for index, paragraph in enumerate(document.findall(".//w:p", NS)):
        before = "".join(paragraph.xpath(".//w:t/text()", namespaces=NS))
        after = before
        for old, new in REPLACEMENTS:
            after = after.replace(old, new)
        if after.startswith("兩組實驗在九次開機矩陣實驗之後進行，用來回應第 8 節的限制。"):
            after = after.replace(
                "兩組實驗在九次開機矩陣實驗之後進行，用來回應第 8 節的限制。",
                "量測完整性與適用條件實驗檢驗第 8 節所列的量測可靠性、環境條件與執行成本。", 1)
        if after != before:
            assert re.findall(r"[0-9]+(?:[.,][0-9]+)*", before) == re.findall(r"[0-9]+(?:[.,][0-9]+)*", after)
            patch_text(paragraph, before, after)
            changes.append({"paragraph_index": index, "before": before, "after": after})
    xml = E.tostring(document, xml_declaration=True, encoding="UTF-8", standalone=True)
    with ZipFile(OUTPUT, "w") as archive:
        for name, (info, payload) in parts.items():
            archive.writestr(info, xml if name == "word/document.xml" else payload)
    text = "".join(document.xpath(".//w:t/text()", namespaces=NS))
    assert not any(term in text for term in ("補充實驗", "主實驗", "正式實驗", "主要觀察", "主要配對", "補強"))
    assert ";" not in text and "；" not in text
    work = ROOT / "_docx_work/wording_20261102"
    work.mkdir(parents=True, exist_ok=True)
    result = {"source_sha256": SOURCE_SHA, "output_sha256": hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),
              "changed_package_parts": ["word/document.xml"], "numeric_tokens_unchanged": True, "edits": changes}
    (work / "changes37.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "sha256": result["output_sha256"], "changed_paragraphs": len(changes)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
