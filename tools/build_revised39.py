# Historical source retained after a comparison was withdrawn.
# Its original paragraph offsets and archived source hashes no longer
# describe the public copy. Do not regenerate historical reports.
if __name__ == "__main__":
    raise SystemExit("Historical generator retired after selective public cleanup")
"""Add verified original-CARAXES evidence without replacing historical results."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
from build_revised37 import patch_text, NS
from build_revised35 import replace
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'paper/cross_layer_directory_entry_consistency_revised38_zhTW.docx'
OUTPUT = ROOT / 'paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx'

def main():
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == 'e5576c97b2911b9bf3a2610ae4189bfe022370857debfd88c264c47fcd4a75f5'
    facts = json.loads((ROOT / 'comparison/public_rootkit/verification.json').read_text())
    assert facts['verified'] and sum((r['n'] for r in facts['detector'])) == 300
    for row in facts['detector']:
        expected = 'different' if row['mode'] == 'getdents64' else 'equal'
        assert row['verdicts'] == {expected: 60}, row
    with ZipFile(SOURCE) as z:
        parts = {i.filename: (i, z.read(i.filename)) for i in z.infolist()}
    document = E.fromstring(parts['word/document.xml'][1])
    paragraphs = document.findall('.//w:body/w:p', NS)
    text = lambda p: ''.join(p.xpath('.//w:t/text()', namespaces=NS))
    oldtables = [E.tostring(t, method='c14n') for t in document.findall('.//w:tbl', NS)]
    edits = []

    def edit(prefix, op):
        matches = [p for p in paragraphs if text(p).startswith(prefix)]
        assert len(matches) == 1, prefix
        p = matches[0]
        before = text(p)
        after = op(before)
        assert after != before
        patch_text(p, before, after)
        edits.append({'before': before, 'after': after})
        return p
    edit('Linux 的 getdents64 透過', lambda t: t + ' 原版 CARAXES 的三開機測試另顯示，getdents64 模式 120 次皆警報並還原，filldir 模式 120 次雖造成清單缺失，但兩端已接受與實收項目相同而未警報，界定了本方法對拒絕項目及提前截斷的限制。')
    edit('在這些假設下，本方法偵測', lambda t: t.replace('項目尚未進入 filldir64 就被排除的隱藏，不會造成兩端差異，因此不在偵測範圍內。', '項目尚未進入 filldir64 就被排除，或在 filldir64 內以 false 拒絕而未被接受，均不會單憑該缺失造成兩端差異。原版 CARAXES 的後一種情形已在 6.10 節實測。掃描器讀到回傳 0 只表示介面宣告列舉結束，不保證所有磁碟項目均被走訪。'))
    matches = [p for p in paragraphs if 'filldir 的原樣轉送、名稱比對與隱藏狀態依 CARAXES' in text(p)]
    assert len(matches) == 1
    p = matches[0]
    before = text(p)
    after = before.replace('依 CARAXES 的 filldir 掛接模式自行縮減實作，', '參照 CARAXES 的 filldir 掛接模式自行縮減實作，隱藏命中時略過原函式並回傳 true，與原版回傳 false 的行為不同，')
    assert before != after
    patch_text(p, before, after)
    edits.append({'before': before, 'after': after})
    heading = next((p for p in paragraphs if text(p) == '7. 討論'))
    style = next((p for p in paragraphs if text(p).startswith('6.9 ')))
    body = next((p for p in paragraphs if text(p).startswith('三次開機的 135 筆')))
    additions = [(style, '6.10 原版 CARAXES 的兩種隱藏模式'), (body, '為檢驗自行縮減模組以外的公開樣本，另由官方提交 899e8be6b5f6c7236bd23b52aa65051de757e0b3 建置 CARAXES[15]。getdents64 配置保留原始來源，filldir 配置僅依作者說明切換 hooks.h 的 include 與五個掛接項目，未更改過濾函式、ftrace helper、回傳值或回呼結構。在原 Ubuntu 虛擬機、Linux 6.8.0-138-generic／ext4 上，以三個新開機驗證。目錄含 64 個一般檔案、3 個名稱含 caraxes 的檔案及共用檢查檔，加上點目錄記錄，正常完整列舉為 70 筆。IBLT 維持 256 格。兩種隱藏模式各測模組先載入與探針先附掛，並用 128 與 65,536 位元組緩衝區各列舉十次。正常狀態每開機二十次，合計 300 次本文量測。另保留無觀測控制、ls 輸出、同次實收記錄與卸載後目錄核對，相容性試跑不列入分母。'), (body, '正常對照 60 次皆有效一致，且實收記錄符合未隱藏目錄清單。原版 getdents64 模式的兩種掛接順序各 60 次，合計 120 次皆有效警報、通過還原核對，並與由同次實收記錄重算的差異一致，每次均缺少三個目標項目。這提供原版公開樣本在已接受後改寫輸出路徑的實測證據，未重跑或合併九次開機矩陣的分母。'), (body, '原版 filldir 模式的兩種掛接順序各 60 次，合計 120 次均有實際清單缺失，但量測有效且兩端指紋一致，因此未警報。原版命中名稱時回傳 false，這些項目未被核心端摘要計入，後續列舉也會提前停止。每次皆只回傳兩筆一般項目，相較正常七十筆缺少六十八筆，受測回傳記錄與核心已接受項目的指紋及 IBLT 相同。這不是「沒有隱藏」，也不能算作成功偵測或故障拒判，而是目前觀測目標的限制。原受控 filldir 模組命中時回傳 true，故形成已接受但未交付的差異，兩者不能視為相同行為。'), (body, '每個開機各狀態五次，正常對照 15 次無目標警報，getdents64 與 filldir 各 15 次皆有目標名稱警報。 filldir 的十五次同時出現檢查檔不可見的品質提示，不能解讀為完整還原全部缺失。 此模式只測模組先載入。'), (body, '三次開機皆成功卸載原版模組，卸載後目錄清單回復。來源、配置差異、建置紀錄、所有觀察、失敗的首次建置呼叫及離線重算入口均封存。首次建置失敗是 Makefile 取用繼承的 PWD 指向錯誤目錄，明確傳入正確 PWD 後兩配置皆編譯成功，沒有修補樣本行為。宿主帳號無 Hyper-V 管理權限，未建立新的檢查點，亦未升級套件。此組結果仍限單一虛擬機、指定核心、ext4 與此固定樣本。')]
    for template, value in additions:
        node = deepcopy(template)
        replace(node, value)
        heading.addprevious(node)
        edits.append({'inserted': value})
    edit('九次開機矩陣實驗的結果來自', lambda t: t.replace('所有隱藏模組仍以 ftrace 掛接，另一作者的過濾函式也共用本研究的 ftrace 輔助程式，', '既有受控模組與本次原版 CARAXES 都以 ftrace 掛接，適用條件實驗的另一作者過濾函式共用本研究的 ftrace 輔助程式，') + ' 原版 CARAXES 已另行實測，結果見 6.10 節。其 filldir 模式的提前截斷未被本方法警報，因此受控差異的檢出率不能當成公開 rootkit 的通用偵測率。')
    edit('兩組實驗另有下列限制', lambda t: t.replace('也沒有新增公開 rootkit。', '該組未新增公開 rootkit，原版 CARAXES 的另組實測見 6.10 節。'))
    edit('本文以 eBPF 與專用 C 掃描器', lambda t: t + ' 原版 CARAXES 另以三開機確認：getdents64 模式 120 次警報並正確還原，正常對照 60 次無警報，filldir 模式 120 次有清單缺失但未產生已接受項目與實收記錄差異，因而未警報。本文驗證的是界定範圍的交付一致性，不能以兩端一致保證目錄沒有被隱藏。')
    edit('這是尚未實作的觀測架構提案', lambda t: t + ' 原版 filldir 的拒絕與提前截斷是另一個已觀察到的邊界，增加函式庫端觀測點本身不能解決。若另以涵蓋此類隱藏為目標，須研究如何區分正常緩衝區重送與刻意拒絕，或提供獨立目錄參照，這會改變目前的判定目標，尚未實作。')
    edit('研究重現套件公開於', lambda t: t + ' 原版 CARAXES 的官方來源、授權、配置差異、建置輸出、試跑及三開機實收記錄另封存於 comparison/public_rootkit，可由其中的 summarize.py 離線重算指紋、IBLT 與工具發現，結果及分母見 6.10 節。')
    assert oldtables == [E.tostring(t, method='c14n') for t in document.findall('.//w:tbl', NS)]
    full = ''.join(document.xpath('.//w:t/text()', namespaces=NS))
    assert not any((s in full for s in ('；', ';', '補充實驗', '主實驗')))
    with ZipFile(OUTPUT, 'w') as z:
        for name, (info, data) in parts.items():
            z.writestr(info, E.tostring(document, xml_declaration=True, encoding='UTF-8', standalone=True) if name == 'word/document.xml' else data)
    (ROOT / 'comparison/public_rootkit/paper_changes.json').write_text(json.dumps({'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(), 'output_sha256': hashlib.sha256(OUTPUT.read_bytes()).hexdigest(), 'existing_tables_unchanged': True, 'edits': edits}, ensure_ascii=False, indent=2), encoding='utf-8')
    print(str(OUTPUT))
if __name__ == '__main__':
    main()
