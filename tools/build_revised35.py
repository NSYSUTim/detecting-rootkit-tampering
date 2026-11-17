# Historical source retained after a comparison was withdrawn.
# Its original paragraph offsets and archived source hashes no longer
# describe the public copy. Do not regenerate historical reports.
if __name__ == "__main__":
    raise SystemExit("Historical generator retired after selective public cleanup")
"""Reconcile the verified current entry and shared comparison into revised34."""
from copy import deepcopy
import hashlib, json
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from lxml import etree as E
ROOT = Path(__file__).resolve().parents[1]
NS = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
W = '{' + NS['w'] + '}'

def text(p):
    return ''.join(p.xpath('.//w:t/text()', namespaces=NS))

def replace(p, value):
    runs = p.findall('.//w:r', NS)
    props = deepcopy(runs[0].find('w:rPr', NS)) if runs and runs[0].find('w:rPr', NS) is not None else None
    for node in list(p):
        if node.tag != W + 'pPr':
            p.remove(node)
    run = E.SubElement(p, W + 'r')
    if props is not None:
        run.append(props)
    E.SubElement(run, W + 't').text = value

def main():
    source = ROOT / 'paper/cross_layer_directory_entry_consistency_revised34_zhTW.docx'
    output = ROOT / 'paper/cross_layer_directory_entry_consistency_revised35_zhTW.docx'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == '9873801930d29ecf62d9acf262953dc65f9cd03882f0fa60d84c0d14d732ba9d'
    verified = json.loads((ROOT / 'comparison/evidence/final_verification.json').read_text())
    facts = json.loads((ROOT / 'comparison/analysis/facts.json').read_text())
    assert verified['passed']
    assert len(verified['comparison_boots']) == 3 and verified['unit_tests'] == 41
    with ZipFile(source) as z:
        parts = {i.filename: (i, z.read(i.filename)) for i in z.infolist()}
    doc = E.fromstring(parts['word/document.xml'][1])
    paras = doc.findall('.//w:p', NS)
    original = [text(p) for p in paras]
    edits = {6: 'Linux 的 getdents64 透過 filldir64 將目錄項寫入使用者緩衝區。 隱藏或過濾模組可使核心端已接受的項目與回傳記錄不同。 本文以 eBPF 記錄回傳 true 的最外層 filldir64 呼叫，由專用 C 掃描器發起並取得同一次完整列舉，兩端同步建立固定大小的多重集合指紋與 Invertible Bloom Lookup Table（IBLT）。 指紋判斷是否有身分差異，IBLT 還原少量差異的識別值、inode 與型態，不保存原始名稱。 九次開機共 1,296 批、25,920 次列舉中，576 個差異批次全數檢出，720 個對照批次未誤報，11,520 次差異列舉皆完整還原。 只比較項目數的召回率為 75%，兩個整次耗時門檻皆低於 5%。 補充實驗另確認返回漏失、載入順序、兩個指定核心、ext4 與 tmpfs 及正常動態目錄，並降低合併狀態版的受測耗時。 現行入口再接入還原指紋核對、入口與返回探針統計及 BPF 遞迴略過檢查。 貢獻是同次已接受項目的對齊、固定摘要與量測失效處理，不主張兩端比較為首創。 結果限於可信量測與受測條件，警報不直接判定惡意，有限容量、碰撞風險及更強攻擊者仍是限制。', 17: original[17].replace('並檢查可取得的 BPF 遞迴略過統計，其確認結果與前述分母分開報告。', '並將入口 tracefs 漏失與 BPF 遞迴略過統計納入拒判。'), 39: original[39].replace('', '5.7 節與 6.8 節另以固定官方版本進行共同名稱目標及成本比較，結果顯示取捨，不能據此推論全面優劣。'), 90: original[90] + ' 5.7 節與 6.8 節另補最接近開源實作的共同比較，仍沿用輸出一致性與成本問題。', 163: original[163].replace('若指紋相同但解碼與還原核對互相矛盾', '現行入口另以明確 tracefs 事件附掛入口探針，列舉前後核對其定義、ID、命中與漏失，品質不符即拒判。若指紋相同但解碼與還原核對互相矛盾'), 173: original[173].replace('新增還原核對與 BPF 程式統計門檻', '新增還原核對、BPF 程式統計門檻及入口 tracefs 統計').replace('其新確認及計時另列', '目前執行入口為 scan_directory.py，舊 campaign 入口保持凍結。2026 年 11 月 1 日的補強版本與翌日加入入口 tracefs 統計的現行版本分開確認，其計時另列'), 228: original[228].replace('入口探針經 Linux 的效能事件', '此處診斷版的入口探針經 Linux 的效能事件'), 239: original[239].replace('此門檻只涵蓋可取得的程式略過與原返回 profile，沒有宣稱覆蓋全部入口漏失。', '2026 年 11 月 1 日的版本只涵蓋上述程式略過與原返回 profile。現行入口另明確建立 tracefs 入口事件，以原 KPROBE 類型的 BPF 程式附掛，並核對該事件的命中、漏失、定義及 ID[17]–[19]。必要統計缺少、身分變動、計數倒退或全域窗口有新增漏失，均拒判。'), 240: '2026 年 11 月 1 日的正常、身分差異與返回漏失確認另留為歷史補強。翌日現行入口以十二種狀態、128 與 4,096-byte 緩衝區各三次，共 72 次確認，另有 24 次無探針控制及六次 filldir 隱藏載入順序確認。新增診斷模組在探針處理期間呼叫 filldir64 的無效名稱返回路徑，製造真實入口 nmissed，而不改寫目錄結果。十個故障窗口各注入十次，前後各一個正常控制。返回漏失以 maxactive=1、十六程序並行注入，再以 256 做兩次循序控制。八格／十六個移除項目及名稱邊界另列。原程式、模組與資料以雜湊核對，規約先行保存，不升級客體套件或核心。原 25,920 次保存還原另行離線重算，不當新樣本。', 418: original[418].replace('31 項', '本輪 41 項'), 419: '2026 年 11 月 1 日版本的 28 次差異與 8 次一致確認符合預期，仍以該版本報告。翌日現行入口的 72 次確認中有 57 次實際差異，均正確警報、精確還原且通過指紋核對；三次小緩衝區新增未施作，未算陽性，24 次無探針控制符合預期。六次載入順序確認皆正確。十個入口故障窗口實際 missed 均正增加且全數拒判，前後二十次控制有效一致。這是全域門檻的整合驗證，不表示目標列舉各漏十筆，也不稱為修復原正式資料中已證明的錯誤一致。十六次返回漏失窗口列舉全拒判，兩次循序控制有效一致。兩次合法小表均警報而未完整定位，名稱邊界正常、過小緩衝區無效。原來源未變，未原生注入所有 BPF 略過。', 423: original[423].replace('本輪補強版新增品質查詢與還原核對，未重做跨開機大目錄成本比較，以上倍率不作為補強版的新效能結果。', '現行入口的共同新程序成本另見 6.8 節，包含編譯與附掛，與本節先前流程不同，以上倍率不套用為新版本的成本。'), 434: '列舉完整性檢查涵蓋名稱讀取、核心端更新、呼叫配對與行程錯誤。原九開機未保存返回漏失統計，無法事後補零。先前 perf 入口的統計不可得，現行入口已改用明確 tracefs 事件，將其 nmissed 納入拒判，並保留返回 profile 及 BPF recursion_misses。三種統計涵蓋不同路徑，沒有漏失報告不等於證明所有量測故障均被排除。十個真實入口故障窗口已確認門檻會拒判，非所有 BPF 略過的原生注入；缺讀數、倒退與身分改變另以離線測試確認。IBLT 失敗仍屬定位不足，指紋不同即保留警報。還原核對拒絕已構造的錯誤空差集，仍受相同指紋碰撞限制。', 438: original[438].replace('', '現行入口的故障確認及三開機共同比較仍限同一實體主機、指定核心與獨立受控目錄，沒有重跑九開機主矩陣，也沒有新增公開 rootkit。首次混合目錄比較未完成且控制無有效輸出，不能當成對方漏報。後續另修復控制模組的重疊搬移長度錯誤並驗證，沒有把修復回填舊來源或合併分母。'), 441: original[441][:original[441].index('補強版另將')] + '現行入口另整合還原核對及入口、返回與 BPF 程式統計，真實入口漏失窗口能拒判。 完整新程序成本顯示本文並非全面較快，大目錄逐項事件觀測也有容量取捨，見 6.8 節。 這些結果支持受測條件下的整合方法，仍保留有限摘要、機率式比對與可信量測的限制。', 445: '量測品質方面，本輪已將入口 tracefs 統計接入拒判，不再列為未完成。 後續可依部署需求比較預編譯、持續附掛或批量掃描的載入成本攤提，保留相同品質檢查，並量測對其他程序的影響。 現有量測介面已能重複掃描，將其工程化不直接等於新研究。 若要擴大掛接家族或環境主張，再補具體機制的直接證據。 rkchk 的不同自訂核心與目標仍是未納入的界線。', 450: original[450] + ' 現行入口、三開機共同比較、未完成嘗試、控制修復與主機取樣另存 comparison 封存，可由 scripts/verify_completion_20261102.py 離線重算，逐開機配對成本見 comparison/analysis。官方執行檔與最小轉接版的來源、雜湊、差異及工具鏈分開記錄。'}
    for i, value in edits.items():
        replace(paras[i], value)
    for p in paras:
        value = text(p)
        if '未共同量測優劣' in value:
            replace(p, value.replace('未共同量測優劣', '共同比較見 6.8 節，仍不推論全面優劣'))

    def insert(anchor, template, values):
        nodes = []
        for value in values:
            node = deepcopy(template)
            replace(node, value)
            anchor.addprevious(node)
            nodes.append(node)
        return nodes
    heading = next((p for p in paras if text(p) == '5.6 還原核對與量測品質補強設計'))
    result_heading = next((p for p in paras if text(p) == '6.7 補強實作確認結果'))
    anchor6 = next((p for p in paras if text(p) == '6. 結果'))
    anchor7 = next((p for p in paras if text(p) == '7. 討論'))
    insert(anchor6, heading, [''])
    insert(anchor6, paras[239], ['十二種狀態各五次，方法先後隨機配對，在同一 VM 的三個不同開機重複。 共同目標為核心產生而回傳缺失的名稱，包含長短改名、移除、filldir 與 getdents 隱藏、政策過濾及等長替換；正常與重排為對照。 新增、inode 與型態另列本文身分目標，不混入共同名稱召回分母。 各狀態另有無探針實收控制，錯誤、跳過與逾時不算乾淨結果。', '官方工具掃多個目錄，不能直接與單目錄比速度。成本因此使用固定來源[21]的最小轉接版，只指定目錄、同目錄檢查檔與可選事後稽核，BPF、名稱集合、缺失重掃及判定不改。每種狀態先與官方版本核對目標發現。128、4,096、65,536 個一般項目，各開機每條件一個暖機及五個主要配對，共 45 配對，逐區組相除後取開機中位數。每次新程序的成本包含編譯或載入、附掛、列舉、品質檢查、輸出及清理，不清除檔案系統快取。GNU time 另記 CPU 與 max RSS，後者不是程序群組加核心 map 的總記憶體。正式計時關閉事後稽核，另次核對入口與實收名稱數。', '首次按原規約在混合 /var/tmp 確認時未完成，保留九十筆已得觀察、無效控制及逾時堆疊。修訂規約後才用獨立目錄進行三開機確認，不合併分母。官方資產的建置資訊為 Go 1.25.14、revision 814633a 且 modified=true；兩相關來源檔與[21]的 blob 一致。轉接版另用可攜 Go 1.25.0，來源差異與二進位雜湊分開保存，不宣稱兩版本逐位元相同。客體未升級。'])
    insert(anchor7, result_heading, [''])
    insert(anchor7, paras[418], ['三開機共 360 筆工具觀察。 共同名稱目標下，兩者均為 105/105 檢出、0/30 對照警報，未顯示本文在此目標的檢出率優勢。 36 次無探針控制皆符合預期，36 次轉接版功能核對與官方版本的目標發現一致。 其他目錄的發現分開，不把全工具功能一併評為優劣。', '新程序完整耗時見表 7。128 與 4,096 項的各開機配對比值中位數，本文為轉接版 3.50–3.73 倍，不能宣稱全面較快。本文包含 BCC 即時編譯，對方使用預編譯 BPF，差距不能直接歸為指紋或 IBLT 演算法速度。GNU time max RSS 的各開機中位數範圍，本文為 126,632–126,764 KiB，轉接版為 82,880–87,320 KiB，不含核心 map，也不是同時使用的程序群組總和。'])
    captions = [p for p in paras if text(p).startswith('表 5')]
    caption_template = captions[0]
    insert(anchor7, caption_template, ['表 7\u3000三開機各五個主要配對的新程序耗時中位數範圍，單位 ms。名稱稽核另次執行，包含一筆檢查檔，未加入計時樣本。'])
    original_table = doc.findall('.//w:tbl', NS)[0]
    table = deepcopy(original_table)
    templates = table.findall('w:tr', NS)
    header = deepcopy(templates[0])
    row_template = deepcopy(templates[1])
    for row in table.findall('w:tr', NS):
        table.remove(row)

    def table_row(template, values):
        row = deepcopy(template)
        for cell, value in zip(row.findall('w:tc', NS), values):
            ps = cell.findall('w:p', NS)
            replace(ps[0], value)
            for extra in ps[1:]:
                cell.remove(extra)
        table.append(row)
    table_row(header, ['項目數', '本文耗時', '', '入口／實收名稱'])
    for size in (128, 4096, 65536):
        c = facts['cost_ranges'][str(size)]

        def span(k):
            return '–'.join((f'{n:,.2f}' for n in c[k]))
        audit = c['name_audits'][0][0]
        table_row(row_template, [f'{size:,}', span('ours_median_ms'), span(''), f"{audit['produced']:,}/{audit['returned']:,}"])
    anchor7.addprevious(table)
    insert(anchor7, paras[418], ['其流程先完成 os.ReadDir 再讀固定 4 MiB ring buffer，無法保存此量的全部逐項事件，且所查程式未記預留失敗數。 這支持此受測流程入口觀測不完整，不是隱藏攻擊試驗，較短耗時不能當同等完整觀測的速度優勢。 128 與 4,096 項的入口與實收名稱數相同。 本文的固定摘要亦非無限還原能力，兩者有不同取捨。', '混合目錄的首次確認未完成，該條件的無探針控制沒有有效記錄，不能據此判對方漏報。另確認舊控制模組在重疊 memmove 後重新讀已覆寫的記錄長度，離線 216-byte 輸入會算出 24,977-byte 輸出，修復後為正確 176 bytes。修復版的混合長短名稱原生確認包含十二次無探針控制、四次本文及四次官方工具，皆符合預期，不併入共同比較分母。這證實控制來源缺陷，不單靠模型宣稱已分離 Go 逾時的完整原因。原正式輸出仍經獨立預期差異核對，原來源與數據不覆寫。'])
    ref = next((p for p in paras if text(p).startswith('[22]')))
    node = deepcopy(ref)
    replace(node, '')
    ref.addnext(node)
    for paragraph in doc.findall('.//w:p', NS):
        if text(paragraph).startswith(tuple((f'[{i}]' for i in range(1, 24)))):
            props = paragraph.find('w:pPr', NS)
            if props is None:
                props = E.Element(W + 'pPr')
                paragraph.insert(0, props)
            keep = props.find('w:keepLines', NS)
            if keep is None:
                keep = E.SubElement(props, W + 'keepLines')
            keep.set(W + 'val', '1')
    punctuation_cleanups = 0
    for node in doc.findall('.//w:t', NS):
        if node.text:
            punctuation_cleanups += node.text.count('；')
            node.text = node.text.replace('；', '。')
    xml = E.tostring(doc, xml_declaration=True, encoding='UTF-8', standalone=True)
    assert not doc.findall('.//w:ins', NS) and (not doc.findall('.//w:del', NS))
    with ZipFile(output, 'w', ZIP_DEFLATED) as z:
        for name, (info, data) in parts.items():
            z.writestr(info, xml if name == 'word/document.xml' else data)
    with ZipFile(output) as z:
        assert all((z.read(n) == d for n, (_, d) in parts.items() if n != 'word/document.xml'))
    work = ROOT / '_docx_work/completion_20261102'
    work.mkdir(exist_ok=True)
    report = {'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'output_sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'changed_package_parts': ['word/document.xml'], 'fullwidth_semicolons_replaced': punctuation_cleanups, 'edits': {str(i): {'before': original[i], 'after': s.replace('；', '。')} for i, s in edits.items()}}
    (work / 'changes35.json').write_bytes(json.dumps(report, ensure_ascii=False, indent=2).encode())
    print(json.dumps({'output': str(output), 'sha256': report['output_sha256'], 'replaced_paragraphs': len(edits)}))
if __name__ == '__main__':
    main()
