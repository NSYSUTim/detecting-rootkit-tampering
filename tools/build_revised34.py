# Historical source retained after a comparison was withdrawn.
# Its original paragraph offsets and archived source hashes no longer
# describe the public copy. Do not regenerate historical reports.
if __name__ == "__main__":
    raise SystemExit("Historical generator retired after selective public cleanup")
"""Update the preserved revised33 OOXML, retaining all other package parts."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from lxml import etree as E
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'paper/cross_layer_directory_entry_consistency_revised33_zhTW.docx'
OUTPUT = ROOT / 'paper/cross_layer_directory_entry_consistency_revised34_zhTW.docx'
NS = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
W = '{' + NS['w'] + '}'

def text(p):
    return ''.join(p.xpath('.//w:t/text()', namespaces=NS))

def replace(p, value):
    runs = p.findall('.//w:r', NS)
    properties = deepcopy(runs[0].find('w:rPr', NS)) if runs and runs[0].find('w:rPr', NS) is not None else None
    for child in list(p):
        if child.tag != W + 'pPr':
            p.remove(child)
    r = E.SubElement(p, W + 'r')
    if properties is not None:
        r.append(properties)
    t = E.SubElement(r, W + 't')
    t.text = value
    if value.startswith(' ') or value.endswith(' '):
        t.set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')

def main():
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == '47169ad7e18b432ce8f66e26d6f2bfaad559d46302f43dd22b56b2711b61bca8'
    evidence = json.loads((ROOT / 'finalization/evidence/verification.json').read_text(encoding='utf-8'))
    assert evidence['passed']
    with ZipFile(SOURCE) as z:
        parts = {i.filename: (i, z.read(i.filename)) for i in z.infolist()}
    root = E.fromstring(parts['word/document.xml'][1])
    body = root.find('w:body', NS)
    p = root.findall('.//w:p', NS)
    before = [text(x) for x in p]
    changes = {6: 'Linux 的 getdents64 透過 filldir64 將目錄項寫入使用者緩衝區。隱藏或過濾模組可使核心端已接受的項目與回傳記錄不同。本文以 eBPF 記錄回傳 true 的最外層 filldir64 呼叫，由專用 C 掃描器發起並取得同一次完整列舉，兩端同步建立固定大小的多重集合指紋與 Invertible Bloom Lookup Table（IBLT）。指紋判斷輸出是否一致，IBLT 還原少量差異的識別值、inode 與型態，不保存原始名稱。九次開機共 1,296 批、25,920 次列舉中，576 個差異批次全數檢出，720 個對照批次未誤報，11,520 次差異列舉皆完整還原。只比較項目數的召回率為 75%，兩個整次耗時門檻皆低於 5%。單次受控外部比較中，重建的 Landauer 等人方法在依測試標籤選最有利門檻時仍有 15.20%–27.18% 誤報。兩組補充實驗另確認返回漏失、載入順序、兩個指定核心、ext4 與 tmpfs，以及正常動態目錄，合併核心狀態後保留定位能力並降低受測條件的耗時。後續補強版新增還原指紋核對與 BPF 遞迴略過統計檢查，原資料離線重算及另列的單開機原生確認皆符合預期，但未重跑原完整矩陣或重新建立成本結論。本方法的貢獻是同次已接受項目的對齊、固定摘要與量測失效處理，不主張兩端比較概念為首創。結果限於可信量測及受測條件，警報表示兩端不一致，不直接判定惡意。一般多重集合還原、未覆蓋的入口漏失及更強攻擊者仍是限制。', 17: before[17] + ' 本文另以補強實作將還原結果的指紋核對接入收集流程，並檢查可取得的 BPF 遞迴略過統計，其確認結果與前述分母分開報告。', 26: '既有方法可依檢查內容整理為完整性檢查、跨視圖比較、時序異常與逐項記錄，另有本文借用的 IBLT，見表 1。這些分類並不互斥，本文亦屬跨視圖比較。以下區分原始碼功能分析與共同環境的實驗比較。', 30: before[30].replace('這類方法需要較難被竄改的低階視圖，例如', '這類方法依賴另一個足以供比較的視圖。例如'), 34: '逐項記錄與本文的觀測位置最接近。 Synacktiv 分析 LinkPro 的公開展示在 filldir64 掛接 kprobe，印出核心端產生的每個目錄項名稱，供與使用者端結果對照[10]。 該展示未提供足以核對完整自動比對、接受規則與量測品質門檻的細節。 本文固定分析提交 08ccebd8fdcc28c56dc6251cad0683b7c9344bd1，不把個人開源實作當成同儕審查論文，但仍將其列為直接相關工作。', 38: '兩端清單比較及 filldir64 觀測點已有公開先例[10][21]，本文不主張這組觀測位置為首創。 本文的切入點是在同一次完整列舉中只計入已接受的最外層呼叫，以名稱、inode 與型態建立固定大小指紋，並用 IBLT 還原兩端獨有的少量差異識別值，配合量測失效時拒判。 其可直接回報缺失名稱，本文則節省逐項保存但不還原名稱，且定位受容量、分布與重複差異限制。', 85: before[85] + ' 5.6 節與 6.7 節另說明收集流程的補強確認，同樣不另立研究問題。', 149: before[149].replace('解碼成功與否取決於差異項目數與儲存格數的比例', '解碼成功與否受差異量、容量與雜湊位置分布共同影響'), 153: before[153] + ' 補強版將還原出的項目帶正負號重新累計成指紋，核對是否等於兩端指紋之差。解碼完成、殘留為零且核對相符時，才標示還原通過核對。指紋不同而解碼或核對失敗時，仍警報並回報無法完整定位。核對沿用原機率式指紋，不構成完全正確的數學證明，也不使原本無法解碼的重複差異變得可還原。', 158: before[158] + ' 補強版再查詢兩支 BPF 程式的 ID、tag 與 recursion_misses，遇到必要讀數缺失、身分改變、計數倒退或窗口內新增略過即拒判，見 5.6 節。若指紋相同但解碼與還原核對互相矛盾，也拒絕產生一致判定。舊版資料不回填新統計。', 168: before[168].replace('本文使用三種實作', '本文依實驗用途區分四種實作').replace('三種實作的指紋定義', '前三種實作的指紋定義') + ' 第四種為補強實作，以外層檢查包裝合併狀態版，新增還原核對與 BPF 程式統計門檻，不改寫原指紋、IBLT 或凍結收集器。其新確認及計時另列，不能沿用前三種實作的全部成本結論。', 299: before[299] + ' 另以相同 X、Y 各一份及 256 格核對時，三個位置的計數相減為零，XOR 內容未歸零，仍沒有可剝離的 ±1 儲存格，解碼失敗。因此沒有重複差異也不保證可解碼。補強版對上述失敗與錯誤空差集均不標為還原通過核對，見 6.7 節。', 412: before[412] + ' 本輪補強版新增品質查詢與還原核對，未重做跨開機大目錄成本比較，以上倍率不作為補強版的新效能結果。', 423: '列舉完整性檢查涵蓋名稱讀取、核心端更新、呼叫配對及量測行程錯誤。九次開機正式資料未保存返回探針漏失統計，無法事後補上。診斷版與合併狀態版加入返回 profile 門檻，補強版另檢查 BPF 程式的 recursion_misses。後者反映追蹤執行路徑因遞迴保護而略過，不能替代入口 perf kprobe 內部全部 nmissed。新原生試驗實際注入返回漏失，未原生注入所有 BPF 略過；讀數缺失、倒退與身分變動的分支另由離線測試檢查。IBLT 失敗屬定位不足，指紋不同仍警報。新增還原核對可拒絕已構造的錯誤空差集，仍受同一指紋的碰撞限制，不能聲稱已消除全部漏失或錯誤還原。', 427: before[427] + '', 430: before[430].replace('尚未完成的方向列於下文。', '補強版另將還原指紋核對及可取得的 BPF 遞迴略過檢查接入流程，28 次新實際差異均正確警報、還原並通過核對，實際返回漏失窗口內 16 次列舉均拒判，分母與原結果分開。這完成了既定範圍內的具體補強，仍保留有限容量、機率式比對與可信量測等限制。'), 432: '未來工作依待解問題選擇，不要求全部執行。直接延續目前方法的是提高差異定位能力：當實際差異量未知、雜湊位置不利或同一身分重複出現時，如何在可控成本下提高完整還原率。可比較支援重複次數的加法型結構或容量協商，保留本輪已完成的還原指紋核對，分開評估警報、核對後完整還原、無法定位及成本。現有容量掃描只支持指定設定，不能把加大表格當成重複差異的通用解法。', 434: '另一項可延續工作是量測品質與比較證據。 需針對目前看不到的入口 perf kprobe 漏失取得可驗證統計，或改用能觀察該失效的附掛方式，並重新確認拒判與正常判讀。 rkchk 的自訂核心與不同檢查目標使其不是本輪完成的必要條件，未量得的比較仍明列缺口。', 436: '觀察一般程式自己的列舉、抵抗辨識掃描器的攻擊者，以及延伸至 /proc，均屬另行選擇的研究範圍，本文未完成這些架構。Linux 6.8 原始碼支持 /proc 列舉可經相同回呼到 filldir64[2]，但換路徑本身不構成新貢獻。已複製到回傳緩衝區的記錄不會因行程後來結束而自行消失，生命週期變動不直接等於兩端差異。若進一步要找出兩端共同看不到的行程，才需要獨立生命週期視圖與跨來源一致性模型。核心內對手的金鑰保護也需要額外信任基礎，不能只改成秘密金鑰雜湊就聲稱解決。以上不列為本方法結案前必做事項。', 439: before[439].replace('完整重現套件', '研究重現套件') + ' 補強實作、兩份預先規約及包含先導與全部試驗輸出的封存另放於 finalization。scripts/verify_finalization.py 可離線重算原保存還原、反例、新實收身分與核對結果，並核對測試版本及封存的 SHA-256。兩組補充與本輪補強分母互不合併。'}
    for i, value in changes.items():
        replace(p[i], value)

    def insert_before(anchor, template, values):
        for value in values:
            node = deepcopy(template)
            replace(node, value)
            anchor.addprevious(node)
    insert_before(p[36], p[34], ['其核心 ring buffer 固定配置為 4 MiB，逐項事件總量與使用者端名稱集合隨目錄大小增加；預留事件失敗的分支未保存丟失計數。 工具另有已知檢查檔、錯誤與跳過處理，不能描述為完全沒有品質檢查。'])
    insert_before(p[233], p[220], ['5.6 還原核對與量測品質補強設計'])
    insert_before(p[233], p[221], ['補強版沿用合併狀態收集器，每次列舉在原品質門檻之外，讀取兩支已載入 BPF 程式的 /proc/self/fdinfo，核對 prog_id、prog_tag 與 recursion_misses 前後讀數。Linux 6.8 在追蹤程式因遞迴保護而略過時累加此計數，並在程式 fdinfo 提供查詢[22]。缺少讀數不當成零。此門檻只涵蓋可取得的程式略過與原返回 profile，沒有宣稱覆蓋全部入口漏失。還原端再把正負差異項目算成指紋，與兩端指紋之差核對，區分量測無效、未觀察到差異、差異且還原通過核對、差異但無法完整定位。', '確認於 2026 年 11 月 1 日在既有 6.8.0-138-generic 虛擬機同次開機執行，不升級套件，原程式與受控模組以雜湊核對，輸出另存。規約在執行前保存。使用原受控模組的正常、重排、新增、名稱增長、名稱縮短、inode、型態、移除與等長替換九種狀態，兩種緩衝區、各兩次，共 36 次量測；另有 18 次無探針實收控制。正常及名稱邊界共十次，包含一次預期無效的過小緩衝區。降低 maxactive 至 1 並啟動 16 個並行掃描，確認返回漏失窗口全數拒判，再以 maxactive 256 取得兩次循序對照。原資料的 25,920 次保存還原及離線反例另行重算，不作為新原生試驗。本輪不新增公開 rootkit、一般程式監控或 /proc 試驗。'])
    insert_before(p[409], p[363], ['6.7 補強實作確認結果'])
    insert_before(p[409], p[407], ['原 25,920 次保存結果全部通過新增還原指紋核對，其中 11,520 次為實際差異。六個既有重複反例的失敗或錯誤空差集均未被接受為通過核對的完整還原，這是離線重算，不增加原實驗分母。31 項離線回歸測試涵蓋原功能、錯誤成功、符號與次數變動、殘留、必要統計缺失、倒退與程式身分改變。', '新原生確認中，28 次實際差異均警報，還原識別值與獨立預期差異逐筆相符，並通過指紋核對；8 次正常或重排均有效一致，18 次無探針控制的實收身分也符合預期。名稱邊界等九次有效一致，另一次過小緩衝區標為無效。實際出現返回漏失的窗口內 16 次列舉全數拒判，兩次循序對照有效一致。十次先導紀錄另保留，不重複計入上述確認。原程式與模組雜湊未變。這些結果支持補強流程接入正確，沒有證明所有入口漏失可見，也沒有原生注入所有 recursion_misses 分支。新增品質查詢及還原核對的耗時已記錄，但未重做跨開機成本比較。'])
    table = root.findall('.//w:tbl', NS)[0]
    rows = table.findall('w:tr', NS)
    syn = rows[6]
    for cell, value in zip(syn.findall('w:tc', NS), ['Synacktiv 展示 [10]', '以 kprobe 在 filldir64 輸出每個名稱，供與使用者端對照', '公開展示不足以確認完整自動比對與品質規則', '本文另定義已接受計入、固定摘要與還原。6.4 節是自製逐項基線，非原工具實測']):
        replace(cell.find('w:p', NS), value)
    row = deepcopy(syn)
    for cell, value in zip(row.findall('w:tc', NS), ['', '自行列舉，以 filldir64 入口名稱集合對照使用者端名稱，重掃缺失候選', '此元件不比 inode、型態或返回接受值；有檢查檔與錯誤處理', '觀測位置相近，可找等量名稱替換並回報名稱。本文用固定摘要、接受規則與雙向差異識別值，未共同量測優劣']):
        replace(cell.find('w:p', NS), value)
    syn.addnext(row)
    ref = p[461]
    for value in ['', '[22] Linux kernel contributors, “BPF tracing recursion protection and program fdinfo,” Linux v6.8, kernel/trace/bpf_trace.c and kernel/bpf/syscall.c. https://github.com/torvalds/linux/blob/v6.8/kernel/trace/bpf_trace.c and https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/syscall.c (accessed Nov. 1, 2026).']:
        node = deepcopy(ref)
        replace(node, value)
        ref.addnext(node)
        ref = node
    data = E.tostring(root, xml_declaration=True, encoding='UTF-8', standalone=True)
    assert not root.findall('.//w:ins', NS) and (not root.findall('.//w:del', NS))
    with ZipFile(OUTPUT, 'w', ZIP_DEFLATED) as z:
        for name, (info, original) in parts.items():
            z.writestr(info, data if name == 'word/document.xml' else original)
    with ZipFile(OUTPUT) as z:
        assert all((z.read(name) == original for name, (_, original) in parts.items() if name != 'word/document.xml'))
    report = {'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(), 'output_sha256': hashlib.sha256(OUTPUT.read_bytes()).hexdigest(), 'modified_package_parts': ['word/document.xml'], 'replaced_original_paragraphs': {str(i): {'before': before[i], 'after': value} for i, value in changes.items()}, 'added_design': '5.6', 'added_results': '6.7', 'added_references': [21, 22]}
    work = ROOT / '_docx_work/finalization_20261101'
    work.mkdir(parents=True, exist_ok=True)
    (work / 'changes.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'output': str(OUTPUT), 'sha256': report['output_sha256'], 'changed_paragraphs': len(changes)}))
if __name__ == '__main__':
    main()
