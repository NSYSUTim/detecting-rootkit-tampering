"""Reconcile paper scope and explanations with verified decisions and sources."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
from build_revised37 import patch_text, NS
from build_revised35 import replace

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'paper/cross_layer_directory_entry_consistency_revised37_zhTW.docx'
OUTPUT = ROOT / 'paper/cross_layer_directory_entry_consistency_revised38_zhTW.docx'
SOURCE_SHA = 'e0c1a7c4915eb572d75a012377d4002d870bf22e8bc50c2ec5a44018625648fb'


def main():
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == SOURCE_SHA
    with ZipFile(SOURCE) as archive:
        parts = {i.filename: (i, archive.read(i.filename)) for i in archive.infolist()}
    document = E.fromstring(parts['word/document.xml'][1])
    paragraphs = document.findall('.//w:p', NS)
    text = lambda p: ''.join(p.xpath('.//w:t/text()', namespaces=NS))
    original_tables = [E.tostring(x, method='c14n') for x in document.findall('.//w:tbl', NS)]
    changes = []

    def edit(prefix, operation):
        matches = [p for p in paragraphs if text(p).startswith(prefix)]
        assert len(matches) == 1, (prefix, len(matches))
        p = matches[0]
        before = text(p)
        after = operation(before) if callable(operation) else operation
        assert before != after, prefix
        patch_text(p, before, after)
        changes.append({'before': before, 'after': after})
        return p

    edit('Linux 的 getdents64 透過', lambda v: v.replace(
        '追加三開機、45 個配對區組，比較準備完成後的掃描判讀，本文於小目錄較慢，65,536 項時為',
        '三開機、45 個配對區組的掃描判讀比較中，本文於 128 項較慢、4,096 項較快，65,536 項為').replace(
        '貢獻是同次已接受項目的對齊、固定摘要與量測失效處理，不主張兩端比較為首創。',
        '貢獻在同次已接受項目的對齊、固定摘要與量測失效處理。'))
    edit('若攻擊者能同時竄改兩端', lambda v: v.replace(
        '這類會針對本方法調整行為的進階攻擊者尚未實驗，列為未來工作，見第 9 節。',
        '這些是可信量測假設的界線，見第 8 節。'))
    anchor = next(p for p in paragraphs if text(p).startswith('對每筆目錄項 e，'))
    motivation = (
        '名稱相同不代表回傳的 inode 與型態相同，這些欄位也會供程式使用。PEP 471 說明目錄列舉提供的型態資訊可省去額外查詢[25]，'
        '而 glibc 2.35 的公開 readdir64 原始碼會略過 inode 為零的記錄[26]。這些例子說明欄位改寫有影響後續處理的程式依據。'
        '本文的 inode 與型態試驗檢驗回傳欄位的不一致，沒有實測上述行為對受測套件、ls 顯示或遞迴遍歷的影響。')
    node = deepcopy(anchor)
    replace(node, motivation)
    anchor.addnext(node)
    changes.append({'inserted': motivation})
    edit('指紋是機率式比對', lambda v: v +
         ' 若只替換名稱且 inode 與型態相同，h₁ 相等時 h₂ 也相等。多筆差異時，B 提供另一項總和相等的檢查，'
         '但非線性混合本身不足以證明兩項檢查獨立，也不能據此給出所有輸入的碰撞率。')
    edit('上述估計假設攻擊者不知道種子', lambda v: v.replace(
        '隨機漏報的估計也不再成立', '不能將前述示意模型的機率當作抵抗主動搜尋的保證'))
    edit('九次開機矩陣實驗含九種狀態', lambda v: v +
         ' 小緩衝區用來增加正常重送，以檢查計入規則。背景負載與重新開機用來檢查實作在受測條件下的重複性。'
         '九次開機仍是同一環境，沒有增加九種隱藏機制。')
    edit('適用條件實驗的因素有核心版本', lambda v: v.replace(
        '差異的還原結果，與依預期',
        '其中新增、改名、inode 與型態改寫是操控 getdents64 回傳記錄，不改動磁碟上檔案的名稱或 inode。正常動態目錄則實際執行建立、改名與刪除。差異的還原結果，與依預期'))
    edit('同一 ext4 目錄有 128', lambda v: v.replace(
        '獨立目錄 目錄清單', '獨立的目錄清單').replace('由 目錄清單 重算', '由目錄清單重算'))
    edit('相對於預設 4 MiB 的計時轉接版', lambda v: v.replace('完整 目錄清單', '完整目錄清單'))
    edit('九次開機矩陣實驗檢驗的是', lambda v: v.replace(
        '更多核心與檔案系統，以及實驗未使用的隱藏模組，仍需要驗證泛化性。',
        '這些結果界定目前的受測範圍，不據此推論其他環境或掛接技術均有相同結果。'))
    edit('政策過濾顯示，',
         '政策過濾顯示，輸出一致性與授權是兩個判定問題。受控政策依事先授權的規則移除項目，仍會造成兩端身分不同，'
         '因此本文將它列為差異批次。警報表示不一致，管理者可依既有的可信政策或過濾紀錄判斷原因。'
         '本文評估量測、配對與差異判讀，不以警報判斷惡意，也不建立授權分類系統。720 個對照批次的零誤報，'
         '是指沒有兩端身分差異的受測狀態未被警報，不是對惡意分類正確率的估計。')
    edit('九次開機矩陣實驗的結果來自', lambda v: v.replace(
        '更多核心與檔案系統，以及實驗未使用的隱藏模組，仍需要以相同的判定規則與參數重新建立矩陣實驗。',
        '本研究未將此矩陣結果外推至未受測的環境或隱藏實作。'))
    edit('本文的跨層比較建立在', lambda v: v.replace('見 3.2、4.1 與第 9 節', '見 3.2 與 4.1 節'))
    edit('九次開機矩陣實驗只驗證 ext4', lambda v: v.replace(
        '/proc 的內容會隨行程建立、結束與 PID 重用變動，這些變動對同次列舉與兩端配對的影響尚未實測，見第 9 節。',
        '/proc 的資料只作無差異控制，不構成行程隱藏偵測的驗證。'))
    edit('兩組實驗另有下列限制', lambda v: v.replace(
        '動態目錄只驗證正常變動下的同次一致性，沒有建立原子快照與行程生命週期模型。',
        '動態目錄檢驗正常變動下的同次交付一致性，結果不代表原子快照或動態隱藏攻擊的偵測率。'))
    edit('本文提出比較 filldir64 與 getdents64',
         '本文以 eBPF 與專用 C 掃描器，比較同一次完整列舉的核心已接受項目與 getdents64 實收記錄。'
         '固定大小指紋負責警報，IBLT 還原差異識別值，還原核對與量測品質檢查則區分完整定位、無法定位及無效量測。'
         '九次開機矩陣的 576 個差異批次全數檢出、720 個對照批次未誤報，11,520 次差異列舉皆正確還原，'
         '支持受測重送、巢狀呼叫與身分改寫下的流程正確性。適用條件實驗中，兩個指定核心與 ext4／tmpfs 的 4,560 次實際差異均判對並還原，'
         '480 次正常動態列舉維持一致。入口與返回探針的受測漏失窗口能被拒判。這些結果限於可信量測與所列實驗條件。'
         '單次 Landauer 比較與 Decloaker 的不同觀測目標見 6.5 節。與 zygarde 的共同名稱測試中，兩者皆為 105/105 檢出、0/30 對照警報，'
         '本文另檢出新增、inode 與型態差異。初版實作的 4.76 倍耗時及合併狀態版相對診斷版的 39.6%–45.1% 降幅使用不同計時流程，見 6.4 節。'
         '128 與 4,096 項的新程序完整成本是本文較高。準備完成後的掃描判讀則在 128 項時較慢，4,096 項時較快，65,536 項時為 88.04–89.06 ms，'
         '觀測完整的 32 MiB zygarde 轉接版為 461.86–469.18 ms，見 6.8–6.9 節。固定的是摘要大小，逐項處理時間仍隨目錄規模增加，'
         '比較結果也受各實作的 API、緩衝區與檢查內容影響。')
    edit('未來工作依待解問題選擇',
         '下一步聚焦增加觀測點，研究差異出現在哪一段。目前只比較 filldir64 與原始 getdents64 記錄，'
         '尚未觀察一般程式經函式庫取得的項目。跨視圖比較已有前例[4][5]，此延伸要回答的是：'
         '能否在同一次完整列舉內，對齊核心已接受項目、系統呼叫回傳記錄及函式庫交付項目，以固定大小摘要區分差異區段。')
    edit('量測品質方面，本輪已將入口',
         '設計上須先對同一程式、同一個開啟的目錄及列舉區間建立配對。glibc 會批次讀取 getdents64 記錄，'
         '再逐筆交付[26]，不能把一次函式庫呼叫當成一次系統呼叫。先在單執行緒、完整讀到結尾的條件下建立三端記錄，'
         '分別比較核心至系統呼叫、系統呼叫至函式庫兩段，再以無過濾、受控核心過濾及受控函式庫過濾核對預期差異。'
         '缺少記錄、未完成列舉及配對失敗均須明確處理，並量測無效率與成本，避免把不同次列舉的目錄變動混為隱藏。')
    edit('觀察一般程式自己的列舉',
         '這是尚未實作的觀測架構提案，目標由判斷兩端是否不同，延伸至指出差異位於哪兩個觀測點之間。'
         '觀測點之間也可能有正常轉換，因此區段判定仍與惡意性分開。新架構沿用可信量測的前提，'
         '須先確認資料取得、配對與失效處理可靠，才能評估增加觀測點所帶來的涵蓋範圍。')
    reference = next(p for p in paragraphs if text(p).startswith('[24]'))
    for value in [
        '[25] B. Hoyt, “PEP 471 – os.scandir() function – a better and faster directory iterator,” Python Enhancement Proposals, 2014. https://peps.python.org/pep-0471/ (accessed Nov. 2, 2026).',
        '[26] Free Software Foundation, “readdir64 implementation,” GNU C Library, glibc-2.35, sysdeps/unix/sysv/linux/readdir64.c. https://github.com/bminor/glibc/blob/glibc-2.35/sysdeps/unix/sysv/linux/readdir64.c (accessed Nov. 2, 2026).',
    ]:
        node = deepcopy(reference)
        replace(node, value)
        reference.addnext(node)
        reference = node
    assert original_tables == [E.tostring(x, method='c14n') for x in document.findall('.//w:tbl', NS)]
    full = ''.join(document.xpath('.//w:t/text()', namespaces=NS))
    assert all(s not in full for s in ('目錄 目錄清單', '完整 目錄清單', '補充實驗', '主實驗', '；', ';'))
    xml = E.tostring(document, xml_declaration=True, encoding='UTF-8', standalone=True)
    with ZipFile(OUTPUT, 'w') as archive:
        for name, (info, payload) in parts.items():
            archive.writestr(info, xml if name == 'word/document.xml' else payload)
    work = ROOT / '_docx_work/conversation_review_20261102'
    work.mkdir(parents=True, exist_ok=True)
    result = {'source_sha256': SOURCE_SHA, 'output_sha256': hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),
        'changed_package_parts': ['word/document.xml'], 'existing_tables_unchanged': True, 'edits': changes}
    (work / 'changes38.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'output': str(OUTPUT), 'sha256': result['output_sha256'], 'edits': len(changes)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
