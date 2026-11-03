"""Add validated per-call completion evidence to the accepted-only paper."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
from build_revised37 import patch_text, NS
from build_revised35 import replace

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx'
OUTPUT=ROOT/'paper/cross_layer_directory_entry_consistency_revised41_zhTW.docx'


def main():
    facts=json.loads((ROOT/'call_completion/verification.json').read_text())
    assert facts['verified'] and facts['native_functional_scans']==1737
    assert facts['regression']['identity_alarms']==555 and facts['regression']['verified_recovery']==555
    assert all(r['completion_alerts']==0 for r in facts['benign_race'].values())
    with ZipFile(SOURCE) as archive:parts={i.filename:(i,archive.read(i.filename)) for i in archive.infolist()}
    xml=E.fromstring(parts['word/document.xml'][1]);paragraphs=xml.findall('.//w:body/w:p',NS)
    text=lambda p:''.join(p.xpath('.//w:t/text()',namespaces=NS))
    tables=[E.tostring(t,method='c14n') for t in xml.findall('.//w:tbl',NS)];edits=[]
    def edit(prefix,change):
        found=[p for p in paragraphs if text(p).startswith(prefix)]
        assert len(found)==1,(prefix,len(found))
        p=found[0];before=text(p);after=change(before);assert before!=after,prefix
        patch_text(p,before,after);edits.append(dict(before=before,after=after));return p
    body=next(p for p in paragraphs if text(p).startswith('三次開機的 135 筆'))
    heading=next(p for p in paragraphs if text(p).startswith('6.9 '))
    def insert(anchor,style,values):
        for value in values:
            node=deepcopy(style);replace(node,value);anchor.addprevious(node);edits.append(dict(inserted=value))
    edit('Linux 的 getdents64 透過',lambda t:t+
      ' 依此邊界另加入同次系統呼叫的完成檢查，區分原版 filldir 的拒絕後回報結束與跨呼叫正常刪除。'
      '新三開機中，原版 getdents64 模式 120 次維持身分警報與正確還原，filldir 模式 120 次皆取得完成異常及一筆遭拒項目。'
      f"正常靜態、實際重疊三種變動與受控刪除競態分別為 120、{facts['dynamic_all_three_operations_overlap']}、30 次，均無新警報，未走訪的全部缺失仍無法還原。")
    edit('本文把偵測範圍限定在',lambda t:t.replace('本文把偵測範圍限定在','身分差異分支把比較範圍限定在',1)+
      ' 本版另以 4.4 節檢查同一次 getdents64 內拒絕項目卻回傳 0 的完成異常，不把拒絕嘗試加入已接受項目的指紋或 IBLT。')
    edit('5.5 節與 6.6 節的兩組實驗',lambda t:t+
      ' 原版 CARAXES 的結果另導出完成檢查問題：能否辨認同一次呼叫拒絕項目卻回報結束，並避免將跨呼叫的正常刪除誤認為此異常。方法與驗證見 4.4 與 6.11 節。')
    edit('在這些假設下，本方法偵測',lambda t:t.replace('在這些假設下，本方法偵測','在這些假設下，身分差異分支偵測',1).replace(
      '原版 CARAXES 的後一種情形已在 6.10 節實測。',
      '原版 CARAXES 的後一種情形已在 6.10 節以原已接受項目版本實測。本版另以 4.4 節的同次呼叫完成檢查辨認受測異常，結果見 6.11 節，仍不表示兩端產生身分差集。'))
    edit('警報代表此範圍內',lambda t:t.replace('警報代表此範圍內','身分差異警報代表此範圍內',1)+
      ' 完成異常警報則表示同一次呼叫的拒絕與結束回報不符合原生受測路徑，兩種警報均不直接判斷惡意。')
    edit('圖 1',lambda t:t+' 本圖呈現已接受項目的身分比對，新增的同次呼叫完成檢查見 4.4 節。')
    method=next(p for p in paragraphs if text(p).startswith('5. 實作'))
    insert(method,heading,['4.4 同次系統呼叫的拒絕與結束配對'])
    insert(method,body,[
      'C 掃描器反覆呼叫 getdents64，一次完整列舉可含多次讀取。僅記住整次列舉最後一個 false 不足以判定異常，因為正常緩衝區拒絕的項目可在下次讀取前被刪除。'
      '本版改用 sys_enter_getdents64 與 sys_exit_getdents64，按同一執行緒配對每次呼叫，分別累計其中的最外層 filldir64 嘗試、接受與拒絕。'
      '當成功掃描的最後一次 getdents64 回傳 0，且該次呼叫有被拒項目、沒有已接受項目時，發出獨立的完成異常警報。'
      'Linux 6.8 原生 filldir64 若第一筆即因空間不足而拒絕，會留下錯誤碼而非正常結束的 0[2]，因此判斷須結合呼叫回報，不能單看 false。',
      '原指紋與 IBLT 的計入規則不變，仍只累計已接受項目。新增檢查核對 syscall 進出數與 C 掃描器自報次數、單一檔案描述符、各次計數與原統計，以及兩支新增程式的身分與 recursion_misses 增量。'
      '原身分量測失效仍無效。只有新增配對無效時，若原指紋不同，保留原警報及通過核對的還原。若原指紋相同，保留身分一致的觀察，整體標為無法判定，不能報成已確認正常。',
      '完成異常另附一筆被拒名稱、識別值、inode 與型態，名稱於拒絕返回時讀取，再與入口建立的識別值核對。此項目沒有被接受，不併入 IBLT 差集。'
      '後續未走訪項目及缺失總數仍未知，完成異常也不直接證明惡意。核心每執行緒狀態由 10,400 增為 10,856 位元組，增加固定 456 位元組，指紋仍為 24 位元組，IBLT 維持 256 格。'
      '這是結構值大小，不是整個工具的記憶體或傳輸量，新增成本另於 6.11 節量測。'])
    edit('本文依實驗用途區分四種實作',lambda t:t.replace('本文依實驗用途區分四種實作','本文先依既有實驗用途區分四種實作',1)+
      ' 第五種為同次呼叫完成檢查版，由凍結的合併狀態來源衍生，並保留第四種的身分量測門檻與還原核對。現行 scan_directory.py 使用第五種，新增來源與三開機資料位於 call_completion，舊來源與分母保持原樣。')
    edit('6.10 原版 CARAXES',lambda t:t+' 已接受項目版本')
    edit('為檢驗自行縮減模組以外的公開樣本',lambda t:'本節保存加入同次呼叫完成檢查之前的結果，新版本見 6.11 節。'+t)
    results=next(p for p in paragraphs if text(p)=='7. 討論')
    insert(results,heading,['6.11 同次呼叫完成檢查的驗證與成本'])
    insert(results,body,[
      '新版本另以三個獨立開機確認，環境仍為 Linux 6.8.0-138-generic，原版 CARAXES 兩個模組位元組及兩種附掛順序均與 6.10 節相同。'
      '正常 60 次皆有效一致，原版 getdents64 模式 120 次皆維持身分警報並正確還原。原版 filldir 模式 120 次的已接受與實收摘要仍相同，但每次均在回傳 0 的同一呼叫內觀察到一個拒絕、零個接受，故皆取得完成異常警報與被拒的 last_caraxes。'
      '只能指出該筆被拒嘗試，不能還原未走訪的全部六十八筆外部缺失。同場固定 zygarde 轉接版對兩模式各 15 次有目標警報，filldir 仍有檢查檔品質提示。新舊版本與分母不合併，也不據此推論全面優劣。',
      '原有十六種受控狀態、四種緩衝區另做 960 次回歸，555 次實際身分差異皆警報並正確還原，405 次實收一致皆未警報。'
      '其中 45 次新增或變長改名受緩衝空間限制而未實際注入，已由模組計數與實收記錄確認，列於一致結果但不算成功陽性。'
      f"正常 ext4 與 tmpfs 的靜態列舉共 120 次、並行建立改名刪除排程共 240 次，皆有效一致且無完成異常。"
      f"其中 {facts['dynamic_all_three_operations_overlap']} 次掃描時段實際重疊三種正常操作，其餘 {len(facts['dynamic_without_confirmed_overlap'])} 次沒有操作重疊，另列為未實際施作該動態條件，不當成動態驗證成功。這不是對動態隱藏攻擊的成效估計。",
      '正常刪除競態另各檔案系統 15 次。先以 64 位元組緩衝區令 candidate 被拒絕，再於下一次讀取前合法刪除。新版本共 30 次均未警報，回傳 0 的呼叫均無拒絕事件。'
      'tmpfs 中先前以整次列舉最後一次 false 判斷的試驗曾 15/15 警報，該規則已撤回，原始資料保留。新規則不把前次拒絕帶入後次結束，因而避開此已知反例。這些有限測試不構成所有正常情況零誤報的保證。',
      '真實小緩衝區錯誤 6 次維持無效，新增資料受控缺失 6 次則保留原身分一致觀察、整體無法判定。配對計數破壞及實際卸除 syscall 入口或出口探針各 6 次，每組正常 3 次無法判定，身分差異 3 次仍警報並正確還原。'
      '原入口漏失 3 個窗口皆拒判，前後 6 次正常控制有效一致。返回探針 maxactive=1 的三個並行壓力窗口中，48 次列舉皆因實際漏失門檻而無效。'
      '故障注入、讀回資料破壞與正常對照分列，不把拒判算成成功檢出，也不宣稱所有失效來源皆已涵蓋。'
      '第三次回歸的完整資料與清理紀錄寫出後，完成回報因連線中斷發生 BrokenPipe，原故障保留，未重跑取代該組資料。'])
    cost_sentences=[]
    for size in (128,4096,65536):
        group=[r for r in facts['paired_cost'] if r['size']==size]
        span=lambda field:'%.2f–%.2f'%(min(r[field] for r in group),max(r[field] for r in group))
        cost_sentences.append(f"{size:,} 項時，原已接受項目版與新版本的各開機中位數分別為 {span('accepted_only_median_ms')} 與 {span('call_completion_median_ms')} ms，配對比值中位數為 {span('paired_ratio_median')}。")
    insert(results,body,[
      '另在相同三開機、三種目錄大小各五組隨機順序配對，共 45 組、90 筆計時，暖機 18 筆另計。兩版本都從掃描器註冊及啟動前量至全部檢查完成，BPF 編譯與附掛在區組外，計時不含逐項擷取。'
      +''.join(cost_sentences)+
      '比值為新版本除以原已接受項目版，包含新增配對與品質查詢，不是純雜湊演算法成本。6.4、6.8 與 6.9 節仍是其原版本的成本，不能直接移作本版數值。'])
    edit('列舉完整性檢查涵蓋',lambda t:t+
      ' 本版另資格化同次呼叫完成檢查，新增資料失效不抹除有效的身分差異警報。原指紋相同而完成檢查無效時，整體無法判定，與原身分量測本身失效分別記錄。')
    edit('九次開機矩陣實驗的結果來自',lambda t:t.replace(
      '其 filldir 模式的提前截斷未被本方法警報，','其 filldir 模式的提前截斷未被原已接受項目版本警報，')+
      ' 同次呼叫完成檢查版另見 6.11 節，其結果仍限此固定原版、指定核心與實測排程，未證明其他拒絕機制或所有合法轉換的判讀。')
    edit('本文以 eBPF 與專用 C 掃描器',lambda t:t.replace('固定大小指紋負責警報','固定大小指紋負責身分差異警報').replace(
      '原版 CARAXES 另以三開機確認','原已接受項目版本的原版 CARAXES 另以三開機確認')+
      ' 本版另以同次呼叫配對補足受測拒絕後回報結束的異常：新三開機的 filldir 模式 120 次皆警報並提供一筆被拒項目，'
      '正常靜態、並行變動及受控刪除競態皆無新警報，原差異偵測與受測品質拒判保留。新增成本與實作的直接配對結果見 6.11 節，未將舊成本或分母當成本版重跑成果。')
    edit('這是尚未實作的觀測架構提案',lambda t:t.replace(
      '原版 filldir 的拒絕與提前截斷是另一個已觀察到的邊界，增加函式庫端觀測點本身不能解決。若另以涵蓋此類隱藏為目標，須研究如何區分正常緩衝區重送與刻意拒絕，或提供獨立目錄參照，這會改變目前的判定目標，尚未實作。',
      '原版 filldir 受測的拒絕後回報結束已由 4.4 節另行處理，但未走訪的後續項目仍未知。若要取得這些項目的完整清單，須另有可信參照與時間一致性條件，增加函式庫觀測點本身不能補回。'))
    edit('研究重現套件公開於',lambda t:t+
      ' 同次呼叫完成檢查的來源、規約、先導、三開機及配對成本另存 call_completion，可由 summarize.py 重新核對，歷史失敗試驗仍保留於 terminal_rejection。')
    assert tables==[E.tostring(t,method='c14n') for t in xml.findall('.//w:tbl',NS)]
    full=''.join(xml.xpath('.//w:t/text()',namespaces=NS))
    assert not any(s in full for s in ('；',';','補充實驗','主實驗'))
    with ZipFile(OUTPUT,'w') as archive:
        for name,(info,data) in parts.items():
            archive.writestr(info,E.tostring(xml,xml_declaration=True,encoding='UTF-8',standalone=True) if name=='word/document.xml' else data)
    (ROOT/'call_completion/paper_changes.json').write_text(json.dumps(dict(source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        output_sha256=hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),edits=edits,old_tables_unchanged=True),ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    print(OUTPUT)


if __name__=='__main__':main()
