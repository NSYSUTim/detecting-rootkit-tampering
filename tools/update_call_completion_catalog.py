"""Publish independently verified completion results without relabelling old data."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
REPORT='CALL_COMPLETION_20261103_zh-TW.md'


def replace_paragraph(text,prefix,value):
    blocks=text.split('\n\n');found=[i for i,b in enumerate(blocks) if b.startswith(prefix)]
    assert len(found)==1,(prefix,len(found))
    blocks[found[0]]=value;return '\n\n'.join(blocks)


def main():
    facts=json.loads((ROOT/'call_completion/verification.json').read_text());assert facts['verified']
    assert facts['native_functional_scans']==1737 and facts['regression']['identity_alarms']==555
    costs=[]
    for size in (128,4096,65536):
        group=[r for r in facts['paired_cost'] if r['size']==size]
        def span(field):return '%.2f–%.2f'%(min(r[field] for r in group),max(r[field] for r in group))
        costs.append(f"| {size:,} | {span('accepted_only_median_ms')} | {span('call_completion_median_ms')} | {span('paired_ratio_median')} |")
    report='''# 同次系統呼叫完成檢查的實作與驗證

已保留原已接受項目的指紋、IBLT、還原核對與品質門檻，另以每一次 getdents64 的進出配對，檢查「同次拒絕項目卻回報結束」。三個新開機的原版 CARAXES filldir 模式 120 次均取得新異常，原 getdents64 模式 120 次維持身分警報並正確還原。正常靜態 120 次、實際重疊三種正常變動 237 次與受控跨呼叫刪除 30 次，均無新警報。

這補足所測固定原版的警報缺口，不能稱為還原全部隱藏項目或判定惡意。單看整次列舉最後一次 false 的舊試驗仍撤回，其正常誤報與原始資料不刪除。

## 方法改了什麼

C 掃描器仍自行反覆讀取指定目錄，沒有改成常駐監控一般程式。原指紋與 IBLT 仍只計最外層回傳 true 的 filldir64。新增兩個 syscall tracepoint，按同一執行緒記錄每次讀取內的嘗試、接受與拒絕。

只有成功列舉回傳 0 的同一次呼叫有拒絕且沒有接受時，才形成完成異常。拒絕發生在前一次呼叫、正常刪除後下一次無項目而結束，不符合新條件。Linux 6.8 原生 filldir64 在第一筆即無法放入緩衝區時會留下錯誤碼，不能把此錯誤當正常結束的 0。[Linux 6.8 原始碼](https://github.com/torvalds/linux/blob/v6.8/fs/readdir.c)、[getdents 回傳值](https://man7.org/linux/man-pages/man2/getdents.2.html)。

| 情況 | 原身分分支 | 新完成分支與整體輸出 |
|---|---|---|
| 原量測品質失效或 syscall 錯誤 | 無效 | 維持 invalid，沒有警報判定 |
| 指紋不同、新配對有效 | 身分警報及經核對的還原 | 原警報保留，完成異常若也成立則分列 |
| 指紋不同、只有新增配對失效 | 身分警報與還原保留 | 完成檢查無法判定，不取消原警報 |
| 指紋相同、完成檢查有效且無異常 | 本次身分一致 | equal，未觀察到兩種異常，不保證沒有隱藏 |
| 指紋相同、同次拒絕且回傳 0 | 本次身分一致 | completion_anomaly，另提供被拒項目 |
| 指紋相同、新配對無效 | 本次身分一致觀察保留 | inconclusive，不能報成整體已確認正常 |

新分支核對 syscall 進出次數與掃描器自報次數、單一描述符、逐次累計與原呼叫統計、程式 ID／tag／recursion_misses 與事件 ID。必要資料缺失不當成零。這只涵蓋明列的可觀測失效，不保證任意核心干擾皆可見。

拒絕見證含名稱、識別值、inode 與型態，名稱在拒絕返回時讀取並與入口身分核對。它不加入 IBLT 差集。後面未走訪的項目與缺失總數仍未知。原 24 位元組指紋及 256 格 IBLT 不改，核心每執行緒狀態由 10,400 增為 10,856 位元組，多固定 456 位元組，並非只多一個位元，也不是整工具記憶體。

## 三個新開機的結果

| 實驗 | 次數 | 結果 |
|---|---:|---|
| 原版 CARAXES 正常對照 | 60 | 有效一致，無警報 |
| 原版 getdents64，兩種附掛順序 | 120 | 原身分警報與精確還原全部保留 |
| 原版 filldir，兩種附掛順序 | 120 | 全部完成異常，提供一筆被拒項目，兩端已接受摘要仍相同 |
| 原有受控狀態回歸 | 960 | 555 次實際差異警報並正確還原，405 次實收一致無警報 |
| 正常 ext4／tmpfs 靜態目錄 | 120 | 有效一致，無新警報 |
| 正常並行建立、改名、刪除排程 | 240 | 237 次重疊三種操作，3 次未重疊，全部未警報，未重疊者不當動態成功 |
| 拒絕後、下次讀取前正常刪除 | 30 | ext4 與 tmpfs 各 15 次均無新警報 |

回歸中 45 次新增或變長改名因緩衝空間而未實際注入，與模組計數、實收記錄及獨立答案逐筆核對，不算成功陽性。正常變動不是動態隱藏攻擊的偵測率。三個開機來自同一實體主機與 VM，不能當成三台獨立機器。

原已接受項目版本的原版 filldir 120 次未警報仍是原版本結果。整次最後 false 的撤回試驗，在 tmpfs 的正常刪除競態曾 15/15 警報。新確認沒有合併或改寫這些結果，新規則在新的 15 次 tmpfs 刪除競態均未觸發。有限測試不構成任意正常情況零誤報的保證。

原版模組仍為官方提交 899e8be6b5f6c7236bd23b52aa65051de757e0b3 的兩個原實驗模組位元組，沒有修補 false、回呼結構、filter 或 helper。同場固定 zygarde 轉接版：正常 15 次無目標警報，兩模式各 15 次有目標警報，filldir 仍有 15 次檢查檔提示。沒有測 zygarde 的上述刪除競態，不據此宣稱新規則在全部情況更好。

## 失效與原功能的保留

真實小緩衝區 syscall 錯誤 6 次皆 invalid。新增資料受控省略 6 次皆 inconclusive。配對計數破壞、實際卸除 syscall 入口、實際卸除 syscall 出口，各 6 次，每組的正常 3 次皆 inconclusive、原身分差異 3 次仍警報並正確還原。讀回計數破壞與真正卸除追蹤點分列。

原入口漏失注入 3 個窗口全部由原入口統計門檻拒判，前後 6 次正常控制有效一致。返回探針 maxactive=1 的三個並行壓力窗口中，48 次列舉皆因實際返回漏失而無效。沒有把這些故障樣本算成檢出或正常樣本。

## 成本

與 11 月 2 日的已接受項目整合版做相同界線的直接配對。三開機、三種大小各五組，45 個配對區組、90 筆計時，18 筆暖機另計。每次從註冊／啟動掃描器前量到全部檢查完成，BPF 編譯及附掛在區組外，計時沒有逐項擷取。兩版本每筆皆通過各自的品質檢查。

| 項目數 | 原已接受項目版 ms | 新版 ms | 新／舊配對比值 |
|---:|---:|---:|---:|
'''+'\n'.join(costs)+'''

表中為三個開機各自中位數的範圍，配對比值先在區組內相除再取開機中位數，沒有用兩個獨立中位數相除。逐區組變異保存在 [paired_cost.csv](../call_completion/paired_cost.csv)。舊 4.76 倍、39.6%–45.1% 改善，以及與 zygarde 比較時本文的 88–89 ms，仍屬原版本，不移作新版實測，也沒有重跑 zygarde 的成本。

## 範圍與尚未解決之處

新增的是「拒絕卻回報正常結束」的可觀測異常，不是一般檔案系統完整性證明。若項目在進入 filldir64 前被排除，或在沒有留下受測拒絕紀錄時提早結束，仍可能沒有警報。若另一種拒絕直接回報錯誤，掃描器會無效，不冒充已辨認隱藏。無法提供未走訪項目的完整清單，也不單靠異常判斷授權或惡意。

仍假設量測可信，未處理控制偵測器的核心對手、已知種子適應性碰撞、函式庫過濾或選擇性放行。指紋及還原核對仍為機率式，原 XOR IBLT 的重複差異及容量限制仍在。已回歸的案例保留能力，不代表未受測輸入都沒有回歸。

## 資料與重現

- [凍結規約](../call_completion/PROTOCOL.md)、[先導紀錄](../call_completion/PILOT_NOTES.md)、[BPF 衍生差異](../call_completion/bpf.patch)。
- [原始封存](../call_completion/call_completion_20261103.tar.gz)、[逐筆重算結果](../call_completion/verification.json)、[現行入口](../scan_directory.py)。
- [原已接受版本的公開樣本](ORIGINAL_CARAXES_20261102_zh-TW.md)、[撤回的最後 false 試驗](TERMINAL_REJECTION_20261103_zh-TW.md)。

三個確認開機來源逐檔一致，C 掃描器、原 BPF 及原 tracefs 比對器不覆寫。新舊原始分母、成本與凍結來源分開。先導、失敗與未實際注入完整保留，成本目錄的空測試檔可依固定生成程式重建，沒有刪除觀察資料。Windows 重算不重建特意造成錯誤的 255 位元組空檔，避免 MAX_PATH，原始封存不改。宿主仍無 Hyper-V 檢查點管理權限，本輪沒有建立新檢查點，也沒有升級套件。所有樣本模組已卸載、tmpfs 已卸掛。

第三次回歸的 479 次量測、320 筆答案與清理紀錄已完整寫出，但最後回報完成時 SSH 通道中斷，留下 BrokenPipeError。已核對同一開機、完整條件與清理，再完成尚未開始的成本測試，沒有重跑或取代該回歸組。原 failure.json、連線錯誤與 TRANSPORT_RECOVERY.json 皆保留。

```bash
python call_completion/summarize.py --archive call_completion/call_completion_20261103.tar.gz --extract-to reproduced/call_completion --output reproduced/call_completion_verification.json
```
'''
    report+=f"\n封存 SHA-256：`{facts['archive_sha256']}`。功能量測 {facts['native_functional_scans']:,} 次，獨立實收控制 102 次，工具觀察 45 次，共 {facts['functional_observations_and_controls']:,} 筆，成本及暖機另計。\n"
    (ROOT/'docs'/REPORT).write_text(report,encoding='utf-8',newline='\n')
    (ROOT/'call_completion/README.md').write_text('# 同次系統呼叫完成檢查\n\n目前入口保留原指紋與 IBLT，新增同一次 getdents64 拒絕卻回傳 0 的檢查。\n\n[結果、成本與限制](../docs/'+REPORT+')、[規約](PROTOCOL.md)、[原始封存](call_completion_20261103.tar.gz)、[逐筆重算](verification.json)、[配對成本](paired_cost.csv)。\n\n舊 terminal_rejection 的最後 false 規則仍撤回，未重新啟用。\n',encoding='utf-8',newline='\n')
    files=['README.md','ARTIFACT_SCOPE.md','THIRD_PARTY_NOTICES.md','docs/METHOD_AND_NEXT_STEPS_zh-TW.md',
           'docs/METHOD_CLOSURE_20261102_zh-TW.md','docs/RELATED_WORK_COMPARISON_zh-TW.md']
    for name in files:
        path=ROOT/name;text=path.read_text(encoding='utf-8')
        link=('' if name.startswith('docs/') else 'docs/')+REPORT
        status='目前入口保留已接受項目的指紋與 IBLT，另加入同次 getdents64 呼叫拒絕項目卻回傳 0 的完成檢查，書面為 revised41。新三開機的原版 CARAXES 兩模式各 120 次警報，正常刪除競態 30 次無新警報。整次最後 false 的舊規則仍撤回，revised40 只留歷史，未重新啟用。 [新結果、成本與限制]('+link+')。'
        text=replace_paragraph(text,'目前已撤回',status)
        text=text.replace('更新日期：2026-11-02','更新日期：2026-11-03').replace('更新至 2026-11-02','更新至 2026-11-03')
        if name=='README.md':
            text=text.replace('目前書面報告（revised39）','目前書面報告（revised41）').replace('cross_layer_directory_entry_consistency_revised39_zhTW','cross_layer_directory_entry_consistency_revised41_zhTW')
            text=text.replace('interview_research_summary_public_sample_zhTW','interview_research_summary_call_completion_zhTW')
            text=text.replace('docs/PUBLICATION_VERIFICATION_ROLLBACK_20261103.json','docs/PUBLICATION_VERIFICATION_CALL_COMPLETION_20261103.json')
            text=replace_paragraph(text,'本說明更新至','本說明更新至 2026-11-03。現行入口的還原核對與入口／返回品質門檻保留，新功能以同次系統呼叫配對處理受測拒絕後結束異常。原已接受版本、撤回的最後 false 試驗與新版本的三開機資料皆各自保存，不合併分母，歷史成本也不當成新版成本。詳見[新實作與直接配對成本](docs/'+REPORT+')。')
            text=text.replace('- 原版 CARAXES 已另行實測。','- 原已接受項目版本的原版 CARAXES 已另行實測。')
            text=text.replace('- 只涵蓋 `filldir64` 接受之後', '- 身分分支涵蓋 `filldir64` 接受之後')
            text=text.replace('均不在範圍內。','仍不能完整觀測。新增完成分支可警報本次受測的同次拒絕加回傳 0，但不列出未走訪的全部項目。',1)
            text=text.replace('`scan_directory.py`、`finalization/tracefs_measurement.py`','`scan_directory.py`、`call_completion/measurement.py`、`finalization/tracefs_measurement.py`')
            text+='\n## 同次呼叫完成檢查\n\n'+status+'\n\n`scan_directory.py` 預設使用新版，`--accepted-only` 可明確執行原已接受項目分支。`different` 與 `completion_anomaly` 分別表示身分差異與完成異常，`invalid` 是原量測無效，`inconclusive` 表示原身分一致但新增檢查無法判定。後兩者退出碼為 2。\n\n```bash\npython call_completion/summarize.py --archive call_completion/call_completion_20261103.tar.gz --extract-to reproduced/call_completion --output reproduced/call_completion_verification.json\n```\n'
        elif name=='ARTIFACT_SCOPE.md':
            text=text.replace('- revised39 論文及一頁摘要','- 歷史 revised39 論文及一頁摘要')
            text=text.replace('## 已收錄\n','## 已收錄\n\n- revised41 論文及一頁摘要、call_completion 來源、規約、三開機功能與配對成本封存、原始先導及獨立重算。revised39 與已撤回 revised40 保留，舊數據未回填。\n',1)
        elif name=='docs/METHOD_AND_NEXT_STEPS_zh-TW.md':
            text=text.replace('[revised39 乾淨版](../paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx)', '[revised41 乾淨版](../paper/cross_layer_directory_entry_consistency_revised41_zhTW.docx)')
            text=text.replace('## 四套實作與證據不能混用','## 各版本實作與證據不能混用')
            text=text.replace('| 現行整合版 |','| 11月2日整合版 |').replace('| 現行入口 | 72 次','| 11月2日入口確認 | 72 次')
            text=text.replace('## 威脅與觀測範圍沒有擴大','## 可信假設與觀測範圍')
            text=replace_paragraph(text,'原版 CARAXES 的 filldir 拒絕與提前截斷是另一個',
              '原版 CARAXES 受測的同次拒絕後回報結束，現已另以完成檢查實作驗證，不再列為尚未實作。未走訪的後續項目仍未知，完整清單須另有可信參照與時間條件，增加函式庫端觀測本身不能補回。')
            text=text.replace('## 已完成的確認及其意義','新增同次呼叫完成版保留上述整合版，另配對每次 getdents64，驗證與成本見[新報告]('+REPORT+')。原版本數值不當成新版本重跑。\n\n## 已完成的確認及其意義',1)
        elif name=='docs/METHOD_CLOSURE_20261102_zh-TW.md':
            text=text.replace('正式書面更新為 revised39','目前書面更新為 revised41，新增同次呼叫實驗見頁首，以下成本屬原整合版')
        elif name=='docs/RELATED_WORK_COMPARISON_zh-TW.md':
            text=text.replace('256 格時核心邏輯摘要約 12.02 KiB；','原多表實作的 256 格邏輯摘要約 12.02 KiB；新合併狀態值含完成檢查為 10,856 位元組，不含 map 配置開銷；')
            text=text.replace('## 論文可直接使用的比較段落','完成檢查版另以每次 syscall 配對拒絕與結束，不把被拒項目加入已接受摘要。原版 CARAXES 的新三開機兩模式各 120 次皆警報，正常刪除競態 30 次無新警報，但未與 zygarde 比較該競態，也未重跑兩工具的新版本成本。被拒見證可含名稱，IBLT 差集本身仍不含名稱。\n\n## 論文可直接使用的比較段落',1)
        path.write_text(text,encoding='utf-8',newline='\n')
    # Old sample paragraphs remain evidence of the explicitly named old version.
    for name in ('ARTIFACT_SCOPE.md','docs/METHOD_AND_NEXT_STEPS_zh-TW.md','docs/METHOD_CLOSURE_20261102_zh-TW.md','docs/RELATED_WORK_COMPARISON_zh-TW.md'):
        path=ROOT/name;text=path.read_text(encoding='utf-8')
        text=text.replace('原版 CARAXES 已完成另一組三開機實測：','原已接受項目版本的 CARAXES 三開機實測：')
        text=text.replace('本次另收錄固定原版 CARAXES 的三開機實驗、','原已接受項目版本另收錄固定原版 CARAXES 的三開機實驗、')
        path.write_text(text,encoding='utf-8',newline='\n')
    paper='''# 書面版本與來源

目前書面為 revised41，現行入口保留已接受項目指紋與 IBLT，另加入同次系統呼叫拒絕與結束配對。原版 CARAXES 的兩種模式在新三開機各 120 次警報，正常刪除競態 30 次無新警報，結果不合併舊版分母。新增量測失效不取消有效的原身分警報，未走訪的全部項目仍無法還原。

| 版本 | 檔案 | 內容 |
|---|---|---|
| 目前論文 | [revised41 Word](cross_layer_directory_entry_consistency_revised41_zhTW.docx)／[PDF](cross_layer_directory_entry_consistency_revised41_zhTW.pdf) | 方法 4.4 與結果 6.11，含已知正常刪除反例、新回歸、故障與相同界線成本 |
| 目前摘要 | [Word](interview_research_summary_call_completion_zhTW.docx)／[PDF](interview_research_summary_call_completion_zhTW.pdf) | 身分比對與完成異常分列，保留範圍及未走訪限制 |
| 已撤回試驗 | [revised40](cross_layer_directory_entry_consistency_revised40_zhTW.docx)／[PDF](cross_layer_directory_entry_consistency_revised40_zhTW.pdf) | 整次最後 false 規則有 tmpfs 正常刪除警報，只保留歷史 |
| 歷史論文 | [revised39](cross_layer_directory_entry_consistency_revised39_zhTW.docx)／[PDF](cross_layer_directory_entry_consistency_revised39_zhTW.pdf) | 原已接受項目版本，原版 filldir 120 次未警報，原數字未改寫 |
'''
    for version in (38,37,36,35,34,33):
        paper+=f'| 歷史論文 | [revised{version}](cross_layer_directory_entry_consistency_revised{version}_zhTW.docx) | 保留當時內容與版本來源 |\n'
    paper+='''| 歷史存檔 | [2026-10-20 提供版本](cross_layer_directory_entry_consistency_zhTW.docx) | 作者原始文件 |

revised41 以 revised39 為底，只改本文 XML，既有圖表、樣式及其他封裝部件維持。新增 4.4、6.11，並同步調整摘要、範圍、圖 1 說明、實作、限制、結論與未來工作。revised39 和撤回的 revised40 不覆寫。

來源：[build_revised41.py](../tools/build_revised41.py)、[逐段修改紀錄](../call_completion/paper_changes.json)、[實作與結果](../docs/CALL_COMPLETION_20261103_zh-TW.md)、[逐筆重算](../call_completion/verification.json)、[發布核對](../docs/PUBLICATION_VERIFICATION_CALL_COMPLETION_20261103.json)。各歷史檔案的 SHA-256 保留於根目錄 FILE_SHA256.csv。

舊 576/576、0/720、4.76 倍、合併狀態改善與 zygarde 成本均對應各自實作及流程，沒有當作新版重跑。新成本是相同界線的 45 組直接配對，包含全部檢查，編譯與附掛在區組外。指紋與還原核對仍非無碰撞證明，有限失效統計不代表所有故障可觀察。
'''
    (ROOT/'paper/README.md').write_text(paper,encoding='utf-8',newline='\n')
    print('Updated current catalogs and publication report')


if __name__=='__main__':main()
