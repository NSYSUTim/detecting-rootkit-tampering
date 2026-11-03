"""Update current entry points, keeping old evidence explicitly historical."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def edit(name,fn):
    p=ROOT/name;s=p.read_text(encoding='utf-8');out=fn(s);assert out!=s,name;p.write_text(out,encoding='utf-8',newline='\n')
def prepend_after_title(text,value):
    at=text.index('\n')+1;return text[:at]+'\n'+value+'\n'+text[at:]

notice=('現行入口另加入終止拒絕檢查：有效列舉結束前最後一次 filldir64 回傳 false 時，另發警報並提供一筆被拒項目。'
 '新三開機的原版 CARAXES 兩種模式各 120 次皆警報，但 tmpfs 正常刪除競態也有 15/15 次相同警報，不能宣稱新版本整體零誤報或完整還原截斷後項目。')
edit('README.md',lambda s:prepend_after_title(s,notice+' [實作、證據與限制](docs/TERMINAL_REJECTION_20261103_zh-TW.md)。').replace(
 '[目前書面報告（revised39）](paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx)／[PDF](paper/cross_layer_directory_entry_consistency_revised39_zhTW.pdf)',
 '[目前書面報告（revised40）](paper/cross_layer_directory_entry_consistency_revised40_zhTW.docx)／[PDF](paper/cross_layer_directory_entry_consistency_revised40_zhTW.pdf)').replace(
 '[面試研究摘要](paper/interview_research_summary_public_sample_zhTW.docx)／[PDF](paper/interview_research_summary_public_sample_zhTW.pdf)',
 '[面試研究摘要](paper/interview_research_summary_terminal_zhTW.docx)／[PDF](paper/interview_research_summary_terminal_zhTW.pdf)').replace(
 '本說明更新至 2026-11-02。','本說明更新至 2026-11-03。下述 revised39 與原版 CARAXES 的第一次測試是加入終止拒絕檢查之前的版本，現行進度以本頁開頭及新規則報告為準。').replace(
 '警報只表示觀測範圍內的不一致，不能由此判定惡意或推論對未知 rootkit 的偵測率。',
 '身分差異警報表示觀測範圍內的不一致，終止拒絕警報則表示最後一次嘗試遭拒，兩者均不能直接判定惡意或推論對未知 rootkit 的偵測率。').replace(
 'docs/PUBLICATION_VERIFICATION_CARAXES_20261102.json','docs/PUBLICATION_VERIFICATION_TERMINAL_20261103.json').replace(
 '## 適用範圍與限制\n','## 適用範圍與限制\n\n- 現行終止拒絕訊號可在兩端一致時警報，正常刪除也可能觸發。它提供一筆被拒項目，不是 IBLT 的全部差集，後續未走訪項目與缺失總數未知。原零誤報與成本數字仍屬各原版本，不套用成新規則保證。\n'))
edit('paper/README.md',lambda s:prepend_after_title(s,'目前為 revised40，Word 匯出 30 頁，面試摘要 1 頁。'+notice+' [新實驗報告](../docs/TERMINAL_REJECTION_20261103_zh-TW.md)。').replace(
 '| 目前書面 | [revised39]', '| 歷史書面 | [revised39]').replace(
 '| 面試摘要 | [Word](interview_research_summary_public_sample_zhTW.docx)', '| 歷史摘要 | [Word](interview_research_summary_public_sample_zhTW.docx)').replace(
 '|---|---|---|','|---|---|---|\n| 目前書面 | [revised40](cross_layer_directory_entry_consistency_revised40_zhTW.docx)／[PDF](cross_layer_directory_entry_consistency_revised40_zhTW.pdf) | 新增 4.4 與 6.11 節，保留原結果並分列終止拒絕及正常刪除警報 |\n| 面試摘要 | [Word](interview_research_summary_terminal_zhTW.docx)／[PDF](interview_research_summary_terminal_zhTW.pdf) | 新規則、被拒項目與正常觸發原因 |'))
edit('docs/METHOD_AND_NEXT_STEPS_zh-TW.md',lambda s:prepend_after_title(s,notice+' [原始資料與重算](TERMINAL_REJECTION_20261103_zh-TW.md)。').replace(
 'revised39','revised40').replace('更新日期：2026-11-02。','更新日期：2026-11-03。').replace(
 '| 量測有效、指紋相同 | 這次未觀察到邊界內差異，不是內容必然相等的證明 |',
 '| 量測有效、指紋相同 | 沒有身分差異訊號，仍另檢查最後一次拒絕，不是目錄未隱藏的證明 |').replace(
 '原版 CARAXES 的 filldir 拒絕與提前截斷是另一個已實測的界線。增加函式庫端觀測本身不能解決。若要另外涵蓋它，必須研究正常緩衝區重送與刻意拒絕的區別，或增加獨立目錄參照，這會改變現在的判定目標，尚未實作，不能將它寫成已完成的防護。',
 '原版 CARAXES 的 filldir 終止拒絕現已用獨立訊號警報，但正常刪除也可觸發，判斷原因與完整列出未走訪項目仍未解決。增加函式庫端觀測本身不能解決這兩件事。'))
for name in ('docs/METHOD_CLOSURE_20261102_zh-TW.md','docs/RELATED_WORK_COMPARISON_zh-TW.md'):
    edit(name,lambda s:prepend_after_title(s,'本頁的既有比較保留其原版本。'+notice+' [新規則報告](TERMINAL_REJECTION_20261103_zh-TW.md)。'))
edit('ARTIFACT_SCOPE.md',lambda s:prepend_after_title(s,'現另收錄 revised40 論文、摘要 Word／PDF、終止拒絕實作與三開機驗證，含全部正常警報及失效案例。'+notice+' [證據入口](terminal_rejection/README.md)。'))
edit('THIRD_PARTY_NOTICES.md',lambda s:prepend_after_title(s,'2026-11-03 的終止拒絕實驗沿用前組固定原版 CARAXES 模組位元組及固定 zygarde 轉接版，沒有修改樣本行為或引入另一套第三方來源。結果、正常刪除警報及原始紀錄見 [terminal_rejection](terminal_rejection/README.md)。'))
print('Current catalogs updated; historical raw records retained.')
