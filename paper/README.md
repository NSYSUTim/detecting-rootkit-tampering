# 書面版本與來源

目前正式提交版本為作者於 2026-11-09 提供的四份最終成品。以下連結已取代 revised41 的現行書面入口，四份檔案內容均與作者提供的原檔相同。

| 最終成品 | 檔案 |
|---|---|
| 中文結案報告 | [Word](final/Project_Final_Report_ZH_B123245021_Wei-Ting_Chiang.docx) |
| 英文結案報告 | [Word，修正分頁版](final/Project_Final_Report_EN_B123245021_Wei-Ting_Chiang.docx) |
| 英文結案報告 PDF | [PDF，51 頁](final/Project_Final_Report_EN_B123245021_Wei-Ting_Chiang.pdf) |
| 英文海報 | [PowerPoint，1 張投影片](final/Poster_EN_B123245021_Wei-Ting_Chiang.pptx) |

原檔對應與 SHA-256 見 [SOURCE_FILES.json](final/SOURCE_FILES.json)，發布核對見[紀錄](../docs/FINAL_REPORT_PUBLICATION_20261109.json)。

## 歷史版本與實驗來源

2026-11-03 的書面版本為 revised41，現行入口保留已接受項目指紋與 IBLT，另加入同次系統呼叫拒絕與結束配對。原版 CARAXES 的兩種模式在新三開機各 120 次警報，正常刪除競態 30 次無新警報，結果不合併舊版分母。新增量測失效不取消有效的原身分警報，未走訪的全部項目仍無法還原。

| 版本 | 檔案 | 內容 |
|---|---|---|
| 歷史論文 | [revised41 Word](cross_layer_directory_entry_consistency_revised41_zhTW.docx)／[PDF](cross_layer_directory_entry_consistency_revised41_zhTW.pdf) | 方法 4.4 與結果 6.11，含已知正常刪除反例、新回歸、故障與相同界線成本 |
| 歷史摘要 | [Word](interview_research_summary_call_completion_zhTW.docx)／[PDF](interview_research_summary_call_completion_zhTW.pdf) | 身分比對與完成異常分列，保留範圍及未走訪限制 |
| 已撤回試驗 | [revised40](cross_layer_directory_entry_consistency_revised40_zhTW.docx)／[PDF](cross_layer_directory_entry_consistency_revised40_zhTW.pdf) | 整次最後 false 規則有 tmpfs 正常刪除警報，只保留歷史 |
| 歷史論文 | [revised39](cross_layer_directory_entry_consistency_revised39_zhTW.docx)／[PDF](cross_layer_directory_entry_consistency_revised39_zhTW.pdf) | 原已接受項目版本，原版 filldir 120 次未警報，原數字未改寫 |
| 歷史論文 | [revised38](cross_layer_directory_entry_consistency_revised38_zhTW.docx) | 保留當時內容與版本來源 |
| 歷史論文 | [revised37](cross_layer_directory_entry_consistency_revised37_zhTW.docx) | 保留當時內容與版本來源 |
| 歷史論文 | [revised36](cross_layer_directory_entry_consistency_revised36_zhTW.docx) | 保留當時內容與版本來源 |
| 歷史論文 | [revised35](cross_layer_directory_entry_consistency_revised35_zhTW.docx) | 保留當時內容與版本來源 |
| 歷史論文 | [revised34](cross_layer_directory_entry_consistency_revised34_zhTW.docx) | 保留當時內容與版本來源 |
| 歷史論文 | [revised33](cross_layer_directory_entry_consistency_revised33_zhTW.docx) | 保留當時內容與版本來源 |
| 歷史存檔 | [2026-10-20 提供版本](cross_layer_directory_entry_consistency_zhTW.docx) | 作者原始文件 |

revised41 以 revised39 為底，只改本文 XML，既有圖表、樣式及其他封裝部件維持。新增 4.4、6.11，並同步調整摘要、範圍、圖 1 說明、實作、限制、結論與未來工作。revised39 和撤回的 revised40 不覆寫。

來源：[build_revised41.py](../tools/build_revised41.py)、[逐段修改紀錄](../call_completion/paper_changes.json)、[實作與結果](../docs/CALL_COMPLETION_20261103_zh-TW.md)、[逐筆重算](../call_completion/verification.json)、[發布核對](../docs/PUBLICATION_VERIFICATION_CALL_COMPLETION_20261103.json)。各歷史檔案的 SHA-256 保留於根目錄 FILE_SHA256.csv。

舊 576/576、0/720、4.76 倍、合併狀態改善與 zygarde 成本均對應各自實作及流程，沒有當作新版重跑。新成本是相同界線的 45 組直接配對，包含全部檢查，編譯與附掛在區組外。指紋與還原核對仍非無碰撞證明，有限失效統計不代表所有故障可觀察。
