# 書面版本與來源

更新日期：2026-11-01。

| 版本 | 檔案 | 來源與定位 |
|---|---|---|
| 目前書面 | [revised34 乾淨版](cross_layer_directory_entry_consistency_revised34_zhTW.docx) | 以 revised33 為底，補入最接近相關工作、已實作的還原核對與部分品質統計，以及另列的新確認 |
| 歷史書面 | [revised33 乾淨版](cross_layer_directory_entry_consistency_revised33_zhTW.docx) | 作者提供的 paper_final_submission_v3_revised33_clean.docx 原樣保留 |
| 歷史存檔 | [2026-10-20 提供版本](cross_layer_directory_entry_consistency_zhTW.docx) | 較早的原主實驗書面，維持既有檔案與雜湊關係 |

revised34 只修改主文件 XML，圖片、樣式及其他封裝部件均維持 revised33 原樣。以本機 Microsoft Word 唯讀匯出為 25 頁，已逐頁檢查，沒有標題單獨落在頁尾或圖表被裁切。不同字型或軟體仍可能改變分頁。這次未製作追蹤修訂版，修訂位置及證據見[本輪書面審查依據](../docs/FINALIZATION_REVIEW_20261101_zh-TW.md)，可用 [build_revised34.py](../tools/build_revised34.py) 重建。

revised34 SHA-256：`9873801930d29ecf62d9acf262953dc65f9cd03882f0fa60d84c0d14d732ba9d`。

revised33 SHA-256：`47169ad7e18b432ce8f66e26d6f2bfaad559d46302f43dd22b56b2711b61bca8`，該檔及歷史核對入口保持原樣。

新舊分母、計時與實作清楚分開。補強版沒有重跑原 1,296 批矩陣，沒有新增公開 rootkit 或 zygarde 的共同環境實測。還原指紋核對不能變成無碰撞證明，BPF recursion_misses 不能變成全部入口漏失可見。一般程式監控、金鑰保護、/proc、程式庫後邊界與第一端前的新視圖均未開始。

相關工作原始碼比較見[專文](../docs/RELATED_WORK_COMPARISON_zh-TW.md)。新原生確認封存及可重算的結果見 [finalization](../finalization/README.md)。原兩輪補充仍用既有 verifier 重算，原資料與凍結程式不覆寫。[歷史核對](../docs/PAPER_REVIEW_FACTS_20261027.json)仍對應 revised33。
