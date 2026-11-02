# 書面版本與來源

更新日期：2026-11-02。

| 版本 | 檔案 | 來源與定位 |
|---|---|---|
| 目前書面 | [revised36 乾淨版](cross_layer_directory_entry_consistency_revised36_zhTW.docx) | 以 revised35 為底，補入相同輸入、相同準備完成後計時範圍的三開機比較，區分預設與增加容量的配置 |
| 歷史書面 | [revised35 乾淨版](cross_layer_directory_entry_consistency_revised35_zhTW.docx) | 保留現行入口的漏失拒判、原生確認、共同功能與完整程序成本比較，以及控制修復確認 |
| 歷史書面 | [revised34 乾淨版](cross_layer_directory_entry_consistency_revised34_zhTW.docx) | 保留前一輪還原核對、部分品質統計與相關工作設計比較的狀態 |
| 歷史書面 | [revised33 乾淨版](cross_layer_directory_entry_consistency_revised33_zhTW.docx) | 作者提供的 paper_final_submission_v3_revised33_clean.docx 原樣保留 |
| 歷史存檔 | [2026-10-20 提供版本](cross_layer_directory_entry_consistency_zhTW.docx) | 較早的原主實驗書面，維持既有檔案與雜湊關係 |

revised36 只修改主文件 XML，原圖片、樣式及其他封裝部件均維持 revised35 原樣，新增掃描判讀成本表及來源說明。以本機 Microsoft Word 唯讀匯出為 28 頁，逐頁檢查版面。不同字型或軟體仍可能改變分頁。未製作追蹤修訂版，定義與原始證據見[相同範圍的成本比較](../docs/SCAN_COST_COMPARISON_20261102_zh-TW.md)，可用 [build_revised36.py](../tools/build_revised36.py) 重建。

revised36 SHA-256：`b11fefb1394dbbcccb797bdcebe02e73b64235515023472579e7070d29895583`。

revised35 SHA-256：`b0c1fe6d6d825f77be4990e9927596d442fd84833abf0a61e8663ec8e0733ce5`。

revised34 SHA-256：`9873801930d29ecf62d9acf262953dc65f9cd03882f0fa60d84c0d14d732ba9d`。

revised33 SHA-256：`47169ad7e18b432ce8f66e26d6f2bfaad559d46302f43dd22b56b2711b61bca8`，該檔及歷史核對入口保持原樣。

新舊分母、計時與實作分開。現行入口沒有重跑原 1,296 批矩陣，沒有新增公開 rootkit；zygarde 則已完成指定共同環境的三開機實測。兩者共同缺失名稱皆為 105/105 檢出、0/30 對照警報。本文還能檢出新增、inode 與型態差異，但包含編譯與附掛的新程序完整成本在 128／4,096 項時較高，不能宣稱全面更快。65,536 項另次稽核的對方入口名稱集合不完整，該時間不能當成同等完整觀測的比較。

還原指紋核對不是無碰撞證明。現行入口已納入 tracefs 入口統計，十個真實漏失窗口全部拒判，但可取得的統計不代表全部量測故障均可見。一般程式監控、金鑰保護、/proc、程式庫後邊界與第一端前的新視圖均未開始，也不是本輪結案前全部必做。

revised36 另以三個不同開機、45 個主要配對區組補充觀測準備完成後的成本。小目錄本文較慢，中／大目錄在受測完整配置下較短。預設 4 MiB 大目錄的十五筆未收齊，另有檢查檔提示，不能用它們排序；增加至 32 MiB 的配置另列，並非官方預設。兩者保留不同 API、語言、內部緩衝區及檢查內容，沒有宣稱純演算法速度或全面優勢。所有主要、暖機與先導另計，原完整程序成本未覆寫。

相關工作與共同實驗見[專文](../docs/RELATED_WORK_COMPARISON_zh-TW.md)及[比較重算](../comparison/evidence/final_verification.json)。前一輪封存見 [finalization](../finalization/README.md)，本輪封存見 [comparison](../comparison/evidence/RECEIPT.json)。原兩輪補充仍用既有 verifier 重算，原資料與凍結程式不覆寫。[歷史核對](../docs/PAPER_REVIEW_FACTS_20261027.json)仍對應 revised33。
