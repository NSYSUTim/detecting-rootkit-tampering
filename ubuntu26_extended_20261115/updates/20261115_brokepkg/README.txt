brokepkg：Ubuntu 26 第一個開機的實測與原始資料重播

本次僅上傳已產生的結果，沒有啟動新實驗。原計畫尚未全部完成。

結果：480 次有效掃描。160 次隱藏狀態皆告警；160 次未載入對照與 160 次載入但未設定隱藏目標的對照皆無差異告警。
第一個開機的 160/160 次有效陽性均完整解碼當次觀測到的 K↔S 差異。三開機的正式彙整見 ../20261116_final_remaining_results/FINAL_RESULTS_AND_REPORT_CONCLUSION.md。


VERIFIED_REPLAY.json 的舊欄位 exact_recovery 指「實際觀測到的 K-S 差異完整解碼」，不等於找回全部設定目標。

版本：釘選 upstream commit 250f132f0d856cb46449de7a6d0dadd878309fb3。原始碼未修改，但使用 PROC_ROOT_INO=PROCFS_ROOT_INO 編譯相容定義，不能省略這項條件而稱為完全無調整的原版建置。
已完成一個開機；原定三個開機的其餘兩個尚未完成。量測結束紀錄確認樣本已卸載。

檔案：RESULTS.json 有彙總與 24 個條件格；CASE_RESULTS.csv 列出 480 次個別結果；VERIFIED_REPLAY.json 保留既有獨立重播紀錄；PROTOCOL.json 記錄樣本版本與測試條件；EVIDENCE_MANIFEST.json 提供本機原始來源與雜湊。
大型原始 observations、syscall bytes 與 fixture 保留在本機 artifacts，這次沒有一併上傳；位置見 EVIDENCE_MANIFEST.json。

可引用的結果敘述：
「在 Ubuntu 26 的第一個開機測試中，brokepkg 的 160 次隱藏觀測皆產生差異告警，320 次對照皆未產生差異告警。所有已觀測到的核心／syscall 差異均可完整解碼。」
