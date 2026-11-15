brokepkg：Ubuntu 26 第一個開機的實測與原始資料重播

本次僅上傳已產生的結果，沒有啟動新實驗。原計畫尚未全部完成。

結果：480 次有效掃描。160 次隱藏狀態皆告警；160 次未載入對照與 160 次載入但未設定隱藏目標的對照皆無差異告警。
對實際觀測到的核心 K 與 syscall S 差異，160 次隱藏測試皆完整解碼。
若分母改為預先設定的全部隱藏目標，則只有 136/160 次完整找回：256-byte buffer 為 56/80 次，65536-byte buffer 為 80/80 次。

另外 24 次小 buffer 測試提前結束列舉，部分項目未到達上游觀測點。這不是先前兩項落入相同三格的 IBLT 碰撞。
隱藏測試中，共 4,344 筆完整 fixture 相較下游的缺失事件；2,820 筆已還原，另 1,524 筆未被上游觀測。各數字包含跨測試的重複事件，不能當成獨立檔案數。

VERIFIED_REPLAY.json 的舊欄位 exact_recovery 指「實際觀測到的 K-S 差異完整解碼」，不等於找回全部設定目標；全目標結果請看 all_configured_targets_recovered。

版本：釘選 upstream commit 250f132f0d856cb46449de7a6d0dadd878309fb3。原始碼未修改，但使用 PROC_ROOT_INO=PROCFS_ROOT_INO 編譯相容定義，不能省略這項條件而稱為完全無調整的原版建置。
已完成一個開機；原定三個開機的其餘兩個尚未完成。量測結束紀錄確認樣本已卸載。

檔案：RESULTS.json 有彙總與 24 個條件格；CASE_RESULTS.csv 列出 480 次個別結果；VERIFIED_REPLAY.json 保留既有獨立重播紀錄；PROTOCOL.json 記錄樣本版本與測試條件；EVIDENCE_MANIFEST.json 提供本機原始來源與雜湊。
大型原始 observations、syscall bytes 與 fixture 保留在本機 artifacts，這次沒有一併上傳；位置見 EVIDENCE_MANIFEST.json。

可引用的結果敘述：
「在 Ubuntu 26 的第一個開機測試中，brokepkg 的 160 次隱藏觀測皆產生差異告警，320 次對照皆未產生差異告警。所有已觀測到的核心／syscall 差異均可完整解碼；其中 136 次隱藏觀測找回全部設定目標，其餘 24 次受小緩衝區下列舉提前結束影響，未到達上游觀測點的項目無法由該次差分恢復。」
