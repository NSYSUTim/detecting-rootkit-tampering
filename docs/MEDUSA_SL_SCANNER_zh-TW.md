# Medusa 的 S↔L 偵測入口

`scan_library.py` 比對一個受控程式在同一次完整目錄列舉中看到的兩個邊界。S 是 `strace` 記錄的 `getdents64` 回傳項目，L 是測試程式從 `readdir64()` 收到的項目。程式沿用本專案的指紋、IBLT 和還原核對。

## 操作

需要 Linux、Python 3.10 以上、gcc 與 strace。掃描器會自行編譯 `collector/library_probe.c`。

```bash
python3 scan_library.py /path/to/test-directory --text
```

在原 Medusa 研究 VM 中，對相同的測試目錄執行受控函式庫條件。`MEDUSA_LIBRARY` 指向該 VM 已準備的實測函式庫。

```bash
python3 scan_library.py "$FIXTURE" --preload "$MEDUSA_LIBRARY" --text
```

`--preload` 經由 `strace -E` 套用到受控測試程式。需要保留逐項輸出和原始系統呼叫時，指定一個新的結果目錄。

```bash
python3 scan_library.py "$FIXTURE" --preload "$MEDUSA_LIBRARY" --output /path/to/new-result-directory
```

結果目錄包含 `getdents64.trace`、`application.txt`、`application.stderr` 和 `result.json`。省略 `--text` 時，終端機也會輸出 JSON。已有的結果目錄會被拒絕。

## 判讀

正常狀態下，S 與 L 的指紋應一致。若 Medusa 在函式庫端過濾項目，S 仍有該項，L 則少一項，掃描器會告警並嘗試用 IBLT 還原差異。`recovery_verified=true` 表示解碼結果同時通過指紋回算與本次逐項觀測的差集核對。畫面上的名稱來自捕捉到的目錄項，再對照已解碼識別值。

量測未完成、系統呼叫錯誤、程式提前關閉串流、資料截斷或無法確認同一個目錄 fd 時，結果為 `invalid`，退出碼為 2。有效的一致或差異判定退出碼為 0。IBLT 容量不足時，已觀測的指紋差異仍會告警，還原核對狀態另列。`--cells` 可調整 IBLT 容量，預設為 256。

## 實作來源與範圍

此次發布把既有實測的 S↔L 路徑整理為獨立入口。C 測試程式來自 `benign_gated_readdir.c`，系統呼叫解析來自 `userland_observer.py`，IBLT 比較流程來自 `live_userland.py`。這些檔案用於 2026-11 的受控應用程式實驗。發布入口加入參數、相依工具檢查、暫存檔管理與可讀結果。

Medusa 使用原作者 `ldpreload/Medusa` 的固定提交 `fdade060f4bc53a356fe62c14e9c830fcc0b968e`。既有實測函式庫的 SHA-256 是 `48615c11b7a5ce7e2033df2d7ff4d9bf948485ac0dd8ce77b8a26fe61b9f2545`，實測以 GID 8888 的測試項目觀察過濾行為。原實驗的編譯環境、函式庫及 fixture 條件須一併考量。[原作者來源](https://github.com/ldpreload/Medusa/tree/fdade060f4bc53a356fe62c14e9c830fcc0b968e)

S↔L 使用系統呼叫追蹤與受控應用程式輸出。K↔S 的 eBPF 入口為 `scan_directory.py`。既有 Medusa 三開機驗證另有 K↔S 與量測品質門檻，360 次嘗試中保留 342 次有效觀測，含 162 次陽性與 180 次正常對照，另有 18 次 invalid。這些歷史分母沿用當時的完整量測協定。[既有結果](../ubuntu26_extended_20261115/updates/20261115_medusa/RESULTS.json) · [既有規約](../ubuntu26_extended_20261115/updates/20261115_medusa/PROTOCOL.json)

這個入口觀察指定測試程式的一次列舉。資料品質判定依賴追蹤器和測試程式的可信輸出，動態目錄的即時變動也須依當時情境解讀。

## 本次發布檢查

2026-11-23 在原 Ubuntu 22.04 研究 VM 現場執行正常列舉，S 與 L 各 7 筆（含 `.`、`..`），指紋一致且沒有告警。另以既有 Medusa 單次開機的 120 份原始追蹤做離線回歸，60 份正常資料一致，54 份完整 Medusa 資料告警且差異還原核對通過，6 份未完成的列舉拒判為 `invalid`。這是新入口的回歸檢查；Medusa 陽性資料來自歷史紀錄。本次沒有重新執行 Medusa，也不以此改寫原三開機實驗結果。
