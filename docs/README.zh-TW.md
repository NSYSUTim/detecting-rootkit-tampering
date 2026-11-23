# Directory Entry Check

Directory Entry Check 偵測 Linux 目錄列舉中的隱藏與竄改。它用 eBPF 觀察核心，並比對核心、系統呼叫和應用程式函式庫列出的目錄項。即使替換前後的總筆數相同，也能還原有差異的項目。

## 跑一次 Demo

在儲存庫根目錄用 Python 3.10 以上執行英文四幕重播。每次按 Enter 換幕。

```sh
python -B demo/replay.py --en --interactive
```

重播會用封存紀錄重算核心與系統呼叫之間的差異還原，並顯示已記錄的時序與函式庫層結果。[Demo 說明](../demo/README.md)也有測試目錄的現場掃描方式。

## 方法

- **核心–系統呼叫（K–S）**：用 eBPF 觀察 `filldir64` 接受的目錄項，與 `getdents64` 回傳的目錄項比對。
- **系統呼叫–函式庫（S–L）**：在同一次列舉中，收集受控程序的 `getdents64` 回傳值與 `readdir64()` 輸出。
- **偵測與還原**：指紋用來偵測差異。可逆布隆查找表（IBLT）解碼成功時，會還原並核對差異項目的身分。另有完成檢查，能偵測部分列舉提早結束的情況。

## 實驗結果

受控實驗使用 Ubuntu 22.04.5 LTS 和 Ubuntu 26.04.1 LTS。

| 實驗 | 觀測結果 |
|---|---|
| [Ubuntu 26.04.1 受控矩陣](../ubuntu26/rerun_20261114/README_zh-TW.md) | 576/576 陽性批次檢出，720 個對照批次均未告警；同一矩陣的 11,520 次陽性列舉皆精確還原差異。 |
| 公開 rootkit 測試 | 有效量測中，CARAXES、[Singularity](../ubuntu26_extended_20261115/updates/20261115_singularity/RESULTS.json) 和 [Medusa](../ubuntu26_extended_20261115/updates/20261115_medusa/RESULTS.json) 的受測隱藏行為皆有檢出。Medusa 有 162 次有效陽性告警且還原差異、180 次正常掃描無告警，另有 18 次無效量測。 |
| 獨立對照 | [Trace of the Times](../ubuntu26_extended_20261115/updates/20261116_trace_normal/RESULTS.json) 的函式分組在負載下對 1/10 正常批次告警。[Decloaker v0.0.9](D9_DECLOAKER_FORMAL_RESULTS_zh-TW.md) 在完整路徑仍可存取的案例中，對 180 次隱藏掃描均未告警。 |

## 審查範圍

還原限於至少在一端有觀測到的項目身分，並取決於 IBLT 能否解碼。不完整的量測另行統計。以上比率只描述受測條件。實驗與證據清單見[研究成品收錄範圍](../ARTIFACT_SCOPE.md)。
