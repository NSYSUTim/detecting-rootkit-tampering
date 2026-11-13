# 2026-11-13 IBLT 位置數實驗封存

這是研究完成後新增的離線敏感度實驗，不能追溯為原研究選參數時已存在的證據。結論與限制見[為什麼保留三個位置](../../docs/IBLT_HASH_COUNT_20261113_zh-TW.md)。

從工作區 `artifacts/iblt_hash_count_20261113` 複製的十二個原始檔保持逐位元相同；`__pycache__` 未收錄。下面的 README、發布核對及儲存庫路徑轉接工具是在發布時新增，不屬於執行前凍結的原始程式。

| 檔案 | 用途 |
|---|---|
| [run_experiment.py](run_experiment.py) | 執行前凍結的原始實驗程式；本機相對路徑保留，請由下列轉接工具執行 |
| [reconciliation_snapshot.py](reconciliation_snapshot.py) | 本次實際使用的既有 IBLT 實作快照 |
| [protocol.json](protocol.json)、[protocol.sha256](protocol.sha256) | 執行前固定的條件、種子、判準、版本與雜湊 |
| [run_started.json](run_started.json) | 原始開始時間與對應規約雜湊 |
| [validation.json](validation.json) | 原版相容、位置不重複、抵銷與重複限制控制 |
| [trials.csv](trials.csv) | 全部 36,864 次版本解碼的逐次原始結果 |
| [summary.json](summary.json)、[summary.csv](summary.csv) | 全部條件、主要配對檢定與時間統計 |
| [REPORT_zh-TW.md](REPORT_zh-TW.md) | 原程式產生的完整報告，保留原樣 |
| [MANIFEST.json](MANIFEST.json) | 原執行完成時十個檔案的 SHA-256 與大小 |
| [verification.json](verification.json) | 原執行後核對，含完整配對與 368 次固定樣本重跑 |
| [publication_verification.json](publication_verification.json) | 本次發布的跨平台入口所產生的核對結果 |

原 `MANIFEST.json` 先於原 `verification.json` 建立，因此不包含後者；它也不包含發布時新增檔案。整個儲存庫的 `FILE_SHA256.csv` 另外收錄本次發布內容，兩份清單的時間與範圍不同。

於儲存庫根目錄執行：

```bash
python scripts/iblt_hash_count_experiment.py verify
python scripts/iblt_hash_count_experiment.py run --output reproduced/iblt_hash_count_20261113
```

轉接工具只改工作目錄、Git 根目錄與快照來源位置，不改固定種子、條件、位置生成或判準。`verify` 核對全部雜湊、36,864 列、9,216 組四版本配對、摘要和主要統計，並重跑原自我檢查及固定的 368 次版本解碼。這個固定樣本不是重跑整輪；完整重現請用 `run`，且目標目錄須尚不存在。時間取決於主機，不能逐位元重現。
