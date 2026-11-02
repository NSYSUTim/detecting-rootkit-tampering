# 相同掃描判讀範圍的比較套件

結果及解讀見[完整報告](../../docs/SCAN_COST_COMPARISON_20261102_zh-TW.md)，正式書面為 revised38。原完整程序成本在 comparison/evidence，沒有被本次結果取代。此處比較三次開機、45 個計時配對區組、135 筆計時樣本及 27 筆暖機，先導另計。

## 檔案與重算

- PROTOCOL.md 是正式確認前的規約，TIMING_BOUNDARY.md 補述上層判定的實際計時區段。
- BUILD.json 與 adapter.patch 對應正式執行的計時轉接版。PILOT_BUILD.json 及封存中的各部署 ZIP 保留較早先導版本。
- RECEIPT.json 與 scan_cost_20261102.tar.gz 保存原始輸出、全部先導、套件及來源核對、獨立目錄清單、計時資料、Go／Python 測試紀錄及主機取樣。
- verification.json 是正式重算結果。verification_portability_attempt.json 是離線工具的失敗紀錄，修正原因見 ANALYSIS_NOTES.md，不當成原生量測失敗或新的分母。
- facts.json、costs.csv 與 paired_ratios.csv 為衍生資料。完整資料時才計算配對比值，不完整的十五筆預設大目錄結果仍在封存及重算結果中。

原始 assessment.correct 是受測目錄的共同名稱判定，不是整個工具狀態或完整觀測的保證。可疑的檢查檔提示、實際 cell_statuses、名稱是否完整與 eligible 分開保存；不只用 correct 旗標決定是否列入速度比較。

從倉庫根目錄執行：

```bash
python scripts/verify_scan_cost.py --check comparison/scan_cost/verification.json
```

核對工具不執行外部二進位、不載入核心模組、不解壓至檔案系統。先檢查封存 SHA-256，再一次解壓至記憶體，逐筆核對原始 stdout、實際名稱集合、指紋、品質、計時和、目錄起訖、隨機順序與所有樣本。重算成功後可執行 `python comparison/scan_cost/summarize.py` 重建衍生表與說明，原始封存不變。

## 固定來源與建置

固定來源為 [zygarde 08ccebd8](https://github.com/waldh4ri/zygarde/tree/08ccebd8fdcc28c56dc6251cad0683b7c9344bd1)。正式二進位 SHA-256 為 `615397c68c403f833aaf903ac447b8ba15f6a2092e5f8b0396407a14746b0d25`，使用 Go 1.25.0。原 BPF C、amd64／arm64 物件未改，其 SHA-256 在 BUILD.json。計時 helper、新增共享既存檢查檔、單目錄及容量參數，均以 patch 公開。

可從固定來源另建新工作目錄，使用自己的 Go 1.25.0 與模組快取：

```bash
python tools/build_scan_cost_adapter.py --upstream /path/to/pinned/upstream --work /path/to/new/work --go /path/to/go/bin/go --cache /path/to/build/cache --module-cache /path/to/module/cache --output /path/to/new/zygarde-adapter --metadata /path/to/new/metadata
```

Windows 的 --go 可用 go.exe。若以 Git checkout 取得來源，保留原 LF 位元組，避免 autocrlf 改變固定來源雜湊。輸出 metadata 請用新目錄，不覆寫本套件已測版本。二進位雜湊描述本次實際檔案，不宣稱不同工具鏈或 VCS 建置資訊下必定逐位元相同。

原始授權為 BSD 2-Clause／GPL v2 雙授權，見 [LICENSE](../zygarde/LICENSE)。未重複散布上游完整專案或二進位。32 MiB 是比較時明列的 map 容量，並非官方預設或新安全功能。

## 執行界線

run.py、scan_entry.py 及 orchestrate.py 是原隔離 VM 的研究入口，目錄需為全新路徑，核心與原模組 SHA-256 固定。重收需先閱讀規約，不能把這些來源當成任意主機可直接執行的部署腳本。本文 root 掃描入口 scan_directory.py 及已凍結研究來源均未修改。
