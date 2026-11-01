# 結案補強版本

本頁記錄 2026-11-01 的還原與 BPF 程式統計補強。2026-11-02 現行入口另加入 tracefs 入口事件統計，使用根目錄 scan_directory.py，已完成入口故障與共同工具確認，見[六項結案工作](../docs/METHOD_CLOSURE_20261102_zh-TW.md)。以下的「入口仍未覆蓋」是前一版本界線，不是現行入口尚未接入。

此目錄以組合方式沿用 `phase2/measurement.py` 的合併狀態收集器，原正式版、兩輪補充的凍結程式、來源鎖及數據維持原樣。新增邏輯在 `src/kicba/recovery_validation.py` 及此目錄，不把新版本說成已重跑原九開機矩陣。

## 已完成

- 還原項目以正負號重新累計成指紋，核對原端點指紋差。原始 `decode_success` 保留診斷用途，不能單獨當作完整還原證據。
- 量測無效、未發現差異、差異警報且還原核對通過、差異警報但不能完整定位，明確分開。
- 沿用返回探針窗口門檻，另核對兩支 BPF 的程式 ID、tag 與 `recursion_misses` 前後讀數。必要計數缺少、倒退、身分變動或非零漏失均拒判。
- 原 25,920 次保存結果全部通過新增還原核對。六組既有反例不會被接受為通過核對的完整還原。
- 新原生確認有 36 次身分／對照量測，其中 28 次差異、8 次一致，均符合獨立實收與還原預期；18 次無探針控制另列。
- 結案版的正常／名稱邊界九次均有效一致，一次過小緩衝區正確無效。實際發生返回漏失的十六次窗口內列舉全部拒判，兩次循序對照有效一致。先導十次另留，不併入以上分母。

## 仍保留的限制

核對通過表示與既有機率式指紋相符，不是數學上排除所有碰撞。它不會讓無法解碼的重複差異突然能還原，也不更換 XOR 結構。256 格與 32 項是設計設定，不是任意輸入的解碼保證。即使沒有重複，差異落在同一組位置時也能解碼失敗。

新讀數涵蓋 BPF 程式的 recursion_misses，不能替代入口 perf kprobe 內部所有 nmissed。原生試驗有製造返回漏失，沒有宣稱已原生注入所有 BPF 略過或所有入口漏失。偵測器可信、公開種子、有限觀測邊界與專用 C 掃描器等假設保持不變。

原 4.76 倍及合併狀態版約四成改善屬原計時流程，不能移植為本輪補強版的效能結果。此處保存含所有新增品質查詢及核對的時間，但沒有重做跨開機的大目錄成本比較。

## 使用及重算

在既有 Linux 研究 VM 內，以原 `phase1/enum_probe.c` 編譯的掃描器執行：

```bash
sudo env PYTHONDONTWRITEBYTECODE=1 python3 finalization/scan.py /path/to/directory --probe /path/to/d9_enum_probe
```

不要只讀 `decode_success`。使用 `verdict`、`alarm`、`recovery_status`、`recovery_verified`；無效時 `alarm` 是 null。

```bash
python scripts/verify_finalization.py --output reproduced/finalization.json
python scripts/verify_finalization.py --check --output finalization/evidence/verification.json
```

原生規約在 `PROTOCOL_20261101.md`、`ADDITIONAL_PROTOCOL_20261101.md`。本輪只有既有受控模組，沒有新增公開 rootkit 樣本，也沒有一般程式監控或 /proc 行程隱藏的新成果。[最接近相關工作比較](../docs/RELATED_WORK_COMPARISON_zh-TW.md)另列。
