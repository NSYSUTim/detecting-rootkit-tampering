# 四幕 Demo

在儲存庫根目錄執行，按 Enter 換幕。只需 Python 3.10+。

```text
python -B demo/replay.py --interactive
```

1. **正常**。我先看同一個目錄，K、S 各 70 筆，內容一致。
2. **CARAXES**。S 剩 67 筆，我重算 IBLT 並核對少掉的三筆。另一組磁碟對照中，Decloaker 對 180 次隱藏掃描都沒告警。
3. **時間法**。預跑的正常負載有 1/10 批誤報。本法在正式比較的另收批次是 0/150 批誤報、100/100 批告警。
4. **Medusa**。看保存的個案，S 端有一個目標沒出現在 L 端，還原通過核對。這組只收 S↔L 資料。

### 當場掃描

在有 BCC、GCC、`strace` 和 `sudo` 的 Linux 研究環境執行。目錄須位於 ext4 根檔案系統，並提供可信的 Decloaker v0.0.9 執行檔路徑。

```bash
bash demo/scan.sh "$DIR" "$DECLOAKER"
```

K↔S、S↔L 和 Decloaker 重新掃同一目錄，Times 讀預跑結果。畫面最後列出原始輸出位置。

原生 Linux 是現場版的基準環境。WSL 的 K↔S 需要支援其 PID namespace 的掃描器。

### 維護

- `replay.py` 放四幕與資料來源；K↔S 重算，Times 和 Medusa 讀封存結果。
- `scan.sh` 呼叫既有掃描器，並共用 `replay.py` 的 Times 輸出。
- 更新資料時一併核對分母與來源，再跑一次四幕。正式對照見 [Times](../docs/D9_TRACE_FORMAL_RESULTS_zh-TW.md) 與 [Decloaker](../docs/D9_DECLOAKER_FORMAL_RESULTS_zh-TW.md)。
