Ubuntu 26 剩餘實驗進度（2026-11-16 07:55 +08:00）

狀態：in_progress。本更新只新增獨立結果，不覆蓋 Ubuntu 22、既有 Ubuntu 26 結果或書面。

已完成並獨立驗證

1. brokepkg 三次乾淨開機已補齊。每次 480 筆、合計 1,440 筆觀測均以保存的 raw dirent bytes 與 IBLT 重新計算：
   - unloaded 480/480：有效、無差異告警、解碼成功。
   - loaded_no_marker 480/480：有效、無差異告警、解碼成功。
   - active 480/480：實際隱藏成立、發出差異告警，並完整解碼當次觀測到的 K↔S 差異。

2. Singularity /proc 原始三開機資料已完成並重播 360/360 筆；同時發現原協定的順序污染：
   - unloaded 真正常對照 120/120 無告警。
   - 每開機第一組 loaded_no_marker 共 6/6 無告警。
   - 第一組 active 使用 signal 59 後，樣本隱藏觸發程序父系；fork 追蹤使後續 worker 在自己的 signal 前已繼承隱藏狀態。因此另 114 筆 loaded_no_marker 的告警是真實 K→S 差異，不能算誤報，也不能當正常對照。
   - active 隱藏狀態 120/120 都被偵測且 worker 仍存活；其中只有每開機第一組共 6 筆是乾淨的明確「未隱藏→signal→隱藏」轉換，其餘 114 筆在自己的 trigger 前已被前序污染。
   - 已保留本批資料，需用先建立全部 worker、先完成所有 no-marker 掃描、再送 trigger 的修正版另存重跑。

正在進行或待補

1. TripleCross：釘選原始版本已進入 Ubuntu 26 / Linux 7.0 建置關卡；目前遇到 eBPF 原始碼引入 glibc 32-bit stub 的建置環境問題，尚無可引用的載入或隱藏結果。
2. Singularity /proc：修正版三開機重跑。
3. Singularity 啟用期間由偵測器 inode 反查名稱並取回內容。
4. bad-bpf：作為 eBPF /proc 補充；若固定版本無法執行，保存明確原因。
5. Trace of Times 新陽性資料：依排程最後執行。

詳細機器可讀資料：

- BROKEPKG_THREE_BOOT_VERIFICATION.json
- SINGULARITY_PROC_CONTAMINATION_AUDIT.json
