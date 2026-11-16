# Ubuntu 26 重點實驗最終結果

日期：2026-11-16（Asia/Taipei）  
環境：Ubuntu 26.04.1 LTS，Linux 7.0.0-43-generic，離線隔離 VM。  
資料政策：本輪只在新資料夾新增紀錄；沒有修改 Ubuntu 22 結果、既有 Ubuntu 26 結果、正式報告或海報。

## 一、完成狀態

| 項目 | 終態 | 主要結果 |
|---|---|---|
| Ubuntu 22 與 Ubuntu 26 主矩陣 | 已完成 | 兩版各 576/576 陽性批次告警，720 正常批次未見告警；各 11,520/11,520 陽性列舉完整還原。 |
| CARAXES | 已完成 | getdents64 組 120 次皆告警並還原三項；filldir 組 120 次皆產生截斷告警。 |
| Singularity 目錄隱藏 | 已完成 | 480 陽性觀測皆告警；1,440 控制觀測無告警。 |
| brokepkg 目錄隱藏 | 已完成 | 3 次乾淨開機；480 陽性觀測皆告警且 IBLT 解碼成功；960 控制觀測無告警。 |
| Medusa userland 隱藏 | 已完成 | 3 次開機、360 觀測；162 有效陽性皆告警並精確解碼，180 正常控制無告警，18 筆因樣本使應用程式回報 ENOENT 而作廢。 |
| BDS / libprocesshider | 已完成 | BDS ext4/tmpfs 40 次陽性、libprocesshider `/proc` 20 次陽性均有 S↔L 告警並還原觀察差異；60 配對控制一致。 |
| Singularity `/proc` PID 隱藏 | 已修正並完成 | 3 次乾淨開機、360 觀測均有效且可解碼；120 陽性皆隱藏、存活並告警；240 控制觀測無告警。共 765 個不同陽性 worker，兩種 buffer 產生 1,530 個 worker-observations。 |
| bad-bpf eBPF `/proc` PID 隱藏 | 已完成 | 3 次乾淨開機、240 觀測。120 正常控制均有效且無告警；120 陽性均證實行程存活但從 `/proc` 消失。其中 65,536-byte 的 60 筆均有效、告警並解碼；256-byte 的 60 筆被原樣本寫成非法 dirent，列為品質無效，不算假陰性。 |
| TripleCross eBPF | 終止於相容性關卡 | 固定上游 commit 在現代 clang / Linux 7.0 最終因 eBPF 512-byte stack limit 無法建置；未做載入或效果宣稱。跨過此關卡需改寫樣本邏輯，不屬於原版樣本實驗。 |
| Trace of Times 全新 traces | 已完成 | 新蓐集 50 正常 + 50 rootkit 批次，每批 100 次 listing，共 10,000 次。四個原已校準情境各取 40 正常 + 40 攻擊批次作正式評分；`ls_basic` 20 批只作描述。 |
| Singularity 啟用期間 inode→名稱→內容 | 依使用者指示跳過 | pilot 已證實偵測器可得三個 inode；原樣本會掛鉤 debugfs/區塊讀取，啟用中的 debugfs 為空，重開機後同一 inode 可正常 `ncheck`。此為同一信任域限制的不同攻擊面，不影響偵測器已輸出 inode 的結論。 |

## 二、Trace of Times 最終評估

主要估計完全沿用之前已封存的模型與門檻，沒有看新測試標籤重新訓練或挑門檻。

| 方法 | 門檻 | TP | FP | FN | TN | Recall | Specificity | Accuracy | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| function-interval（凍結，主要） | 2.1544346900318954e-17 | 40 | 9 | 0 | 31 | 1.000 | 0.775 | 0.8875 | 0.8989 |
| sequence（凍結，主要） | 0 | 0 | 0 | 40 | 40 | 0 | 1.000 | 0.5000 | 0 |
| function-interval（同測試標籤最佳 F1，只作樂觀對照） | 5e-324 | 40 | 1 | 0 | 39 | 1.000 | 0.975 | 0.9875 | 0.9877 |
| sequence（同測試標籤最佳 F1，只作樂觀對照） | 5e-324 | 40 | 5 | 0 | 35 | 1.000 | 0.875 | 0.9375 | 0.9412 |

function-interval 凍結門檻的分情境結果：

| 情境 | TP/10 | FP/10 | Accuracy | F1 |
|---|---:|---:|---:|---:|
| default | 10 | 4 | 0.80 | 0.8333 |
| file_count | 10 | 2 | 0.90 | 0.9091 |
| filename_length | 10 | 2 | 0.90 | 0.9091 |
| system_load | 10 | 1 | 0.95 | 0.9524 |

舊封存 trace 的同一凍結 function-interval 門檻在 400 陽性 + 200 正常批次上為 TP=400、FP=11、FN=0、TN=189（F1 約 0.9864，specificity 0.945）。新跨日期資料仍找到全部攻擊批次，但正常資料的誤報升高。這表示時間特徵與門檻對新開機、排程與負載分布有敏感性；它適合當補充性比較，不應取代本方法的身分差異告警。sequence 的凍結門檻為 0，而規則是分數小於門檻才告警，因此本質上不會告警；新結果與舊資料的 0/400 陽性告警一致。

## 三、與原結果的重點比較

1. **主方法的 Ubuntu 22→26 結論沒有變。**兩版主矩陣的完整身分告警、正常控制和還原分母一致。
2. **新增的證據是機制廣度，不是把全部樣本包成一個百分比。**現在有核心 ftrace/LKM、userland readdir/LD_PRELOAD、`/proc` PID 隱藏與 eBPF getdents64 過濾的分開結果。
3. **差異告警與「找回所有預設目標」是不同指標。**brokepkg 的 480 個陽性觀測均告警且解碼所觀察差異；其中 408 觀測找到全部預設目標，其餘 72 個是 256-byte buffer 在目標全數進入上游觀測前已結束，不是 IBLT 解碼失敗。
4. **73→71 的舊邊界案例不影響告警。**兩個不同身分落入同一組三格而無法剝離；放大容量後可完整還原。報告應將告警與完整還原分開陳述。
5. **Singularity `/proc` 早期 114 個 no-marker 告警已查明並排除。**原排程在第一次 signal 59 後才建立後續 worker，使 worker 透過 fork tracepoint 繼承隱藏狀態。修正版先建立全部 cohort，先量完 no-marker，才送出隱藏信號；最終 120 個 no-marker 控制均無告警。

## 四、可放進報告的結論

> 本研究在 Ubuntu 26.04.1 LTS / Linux 7.0 環境重驗核心至系統呼叫、系統呼叫至應用程式的目錄項差異觀測。Ubuntu 22 與 Ubuntu 26 的主矩陣結論一致：所有受測有效陽性批次均觀察到身分差異，正常控制未見差異告警。延伸實驗另覆蓋核心 ftrace/LKM、userland readdir/LD_PRELOAD、`/proc` PID 過濾與 eBPF getdents64 過濾；在各樣本的有效觀察分母內，偵測器均可對實際成立的隱藏產生告警，並還原觀察到的 inode、類型與名稱身分差異。這些結果支持本方法不依賴特定 rootkit 家族名稱，而是依賴隱藏必須在觀測邊界間改變列舉身分的性質。

> 對照的時間特徵法在全新 10,000 次 listing 中，function-interval 凍結門檻找到全部 40 個攻擊批次，但在 40 個正常批次中產生 9 次誤報；sequence 的凍結門檻為零，因此沒有告警。同測試標籤重選門檻雖可得到更高分數，但只能視為偏樂觀的重現對照。因此，時間法可顯示不尋常行為，但對新環境與負載有敏感性；本研究的身分差異觀測提供了更直接、可解釋且可輸出具體 inode/類型/名稱的證據。

> 本結論限於已實測樣本、已觀察邊界與有效分母。樣本造成的非法 dirent、應用程式中止、上游列舉未走到預設目標，以及不相容於現代核心的原版樣本，均另行保留並分類，沒有當成偵測器成功或失敗。如攻擊者進一步篡改偵測探針、區塊讀取或鑑識工具，仍屬於同一核心信任域的既有限制。

## 五、證據檔

- `BROKEPKG_THREE_BOOT_VERIFICATION.json`
- `BADBPF_THREE_BOOT_VERIFICATION.json`
- `SINGULARITY_PROC_CONTAMINATION_AUDIT.json`
- `SINGULARITY_PROC_CORRECTED_THREE_BOOT_VERIFICATION.json`
- `TRACE_FRESH_COMPLETE_EVALUATION.json`
- `TRACE_POSITIVE_RETRY_MANIFEST.json`
- `trace_positive_raw.tar.gz`
- `retry_ls_basic_09.tar.gz`

上述路徑均位於 `artifacts/ubuntu26_remaining_20261116/`。TripleCross 的建置關卡證據位於 `artifacts/ubuntu26_extended_20261116_triplecross/`；Medusa 三次開機驗證位於 `artifacts/ubuntu26_extended_20261115_run11/VERIFIED_MEDUSA_THREE_BOOT.json`。

