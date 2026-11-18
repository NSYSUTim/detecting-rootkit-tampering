# 跨層目錄項一致性檢查

目前入口保留已接受項目的指紋與 IBLT，另加入同次 getdents64 呼叫拒絕項目卻回傳 0 的完成檢查，最新結案書面為 2026-11-09 作者提供的中英文報告。新三開機的原版 CARAXES 兩模式各 120 次警報，正常刪除競態 30 次無新警報。整次最後 false 的舊規則已撤回，相關實驗紀錄保留。 [新結果、成本與限制](docs/CALL_COMPLETION_20261103_zh-TW.md)。

本儲存庫對應論文〈跨層目錄項一致性檢查：以 eBPF 指紋與 IBLT 偵測 filldir64 與 getdents64 間的身分差異〉，保存原始碼、受控實驗模組、資料與重現工具。

本方法比較同一次完整目錄列舉中，核心端 `filldir64` 已接受的目錄項，與使用者端從全部 `getdents64` 分頁收到的目錄項。兩端各自建立固定大小的多重集合指紋與 IBLT：指紋判斷是否有差異，IBLT 用於還原差異項目的識別值、inode 與型態。解碼能力受容量、項目分布及重複差異限制，成功旗標本身不保證任意輸入下的還原正確性。

本研究的實驗檢驗偵測正確性、差異還原、量測可靠性、適用條件與執行成本，並與既有工具比較。九次開機矩陣涵蓋單一核心、ext4 與靜態目錄；量測完整性及適用條件實驗檢驗探針漏失、載入順序、指定 Linux 6.8／6.5、ext4／tmpfs、正常動態目錄與更多身分改寫，並驗證合併核心狀態的成本改良。現行警報分為身分差異與完成回報異常，不能由此判定惡意或推論對未知 rootkit 的偵測率。

- [最終中文結案報告（Word）](paper/final/Project_Final_Report_ZH_B123245021_Wei-Ting_Chiang.docx)
- [最終英文結案報告（Word，修正分頁版）](paper/final/Project_Final_Report_EN_B123245021_Wei-Ting_Chiang.docx)
- [最終英文結案報告（PDF，48 頁）](paper/final/Project_Final_Report_EN_B123245021_Wei-Ting_Chiang.pdf)
- [最終英文海報（PowerPoint）](paper/final/Poster_EN_B123245021_Wei-Ting_Chiang.pptx)
- [最終成品與原檔雜湊](paper/final/README.md)
- [為什麼每筆更新三個 IBLT 位置：2026-11-13 新增離線比較](docs/IBLT_HASH_COUNT_20261113_zh-TW.md)
- [原版 CARAXES 三開機實測與未檢出邊界](docs/ORIGINAL_CARAXES_20261102_zh-TW.md)

- [六項結案工作與三開機共同工具比較](docs/METHOD_CLOSURE_20261102_zh-TW.md)
- [現行掃描入口](scan_directory.py)與[共同比較重算](comparison/evidence/final_verification.json)
- [前一輪完成內容與書面審查依據](docs/FINALIZATION_REVIEW_20261101_zh-TW.md)
- [filldir64／getdents64 最接近相關工作比較](docs/RELATED_WORK_COMPARISON_zh-TW.md)
- [新增還原核對、品質門檻及原生確認](finalization/README.md)
- [定稿後的方法與證據核對](docs/PAPER_REVIEW_UPDATES_20261027_zh-TW.md)
- [最終結案報告與海報](paper/README.md)
- [量測品質與成本拆分證據](phase1/REPORT_zh-TW.md)
- [適用條件與合併狀態改良證據](phase2/REPORT_zh-TW.md)
- [目前方法與下一步](docs/METHOD_AND_NEXT_STEPS_zh-TW.md)
- [報告修正與證據界線](docs/REVIEW_CORRECTIONS_20261102_zh-TW.md)
- [量測可靠性與適用條件實驗發布核對紀錄（2026-10-24）](docs/PUBLICATION_VERIFICATION_20261024.json)
- [目前版本的發布核對紀錄](docs/PUBLICATION_VERIFICATION_CALL_COMPLETION_20261103.json)
- [離線反例與含查詢成本的重算結果](docs/PAPER_REVIEW_FACTS_20261027.json)
- [收錄範圍](ARTIFACT_SCOPE.md)
- [第三方來源與比較範圍](THIRD_PARTY_NOTICES.md)

本說明更新至 2026-11-13；最終結案書面仍為 2026-11-09 版本。本次另收錄位置數的離線敏感度實驗，不回填原研究的選參數歷史或實驗分母。現行入口的還原核對與入口／返回品質門檻保留，新功能以同次系統呼叫配對處理受測拒絕後結束異常。原已接受項目實作、撤回的最後 false 試驗與同次呼叫完成檢查的三開機資料皆各自保存，不合併分母，歷史成本也不當成新版成本。詳見[新實作與直接配對成本](docs/CALL_COMPLETION_20261103_zh-TW.md)。

在原 Linux 研究環境中使用新入口，將 --probe 指向原 C 完整列舉程式的執行檔。以下從既有來源另行編譯，不覆寫原實驗執行檔：

```bash
gcc -O2 -Wall -Wextra phase1/enum_probe.c -o /tmp/kicba_enum_probe
sudo env PYTHONDONTWRITEBYTECODE=1 python3 scan_directory.py /path/to/directory --probe /tmp/kicba_enum_probe
```

舊 collector campaign 與 2026-11-01 的 finalization/scan.py 保留作版本重現，不把它們冒充已加入 tracefs 入口統計的現行入口。新入口仍是專用掃描器同次列舉，不是背景監控所有 ls。

## 方法流程

1. **配對同一次列舉。** 控制程式先登記量測行程的 PID，再讓 C 語言量測程式反覆呼叫 `getdents64`，直到回傳 0。
2. **記錄核心端已接受項目。** eBPF 觀測 `filldir64` 進入與返回，只計入回傳 `true` 的最外層呼叫，避免巢狀呼叫重複計算，也避免把緩衝區不足而回傳 `false` 的正常重送計入。
3. **在兩端建立摘要。** 以名稱位元組、inode 與 `d_type` 建立識別值；指紋保存項目數及兩個 64 位元雜湊總和，IBLT 同步累計各項目。指紋與列舉順序無關，能辨識數量不變但身分改變的替換。
4. **先檢查量測有效性，再比較。** 名稱讀取、資料表更新、呼叫配對或量測行程等檢查失敗時，不產生一致或差異判定。量測有效且指紋不同時警報；IBLT 解碼失敗只表示無法完整定位，警報仍成立。

IBLT 還原的是識別值、inode 與型態，不含原始名稱。矩陣實驗設定為 256 個儲存格，以 32 個差異項目為設計目標作八倍預留；這是經驗設定，不保證任意輸入都能成功解碼。固定大小指的是容量固定時的摘要資料量；逐項讀取名稱、雜湊與更新 IBLT 的時間仍隨目錄項數增加。

每筆更新多個位置是為了逐步剝離差異：某格只剩一筆且通過校驗時，就可還原該筆，再從其餘對應位置消去。2026-11-13 新增的固定規約離線比較中，在既有 256 格、32 個差異設定下，二個位置正確還原 2,006/2,048，三、四、五個位置皆為 2,048/2,048；三個位置是本次達到全部正確還原的最少位置數，其 Python 建表及解碼耗時中位數亦低於四、五個位置。這支持目前設定下保留三個位置的工程折衷，沒有證明其在所有情況最好；較小容量的部分條件，四、五個位置的還原率反而較高。這是研究完成後新增的驗證，不是原選參數時已做過的比較，也不是原生 eBPF 或 rootkit 檢出率驗證。[規約、完整結果與限制](docs/IBLT_HASH_COUNT_20261113_zh-TW.md)

本實作以計數與 XOR 累計 IBLT。一端兩份 X、另一端為空時，內容抵消但三格計數仍為 2，無法剝離；兩端各兩份 X／Y 且位置相同時，整表歸零而原解碼器錯誤回報成功。沒有重複的項目也能因位置分布不利而無法解碼。現行整合版已把還原指紋核對接入流程，錯誤空差集不再標為通過核對的完整還原，警報仍成立；它沒有更換原 XOR 結構，也不是不碰撞的證明。舊收集器保留原樣。[還原核對與證據](finalization/README.md)

## 實驗結果

### 偵測正確性與差異還原

環境為 Ubuntu 22.04.5、Linux `6.8.0-138-generic`、x86-64、ext4，使用 Hyper-V 虛擬機、4 vCPU 與固定 8 GiB 記憶體。九種模組狀態、四種背景負載及四種緩衝區大小，在九次開機中共產生 1,296 批、25,920 次完整列舉，每批 20 次。

| 方法 | 差異批次檢出數 | 對照批次誤報數 | 召回率 | 誤報率 |
|---|---:|---:|---:|---:|
| 多重集合指紋與 IBLT | 576 / 576 | 0 / 720 | 100% | 0% |
| 只比較項目數 | 432 / 576 | 0 / 720 | 75.00% | 0% |
| 固定 MAD 時序門檻 | 28 / 576 | 51 / 720 | 4.86% | 7.08% |
| 固定時序上界門檻 | 9 / 576 | 17 / 720 | 1.56% | 2.36% |

全部 144 個等量替換批次均被指紋檢出，均未被項目數基線檢出。11,520 次差異列舉的 IBLT 差集全部正確還原，矩陣實驗資料未出現無效列舉或錯誤的成功解碼。兩個時序門檻只是整次列舉耗時的簡單對照，不能代表 Trace of the Times。

批次層級 Wilson 95% 信賴區間為召回率 99.34%–100%、誤報率 0%–0.53%，計算假設批次獨立。同批 20 次列舉不當成獨立樣本；九次開機全部達成差異全檢出、對照零誤報，其開機層級成功率區間為 70.09%–100%。完美點估計只描述受測矩陣。各批次是否應有差異由受控模組事先決定，因此主要驗證量測、完整列舉、配對與差異還原流程。

### 公開樣本的目錄隱藏實測

在 Ubuntu 26.04.1 的 Singularity 與 brokepkg 目錄實驗中，兩個樣本各有 **480/480 次有效陽性掃描告警**，且各有 **480/480 次完整解碼當次觀測到的 K↔S 目錄項差異**。解碼輸出包含差異項目的名稱識別值、inode 與類型。[結果與驗證紀錄](ubuntu26_extended_20261115/updates/20261116_final_remaining_results/FINAL_RESULTS_AND_REPORT_CONCLUSION.md)

### 執行成本

單次開機、無背景負載、65,536 個項目時，原始列舉平均 38.16 ms，只在使用者端建立摘要為 45.59 ms，完整方法為 181.51 ms，約為原始列舉的 4.76 倍。12 種項目數與負載組合的倍率範圍為 3.72–7.94。這是原成本流程；後續的成本拆分與診斷版／候選比較另列如下，不回填或覆寫原數字。

另一個分開執行的逐項追蹤比較流程中，完整方法為 221.62 ms，逐項追蹤為 2,480.72 ms；核心端資料結構的邏輯資料量分別為 12.02 KiB 與 17,920.55 KiB。這是欄位大小加總，不含配置額外開銷，也不是實測輸出流量。逐項追蹤為本研究自行實作，不能代表 Synacktiv 等工具；兩個流程的時間不合併計算倍率。

### 外部方法比較

- **Trace of the Times：** 同一虛擬機環境中分開收集的一次四情境比較。原作者依測試標籤選 F1 最大門檻時，函式分組的召回率／誤報率為 93.89%／15.20%，序列分組為 98.00%／27.18%；本方法在另外收集的 1,000 批為 100%／0%。無法確認兩方法位於同一次開機，也不是逐次列舉配對；尚需共同設計的多開機重複驗證。
- **Decloaker v0.0.9：** 九次開機、720 次掃描中，180 次受測隱藏皆未輸出 `HIDDEN`，540 次對照也未警報。依本研究檢視，`disk ls --compare` 比較原始磁碟列出的完整路徑能否解析；受測隱藏針對父目錄列舉，保留已知完整路徑的存取。此結果反映觀測目標不同，不能寫成工具整體失效；其他功能未測試。
- **rkchk：** 尚未在其要求的 Rust for Linux 自訂核心重現，不提供未量得的比較數值。

Trace of the Times 的逐事件資料及第三方專案本體未收錄；本套件能查核摘要與驗證紀錄，完整重算需取得固定版本並重新收集資料。外部比較的排除、重跑與事後分析另有紀錄。

## 量測可靠性、適用條件與成本改良

初版實作、診斷版與合併核心狀態候選的證據分開報告。候選仍同步建立指紋與完整 IBLT，維持原接受規則與拒判檢查；它減少逐項 map 查詢和讀回／清理，沒有改為觀察其他程式，也沒有替換初版 collector 入口。

| 工作 | 已完成證據 | 結果與邊界 |
|---|---|---|
| 返回漏失 | 三開機、90 個真正漏失窗口、1,680 次列舉 | 全部拒判；不是證明修復了舊版 false-valid，入口 perf 統計仍有限 |
| 載入順序與干擾 | 三開機、1,800 次實收輸出，其中 720 次完整判讀／還原 | 受測 ftrace 組合兩種先後皆符合預期，不代表所有掛接技術 |
| 新差異、核心與 FS | 兩指定核心各三開機；ext4／tmpfs；兩版合計 5,760 次量測靜態，另有 264 次無探針控制 | 4,560 次實際差異均判對、完整還原；252 次新增未實際注入含控制，未算成功陽性 |
| 正常動態 | 480 次，掃描時段內確有建立／改名／刪除 | 全部有效一致；不等於原子快照或動態攻擊驗證 |
| 另一作者過濾 | 固定 xcellerator 原始過濾函式，相容移植及兩種先後 | 共用 ftrace helper，不宣稱獨立掛接家族 |
| 成本拆分 | 三開機，1,800 次計時樣本與 360 次暖機 | 核心逐項路徑重要；解碼約 2 ms，不能視為唯一瓶頸 |
| 保留定位的成本改良 | 兩核心各三開機，1,080 次成本計時樣本與 216 次暖機 | 65,536 項、無額外負載，各開機配對耗時中位數降低 39.6%–45.1% |

成本改良比較原診斷完整版與合併完整候選，含程序啟動、登記、掃描、讀回、解碼與清理，編譯／附掛另計。上述 39.6%–45.1% 不含列舉前後的返回探針統計與事件身分查詢，事前採用條件使用這個指標。由同一批原始資料追加重算，含查詢時各開機配對比值中位數為 0.553–0.606，降幅為 39.4%–44.7%；這是追加核對，不另立採用條件。統計取自 `kprobe_profile`，事件身分另由 `kprobe_events` 與事件的 `id` 檔確認。不同條件及 IQR 全部保留，不把大目錄條件的改善推成全部情境，也不把原論文 4.76 倍直接換成新倍率。[原配對結果](phase2/analysis/paired_costs.csv)與[含查詢時間的重算](docs/PAPER_REVIEW_FACTS_20261027.json)

另量得全域 BPF map fdinfo memlock 約由 7.50 MiB 至 2.60 MiB；每次 256-cell 邏輯摘要仍約 12.02 KiB。這些不是整工具實體峰值或輸出流量。候選的固定預留與併發上限有取捨，只做過 16 程序並行檢查。

偵測正確性矩陣以批次評估；量測可靠性、適用條件與成本實驗依目的，以單次列舉、窗口或配對區組評估。不能合併分母、沿用原信賴區間或將先導與故障控制算成偵測成效樣本。詳見兩輪[來源與規約](docs/PAPER_UPDATE_GUIDE_20261024_zh-TW.md)。

## 適用範圍與限制

- 原已接受項目版本的原版 CARAXES 已另行實測。 getdents64 模式每次缺少三筆並警報；filldir 模式回傳 false，正常 70 筆的目錄只交付 2 筆，核心摘要也只接受相同 2 筆，120 次均未警報。 [規約、原始資料及重算](comparison/public_rootkit/README.md)

- 身分分支涵蓋 `filldir64` 接受之後到 `getdents64` 輸出之前的身分差異。項目在觀測點之前被排除，或因提早回傳 0 而根本未走訪，仍不能完整觀測。新增完成分支可警報本次受測的同次拒絕加回傳 0，但不列出未走訪的全部項目。
- 假設 eBPF、使用者量測程式與控制程式未被攻擊者控制。原矩陣實驗先掛 eBPF，再載入 ftrace 模組；條件確認實驗已測受測 ftrace 組合的反向順序，其他掛接技術仍未驗證。
- 現有 FNV-1a 與混合函式不提供密碼學保證。矩陣實驗種子由固定起始值與開機編號產生並記錄，可重現而非祕密金鑰；尚未驗證已知種子、主動碰撞或辨識量測程式後選擇性放行的攻擊。
- IBLT 的 XOR 版本無法視為一般多重集合還原器；重複差異的兩個離線反例包含解碼失敗與錯誤成功。它們是資料結構檢查，沒有作為虛擬機攻擊試驗，也不併入檢出率或還原率的分母。
- 九次開機矩陣仍限單一核心、ext4、靜態目錄。條件確認實驗增加指定 6.8／6.5、tmpfs 和正常動態，仍只有同一實體主機；overlayfs、namespace 等未完成相同確認，更多硬體與環境仍待驗證。
- 診斷版的 perf 入口統計未提供同等漏失可見性；現行入口已改用明確 tracefs 事件，將其 nmissed 納入拒判，並通過十個真實入口漏失窗口及正常對照。仍不能宣稱排除了所有故障，也不能事後替舊矩陣實驗資料補出 missed=0。`/proc` 行程隱藏與獨立生命週期模型未研究。
- 偵測器選擇性放行、一般程式列舉監控、程式庫返回後過濾與第一端之前的隱藏均未納入本輪。函式庫觀測點列為下一步的研究提案，第一端之前的視圖不加入本次。

## 下一步

下一步聚焦增加觀測點，研究差異出現在哪一段。保留同次列舉與固定摘要的原則，規劃對齊核心已接受項目、getdents64 回傳記錄及程式經函式庫取得的項目，再比較相鄰兩端。

這是尚未實作的研究提案。須先處理函式庫批次讀取與逐筆交付的配對、未完成列舉及缺失資料，再以正常、受控核心過濾、受控函式庫過濾驗證差異區段、無效率與成本。區段差異仍不直接代表惡意。具體說明與文獻見[報告修正依據](docs/REVIEW_CORRECTIONS_20261102_zh-TW.md)。

IBLT 容量與重複差異、可信量測及未受測環境保留在方法限制中。 金鑰保護、辨識掃描器、單純換成 /proc、預編譯或掃描整個檔案系統，不另列為本研究的下一步。

## 程式與證據位置

原始檔名與資料目錄沿用實驗時的名稱，供既有分析鎖與雜湊核對；閱讀時以下表的功能名稱為準。

| 功能 | 位置 |
|---|---|
| 識別值、指紋與 IBLT | `src/kicba/reconciliation.py` |
| 現行完整入口及入口品質窗口 | `scan_directory.py`、`call_completion/measurement.py`、`finalization/tracefs_measurement.py` |
| 核心端 eBPF 與共用雜湊規則 | `collector/bpf_d9_reconciliation.c`、`collector/d9_reconciliation_hash.h` |
| 使用者端完整列舉 | `collector/d9_enum_probe.c` |
| 正式收集與多開機排程 | `collector/run_d9_campaign.py`、`scripts/run_d9_multiboot.py` |
| 鎖定分析 | `scripts/analyze_d9_formal.py` |
| 正式原始資料、分析鎖及報告 | `results/d9_formal/` |
| 容量、邊界、穩健性與成本 | `results/d9_development/` |
| 新增二／三／四／五位置離線比較 | `results/iblt_hash_count_20261113/`、`scripts/iblt_hash_count_experiment.py` |
| 外部比較摘要、清單與驗證 | `results/d9_external_comparison/` |
| 實驗規約 | [原始鎖定規約](docs/D9_RECONCILIATION_RESEARCH_PROTOCOL_zh-TW.md) |
| 矩陣實驗結果 | [原始結果紀錄](docs/D9_CONFIRMATORY_RESULTS_zh-TW.md) |
| 外部比較與排除紀錄 | [時序比較](docs/D9_TRACE_FORMAL_RESULTS_zh-TW.md)、[磁碟視圖比較](docs/D9_DECLOAKER_FORMAL_RESULTS_zh-TW.md)、[偏差紀錄](docs/D9_EXTERNAL_METHOD_COMPARISON_DEVIATIONS_zh-TW.md) |
| 返回漏失、干擾與成本拆分 | `phase1/`，含鎖、六份封存及故障／原版對照 |
| 適用條件及合併狀態候選 | `phase2/`，含兩核心來源鎖、十一份封存、配對成本與原生控制 |
| 目前書面與方法核對 | [書面版本](paper/README.md)、[定稿後核對](docs/PAPER_REVIEW_UPDATES_20261027_zh-TW.md) |
| 環境與工具鏈 | [環境追溯紀錄](docs/D9_ENVIRONMENT_AUDIT_20261004_zh-TW.md)、`results/environment/` |

原始規約與結果紀錄保留實驗當時的描述。種子性質、外部比較進度、資料量定義與目前證據範圍，以本頁、目前書面及上述核對說明解讀。

## 快速重現

以下是讀取既有資料的離線分析，不需載入核心模組。從儲存庫根目錄執行，使用 Python 3.10 或更新版本。分析只使用標準函式庫；單元測試需讓 Python 找到 `src`。

Linux / macOS：

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/analyze_d9_formal.py --input results/d9_formal/raw --timing-model results/d9_formal/timing_model.json --lock results/d9_formal/analysis_lock.json --output reproduced/formal_results.json
```

Windows PowerShell：

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python scripts/analyze_d9_formal.py --input results/d9_formal/raw --timing-model results/d9_formal/timing_model.json --lock results/d9_formal/analysis_lock.json --output reproduced/formal_results.json
```

預期得到 `passed: true`、1,296 批、25,920 次列舉、空的完整性錯誤清單與全部 12 項判準通過。核對 `methods`、`transaction_counts`、`criteria` 等統計欄位與 `results/d9_formal/analysis_r1/results.json` 一致；輸入路徑字串會依作業系統而異。輸出檔已存在時程式會拒絕覆寫，請換用新檔名。

量測完整性與適用條件實驗可在含歷史的 Git clone 中離線核對，不必重開 VM 或載入模組：

```bash
python scripts/verify_research_updates.py --recompute --output reproduced/research_updates.json
```

此入口核對歷史 Git 基準、17 份封存與 37／66／66 個來源鎖項目，再由原始記錄重算兩輪摘要，逐筆核對第二輪靜態輸出、差異還原、動態指紋／cells／操作時間窗口。來源鎖項目彼此有重複，不是 169 個獨立檔案。僅允許明列的閱讀文件更新，原資料和鎖不覆寫；輸出檔須是新檔。

定稿時新增的兩個 IBLT 離線反例及含查詢成本，可直接從現有程式與六份原始封存重算核對，不需解壓或執行 VM：

```bash
python scripts/verify_paper_review_checks.py --check docs/PAPER_REVIEW_FACTS_20261027.json
```

若要另存結果，改用 `--output reproduced/paper_review_checks.json`，目標須為新檔。此檢查不改解碼器，不新增或合併實驗分母。

歷史 `make_report.py` 含實驗當時特定本機 checkout 的完整性稽核，發布後目錄／閱讀文件更新不宜用它回寫歷史報告；請使用上面的可攜入口。舊九次開機矩陣實驗分析指令仍保持可用。

重新收集需隔離、可還原的原生 Linux 虛擬機、root、BCC/eBPF、編譯器與相符 kernel headers；步驟以原始鎖定規約為準。

## 資料完整性

新增的位置數實驗可離線核對原始檔雜湊、全部配對及主要統計，並重跑固定 368 次版本解碼；完整重現使用固定規約與實作快照，目標目錄必須尚不存在：

```bash
python scripts/iblt_hash_count_experiment.py verify
python scripts/iblt_hash_count_experiment.py run --output reproduced/iblt_hash_count_20261113
```

現行入口、共同工具比較與另列的控制修復可直接從封存離線核對：

```bash

```

原規約首次混合目錄確認未完成、無效控制與逾時堆疊均保留，修訂後三開機確認分開。控制修復只寫入新來源，沒有覆寫舊 getdents 控制。先前四十五項離線測試已在原 Linux VM 及具正常暫存目錄權限的 Windows 通過；本次發布另在 Windows 執行目前完整六十七項測試，全部通過。先前 Windows 沙箱暫存 ACL 與新增比較的先導／離線路徑修正另留紀錄，未略過失敗測試或降低判準。

`FILE_SHA256.csv` 列出研究檔案的相對路徑、SHA-256 與位元組數，不包含清單本身及 Git 內部檔案。矩陣實驗另以分析鎖、各 `campaign.sha256` 及外部比較鎖定檔約束原始資料和實作版本。這次重新產生的是公開套件檔案清單；九次開機矩陣實驗、量測完整性與適用條件實驗的原始資料、凍結來源與實驗鎖保持原樣。新增的可攜核對程式把發布後閱讀文件變動與原歷史基準分開驗證。

## 同次呼叫完成檢查

目前入口保留已接受項目的指紋與 IBLT，另加入同次 getdents64 呼叫拒絕項目卻回傳 0 的完成檢查，最新結案書面為 2026-11-09 作者提供的中英文報告。新三開機的原版 CARAXES 兩模式各 120 次警報，正常刪除競態 30 次無新警報。整次最後 false 的舊規則已撤回，相關實驗紀錄保留。 [新結果、成本與限制](docs/CALL_COMPLETION_20261103_zh-TW.md)。

`scan_directory.py` 預設使用新版，`--accepted-only` 可明確執行原已接受項目分支。`different` 與 `completion_anomaly` 分別表示身分差異與完成異常，`invalid` 是原量測無效，`inconclusive` 表示原身分一致但新增檢查無法判定。後兩者退出碼為 2。

```bash

```

## 2026-11-17 公開版整理

依作者要求移除一項未發表工具的比較、程式與引用。含該項比較的混合原始封存另存於作者本機，公開版保留本方法的量測摘要與其他獨立比較。歷史驗證紀錄的總數沿用原採集單位，不作為整理後公開檔案數量的保證。
