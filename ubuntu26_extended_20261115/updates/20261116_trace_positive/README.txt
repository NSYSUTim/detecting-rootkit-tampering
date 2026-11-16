Trace of the Times 新陽性資料
更新時間：2026-11-16T15:30:00+08:00

結論：同一個 Ubuntu 26 / 7.0.0-43-generic 新開機下，用先前凍結的四情境 Trace 模型與門檻對新陽性批次評分。四個校準情境、每情境 10 批、共 40 批（4,000 次列舉）；ls_basic 的 10 批列入觀測但不含在原來的四情境分割，不列入靈敏度。

搭配先前已發佈的新正常對照（20261116_trace_normal/），本更新提供這組新開機下的點估：

- fun 方法：陽性 40/40 皆告警（sensitivity 1.000）；配合新正常 FPR 9/40（0.225），precision 0.816，F1 ≈ 0.899。
- seq 方法：門檻 0.0，決策規則要分數小於門檻，因此任何批次都不會告警；陽性 0/40，正常 0/40，F1 無法定義。

這是「同一組凍結模型與門檻、不新 refit」的情況下對新資料的一次點量測。單一開機，沒做跨開機、重複試驗或 bootstrap，不足以當 J19 完整重跑。

範圍與方法

- 樣本：kicba_d7_hiding.ko，由 attack_variants/d7_controls_r2/kicba_d7_hiding.ko（上游釘選版本）；linux.py 以 insmod ... magic_word=caraxes counter_comm=ls 插入，probing.py 每批結束以 rmmod 卸除。
- 情境與批次數：default、file_count、filename_length、system_load、ls_basic 各 10 批，每批 100 次列舉，共 5,000 次列舉；與新正常對照同配額。
- 隨機種子：20261116。每個情境的 --hidden-files／--visible-files／--file-name-length 由 f"{SEED}:{scenario}:{index}" 的 Random 決定。
- 評分：trace_heldout.fit() 由四情境訓練分割重建；每批 fun／seq 分數與原凍結門檻比較；score < threshold 視為 correct_rootkit，否則 missed_rootkit。ls_basic 無模型，列為 outside_calibrated_scenarios。

正式結果（本單一新開機、點估）

各情境本次陽性 10/10 fun correct_rootkit（default、file_count、filename_length、system_load），seq 10/10 missed_rootkit。細節見 RESULTS.json。合併新正常與新陽性的 TP/FP/TN/FN 與 F1 見 COMBINED_NORMAL_POSITIVE.json。

比較基準

- 新正常對照（已發佈）：fun FPR 9/40，seq FPR 0/40。
- 新陽性（本次）：fun TP 40/40，seq TP 0/40。
- 新 F1（fun）：約 0.899；seq 的 precision 為 0/0 無法定義。

限制

- 單一新開機、無多次重複、無 refit 門檻；與先前 Ubuntu 22 實驗的 F1=0.9901 不直接比較，因為那是跨多開機、跨配置的結果。此資料僅說明「新環境下、沿用舊模型與舊門檻的一次點量測」。
- seq 的門檻 0.0 搭配「score < 0 才告警」的規則，在本次資料與新正常對照上都不告警。這是門檻／分數分佈本身的事實，不是本次新資料的問題。
- 本次用的 kicba_d7_hiding 模組由上游釘選版本編譯；未修改原始程式。probing.py、kernel.c、data_classes.py、ls-basic、linux.py 的 SHA-256 保存在 PROTOCOL.json。

證據與版本

- upstream probing.py 位於 artifacts/ubuntu26_lts_full_rerun_20261114/observations/trace_sources/；本次 collect_positive.py 的 insmod 參數為 magic_word=caraxes counter_comm=ls。
- 凍結模型與門檻：ubuntu26_extended_20261115_run02/trace_heldout_protocol.json、trace_frozen_thresholds.json（均比對 SHA-256）。
- 本機完整原始 50 批 .json.gz、probing stdout／stderr、原始 tar 位於 artifacts/ubuntu26_extended_20261116_trace_positive/，GitHub 僅發佈協定、COLLECTION.jsonl、RESULTS.json、COMBINED_NORMAL_POSITIVE.json、兩個執行腳本。
- 搭配本更新的新正常對照見 ubuntu26_extended_20261115/updates/20261116_trace_normal/。

可放入報告的敘述

「在 Ubuntu 26 的指定核心、以凍結的四情境 Trace of the Times 模型與門檻對新一組 40 批陽性（kicba_d7_hiding 載入下）與 40 批正常批次評分：fun 方法陽性 40/40 皆告警，與正常 9/40 誤報的組合在本單一新開機下的點估為 precision ≈ 0.816、recall = 1.000、F1 ≈ 0.899；seq 方法門檻 0.0 下任何批次皆不告警，無新敏感度或 F1。這是不新 refit 的單一新開機點量測，不等同於原 Ubuntu 22 跨配置實驗的 F1=0.9901 結果。」

完成範圍僅為上述單一新開機陽性與匹配的 F1 計算。完整 J19（跨多次正常／陽性開機、refit 門檻、bootstrap）仍未完成。
