# filldir64 與 getdents64 相關方法比較

本研究核對同一次列舉中 filldir64 已接受的項目與 getdents64 回傳項目。指紋辨認差異，IBLT 還原容量內的觀測差集，完成檢查另處理受測的拒收後結束異常。方法與結果見[同次呼叫完成檢查](CALL_COMPLETION_20261103_zh-TW.md)。

## Synacktiv 的事件調查

[Synacktiv 的 CoRIIN 2026 展示](https://www.synacktiv.com/sites/default/files/2026-04/synacktiv-coriin_2026-analyse_linkpro_ebpf_aws.pdf)第 35 頁展示 filldir64 的核心端名稱輸出，供與一般列舉結果對照。這項資料支持跨視圖觀測的研究背景。本文採已接受身分、固定摘要、差集解碼與量測品質檢查，並保留所測條件及容量限制。

| 項目 | Synacktiv 公開展示 | 本研究 |
|---|---|---|
| 核心觀測 | 逐筆名稱輸出 | 最外層 filldir64 成功接受的項目 |
| 比較身分 | 名稱 | 名稱位元組、inode、型態 |
| 輸出 | 名稱紀錄 | 固定指紋與 IBLT，容量內解出身分差異 |
| 成效證據 | 事件分析展示 | 自製受控模組與公開樣本的獨立實驗 |

## 其他方法及實測範圍

[Trace of the Times](https://doi.org/10.1145/3770085)使用核心函式時間分布。本文依公開評估器執行，另行記錄正常校準後凍結門檻的評估。專題比較使用自製 kicba_d7_hiding 模組，各方法分開收集，分母保留於[Trace 結果](D9_TRACE_FORMAL_RESULTS_zh-TW.md)及[Ubuntu 26 後續評估](../ubuntu26_extended_20261115/updates/20261116_final_remaining_results/FINAL_RESULTS_AND_REPORT_CONCLUSION.md)。

Decloaker v0.0.9 在自製 filldir 列舉隱藏下檢查 raw ext4 的完整路徑可存取性。本方法 180/180 陽性告警，Decloaker 0/180，兩者在 540 個控制中均無告警。該條件保留完整路徑的存取能力，結果的解讀見[Decloaker 正式比較](D9_DECLOAKER_FORMAL_RESULTS_zh-TW.md)。

逐筆記錄比較器由本研究自行實作，以 BPF map 保存項目的名稱、inode 與型態。65,536 項的舊版共同計時流程為本方法 221.62 ms、逐筆記錄 2,480.72 ms，邏輯資料量分別為 12.02 KiB、17,920.55 KiB。這些值限該版本及量測範圍，來源見[原共同量測](D9_CONFIRMATORY_RESULTS_zh-TW.md)。

公開樣本延伸由本方法執行，涵蓋 CARAXES、Singularity、brokepkg、Medusa、BDS userland、libprocesshider 與 bad-bpf pidhide。各樣本的有效性、控制與解碼分母另列。

## 研究限制

兩端差異是異常證據，惡意判斷需要授權及其他線索。解碼受容量、碰撞與重複身分限制。固定摘要不代表固定掃描時間或整工具記憶體。觀測完整性與同核心信任假設，以及未受測環境，均限制覆蓋主張。

## 業界證據支持哪些研究問題

部分來源直接證明目錄列舉觀測區間與實際攻擊有關，部分來源支持事件規模或嚴重性。觀測點與事件的對應是依原文描述修改位置作的機制分析。這項對應與本研究對固定樣本所做的效果測試，各有自己的證據。

| 來源 | 已核對事實 | 對本研究的支持 |
|---|---|---|
| Virus Bulletin 2025 圖 13 | 選定的 20 個核心層家族中，12 個掛接 getdents64，在所列系統呼叫中數量最高 | 對應列舉介面的樣本內量化證據。分母限該集合，不能改寫為全體攻擊盛行率 |
| Synacktiv LinkPro | AWS EKS 入侵中，以 eBPF 修改 getdents/getdents64 的回傳記錄 | 直接支持 K/S 區間的實際營運重要性 |
| Elastic SANSAR | GPU 主機事件中以 ftrace 包裝 getdents64，原呼叫返回後刪除或跳過目錄項 | 直接支持 K/S 區間，並提供 GPU 運算場景 |
| Elastic PUMAKIT | 樣本分析明列 getdents_hook/getdents64_hook 過濾名稱 | 支持相同介面的機制重現。該文章的樣本來源是 VirusTotal，沒有提供這種攻擊的母體發生率 |
| ESET Ebury | 較新版本以 readdir/readdir64 隱藏檔案與程序 | 直接支持 S/L 的動機。自 2009 年累計近 40 萬台是 Ebury 整個活動的受害規模 |
| Mandiant UNC3886 | 間諜行動使用 REPTILE 與 MEDUSA 衍生版 | 主要支持嚴重性及實務使用。MEDUSA 的 LD_PRELOAD 機制與 S/L 有關。事件變種與本研究的上游測試版本各自標示 |
| NSA/FBI Drovorub | 具國家歸責的核心 rootkit，具有檔案、程序與連線隱藏能力 | 支持威脅重要性。若在 filldir64 之前排除項目，便落在 K 之前 |
| CARAXES 與 Diamorphine 的本機紀錄 | CARAXES 有效果測試；釘選 Diamorphine 在指定核心載入失敗 | 支持實驗效果或相容性。這兩項本機紀錄本身無法給出產業受害規模 |

原始來源見 [VB2025](https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/Unmasking-the-unseen-a-deep-dive-into-modern-Linux-rootkits-and-their-detection.pdf)、[LinkPro](https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis)、[SANSAR](https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware)、[PUMAKIT](https://www.elastic.co/security-labs/threat-command/declawing-pumakit)、[Ebury 白皮書第 19 頁起](https://web-assets.esetstatic.com/wls/en/papers/white-papers/ebury-is-alive-but-unseen.pdf)、[UNC3886](https://cloud.google.com/blog/topics/threat-intelligence/uncovering-unc3886-espionage-operations)及 [Drovorub](https://media.defense.gov/2020/Aug/13/2002476465/-1/-1/0/CSA_DROVORUB_RUSSIAN_GRU_MALWARE_AUG_2020.PDF)。

## 原始來源已提供的防禦

上述文獻包含既有偵測與調查方法。VB2025 的內容涵蓋 rootkit 偵測。LinkPro 提供 YARA，Synacktiv 在 CoRIIN 2026 投影片第 35 頁另展示 filldir64 名稱觀測。SANSAR 提供 YARA 與 IoC。PUMAKIT 提供 EQL/KQL、syslog、模組載入與 YARA 偵測。Ebury 提供可信 shell 與 userland rootkit 查核。UNC3886 及 Drovorub 另提供獵捕、鑑識、特徵或平台強化建議。

因此，本文以這些來源支持觀測介面的實務重要性，並以自己的實驗評估同次列舉的身分摘要、差集定位及有效性檢查。現有證據沒有建立「這個觀測點最缺乏通用解法」的比較排名，也無法僅憑文獻未描述某個設計便證明世界上沒有其他解法。
