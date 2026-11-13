# IBLT 位置數離線比較（2026-11-13）

這是新做的離線敏感度實驗，不是先前研究的事前證據，也不是 Linux/eBPF 原生驗證。
規約 SHA-256：`472342278a42d6034ac267100c589a9c8e2b89c88ea9f442232db8916dcba690`。完整完成 36,864 次版本解碼，共 9,216 組配對輸入。
程式執行 285.0 秒。所有錯誤成功解碼：0。

## 事前指定主要條件：256 格、32 個差異項目

missing 與 substitution 各 1,024 次。四種 k 使用同一批輸入與種子。

| 位置數 | 正確完整還原 | 還原率 | Wilson 95% 區間 | 建表中位數 ms | 解碼中位數 ms |
|---:|---:|---:|---:|---:|---:|
| 2 | 2006/2048 | 97.9492% | 97.2397%–98.4792% | 0.7443 | 1.9075 |
| 3 | 2048/2048 | 100.0000% | 99.8128%–100.0000% | 0.8714 | 2.2856 |
| 4 | 2048/2048 | 100.0000% | 99.8128%–100.0000% | 0.9775 | 2.6128 |
| 5 | 2048/2048 | 100.0000% | 99.8128%–100.0000% | 1.0846 | 2.9428 |

主要比較採配對 exact McNemar 檢定，三項比較使用 Holm 校正。
- 3 對 2：只有 3 正確 42 次，只有對方正確 0 次；校正 p=1.36424e-12。
- 3 對 4：只有 3 正確 0 次，只有對方正確 0 次；校正 p=1。
- 3 對 5：只有 3 正確 0 次，只有對方正確 0 次；校正 p=1。

依事前規則，3 個位置的嚴格還原優勢：未獲證明。沒有證明全域最佳參數。

## 完整受測條件

下列不挑選情境；數字合併兩種模式，詳見 summary.csv 的分模式結果。

| 雜湊方式 | 角色 | 差異量 | 格數 | k=2 | k=3 | k=4 | k=5 |
|---|---|---:|---:|---:|---:|---:|---:|
| deployed_prefix | capacity_sensitivity | 32 | 512 | 100.00% | 100.00% | 100.00% | 100.00% |
| deployed_prefix | difference_stress | 128 | 256 | 38.67% | 99.80% | 100.00% | 100.00% |
| deployed_prefix | difference_stress | 64 | 256 | 91.60% | 100.00% | 100.00% | 100.00% |
| symmetric_salts | hash_family_sensitivity | 128 | 256 | 40.62% | 99.80% | 100.00% | 100.00% |
| deployed_prefix | difference_stress | 1 | 256 | 100.00% | 100.00% | 100.00% | 100.00% |
| deployed_prefix | capacity_sensitivity | 32 | 64 | 54.30% | 98.24% | 100.00% | 99.80% |
| deployed_prefix | capacity_sensitivity | 32 | 32 | 0.00% | 0.00% | 0.00% | 0.00% |
| deployed_prefix | primary | 32 | 256 | 97.95% | 100.00% | 100.00% | 100.00% |
| deployed_prefix | capacity_sensitivity | 32 | 128 | 92.77% | 99.61% | 100.00% | 100.00% |
| deployed_prefix | difference_stress | 512 | 256 | 0.00% | 0.00% | 0.00% | 0.00% |
| deployed_prefix | difference_stress | 4 | 256 | 100.00% | 100.00% | 100.00% | 100.00% |
| deployed_prefix | difference_stress | 16 | 256 | 99.80% | 100.00% | 100.00% | 100.00% |
| symmetric_salts | hash_family_sensitivity | 32 | 256 | 98.44% | 100.00% | 100.00% | 100.00% |
| deployed_prefix | difference_stress | 256 | 256 | 0.00% | 0.00% | 0.00% | 0.00% |
| symmetric_salts | hash_family_sensitivity | 256 | 256 | 0.00% | 0.00% | 0.00% | 0.00% |

## 解讀限制

- Offline Python simulation, not Linux/eBPF integration or rootkit detection accuracy
- Random unique-token inputs; no proof for adversarial hashes or general multisets
- Net difference is inserted directly as in original capacity sweep; common-stream cancellation separately checked
- 3 vs 4/5 uses a predeclared extension of deployed hashing; second family checks limited sensitivity
- Zero observed failures does not imply zero population failure probability; timings specific to this process and host

所有原始試次保存在 trials.csv；完整規則、驗證、統計及每條件時間保存在 protocol.json、validation.json、summary.json 與 summary.csv。
重現：在此資料夾保留原檔，再複製 run_experiment.py 至新的同層資料夾，依序執行 python run_experiment.py prepare 與 python run_experiment.py run。固定種子應重現還原結果，時間不會逐位元相同。
