# zygarde 固定版本的共同比較

功能確認使用官方 v0.2.1 Linux amd64 執行檔，先核對發布資產 SHA-256，再以原始功能選項只執行 hidden_file。為符合既有受控模組的程序名稱條件，只改執行檔的存放檔名，內容不變。獨立目錄以工具原有的 PATH 掃描功能加入，不改官方演算法。

官方執行檔的建置資訊為 Go 1.25.14、revision 814633a0e5ba018aa9dc8e9749c0375e8cf0197f 且 modified=true。這是官方資產本身的資訊，不將它冒充與另一來源快照逐位元相同。兩個提交的 file.go 與 file.bpf.c blob 已核對一致，原始碼分析仍固定為 08ccebd8fdcc28c56dc6251cad0683b7c9344bd1。

效能使用後者來源的最小轉接版，因為官方工具會掃多個系統目錄，不能直接和只掃一個目錄的本文比速度。轉接版只增加指定目錄、同目錄檢查檔與可選的列舉後稽核，沒有更動 BPF 物件、名稱集合、缺失重掃或警報規則。正式計時關閉稽核檔輸出；另次稽核計數不混入成本樣本。

三開機確認、樣本單位與失敗處理以[規約](../../finalization/COMPLETION_PROTOCOL_20261102.md)及[比較修訂](../../finalization/COMPARISON_AMENDMENT_20261102.md)為準。首次混合目錄確認未完成的逾時資料保留，不把它改為正常結果，也不與修訂後獨立目錄確認合併。

## 重建轉接版

取得固定來源及其相依，另建工作目錄，不改研究 VM 的核心或套件：

```bash
git clone https://github.com/waldh4ri/zygarde.git zygarde-comparison
cd zygarde-comparison
git checkout 08ccebd8fdcc28c56dc6251cad0683b7c9344bd1
git apply /path/to/kicba-thesis-artifact/comparison/zygarde/adapter.patch
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o zygarde-adapter ./cmd/zygarde
```

本次轉接版使用可攜 Go 1.25.0；工具鏈及來源 ZIP 的 SHA-256 見 download_provenance.json，兩個改動檔案的前後 SHA-256 見 adapter_sources.json。BPF 物件直接使用固定上游的產物，沒有在客體升級 LLVM 或重新產生。

以 KICBA_BENCH_DIR 指定目錄，KICBA_AUDIT_PATH 可另指定稽核 JSONL。正式計時不可設後者。冷啟動成本包含程序、BPF 載入／附掛、列舉、各自品質檢查、輸出與清理；本文另包含 BCC 即時編譯。它回答的是這兩個實作實際完成同目標掃描的成本，不是純雜湊或純列舉迴圈的速度。

檢查目標分開評估：共同目標為核心產生而回傳缺失的名稱；新增、inode-only 與 type-only 另列身分差異，不混算共同召回率。錯誤、跳過、逾時及事件不完整不能算作乾淨陰性。記憶體指標為 GNU time max RSS，不是核心 map 或整個程序群組同時占用的總和。

此比較沒有將官方全工具的其他檢查一併評為優劣。約十一倍及一千四百九十倍仍只屬先前自製逐項 map 基線，不套用到此工具。

來源：[上游](https://github.com/waldh4ri/zygarde/tree/08ccebd8fdcc28c56dc6251cad0683b7c9344bd1)、[官方發布](https://github.com/waldh4ri/zygarde/releases/tag/v0.2.1)。來源採 BSD 2-Clause／GPL v2 雙授權，LICENSE 隨比較轉接資訊保存。第三方完整專案及官方二進位不在本研究程式目錄重複散布。
