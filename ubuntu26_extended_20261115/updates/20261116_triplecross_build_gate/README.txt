TripleCross 在 Ubuntu 26 / 7.0.0-43-generic 的建置關卡
更新時間：2026-11-16T15:55:00+08:00

結論：釘選的原版 h3xduck/TripleCross（commit d825d4c8c0575ad1cc9e23beab8b2e466a385fab）在本專案隔離研究 VM 上無法完整建置，未進入載入與隱藏關卡，未取得三開機偵測資料。失敗根因已釐清為真實相容性限制（BPF 512-byte stack 上限），不是暫時性環境雜訊。

範圍：共四次嘗試，皆在 Ubuntu 26.04 LTS、kernel 7.0.0-43-generic、無 default route 的隔離 VM 中、以上游自帶的 Makefile 與 libbpf／bpftool 進行。每次嘗試單獨使用 systemd-run 作為 cgroup 範圍，在乾淨開機下進行；每次嘗試之間重開機清場。工具版本記錄在 attempts/attempt_4_boot_347d215c/tool_versions.json。

四次嘗試與失敗根因

1. 並行 race（make -j4）：module_manager.c 編譯在 bpftool 生成 kit.skel.h 之前執行而找不到檔。改為序列化（make all，不加 -j）後排除。
2. 序列化後，ebpf/kit.bpf.c 經 ebpf/include/bpf/fs.h 引入 <ctype.h>，連鎖觸發 /usr/include/x86_64-linux-gnu/gnu/stubs-32.h。該檔由 gcc-multilib 提供；VM 無 default route，不能 apt install。
3. 以 build-env compat patch 移除 fs.h 的 <ctype.h>（dead-include，整個 src/ebpf grep 不到任何 ctype 函式；見 BUILD_ENV_COMPAT_PATCH.json 與 patch.diff）。同一相依鏈再次由 fs.h:12 的 <string.h> 觸發。
4. 再次以同類 patch 移除 <string.h>（dead-include；eBPF 程式一律用 __builtin_memcpy 這個 compiler builtin，不是 libc；上游 strings.h 註解本身即說「ebpf 無法使用 strcmp」）。結果編譯推進到 .output/kit.bpf.o 階段，由 clang BPF backend 擲出：

   ebpf/kit.bpf.c:67, :70, :92 皆報「Looks like the BPF stack limit is exceeded. Please move large on stack variables into BPF per-cpu array map. For non-kernel uses, the stack can be increased using -mllvm -bpf-stack-size.」

   這是真實相容性牆：kit.bpf.c 中 bpf_printk 與 xdp_receive 的呼叫鏈在新版 clang + libbpf 下累計 on-stack 使用超過 BPF 的 512-byte stack 上限。即使強行以 -mllvm -bpf-stack-size=NNN 繞過編譯，kernel BPF verifier 仍以同樣門檻在載入時拒收。

已套用的來源變動與邊界

本次僅套用兩個 dead-include 移除，兩者均在提交前以 grep 確認語意不變：
- 移除 ebpf/include/bpf/fs.h 的 #include <ctype.h>
- 移除 ebpf/include/bpf/fs.h 的 #include <string.h>

兩處合併成單一註解方塊，實際 diff 見 patch.diff，詮釋與 SHA 見 BUILD_ENV_COMPAT_PATCH.json。未修改任何 rootkit 邏輯或 Makefile 旗標；未呼叫任何上游安裝／持久化腳本。原始 upstream tarball SHA-256 記錄在 BUILD_GATE_RESULT.json，可自行以該 commit 重現。

跨越 BPF stack 限制所需的工作（未執行）

- 切割 kit.bpf.c 的 handler，讓單一呼叫鏈的 on-stack 累計不超過 512 bytes。
- 將在 stack 上的 struct 搬到 BPF_MAP_TYPE_PERCPU_ARRAY 並用 index 取用。
- 以上為對 rootkit 原始碼本體的功能性改動，超出「不修改樣本程式本身」的規範範圍，因此未進行。

可放入報告的敘述

「在 Ubuntu 26 的指定核心、以上游釘選 commit 的 TripleCross 進行建置關卡的四次嘗試中，所有嘗試均未進入載入階段。排除過並行與可驗證為 dead-code 的 libc include 之後，真正的相容性限制為 kit.bpf.c 的 on-stack 累計超過 BPF 512-byte stack 上限，由現代 clang BPF backend 擲出並由 kernel BPF verifier 在載入時以同樣門檻把關。因此本輪 TripleCross 未產生可引用的隱藏效果資料；上述結論僅為建置相容性限制。」

完成範圍僅為上述建置關卡。載入關卡、隱藏關卡、三開機矩陣均未執行；bad-bpf 與 Trace of Times 不在本更新範圍。

檔案

- BUILD_GATE_RESULT.json：四次嘗試的 boot id、make 旗標、根因、是否修改來源。
- BUILD_ENV_COMPAT_PATCH.json：兩次 dead-include 移除的理由、grep 驗證、檔案 SHA-256。
- patch.diff：完整的 unified diff（僅觸及 ebpf/include/bpf/fs.h 第 11–12 行）。
- build_gate.py：本次使用的 build 關卡 harness。
- attempts/attempt_4_boot_347d215c/：最後一次嘗試的 stderr、stdout、systemd unit 最終狀態、工具版本、bin 列目、stage 結果、summary。

本機完整四次嘗試（前三次的 build_result_<boot>/ 已在重試前清除）保留在 artifacts/ubuntu26_extended_20261116_triplecross/；GitHub 僅發佈最後一次的完整 stderr／stdout 與全部四次的 JSON 摘要。原始上游 tarball 由 commit d825d4c8c0575ad1cc9e23beab8b2e466a385fab 可自行重現取回。
