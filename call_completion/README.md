# 同次系統呼叫完成檢查

目前入口保留原指紋與 IBLT，新增同一次 getdents64 拒絕卻回傳 0 的檢查。

[結果、成本與限制](../docs/CALL_COMPLETION_20261103_zh-TW.md)、[規約](PROTOCOL.md)、[原始封存](call_completion_20261103.tar.gz)、[逐筆重算](verification.json)、[配對成本](paired_cost.csv)。

舊 terminal_rejection 的最後 false 規則仍撤回，未重新啟用。
