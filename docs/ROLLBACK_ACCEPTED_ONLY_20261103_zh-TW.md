# 恢復已接受項目比對

依作者要求，撤回「列舉結束前最後一次 filldir64 回傳 false 即警報」的預設功能。根目錄 `scan_directory.py` 已逐位元恢復為提交 `921319d5f0612227a14a8cad91065dfc18730092` 的接受項目比對入口，現行書面及一頁摘要也恢復為 revised39 對應版本。這是新增正常提交，不重寫 Git 歷史。

## 為什麼撤回

相同的最後一次拒絕訊號，可由兩種原因造成：原版 CARAXES 拒絕仍存在的項目，或正常緩衝區拒絕的項目在重送前被刪除。已實測的 tmpfs 正常刪除競態十五次均警報。只看該訊號無法區分原因，因此不能把它當作已可靠修補的隱藏偵測規則。重掃也只是另一個時間點的觀察。

上一步將這項仍有正常誤報的試驗接為預設入口，並不適合作為結案狀態，現已撤回。試驗程式、revised40、三開機原始資料及其正常警報保留作歷史，不刪除不利結果，也不再列為現行防護能力。

## 恢復後的範圍

目前只比較同一次完整列舉的 filldir64 已接受項目與 getdents64 實收記錄。量測有效且指紋不同才形成身分差異警報，IBLT 與還原核對保留，量測品質失效仍拒判。

原版 CARAXES 的 getdents64 模式在原三開機 120 次皆檢出並還原，正常 60 次未警報。filldir 模式的 120 次提前截斷仍未被此方法警報，這個已確認限制保持公開，不會因撤回新規則而消失。不能宣稱目前能涵蓋原版 CARAXES 的所有模式或所有檔案隱藏。

目前使用：

- [現行入口](../scan_directory.py)。
- [revised39 Word](../paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx)／[PDF](../paper/cross_layer_directory_entry_consistency_revised39_zhTW.pdf)。
- [對應摘要 Word](../paper/interview_research_summary_public_sample_zhTW.docx)／[PDF](../paper/interview_research_summary_public_sample_zhTW.pdf)。
- [原版樣本結果](ORIGINAL_CARAXES_20261102_zh-TW.md)。
- [已撤回試驗與正常刪除反例](TERMINAL_REJECTION_20261103_zh-TW.md)。

## 後續若要解決

不是已證明所有方案都不可行，而是目前沒有經過驗證、能可靠區分這兩種原因的解法。例如，可研究在同一開啟目錄中查詢被拒名稱是否仍存在，搭配 inode 身分與目錄變動證據。但查詢發生在另一個時間，還要處理改名、刪除後重建及量測失效，不能直接把「查得到」當成隱藏證明。

這是候選設計，尚未實作或驗證，本次不再自動修改方法。`fstatat` 的相對名稱可依指定目錄描述符查詢；其檔案狀態查詢不構成整次列舉的原子快照。[Linux man-pages stat/fstatat](https://man7.org/linux/man-pages/man2/stat.2.html)。

## 核對

核對入口與上述基準提交完全一致，原先已接受項目方法的原始來源及證據維持不變。原虛擬機的正式目錄未被試驗覆寫，終止拒絕程式位於獨立試驗目錄。另在原入口執行兩個正常緩衝區控制，並將試驗目錄標為撤回。所有單元測試及原版公開樣本的離線核對仍執行，結果記於 [發布核對](PUBLICATION_VERIFICATION_ROLLBACK_20261103.json)。
