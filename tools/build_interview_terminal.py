"""Update the one-page summary without concealing observed benign alerts."""
import json
from pathlib import Path
from docx import Document

ROOT=Path(__file__).resolve().parents[1]
def main():
    facts=json.loads((ROOT/'terminal_rejection/verification.json').read_text());assert facts['verified']
    doc=Document(ROOT/'paper/interview_research_summary_public_sample_zhTW.docx')
    changes={
      '方法｜':'專用 C 掃描器反覆呼叫 getdents64 至回傳 0。eBPF 記錄 filldir64 入口與返回，只將回傳 true 的最外層呼叫計入指紋與 256 格 IBLT，避免重送與巢狀重算。兩端以名稱、inode、型態比對。有效時指紋不同即形成身分差異警報，並核對 IBLT 還原。新版本另保存最後一次嘗試的結果，若結束時仍為 false，則發出終止拒絕警報並提供一筆被拒項目。這筆不併入 IBLT 差集，後續未走訪的項目與缺失總數未知。',
      '受控驗證｜':'初版九次開機矩陣共 1,296 批：576 個差異批次均警報，720 個一致批次未警報，11,520 次差異列舉正確還原。另在兩指定核心及 ext4／tmpfs，4,560 次實際差異均檢出並還原，480 次正常動態列舉均一致。這些是原版本結果，不能當作新增規則後的整體零誤報保證。',
      '原版公開樣本｜':'固定 CARAXES 官方版本、兩種掛接順序與兩種緩衝區。增補前 getdents64 模式 120 次檢出，filldir 模式 120 次截斷但兩端一致而未警報。新三開機中，getdents64 模式 120 次維持警報與還原，filldir 模式 120 次皆觸發終止拒絕警報，並指出最後被拒項目。正常對照 60 次一致。同場 zygarde 對兩模式各 15 次有目標警報，filldir 同時有檢查檔品質提示。',
      '成本與取捨｜':'指紋及 IBLT 配置不變，新增固定 296 位元組的核心狀態以保存終止結果與一筆名稱。舊版 65,536 項的準備完成後掃描判讀約 88–89 ms，完整觀測的 32 MiB zygarde 轉接版約 462–469 ms；本文新程序完整耗時較高。這些成本沒有用新規則重跑，不代表新版本耗時或純演算法優勢。',
      '限制｜':f"正常刪除競態也可觸發新訊號：受測 ext4 為 {facts['benign_race']['ext4']['terminal_alerts']}/15，tmpfs 為 {facts['benign_race']['tmpfs']['terminal_alerts']}/15。終止拒絕不能單獨證明隱藏或惡意，也不能完整還原截斷後的項目。兩端一致仍不保證沒有其他隱藏。實驗限同一主機，假設量測程式可信，指紋可能碰撞，種子未保護，IBLT 受容量與重複差異限制。",
      '下一步｜':'規劃增加函式庫 readdir 觀測點，對齊核心接受、系統呼叫回傳與函式庫交付，研究差異區段，尚未實作。此延伸不能直接判定終止拒絕的原因或補回未走訪項目。',
    }
    for p in doc.paragraphs:
        for prefix,value in changes.items():
            if p.text.startswith(prefix):
                p.clear();p.add_run(prefix).bold=True;p.add_run(value)
        if p.text.startswith('版本：'):p.text='版本：2026-11-03｜規約、逐次資料及重算入口見 GitHub terminal_rejection'
    target=ROOT/'paper/interview_research_summary_terminal_zhTW.docx';doc.save(target);print(target)
if __name__=='__main__':main()
