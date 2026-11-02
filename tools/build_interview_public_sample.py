"""One-page research summary, updated from the author's supplied PDF content."""
import json
from pathlib import Path
from docx import Document
from docx.shared import Cm,Pt,RGBColor
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

ROOT=Path(__file__).resolve().parents[1]

def main():
    facts=json.loads((ROOT/'comparison/public_rootkit/verification.json').read_text());assert facts['verified']
    doc=Document();s=doc.sections[0]
    s.page_width=Cm(21);s.page_height=Cm(29.7)
    s.top_margin=s.bottom_margin=Cm(1.55);s.left_margin=s.right_margin=Cm(1.65)
    normal=doc.styles['Normal'];normal.font.name='Microsoft JhengHei';normal.font.size=Pt(10)
    normal.element.rPr.rFonts.set(qn('w:eastAsia'),'Microsoft JhengHei')
    normal.paragraph_format.line_spacing=1.05;normal.paragraph_format.space_after=Pt(5)
    title_style=doc.styles['Title'];title_style.font.name='Microsoft JhengHei'
    title_style.font.color.rgb=RGBColor(0,0,0)
    title_style.element.rPr.rFonts.set(qn('w:eastAsia'),'Microsoft JhengHei')
    for border in title_style.element.xpath('./w:pPr/w:pBdr'):border.getparent().remove(border)
    title=doc.add_paragraph(style='Title');title.paragraph_format.space_after=Pt(4)
    r=title.add_run('跨層目錄項一致性檢查');r.bold=True;r.font.size=Pt(17)
    p=doc.add_paragraph('以 eBPF 指紋與 IBLT 檢查 filldir64 與 getdents64 間的身分差異')
    p.paragraph_format.space_after=Pt(3)
    doc.add_paragraph('國立中山大學 資訊工程學系｜江威廷')
    blocks=[
      ('研究問題','同一次 Linux 目錄列舉中，核心已接受的項目與使用者實收記錄是否一致？若不同，能否還原差異？警報表示交付不一致，不直接判定惡意。'),
      ('方法','專用 C 掃描器反覆呼叫 getdents64 至回傳 0。eBPF 觀測 filldir64 入口與返回，只計回傳 true 的最外層呼叫，排除緩衝區不足的正常重送與巢狀重算。以 PID 配對同次列舉，兩端同步建立固定大小指紋與 256 格 IBLT。身分含名稱、inode、型態。先檢查量測品質，有效時指紋不同即警報，再核對 IBLT 還原結果；定位失敗不取消警報。還原值不含原始名稱。'),
      ('相關方法','完整性檢查尋找程式碼或資料竄改，Trace of the Times 觀察時間分布，跨視圖法與 zygarde 比較不同來源的清單。本文著重同次接受規則、完整身分、固定摘要及量測失效處理，不主張率先觀測 filldir64。'),
      ('受控驗證','九次開機矩陣共 1,296 批：576 個差異批次均警報，720 個一致批次均未警報，11,520 次差異列舉正確還原。兩指定核心與 ext4／tmpfs 的另一組測試，4,560 次實際差異均檢出並還原，480 次正常動態列舉均一致。受測入口與返回探針漏失會拒判。正常動態結果不代表動態隱藏攻擊的偵測率。'),
      ('原版公開樣本','另固定 CARAXES 官方版本，於 Linux 6.8／ext4 做三次開機，測兩種掛接順序及兩種緩衝區。getdents64 模式 120 次均警報並正確還原，正常對照 60 次均一致。filldir 模式 120 次雖有清單缺失，卻未警報：原版回傳 false，拒絕項目與後續未走訪項目不在已接受摘要中，兩端因而一致。同場 zygarde 轉接版對兩種模式各 15 次皆有目標警報；filldir 同時有檢查檔不可見提示，不代表完整還原。'),
      ('成本與取捨','摘要各端約 12 KiB，逐項處理時間仍隨目錄規模增加。65,536 項的準備完成後掃描判讀約 88–89 ms，觀測完整的 32 MiB zygarde 轉接版約 462–469 ms；本文的新程序完整耗時較高。各數字來自不同既定流程，不能直接歸因於摘要演算法或宣稱全面優勢。'),
      ('限制','實驗限同一實體主機，假設量測程式可信。指紋可能碰撞，種子未保護，IBLT 受容量與重複差異限制。兩端一致不能證明沒有隱藏；原版 filldir 的提前截斷即為實測例子。未涵蓋更早排除、函式庫過濾與規避量測的攻擊。'),
      ('下一步','擬增設函式庫 readdir 觀測點，對齊「核心接受、系統呼叫回傳、函式庫交付」，研究差異所在區段，尚未實作。這項延伸不能直接解決原版 filldir 的提前截斷，若要涵蓋它，須另研究拒絕行為判讀或獨立參照。'),
    ]
    for heading,body in blocks:
        p=doc.add_paragraph();p.add_run(heading+'｜').bold=True;p.add_run(body)
        p.paragraph_format.widow_control=True
    p=doc.add_paragraph('版本：2026-11-02｜原始紀錄、規約與重算入口見 GitHub comparison/public_rootkit')
    p.runs[0].font.size=Pt(8)
    output=ROOT/'paper/interview_research_summary_public_sample_zhTW.docx'
    doc.save(output)
    print(output)

if __name__=='__main__':main()
