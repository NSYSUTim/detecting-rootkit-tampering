# Historical source retained after a comparison was withdrawn.
# Its original paragraph offsets and archived source hashes no longer
# describe the public copy. Do not regenerate historical reports.
if __name__ == "__main__":
    raise SystemExit("Historical generator retired after selective public cleanup")
"""One-page summary with separate identity and per-call completion evidence."""
import json
from pathlib import Path
from docx import Document
from docx.shared import Cm, Pt, RGBColor
from docx.oxml.ns import qn
ROOT = Path(__file__).resolve().parents[1]

def main():
    facts = json.loads((ROOT / 'call_completion/verification.json').read_text())
    assert facts['verified']
    large = [r for r in facts['paired_cost'] if r['size'] == 65536]
    timing = '%.1f–%.1f' % (min((r['call_completion_median_ms'] for r in large)), max((r['call_completion_median_ms'] for r in large)))
    doc = Document()
    section = doc.sections[0]
    section.page_width = Cm(21)
    section.page_height = Cm(29.7)
    section.top_margin = section.bottom_margin = Cm(1.5)
    section.left_margin = section.right_margin = Cm(1.65)
    normal = doc.styles['Normal']
    normal.font.name = 'Microsoft JhengHei'
    normal.font.size = Pt(10)
    normal.element.rPr.rFonts.set(qn('w:eastAsia'), 'Microsoft JhengHei')
    normal.paragraph_format.line_spacing = 1.05
    normal.paragraph_format.space_after = Pt(5)
    style = doc.styles['Title']
    style.font.name = 'Microsoft JhengHei'
    style.font.color.rgb = RGBColor(0, 0, 0)
    style.element.rPr.rFonts.set(qn('w:eastAsia'), 'Microsoft JhengHei')
    for border in style.element.xpath('./w:pPr/w:pBdr'):
        border.getparent().remove(border)
    p = doc.add_paragraph(style='Title')
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run('跨層目錄項一致性檢查')
    run.bold = True
    run.font.size = Pt(17)
    doc.add_paragraph('以 eBPF 指紋與 IBLT 檢查身分差異及同次列舉呼叫的完成異常')
    doc.add_paragraph('國立中山大學 資訊工程學系｜江威廷')
    blocks = [('研究問題', '同一次 Linux 目錄列舉中，核心已接受的項目與使用者實收是否一致？若不同，能否還原差異？另檢查是否有單次讀取拒絕項目，卻回報列舉結束的異常。兩種警報均不直接判斷惡意。'), ('身分比對', '專用 C 掃描器反覆呼叫 getdents64 至回傳 0。eBPF 只計最外層回傳 true 的 filldir64，排除正常緩衝區重送與巢狀重算。兩端同步建立 24 位元組指紋與 256 格 IBLT，身分含名稱、inode、型態。指紋不同即警報，IBLT 還原識別值、inode、型態，不含名稱，再以指紋核對。定位失敗不取消差異警報。'), ('完成檢查', '以系統呼叫入口與出口配對每次 getdents64。回傳 0 的同一次呼叫若有拒絕、沒有接受，另發完成異常警報並提供一筆被拒名稱。前一次正常拒絕不帶入後一次判斷。新增配對失效不取消有效的身分差異警報，原身分一致而完成檢查失效時，整體無法判定。'), ('相關方法', '跨視圖比較已有研究。 本文著重同次接受規則、完整身分、固定摘要、還原及品質門檻，不主張率先比較這兩個位置。'), ('受控驗證', '初版九開機矩陣中，576 個差異批次皆檢出，720 個一致批次無警報。新版本另做 960 次回歸，555 次實際差異均警報並正確還原、405 次實收一致均未警報，含 45 次未實際注入的動作，不算成功陽性。兩版本分母未合併。'), ('公開樣本與正常控制', f"新三開機以固定原版 CARAXES 測兩種附掛順序與緩衝區。getdents64 模式 120 次均維持身分警報及還原，filldir 模式 120 次均取得完成異常與被拒項目，正常 60 次未警報。正常靜態 120 次、實際重疊建立改名刪除 {facts['dynamic_all_three_operations_overlap']} 次及受控跨呼叫刪除 30 次均無新警報。另 {len(facts['dynamic_without_confirmed_overlap'])} 次動態排程未重疊操作，不算動態條件成功。先前的 tmpfs 刪除誤報案例未再觸發。"), ('可靠性與成本', f'原入口漏失 3 個窗口與返回漏失下的 48 次列舉仍拒判。實際卸除新增配對探針時，新檢查無法判定，身分差異仍警報及還原。新增核心狀態每執行緒固定 456 位元組，總值為 10,856 位元組，不含 map 配置開銷。45 組相同計時界線的成本配對中，65,536 項新版本的各開機耗時中位數為 {timing} ms，含全部檢查，編譯與附掛在區組外。'), ('限制與後續', '指紋可能碰撞，IBLT 受容量、分布及重複差異限制，假設量測可信。完成檢查只涵蓋所述拒絕與回報組合，無法還原未走訪的全部項目，也不涵蓋更早排除、函式庫過濾或規避偵測器。擬增設函式庫觀測點以判定差異區段，完整缺失清單則需另有可信參照，均尚未實作。')]
    for title, body in blocks:
        p = doc.add_paragraph()
        p.add_run(title + '｜').bold = True
        p.add_run(body)
        p.paragraph_format.widow_control = True
    p = doc.add_paragraph('版本：2026-11-03｜來源、原始紀錄與獨立重算入口：GitHub call_completion')
    p.runs[0].font.size = Pt(8)
    output = ROOT / 'paper/interview_research_summary_call_completion_zhTW.docx'
    doc.save(output)
    print(output)
if __name__ == '__main__':
    main()
