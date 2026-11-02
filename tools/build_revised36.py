"""Append verified matched scan-cost evidence while preserving revised35."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
from lxml import etree as E
from build_revised35 import text,replace,NS,W

ROOT=Path(__file__).resolve().parents[1]


def main():
    source=ROOT/'paper/cross_layer_directory_entry_consistency_revised35_zhTW.docx'
    assert hashlib.sha256(source.read_bytes()).hexdigest()=='b0c1fe6d6d825f77be4990e9927596d442fd84833abf0a61e8663ec8e0733ce5'
    data=json.loads((ROOT/'comparison/scan_cost/verification.json').read_text(encoding='utf-8'));assert data['passed']
    facts=json.loads((ROOT/'comparison/scan_cost/facts.json').read_text(encoding='utf-8'))
    with ZipFile(source) as z:parts={i.filename:(i,z.read(i.filename)) for i in z.infolist()}
    doc=E.fromstring(parts['word/document.xml'][1]);paras=doc.findall('.//w:p',NS)
    changes=[]
    def edit(p,value):
        changes.append({'before':text(p),'after':value});replace(p,value)
    def span(size,method):
        values=facts['ranges'][str(size)]['median_ms'][method]
        return '–'.join(f'{v:.2f}' for v in values) if values else '觀測不完整'
    abstract=next(p for p in paras if text(p).startswith('Linux 的 getdents64 透過'))
    value=text(abstract)
    old=value[value.index('相同目錄的新程序完整成本中'):value.index('貢獻是同次已接受項目')]
    new=('相同目錄的新程序完整成本在小、中目錄較高。追加三開機、45 個配對區組，比較準備完成後的掃描判讀，本文於小目錄較慢，65,536 項時為 '
         +span(65536,'ours')+' ms，配 32 MiB 且觀測完整的 zygarde 轉接版為 '+span(65536,'zygarde_32m')+' ms。')
    assert old in value;edit(abstract,value.replace(old,new))
    heading=next(p for p in paras if text(p)=='5.7 與 zygarde 的共同比較設計')
    body=next(p for p in paras if text(p).startswith('使用 zygarde 官方 v0.2.1 Linux'))
    result_heading=next(p for p in paras if text(p)=='6.8 與 zygarde 的共同比較結果')
    result_body=next(p for p in paras if text(p).startswith('三開機共 360 筆工具觀察'))
    anchor6=next(p for p in paras if text(p)=='6. 結果');anchor7=next(p for p in paras if text(p)=='7. 討論')
    def insert(anchor,template,values):
        for value in values:
            node=deepcopy(template);replace(node,value.replace('manifest','目錄清單'));anchor.addprevious(node)
    insert(anchor6,heading,['5.8 準備完成後的掃描判讀成本設計'])
    insert(anchor6,body,[
      '本節另固定共同計時範圍，排除兩工具不同的編譯、載入、附掛及最終卸載，從觀測程式、事件讀取器與目錄檢查檔準備好開始，計至列舉、資料取得、比對及必要品質檢查形成判定。本文包含 C 子程序啟動、登記、分頁列舉、摘要讀回、解碼、還原核對與全部品質查詢。zygarde 包含列舉、事件讀取、名稱集合、必要重掃及上層對 findings、canary 與錯誤的狀態判定。因其清理發生在掃描與上層判定之間，實際計時分成這兩段相加，分段值另存，沒有將中間卸載或稽核序列化計入。',
      '同一 ext4 目錄有 128、4,096 或 65,536 個一般項目，另加兩工具共用且保留相同 inode 的一筆檢查檔。保留各自列舉 API，本文緩衝區 65,536 bytes，Go 1.25.0 的 os.ReadDir 以 8,192-byte 緩衝區讀取並排序[24]，不宣稱為相同內部操作或純演算法比較。zygarde 的 BPF 指令與名稱判定不改，預設 4 MiB 與只將 events map 改為 32 MiB 的配置另列，後者不是官方預設。兩者實際名稱集合在時間終點後輸出，逐筆對照獨立目錄 manifest，本文指紋也由 manifest 重算，輸入起訖均保存。',
      '三個不同開機、相同指定核心與套件，每個目錄大小一個暖機區組與五個主要區組，三方法順序隨機。合計 45 個主要配對區組、135 筆主要觀察與 27 筆暖機。逐區組相除後按開機報告中位數與 IQR，觀測未收齊、錯誤與跳過不列入完整服務的速度比較，不補抽成功樣本。最終計時版先以十二種狀態、36 筆方法觀察與十二次無探針控制確認功能，先導與修正過程分開保留。這是正常靜態目錄的實作成本，未量動態隱藏的成本。'])
    insert(anchor7,result_heading,['6.9 相同掃描判讀範圍的成本結果'])
    insert(anchor7,result_body,[
      '三次開機的 135 筆主要觀察與 27 筆暖機均保存。本文及 32 MiB 配置的主要觀察各 45 筆皆符合完整性與判讀條件。預設 4 MiB 在 128 與 4,096 項各十五筆完整，但 65,536 項的十五筆入口名稱未收齊，不作完整觀測下的速度排序。各開機五次主要觀察的中位數範圍列於表 8，配對比值及 IQR 存於重現套件。'])
    caption=next(p for p in paras if text(p).startswith('表 7'))
    insert(anchor7,caption,['表 8　觀測準備完成後至判定的耗時，各開機五次主要觀察之中位數範圍，單位 ms。zygarde 兩欄均為計時轉接版，32 MiB 非官方預設。'])
    table=deepcopy(doc.findall('.//w:tbl',NS)[0]);templates=table.findall('w:tr',NS)
    for row in list(table):
        if row.tag==W+'tr':table.remove(row)
    for i,values in enumerate([['項目數','本文','zygarde 4 MiB','zygarde 32 MiB'],
        *[[f'{size:,}',span(size,'ours'),span(size,'zygarde_4m'),span(size,'zygarde_32m')] for size in (128,4096,65536)]]):
        row=deepcopy(templates[0 if i==0 else 1])
        for cell,value in zip(row.findall('w:tc',NS),values):
            ps=cell.findall('w:p',NS);replace(ps[0],value)
            for extra in ps[1:]:cell.remove(extra)
        table.append(row)
    anchor7.addprevious(table)
    insert(anchor7,result_body,[facts['paper_result_paragraph'],
      '這組結果將啟動方式與掃描判讀成本分開，但不能把所有差距歸因於摘要演算法。兩端仍有語言、API、排序、緩衝區、子程序與品質檢查差異，32 MiB 配置也有額外容量代價。全部掃描均是同一主機、單一指定核心與正常靜態 ext4，快取未清除，每個開機每條件五次。第 6.8 節完整程序成本維持原定義，不由此將約兩秒全部歸因於 BCC 編譯，也不把新增稽核輸出的程序時間回填舊結果。'])
    discussion=next(p for p in paras if '現行入口的共同新程序成本另見 6.8 節' in text(p))
    edit(discussion,text(discussion)+' 第 6.9 節另以共同準備完成後的範圍補充掃描判讀成本，兩者回答不同使用問題，不能只選對本文有利的範圍作全面優勢宣稱。')
    conclusion=next(p for p in paras if text(p).startswith('本文提出比較 filldir64 與 getdents64'))
    edit(conclusion,text(conclusion)+' 追加的相同掃描判讀範圍比較見 6.9 節，將完整觀測與不同緩衝區配置分開。相同計時起訖不代表相同內部工作量，結果呈現實作及目錄大小的取捨。')
    reproducibility=next(p for p in paras if text(p).startswith('研究重現套件公開於'))
    edit(reproducibility,text(reproducibility)+' 新掃描判讀成本的規約、計時差異、先導、全部原始輸出與重算另存 comparison/scan_cost，可由 scripts/verify_scan_cost.py 重算，不併入原實驗及前次共同比較分母。')
    ref=next(p for p in paras if text(p).startswith('[23]'));node=deepcopy(ref)
    replace(node,'[24] The Go Authors, “os.ReadDir and Unix directory buffer implementation,” Go 1.25.0, src/os/dir.go and src/os/dir_unix.go. https://github.com/golang/go/tree/go1.25.0/src/os (accessed Nov. 2, 2026).');ref.addnext(node)
    ref21=next(p for p in paras if text(p).startswith('[21]'))
    edit(ref21,text(ref21).replace('file.go and file.bpf.c','file.go, file.bpf.c, and internal/core/runner.go'))
    all_text=''.join(doc.xpath('.//w:t/text()',namespaces=NS));assert ';' not in all_text and '；' not in all_text
    xml=E.tostring(doc,xml_declaration=True,encoding='UTF-8',standalone=True)
    output=ROOT/'paper/cross_layer_directory_entry_consistency_revised36_zhTW.docx'
    with ZipFile(output,'w',ZIP_DEFLATED) as z:
        for name,(info,payload) in parts.items():z.writestr(info,xml if name=='word/document.xml' else payload)
    work=ROOT/'_docx_work/scan_cost_20261102';work.mkdir(parents=True,exist_ok=True)
    (work/'changes36.json').write_bytes(json.dumps({'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'changed_package_parts':['word/document.xml'],'edits':changes},ensure_ascii=False,indent=2).encode())
    print(json.dumps({'output':str(output),'sha256':hashlib.sha256(output.read_bytes()).hexdigest()}))


if __name__=='__main__':main()
