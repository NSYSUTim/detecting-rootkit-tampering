"""Document the added terminal signal, including its observed benign alerts."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
from build_revised37 import patch_text,NS
from build_revised35 import replace

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'paper/cross_layer_directory_entry_consistency_revised39_zhTW.docx'
OUTPUT=ROOT/'paper/cross_layer_directory_entry_consistency_revised40_zhTW.docx'

def main():
    facts=json.loads((ROOT/'terminal_rejection/verification.json').read_text());assert facts['verified']
    public=facts['public_sample'];get=[r for r in public if r['mode']=='getdents64'];fill=[r for r in public if r['mode']=='filldir']
    assert sum(r['alarms'] for r in get)==120 and sum(r['terminal_alerts'] for r in fill)==120
    benign=sum(r['terminal_alerts'] for r in facts['benign_race'].values())
    with ZipFile(SOURCE) as z:parts={i.filename:(i,z.read(i.filename)) for i in z.infolist()}
    xml=E.fromstring(parts['word/document.xml'][1]);paragraphs=xml.findall('.//w:body/w:p',NS)
    text=lambda p:''.join(p.xpath('.//w:t/text()',namespaces=NS))
    tables=[E.tostring(t,method='c14n') for t in xml.findall('.//w:tbl',NS)];edits=[]
    def edit(prefix,op):
        matches=[p for p in paragraphs if text(p).startswith(prefix)];assert len(matches)==1,(prefix,len(matches))
        p=matches[0];before=text(p);after=op(before);assert before!=after;patch_text(p,before,after);edits.append({'before':before,'after':after});return p
    def insert_before(anchor,style,values):
        for value in values:
            p=deepcopy(style);replace(p,value);anchor.addprevious(p);edits.append({'inserted':value})
    body=next(p for p in paragraphs if text(p).startswith('三次開機的 135 筆'))
    hstyle=next(p for p in paragraphs if text(p).startswith('6.9 '))
    edit('Linux 的 getdents64 透過',lambda t:
      'Linux 目錄項可能在核心接受後到 getdents64 交付前被刪改。本文以 eBPF 與專用 C 掃描器，對同次完整列舉同步建立固定大小指紋及 IBLT，'
      '比較名稱、inode 與型態。核心只計回傳 true 的最外層 filldir64，避免正常重送與巢狀重算。指紋不同形成身分差異警報，IBLT 還原少量差異的識別值、inode 與型態，'
      '並以指紋核對還原結果。初版九次開機矩陣中，576 個差異批次均檢出、720 個一致批次未警報，11,520 次差異列舉正確還原。'
      '另在兩個指定核心及 ext4／tmpfs 驗證實作條件與正常動態目錄。原版 CARAXES 測試揭露了接受規則的邊界：其 filldir 模式拒絕項目並使列舉截斷，兩端仍可一致。'
      '因此新增獨立的終止拒絕檢查，保存最後一次外層呼叫結果與被拒項目。新三開機中，原版 getdents64 與 filldir 模式各 120 次均警報，後者能指出一筆被拒項目，'
      f'不能列出未走訪的全部缺失。正常刪除競態另有 {benign}/30 次觸發相同訊號，故新警報不證明惡意或必然截斷。'
      '量測品質失效仍拒判，固定摘要仍受碰撞、容量與可信量測假設限制。新增狀態空間固定，逐項處理時間仍隨目錄規模增加，各版本的成效與成本分開報告。')
    edit('本文把偵測範圍限定在',lambda t:t+
      ' 增補版本另檢查列舉結束前最後一次外層 filldir64 是否回傳 false，形成不同於身分差異的終止拒絕訊號，見 4.4 節。')
    edit('在這些假設下，本方法偵測',lambda t:t.replace(
      '原版 CARAXES 的後一種情形已在 6.10 節實測。',
      '原版 CARAXES 的後一種情形已在 6.10 節實測。增補版本另以最後一次拒絕紀錄警報，能指出當時被拒的項目，仍無法列出後續未走訪的全部項目，見 4.4 與 6.11 節。'))
    edit('警報代表此範圍內',lambda t:t.replace('警報代表此範圍內','身分差異警報代表此範圍內')+
      ' 新增的終止拒絕警報只代表列舉結束前最後一次嘗試遭拒，正常刪除也可形成相同訊號，不作惡意判定。')
    captions=[p for p in paragraphs if text(p).startswith('圖 1')];assert len(captions)==1
    p=captions[0];before=text(p);after=before+' 此圖呈現已接受項目的身分比對路徑，終止拒絕檢查另見 4.4 節。';patch_text(p,before,after)
    methodanchor=next(p for p in paragraphs if text(p).startswith('5. 實作'))
    insert_before(methodanchor,hstyle,['4.4 列舉結束前的拒絕訊號'])
    insert_before(methodanchor,body,[
      '保留前述指紋、IBLT、還原核對與量測品質門檻，另保存最後一次最外層 filldir64 呼叫的回傳值與項目身分。'
      '專用 C 掃描器只在反覆呼叫 getdents64 取得 0 且解析成功後正常結束。量測有效且正常結束時，若最後一次外層回傳 false，即增加終止拒絕警報。'
      '因此整體警報為有效量測下「指紋不同，或終止拒絕」。錯誤回傳、缺少終止觀測、呼叫計數不符與任何品質門檻失敗均維持無效，不能提升為正常或警報。',
      '兩條警報路徑分別保留。指紋不同仍嘗試 IBLT 差異還原，終止拒絕則另提供最後被拒項目的名稱、識別值、inode 與型態。'
      '兩端一致但終止拒絕時，不將被拒項目加入 IBLT 差集，也不稱為完整還原。後續沒有經過觀測點的項目與外部缺失總數仍未知。'
      '名稱由入口取得並與識別值核對，一次僅保存一筆，不能說只多一個位元。指紋與 256 格 IBLT 配置不變，核心每執行緒狀態由 10,400 增為 10,696 位元組，增加固定 296 位元組。',
      '這個訊號不專屬隱藏。正常緩衝區拒絕的項目若在重送前被刪除，可能使最後一次外層結果停在 false。'
      '也不能把「下一次一定接受」或「正常最後一定是 true」當成所有環境的通則。重掃只能提供另一個觀察，無法證明第一次的原因。'
      '本研究以正常刪除的受控競態直接檢驗此限制，見 6.11 節。'])
    edit('本文依實驗用途區分四種實作',lambda t:t+
      ' 第五種是本次終止拒絕增補版，另存衍生 BPF 來源，現行 scan_directory.py 使用此版。原 tracefs 比對器、C 掃描器與舊資料保留，6.4、6.8 與 6.9 節成本仍對應增補前版本。')
    edit('6.10 原版 CARAXES',lambda t:t+' 增補前版本')
    edit('為檢驗自行縮減模組以外的公開樣本',lambda t:'本節保存加入終止拒絕檢查之前的實測，增補後另見 6.11 節。'+t)
    resultsanchor=next(p for p in paragraphs if text(p)=='7. 討論')
    insert_before(resultsanchor,hstyle,['6.11 終止拒絕檢查的驗證與正常刪除案例'])
    insert_before(resultsanchor,body,[
      '在同一 Linux 6.8.0-138-generic／ext4 虛擬機，另以三個新開機驗證新版本。原版 CARAXES 的來源、模組及兩種掛接順序維持前組設定，'
      '正常狀態共 60 次有效一致，原版 getdents64 模式 120 次維持指紋警報並正確還原，原版 filldir 模式 120 次皆有終止拒絕警報。'
      '後者兩端摘要仍一致，新版本另外指出最後被拒的 last_caraxes，未宣稱還原原目錄缺少的全部項目，也沒有將新舊分母合併。'
      '同場固定 zygarde 轉接版的兩模式各 15 次有目標警報，filldir 仍同時有檢查檔品質提示。此條件下新規則補足原本的警報缺口，不構成全面優勢。',
      f"原有受控狀態另做 {facts['regression']['n']} 次回歸，包含四個不改內容的掛接對照，以及重排、新增、長短改名、inode、型態、移除、隱藏、政策過濾及等量替換。"
      f"原預期輸出、指紋判讀與還原皆符合逐次核對，{facts['unexercised_attempts']} 次受限緩衝空間未實際注入的動作另計，不當成成功陽性。"
      f"正常 ext4／tmpfs 靜態目錄 {facts['normal']['n']} 次，並行建立、改名與刪除的動態目錄 {facts['dynamic']['n']} 次，其終止拒絕警報依原始結果分別為 {facts['normal']['terminal_alerts']} 與 {facts['dynamic']['terminal_alerts']} 次。"
      '這些結果只代表受測排程與變動，不能據此證明所有正常情況均無警報。',
      f"受控正常刪除競態共 30 次，不載入惡意模組，先讓正常緩衝區拒絕候選項目，再於下一次讀取前刪除。ext4 的終止拒絕警報為 {facts['benign_race']['ext4']['terminal_alerts']}/15，tmpfs 為 {facts['benign_race']['tmpfs']['terminal_alerts']}/15。"
      'tmpfs 的候選項目刪除後未再被接受，新規則因此警報，證明該訊號不能單獨判斷惡意隱藏。ext4 的受測流程仍交付已刪除的候選項目，最後結果為 true。'
      '不能將任一結果推成所有檔案系統的固定行為，亦未估計這種競態在實際使用中的發生機率。',
      '另外，各檔案系統的真實 getdents64 錯誤及受控刪除終止讀回欄位，各三開機合計六次，均維持無效而未警報。'
      '51 項單元測試檢查新警報不取消舊警報、不虛構差集、品質失效優先及名稱與識別值核對。來源、試跑、未實際注入動作、正常競態與所有警報均保存。'
      '本組沒有重跑原 1,296 批矩陣或成本基準，因此不能把原零誤報率與耗時數字當作新版本的整體保證。'])
    edit('列舉完整性檢查涵蓋',lambda t:t+
      ' 終止拒絕增補版另要求終止觀測可用且外層返回數等於入口數，所提供的被拒項目不併入 IBLT 還原清單。')
    edit('本文以 eBPF 與專用 C 掃描器',lambda t:t.replace('固定大小指紋負責警報','固定大小指紋負責身分差異警報').replace(
      '原版 CARAXES 另以三開機確認','增補前版本的原版 CARAXES 另以三開機確認')+
      f' 新增終止拒絕規則後，另一組三開機的原版 filldir 模式 120 次均警報並提供一筆被拒項目。正常刪除競態也有 {benign}/30 次相同警報，'
      '因此目前結果區分已接受項目的身分差異與終止拒絕訊號，後者不能保證惡意或完整定位，原版本的零誤報與成本數字不回填新版本。')
    edit('這是尚未實作的觀測架構提案',lambda t:t.replace(
      '原版 filldir 的拒絕與提前截斷是另一個已觀察到的邊界，增加函式庫端觀測點本身不能解決。若另以涵蓋此類隱藏為目標，須研究如何區分正常緩衝區重送與刻意拒絕，或提供獨立目錄參照，這會改變目前的判定目標，尚未實作。',
      '原版 filldir 的終止拒絕現已另以新訊號警報，但正常刪除也可觸發，區分原因與還原未走訪項目仍未解決。增加函式庫觀測點本身不能補回這些項目。'))
    edit('研究重現套件公開於',lambda t:t+
      ' 終止拒絕新版本與三開機、正常刪除競態另存 terminal_rejection，可由其中 summarize.py 從封存重算。')
    assert tables==[E.tostring(t,method='c14n') for t in xml.findall('.//w:tbl',NS)]
    full=''.join(xml.xpath('.//w:t/text()',namespaces=NS));assert not any(s in full for s in ('；',';','補充實驗','主實驗'))
    with ZipFile(OUTPUT,'w') as z:
        for name,(info,data) in parts.items():z.writestr(info,E.tostring(xml,xml_declaration=True,encoding='UTF-8',standalone=True) if name=='word/document.xml' else data)
    (ROOT/'terminal_rejection/paper_changes.json').write_text(json.dumps({'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'output_sha256':hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),'edits':edits,'old_tables_unchanged':True},ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    print(OUTPUT)
if __name__=='__main__':main()
